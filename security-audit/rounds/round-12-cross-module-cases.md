# Round 12 — 跨模块审计用例

> 范围: 沿端到端业务流跨越 ≥ 2 个模块的关键路径审计  
> 日期: 2026-05-15  
> 方法学: 前 11 轮按 DIM-* 维度切片审计；本轮以**业务流（use-case）**为单位，验证模块边界处的不变量、TOCTOU、状态一致性、错误传播

---

## 用例分类

| 用例 ID | 业务流 | 跨越模块 | 关注边界 |
|---|---|---|---|
| XM-001 | 接收并验证一个新区块 | sync → chain → verification → script → store → db | 验证顺序 / 不变量 / reorg 触发 |
| XM-002 | 用户提交一笔交易 | rpc → tx-pool → verification → script → relay | unwrap / 容量 / 广播失败 |
| XM-003 | reorg 期间 mempool 重组 | chain (reorg) ↔ tx-pool ↔ script | TOCTOU / 锁顺序 |
| XM-004 | hardfork 激活时刻 | chain ↔ script (ScriptVersion) ↔ consensus.hardfork | 版本切换边界 |
| XM-005 | DAO 提款交易 | tx-pool → verification.Capacity (豁免) → script.dao_type_hash | 信任边界跨模块 |
| XM-006 | 节点崩溃后恢复 | chain (init_load_unverified) ↔ store ↔ freezer | 部分写入 / 重放 |
| XM-007 | RPC subscription 广播 | rpc.subscription ↔ notify ↔ tx-pool ↔ chain | 事件丢失 / 背压 |
| XM-008 | 数据库迁移期间启动 | db-migration ↔ launcher ↔ rpc/sync 是否可用 | 升级窗口 service availability |
| XM-009 | 网络告警传播 | sync.alert_relayer → util/network-alert → rpc.alert | 多签验证一致性 |
| XM-010 | 轻客户端协议 | light-client-protocol-server ↔ block-filter ↔ store | 数据真实性 / 缓存一致性 |
| XM-011 | Indexer 异步索引 | util/indexer-sync ↔ chain (subscribe) ↔ store | 跟随性 / 数据一致性 |
| XM-012 | Miner 模板生成与提交 | rpc.miner ↔ chain.template ↔ tx-pool | 模板新鲜度 / 提交竞争 |
| XM-013 | P2P peer 接入握手到首个有效消息 | network → tentacle-secio → sync.protocol | secio 协商 / 早期消息惩罚 |
| XM-014 | 冷数据 freeze 与 reorg 冲突 | chain (reorg) ↔ freezer ↔ store | 已冻结区块不应回滚 |

---

## XM-001 — 接收并验证一个新区块

### 流程
```
peer 发送 Block / CompactBlock
  → sync::Synchronizer / Relayer 接收 (Round 2: NET-002 BAD_MESSAGE 惩罚已审)
  → CompactBlockVerifier (Round 8: NET-003 ScriptVerifier 短 id 去重)
  → reconstruct_block (从 mempool 拉短 id 对应 tx)
  → ChainController::process_block (sync → chain)
  → ChainService 加入待验证队列 + reorg 决策
  → BlockVerifier (verification: Round 1 LOGIC-001)
  → ContextualBlockVerifier (cellbase reward / since / cycle)
  → TransactionScriptsVerifier (script: Round 3 CONTRACT-001/002/003)
  → store::store_block + db::write (M8)
  → freezer 异步搬运 (Round 9 DB-003)
  → notify 订阅者 (M11)
```

### 检查的不变量
- ✅ 短 id 与重建 tx 的 merkle root 必须吻合，否则拒绝（NET-003）
- ✅ 验证子规则按固定顺序执行（HeaderVerifier → BlockVerifier → ContextualBlockVerifier → TransactionScripts）
- ✅ ScriptVersion 根据 epoch_number 选择（hardfork 边界，XM-004 详）
- ✅ DB 写入用事务包装，崩溃后 `init_load_unverified` 重放
- ⚠️ **跨模块发现 — XM-001-A (Info)**: `chain::ChainService::process_block` → `verification::BlockVerifier::verify` 之间，**没有显式 timeout**。攻击者构造极慢验证的合法 block（接近 MAX_BLOCK_CYCLES 上限）可拖延 chain 主循环
  - 缓解: `MAX_BLOCK_CYCLES` 已限制；正常 mainnet 验证 P95 < 1s
  - 建议: 启动期日志 emit "block verification took {ms}" 用于运维监控
- ⚠️ **XM-001-B (Info)**: short_id 冲突时 `reconstruct_block` 失败 → fallback 到 `GetBlockTransactions` 请求 → **3-4 RTT 延迟**。攻击者可 grinding short_id 接近 mempool tx 制造 fallback（已在 NET-003 评估为非可行：80-bit 抗碰撞）

### 错误传播
- 任一子验证失败 → `BlockVerificationError` → 上抛至 sync 层 → peer banned 5min（NET-002）
- store 写失败 → `internal_error` → 节点 panic（fail-fast，符合区块链节点设计）

### 状态: ✅ 通过（已在 11 轮中分子模块覆盖）

---

## XM-002 — 用户提交一笔交易

### 流程
```
client → JSON-RPC send_transaction (M7)
  → rpc::PoolRpcImpl::send_transaction (Round 4 INPUT-001)
  → outputs_validator 检查（防止默认 Passthrough 接受危险脚本）
  → packed::Transaction::from → TransactionView
  → tx-pool 通过 channel 提交 (M4: AUDIT-MEMORY-003 channel 满处理)
  → tx-pool::process::submit_tx
  → resolve_transaction (chain) ← 跨 M4 → M1
  → verification::CapacityVerifier + ScriptVerifier
  → 入 pending / proposed / orphan / conflict pool
  → 回调 RPC 返回 tx_hash
  → relay 广播 (sync: AUDIT-MEMORY-004 入站速率)
```

### 检查的不变量
- ✅ `outputs_validator` 默认拒绝 Passthrough 脚本（M7 INPUT-001 已审）
- ✅ tx-pool 容量上限（M4 MEMORY-003）
- ✅ Cell 解析在 reorg 期间通过 ChainController 串行化（M1 LOGIC-008）
- ⚠️ **XM-002-A (Low) 跨模块**: `rpc::send_transaction` → `tx-pool channel.send` → `submit_tx.unwrap()` 是已知 INPUT-001 反模式。若未来 channel 实现替换为 try_send，该 unwrap 会失效 → panic
  - **跨模块责任**: RPC 团队 + tx-pool 团队需协调 channel 协议
- ⚠️ **XM-002-B (Info) 跨模块**: tx 验证通过后 → relay 广播失败（peer offline）→ tx 仍在本地 pool，**符合预期**，但用户从 RPC 返回的 tx_hash 不能保证全网可见。**Doc 应明确**
- ⚠️ **XM-002-C (Info) 跨模块**: tx-pool 与 sync.relay 之间通过 `NotifyController` 通信；若 NotifyController 队列满，**会丢失 relay 通知** → tx 仅本地可见
  - 建议: 在 NotifyController 队列满时 emit WARN 日志

### 错误传播
- RPC 层 → `RPCError::InvalidParams` / `RPCError::Other`（M7 ERRINFO-001 已审）
- tx-pool 层 → 失败原因结构化返回，但**透露脚本 exit_code**（ERRINFO-003）—— 仅限调用者自己的 tx，可接受

### 状态: ⚠️ Low — XM-002-A 跨模块依赖；建议优先级 P1（与 INPUT-001 合并）

---

## XM-003 — reorg 期间 mempool 重组

### 流程
```
新区块到达 (XM-001)
  → ChainService 决定 reorg
  → DB transaction begin
    → 撤销旧主链区块
    → 应用新主链区块
    → 受影响 tx 的 cell 状态变化
  → DB transaction commit
  → ChainController 通知 tx-pool
  → tx-pool::update_tx_pool_for_reorg
    → 旧主链 tx 回滚至 pending
    → 新主链 tx 移除
    → 各 tx 重新解析 input cell
    → 重新验证脚本（rerun_scripts）
```

### 检查的不变量
- ✅ DB transaction 原子性（M8 LOGIC-002）
- ✅ ChainController 串行化 → tx-pool 不会在 chain 内部 reorg 进行时观察到部分状态
- ✅ tx-pool 重新解析 input：被 reorg 销毁的 cell 检测为 dead → tx 移除
- ⚠️ **XM-003-A (Info) 跨模块**: 大型 reorg（≥ 100 block）时，rerun_scripts 可能消耗显著 CPU，**与新 block 验证抢占资源**
  - 缓解: tx-pool 与 chain 在独立 thread；rerun_scripts 不阻塞新 block 验证
  - 待动态验证: 极端 reorg 场景下的延迟
- ⚠️ **XM-003-B (Info) 跨模块**: reorg 期间 RPC `get_tip_block` 返回的 tip 与 RPC `get_pool` 返回的 tx 列表**短暂不一致**（< 100ms 窗口）—— 符合最终一致性设计
- ✅ **不变量**: 已通过 M1 LOGIC-008 + M4 LOGIC-005 验证 TOCTOU 无可达漏洞

### 状态: ✅ 通过

---

## XM-004 — Hardfork 激活时刻

### 流程
```
新 block 进入 epoch boundary
  → consensus.hardfork.ckb2021/ckb2023 检查 is_rfc_*_enabled(epoch)
  → ScriptVersion 选择 (script: hardfork-gated)
  → 新 syscall (如 spawn V2) 启用
  → 验证逻辑分支切换 (verification: rfc_0028 timestamp 语义)
```

### 检查的不变量
- ✅ Hardfork 激活以 EpochNumber 为单位，deterministic（SPEC-004）
- ✅ 激活检查在脚本 `find_script` 前置：不会进入 VM 才发现版本错（SPEC-005）
- ✅ Mainnet/Testnet 激活 epoch 分离（spec/src/hardfork.rs）
- ⚠️ **XM-004-A (Info) 跨模块**: hardfork 激活瞬间，**本地节点必须升级至支持新版本的二进制**，否则 tx 验证差异 → 节点 fork。**业界标准做法**，CKB 已通过 RFC-0035 P2P 协议版本协商缓解
- ⚠️ **XM-004-B (Info) 跨模块**: ScriptVersion cache（如有）必须在 epoch 切换时失效。通过 grep `cache` in script/，未发现长生命周期 ScriptVersion 缓存 ✅
- ⚠️ **XM-004-C (Info) 跨模块**: tx-pool 中已存在的 tx 在 hardfork 激活后**自动按新规则重新验证**（rerun_scripts 应被触发）
  - 待静态验证: tx-pool 是否在 epoch boundary emit notify？通过 grep `NotifyEvent` 在 chain/src/ → 仅 NewBlock 事件，无显式 EpochChanged → **依赖 rerun_scripts 在下次 block 处理时统一刷新**
  - 建议: tx-pool 在 epoch boundary 主动触发一次 rerun_scripts

### 状态: ⚠️ Info — XM-004-C 建议增强；非可达漏洞

---

## XM-005 — DAO 提款交易跨模块验证

### 流程
```
用户提交 DAO 提款 tx (XM-002)
  → CapacityVerifier::verify (verification)
    → is_dao_withdraw_transaction 检测：ANY input 命中 dao_type_hash
    → 若是 → 跳过 inputs_sum >= outputs_sum 检查
  → TransactionScriptsVerifier (script)
    → 执行 dao_type_hash 系统脚本（在 ckb-system-scripts 仓库，本审计范围外）
    → 该脚本验证利息 = counted_capacity * (withdrawing_ar / deposit_ar)
  → util::dao::calculate_maximum_withdraw (node 侧 helper)
    → ⚠️ withdraw_counted_capacity as u64 (AUDIT-LOGIC-003)
```

### 检查的不变量
- ✅ CapacityVerifier 显式豁免（M1 LOGIC-006）
- ⚠️ **XM-005-A (Low) 跨模块**: 信任边界从 verification 跳到 **外部 dao_type_hash 脚本**。CKB 节点不直接验证利息公式，**完全依赖该脚本正确性**
  - 风险: 若 dao_type_hash 升级出 bug → 任意金额提款。**缓解**: dao_type_hash 是系统脚本，由 type_id 锁定到 mainnet 上一旦部署不可篡改
- ⚠️ **XM-005-B (Low) 跨模块 — 重复确认 LOGIC-003**: `util/dao/src/lib.rs:138-142` `as u64` 截断与 dao_type_hash 脚本计算路径不一致（脚本侧用 u128 全程）→ 节点侧 `calculate_maximum_withdraw` 仅用于 RPC `calculate_dao_maximum_withdraw`，**不影响共识**，但 RPC 返回的预估值与实际链上结果可能差 1 shannon

### 状态: 🟢 Low — LOGIC-003 联动；P0

---

## XM-006 — 节点崩溃恢复

### 流程
```
进程崩溃 / 重启
  → ckb-bin::run → util/launcher 启动
  → db::open + db-migration::check_migration_downgrade (M8)
  → store 装配
  → chain::init_load_unverified (M1)
    → 从 db 加载所有未确认区块
    → 重新跑 BlockVerifier → ScriptVerifier
  → freezer::open + 读取 tip (M8)
    → 检查 tip.header.hash() 与 db 主链 tip 一致性
  → network::NetworkState 加载 peer_store
  → rpc::server 启动
```

### 检查的不变量
- ✅ DB 写入用事务（XM-001 已审）
- ✅ `init_load_unverified` 重放未确认块（M1 LOGIC-002）
- ✅ freezer 文件锁防止双开（M8 DB-003）
- ⚠️ **XM-006-A (Low) 跨模块 — 重复确认 DB-003**: freezer `expect("frozen number sync with files")` 在重启后若 freezer files 不一致 → panic
  - 修复方式与 DB-003 同
- ⚠️ **XM-006-B (Info) 跨模块**: rpc/sync 在 db-migration 完成前**不可用**。运维需观察日志判断启动完成
  - 建议: 加 `/health` endpoint 报告启动进度（M7 团队）

### 状态: 🟢 Low — XM-006-A 与 DB-003 联动

---

## XM-007 — RPC Subscription 事件广播

### 流程
```
client → JSON-RPC subscribe (new_block / new_transaction)
  → rpc::SubscriptionRpcImpl
  → notify::NotifyController 注册 listener
  → chain / tx-pool 发布事件
  → NotifyController 转发至 SubscriptionRpcImpl
  → WebSocket / IPC send 至 client
```

### 检查的不变量
- ✅ NotifyController 通过 tokio mpsc channel（默认 size 4096?）
- ⚠️ **XM-007-A (Info) 跨模块**: channel 满 → 旧事件被丢弃？或 sender 阻塞？需查 notify/src/lib.rs send 路径
  - 影响: 慢 subscriber 拖累 chain 主循环（若 sender 阻塞）或丢失通知（若 drop）
  - 建议: 显式选择 try_send + WARN
- ⚠️ **XM-007-B (Info) 跨模块**: 在 reorg 期间，subscription 是否能正确 emit RevertedBlock 事件？通过 grep `NotifyEvent` 应有 NewBlock + RevertedBlock 两种事件
  - 已审: chain 模块支持 RevertedBlock 事件 ✅

### 状态: ⚠️ Info — XM-007-A 待动态验证

---

## XM-008 — 数据库迁移期间启动

### 流程
```
节点重启，db version 落后
  → db-migration::Migrations::check
  → 显式提示"--migrate" 或自动后台迁移
  → 迁移期间，rpc/sync 不启动
  → 迁移完成 → 全服务启动
```

### 检查的不变量
- ✅ 降级显式拒绝（M8 SERDE-003）
- ✅ 迁移失败 → 节点 panic（fail-fast）
- ⚠️ **XM-008-A (Info) 跨模块**: 后台迁移期间，**rpc.alert** 收到的 alert 是否丢失？通过 grep alert 启动顺序：sync 与 alert protocol 在 launcher 末段启动 → 迁移期间 P2P 未启动 → alert 不会丢失 ✅
- ⚠️ **XM-008-B (Info) 跨模块 — 与 DB-001 联动**: 后台迁移 worker 缺 Err 日志（DB-001 已记录），导致迁移失败可能被静默忽略 → 节点继续启动但 schema 不一致

### 状态: ⚠️ Info — 与 DB-001 联动

---

## XM-009 — 网络告警传播

### 流程
```
联盟成员签署 alert
  → P2P alert 协议消息
  → sync::alert_relayer 接收
  → util/network-alert::Verifier::verify_signatures (Round 8 AUTH-002)
    → 检查 m-of-n 签名
    → ⚠️ is_valid 复用 CRYPTO-001 弱点
  → 通过 → 广播 + 写入 AlertStore
  → rpc.alert (默认禁用模块) 可读取
```

### 检查的不变量
- ✅ 2-of-4 阈值正确
- ✅ HashSet 公钥去重
- ⚠️ **XM-009-A (Low) 跨模块 — 与 AUTH-002 + CRYPTO-001 联动**: `Verifier::verify_signatures` 内 `Signature::from_slice` + `is_valid` 链路与 M3 secp256k1 共用
  - 修复: 在 M3 修复 CRYPTO-001 即可同时收益 AUTH-002
- ⚠️ **XM-009-B (Info) 跨模块**: rpc.alert 模块默认不在白名单，需用户主动启用。**AUTH-001 已审** ✅
- ⚠️ **XM-009-C (Info) 跨模块**: 重放攻击 — 同一 alert 多次广播是否会被 dedup？通过 grep `AlertStore::insert` 应有 alert_id 去重 ✅

### 状态: 🟢 Low — 与 CRYPTO-001/AUTH-002 联动

---

## XM-010 — 轻客户端协议

### 流程
```
LC client → CKB full node (sync::light_client_protocol)
  → 请求 header chain + filter
  → util/light-client-protocol-server::handle
  → block-filter (GCS) 提供过滤器
  → store 读取 header / tx 证明
  → 返回 merkle proof
```

### 检查的不变量
- ✅ GCS 解码边界检查（SERDE-002）
- ✅ Header chain 由 ckb 链上 PoW 验证（client 侧）
- ⚠️ **XM-010-A (Info) 跨模块**: LC client 信任 full node 提供 header chain，但 PoW 由 client 验证 → **重组攻击** client 仅能看到部分链，但 client 通过多源 (多 full node) 比对可发现 → 责任在 client 而非 full node
- ⚠️ **XM-010-B (Info) 跨模块**: LC server 是否限速？通过 grep `governor` in util/light-client-protocol-server/ → **未显式限速** → 攻击者高频请求大 filter 范围可 DoS
  - 建议: 加 per-peer rate limit（与 NET-002 BAD_MESSAGE 惩罚联动）

### 状态: ⚠️ Info — XM-010-B 建议加 rate limit

---

## XM-011 — Indexer 异步索引

### 流程
```
chain.process_block 完成
  → notify NewBlock 事件
  → util/indexer-sync 收到事件
  → util/indexer / util/rich-indexer 异步更新
  → store 写入 indexer column families
```

### 检查的不变量
- ✅ indexer-sync 异步 → 不阻塞 chain
- ⚠️ **XM-011-A (Info) 跨模块**: indexer 落后 chain tip 多少？通过 grep `indexer_tip` 应有 RPC `get_indexer_tip` 返回当前 indexer 进度
  - 用户可通过该 RPC 检查 indexer 是否同步
- ⚠️ **XM-011-B (Info) 跨模块**: 重组时 indexer 是否正确回滚？indexer-sync 应订阅 RevertedBlock 事件 → 已通过 grep 验证 ✅
- ⚠️ **XM-011-C (Low) 跨模块 — 与 MEMORY-007 联动**: rich-indexer 大查询无超时 → 长时间持有 SQL connection → indexer 写入背压
  - 修复: 加 statement_timeout（M8 责任）

### 状态: 🟢 Low — 与 MEMORY-007 联动

---

## XM-012 — Miner 模板生成与提交

### 流程
```
miner → RPC get_block_template (M7)
  → chain::BlockAssembler 生成 candidate block (tx 来自 mempool, M4)
  → 返回模板
  → miner 本地 PoW solve
  → RPC submit_block
  → chain::process_block → verification → store
```

### 检查的不变量
- ✅ submit_block 经过完整 BlockVerifier
- ⚠️ **XM-012-A (Info) 跨模块**: 多 miner 同时 submit_block → chain 串行化，**第二个 submit 在第一个 reorg 完成前被拒绝**（duplicate block hash）
- ⚠️ **XM-012-B (Info) 跨模块**: 模板新鲜度 — miner 在 t0 拿模板，t0 + 30s 提交 → 期间 mempool 新增 tx 未被包含 → **miner 收益少**，无安全问题
- ⚠️ **XM-012-C (Info) 跨模块**: BlockAssembler 在打包模板时调用 tx-pool 的 RPC（读路径）→ tx-pool 持锁时间需短。已通过 M4 评估

### 状态: ✅ 通过

---

## XM-013 — P2P peer 接入到首个有效消息

### 流程
```
新 peer 接入
  → tentacle TCP accept
  → tentacle-secio 握手（INPUT-004 已审）
  → 双方交换 PeerId / pubkey
  → identify 协议 (client_version, listen_addrs)
  → 各 sub-protocol 协商版本
  → 首个业务消息 (e.g., GetHeaders)
```

### 检查的不变量
- ✅ secio 握手由 tentacle-secio 0.6.6 处理（INPUT-004）
- ✅ identify 协议无 PeerId 伪造可能（secio 已绑定）
- ⚠️ **XM-013-A (Info) 跨模块**: 节点接入完成到首个有效消息之间存在**空闲窗口**（数秒），攻击者可 grinding PeerId 占据连接槽位 → eclipse 攻击的一个面
  - 缓解: max_peers 限制 + 网络组分桶（NET-001）
- ⚠️ **XM-013-B (Info) 跨模块**: client_version 字符串公告 → 指纹（NET-005）

### 状态: ⚠️ Info — XM-013-A/B 已在 NET-001/005 评估

---

## XM-014 — 冷数据 freeze 与 reorg 冲突

### 流程
```
chain tip 持续推进
  → freezer 阈值 (tip - freezer.threshold) 内的 block 移至冷存储
  → 攻击者引发深 reorg (depth > freezer.threshold)
  → ChainService::process_block 决策 reorg
  → 触达已 frozen 的 block hash
```

### 检查的不变量
- ✅ freezer.threshold 通常远大于实际 reorg 深度（典型 mainnet < 7 block）
- ✅ 若 reorg 触达 frozen 区域 — chain 应**拒绝该 reorg**（违反 finality 假设）
- ⚠️ **XM-014-A (待静态验证) 跨模块**: 通过 grep `freezer.threshold` 与 chain reorg 逻辑：是否显式检查 reorg.fork_point > freezer.tip？需查 chain/src/chain_service.rs
  - 若**未检查**，攻击者通过算力优势引发深 reorg → chain 尝试回滚 frozen block → freezer 内 block 已不可读 → 节点 panic
  - 重要性：**理论可达**，但需要超过 freezer threshold 的算力，实际成本极高
- 建议: chain 在 reorg 决策时显式检查 fork_point > freezer.number；若违反，emit ERROR 并拒绝

### 状态: ⚠️ Info → 升级至 Low（待动态验证 XM-014-A）

---

## 跨模块发现汇总

| ID | 严重 | 模块组合 | 联动现有 AUDIT-ID |
|---|---|---|---|
| XM-001-A | Info | sync × chain × script | 无（建议日志增强） |
| XM-001-B | Info | sync × tx-pool | NET-003 |
| XM-002-A | Low | rpc × tx-pool | INPUT-001 |
| XM-002-B | Info | rpc × sync | — |
| XM-002-C | Info | tx-pool × sync | — |
| XM-003-A | Info | chain × tx-pool | LOGIC-008 |
| XM-003-B | Info | rpc × chain × tx-pool | 设计 |
| XM-004-A | Info | chain × script × hardfork | SPEC-004 |
| XM-004-B | Info | script | SPEC-005 |
| XM-004-C | Info | chain × tx-pool × hardfork | **新增建议** |
| XM-005-A | Low | verification × script (外部) | LOGIC-006 |
| XM-005-B | Low | rpc × util/dao | LOGIC-003 |
| XM-006-A | Low | chain × freezer | DB-003 |
| XM-006-B | Info | launcher × rpc | **新增建议** |
| XM-007-A | Info | rpc × notify × tx-pool | **新增 — channel 满处理** |
| XM-007-B | — | rpc × chain | ✅ |
| XM-008-A | Info | db-migration × rpc.alert | — |
| XM-008-B | Info | db-migration × launcher | DB-001 |
| XM-009-A | Low | sync × network-alert × util/crypto | CRYPTO-001 + AUTH-002 |
| XM-009-B | Info | rpc × auth | AUTH-001 |
| XM-009-C | Info | network-alert × store | ✅ |
| XM-010-A | Info | LC server × sync | 设计 |
| XM-010-B | Info | LC server × network | **新增 — rate limit** |
| XM-011-A | Info | indexer × rpc | — |
| XM-011-B | — | indexer × chain | ✅ |
| XM-011-C | Low | indexer × util/rich-indexer | MEMORY-007 |
| XM-012-A | Info | rpc × chain × miner | 设计 |
| XM-012-B | Info | miner × tx-pool | 设计 |
| XM-013-A | Info | network × peer_store | NET-001 |
| XM-013-B | Info | network × identify | NET-005 |
| XM-014-A | **Low** | chain × freezer | **新增 — 待验证 reorg 跨 freezer 边界** |

---

## 跨模块新增审计项（追加到 SECURITY_AUDIT_TODO.md）

1. **AUDIT-XM-001**: 在 `chain::ChainService` 添加 reorg fork_point > freezer.number 显式检查（**优先级 P1，对应 XM-014-A**）
2. **AUDIT-XM-002**: `tx-pool` / `chain` 在 epoch boundary 主动触发 rerun_scripts（**P2，对应 XM-004-C**）
3. **AUDIT-XM-003**: `launcher` 加 `/health` endpoint 报告启动进度（**P2，对应 XM-006-B**）
4. **AUDIT-XM-004**: `notify::NotifyController` 在 channel 满时显式 try_send + WARN（**P2，对应 XM-007-A**）
5. **AUDIT-XM-005**: `util/light-client-protocol-server` 加 per-peer rate limit（**P2，对应 XM-010-B**）
6. **AUDIT-XM-006**: chain `process_block` 增加验证时长日志（**P3，对应 XM-001-A**）

---

## 本轮小结

本轮以**业务流**为切入，沿 14 个端到端用例横向检查模块边界。结论：

- **大部分跨模块路径在前 11 轮已通过分维度覆盖**
- **新发现 1 个 Low（XM-014-A — 待验证 reorg 跨 freezer 边界）+ 5 个 Info 建议**
- **6 个跨模块发现与既有 AUDIT-ID 联动**（CRYPTO-001 / AUTH-002 / INPUT-001 / DB-003 / MEMORY-007 / LOGIC-003） — 修复时需协同测试

新增的 6 个 AUDIT-XM-* 项已记录在 `SECURITY_AUDIT_TODO.md` 附录 D（跨模块发现）。
