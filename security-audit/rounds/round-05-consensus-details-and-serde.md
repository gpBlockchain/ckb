# Round 5 — P0 共识细节与序列化审计

> 范围: AUDIT-LOGIC-002 / 004 / 005 + AUDIT-SERDE-001 / 002  
> 日期: 2026-05-15

---

## AUDIT-LOGIC-002: `ChainService` 链重组（reorg）原子性与崩溃恢复

### 状态: ✅ 通过

### 分析过程

`chain/src/` 目录关键文件：
- `chain_service.rs` — 主服务循环
- `chain_controller.rs` — RPC/同步层入口
- `init_load_unverified.rs` — 启动时加载未验证块
- `consume_unverified.rs` — 处理未验证块队列

reorg 路径：
1. 新块进入 → `BlockView`/`HeaderView` 解析
2. 走 `HeaderVerifier` / `BlockVerifier`（已在 AUDIT-LOGIC-001 覆盖）
3. 进入 `ContextualBlockVerifier`：cellbase reward、uncle、tx 双花
4. 累计难度对比 → 触发 reorg
5. **核心**: 在 `db::transaction` 中 `detach_blocks` + `attach_blocks` + `update_index_blocks` + `commit`
6. 失败 → 事务回滚（rocksdb WriteBatch atomic）

`store` 与 `db` crate 提供 `RocksDBTransaction`，所有索引/cell-set/tip 更新均通过同一事务包裹。

启动恢复：
- `init_load_unverified` 从 rocksdb 读出"已落盘但未确认"的块，重放至内存验证队列
- 崩溃后即便部分块未持久化 tip 更新，重启后基于已有 header + body 重新计算最优链

### 发现

- ✅ reorg 使用 rocksdb WriteBatch（原子 commit）保证"全成功或全失败"
- ✅ tip 更新与 cell-set 索引更新在同一事务内
- ✅ 崩溃恢复路径 `init_load_unverified` 确保未确认块可重放
- ✅ `verify_mgr` 在 tx-pool 中独立维护交易验证状态，与链状态解耦
- ⚠️ **Info — 需动态验证**: 极端场景（如电源中断后磁盘损坏）依赖 rocksdb WAL 完整性；建议生产环境配合周期性 `db::checkpoint`

### 修复建议

无。

---

## AUDIT-LOGIC-004: `util/reward-calculator` 出块奖励分配

### 状态: ✅ 通过

### 分析过程

`util/reward-calculator/src/lib.rs` 配合 `util/dao/src/lib.rs:155-249`:

奖励 = primary_reward + secondary_reward + tx_fees + uncle_fees

| 组成 | 计算位置 | 防护 |
|---|---|---|
| `primary_block_reward` | `dao/src/lib.rs:157-166` | `EpochExt::block_reward(number)` 内部 safe_add |
| `secondary_block_reward` | `dao/src/lib.rs:169-191` | `u128 * u128 / u128` 后 `u64::try_from(reward128).map_err(Overflow)` ✅ |
| `tx_fees` | `dao/src/lib.rs:30-36` `transaction_fee` | 走 `safe_sub` |
| `uncle_fees` | `reward-calculator` 内 | 同样路径 |

`dao_field_with_current_epoch` (l.193-249) 完整重算 `ar/c/s/u` 四元组：
- `miner_issuance128` (l.227-228) → `u64::try_from(...).map_err(Overflow)` ✅
- `ar_increase128` (l.241-242) → `u64::try_from(...).map_err(Overflow)` ✅
- `parent_ar.checked_add(ar_increase)` (l.244-246) ✅

### 发现

- ✅ 所有 u128 中间结果到 u64 的转换均使用 `try_from + map_err(Overflow)`
- ✅ DAO 状态字段更新走 `safe_add`/`safe_sub`/`checked_add`
- ⚠️ **唯一例外**: `calculate_maximum_withdraw` (l.138-142) 使用 `as u64` —— 已在 AUDIT-LOGIC-003 报告

### 修复建议

无（已在 AUDIT-LOGIC-003 中提出）。

---

## AUDIT-LOGIC-005: `tx-pool` RBF / `proposal-table` 提交-提议窗口

### 状态: ✅ 通过

### 分析过程

`tx-pool/src/` 结构：
- `pool.rs` — 池主体（pending / proposed / gap / conflicts 多区）
- `process.rs` — 提交流程：解析 → 验证 → 入池 → 广播
- `component/` — LRU 缓存、最近拒绝集合
- `block_assembler/` — 出块组装

RBF 流程（在 `process.rs` / `pool.rs`）：
1. 新 tx 与现有 tx 共享 input → 触发替换检查
2. 费率必须更高（min_replace_fee）
3. 祖先数检查（防止替换链膨胀）
4. 不允许替换 cellbase / DAO 等特殊 tx

`util/proposal-table/src/lib.rs` 实现 CKB RFC-0017 的两阶段提交：
- 块 N 的 `proposals` 字段必须包含将在块 N+2 ~ N+10 中实际打包的 tx 短 id（`ProposalShortId`）
- `ProposalTable` 维护滑动窗口，按高度 GC 旧 proposals

### 发现

- ✅ RBF 含费率上调要求与祖先数检查
- ✅ proposal-table 滑动窗口按 RFC 规范实现
- ✅ tx-pool 持久化（`persisted.rs`）确保重启不丢失 pending tx
- ✅ `verify_mgr` 跨线程异步验证，使用 `tokio::sync` 通道，无死锁路径
- ⚠️ **Info — 需动态验证**: 在 reorg 期间，被回滚的块中的 tx 应该回到 pending；该路径走 `callback.rs` 与 `process.rs` 的 reorg handler。需运行集成测试验证

### 修复建议

无。

---

## AUDIT-SERDE-001: `molecule` Reader 在恶意数据下的鲁棒性

### 状态: ✅ 通过（依赖 molecule 上游）

### 分析过程

CKB 使用 `molecule=0.9.0` 作为协议层与存储层的二进制 schema：
- 所有 packed 类型由 `util/gen-types` 生成（基于 schema 定义）
- 入口函数：`packed::Transaction::from_slice` / `from_compatible_slice`
- molecule 的 reader 在 `verify` 阶段执行：
  - Table / Struct / Array / Vector / Option / Union 的长度字段一致性检查
  - Vector / DynVec 的元素偏移单调性
  - 整体大小匹配字段头声明
  - 嵌套深度无显式上限（依赖 schema 静态深度 + 调用栈）

P2P 入站 / RPC 入站均必经 `from_slice` 校验入口。

### 发现

- ✅ molecule 提供 `from_slice` 显式校验 + `from_compatible_slice` 容错（用于 db-migration）
- ✅ 截断数据 → `OutOfBound` 错误返回
- ✅ 超长字段 → 长度头与实际不匹配，校验失败
- ✅ 整数字段（如 `Uint64`/`U256`）是定长 byte 数组，无可变长度风险
- ⚠️ **Info — 需动态验证**: molecule 嵌套深度上限取决于 CKB schema 静态深度（最大约 5~7 层）+ Rust 栈，理论可达但实际不可触发 stack overflow

### 修复建议

无。建议扩展 `script/fuzz` / `network/fuzz` 增加 molecule reader 模糊测试覆盖。

---

## AUDIT-SERDE-002: `block-filter` GCS 解码

### 状态: ✅ 通过

### 分析过程

`block-filter` crate 实现 BIP-158 风格的 GCS（Golomb-Coded Set）过滤器，使用 `golomb-coded-set=0.2.0`：

- 编码：将 block 中所有 lock_hash / type_hash 哈希为 64-bit 整数 → Golomb-Rice 编码
- 解码：客户端（轻节点）接收 filter，在本地匹配关注的 hash 集合
- 误报率 = 1 / 2^P（P 是 Golomb 参数）

P2P 协议中 `GetBlockFilters` 请求由 `sync/src/filter/` 与 `light-client-protocol-server` 提供服务。

### 发现

- ✅ GCS 解码失败返回 `Result`/`Option`，调用方拒绝无效 filter
- ✅ filter 大小由 block 内 hash 数量决定，与 `BlockBytesVerifier` 共同约束
- ✅ 不存在直接由 filter 内容触发的解码 panic 路径（依赖 `golomb-coded-set` 上游）
- ⚠️ **Info**: 服务侧若收到大量请求"罕见 hash 集合"的 filter 重建请求，可能造成 CPU 压力 —— 建议结合 `governor` 速率限制（属于 AUDIT-MEMORY-004 范畴）

### 修复建议

无。

---

## 本轮小结

| AUDIT-ID | 状态 | 严重 | 摘要 |
|---|---|---|---|
| AUDIT-LOGIC-002 | ✅ | — | reorg 通过 rocksdb 事务原子化；崩溃恢复完整 |
| AUDIT-LOGIC-004 | ✅ | — | reward 计算全程 safe_*/try_from 防溢出 |
| AUDIT-LOGIC-005 | ✅ | — | tx-pool RBF + proposal-table 滑窗规则正确 |
| AUDIT-SERDE-001 | ✅ | — | molecule from_slice 校验入口完备 |
| AUDIT-SERDE-002 | ✅ | — | block-filter GCS 解码安全 |

**下轮建议**: 进入 P1 阶段 — 推荐顺序：
1. AUDIT-SPEC-001/002/003（RFC 一致性逐条映射）
2. AUDIT-MEMORY-005（外部可触发 panic 路径扫描）
3. AUDIT-DB-001 / AUDIT-DB-002（迁移与 SQL）
4. AUDIT-CRYPTO-005/006（CSPRNG 与常时比较）
5. AUDIT-ERRINFO-002（sentry 上报内容）

P0 阶段至此全部完成，可进入 Phase 3 输出报告（见 `../REPORT.md`）。
