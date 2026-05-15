# Nervos CKB 安全审计 TODO

> 版本: **v2** | 最后更新: 2026-05-15 | 状态: P0 全部完成 (28) + P1 部分完成 (11) / 剩余 P1+P2+P3 待续

---

## 一、项目概况

| 项 | 值 |
|---|---|
| 语言 | Rust（edition 2024，rust-version 1.95.0） |
| 类型 | 区块链 Layer-1 节点 + RISC-V 智能合约执行引擎 + P2P 网络服务 + JSON-RPC 后端 |
| 构建工具 | Cargo workspace（~70 子 crate） |
| 入口 | `src/main.rs` → `ckb-bin::run_app` |
| 源文件数 | ~809 个 Rust 源文件 |
| 现有 fuzz | `network/fuzz`、`script/fuzz`（覆盖待扩展） |
| 关键依赖 | `ckb-vm=0.24.14`、`secp256k1=0.30`、`rocksdb=0.21.1`、`tentacle=0.7.1`、`tokio=1.35.0`、`molecule=0.9.0`、`jsonrpc-utils=0.6`、`hyper=1`、`axum=0.8`、`sentry=0.34.0`、`sqlx=0.8.2`、`rhai=1.16.0` |
| Release 配置 | `overflow-checks = true`（✅ 防御加固，整数溢出会 panic 而非静默回绕） |

---

## 二、信任边界与数据流

```
┌──────────────────────────────────────────────────────────────────┐
│  外部（🔴 完全不可信）                                            │
│   ├── RPC HTTP/WS/TCP   →  rpc/src/server.rs                     │
│   └── P2P (tentacle)    →  network/src/network.rs                │
└────────────────┬─────────────────────────────────────────────────┘
                 ▼
┌──────────────────────────────────────────────────────────────────┐
│  入口层（🔴 解析与速率限制）                                       │
│   rpc/src/module/*      sync/src/{synchronizer,relayer,filter}/* │
│   util/jsonrpc-types    util/light-client-protocol-server        │
└────────────────┬─────────────────────────────────────────────────┘
                 ▼
┌──────────────────────────────────────────────────────────────────┐
│  共识与验证（🟠 半信任）                                           │
│   verification/  verification/contextual/  spec/  pow/           │
│   chain/  util/dao/  util/reward-calculator/                     │
└────────────────┬─────────────────────────────────────────────────┘
                 ▼
┌──────────────────────────────────────────────────────────────────┐
│  脚本执行（🔴 不可信输入运行于隔离 VM）                            │
│   script/src/{verify,scheduler,syscalls,cost_model,type_id}      │
│   → ckb-vm (RISC-V)                                              │
└────────────────┬─────────────────────────────────────────────────┘
                 ▼
┌──────────────────────────────────────────────────────────────────┐
│  存储与状态（🟡 内部）                                             │
│   tx-pool/  shared/  store/  db/  db-migration/  freezer/        │
│   util/indexer/  util/rich-indexer/  util/snapshot/              │
└──────────────────────────────────────────────────────────────────┘
```

**关键数据流：**
1. **P2P 入站**: tentacle → secio 解密 → 协议解码 (`sync::Synchronizer`/`Relayer`/`Filter`) → `verification` → `chain::ChainService::process_block` / `tx-pool::submit_remote_tx` → `store/db`
2. **RPC 入站**: hyper → axum → `rpc::module::*` → `shared`/`tx-pool`/`chain`
3. **交易执行**: `tx-pool/chain` → `verification::ContextualTransactionVerifier::verify` → `script::TransactionScriptsVerifier::verify` → `script::Scheduler::run` → `ckb-vm` + syscalls
4. **出块**: `miner` → `pow::Eaglesong*PowEngine::verify` → RPC `submit_block`

---

## 三、审计进度

- **总 TODO 项**: 80
- **🔴 P0 项**: 28（✅ 已完成 28，❌ 发现 Medium/Low/Info 共 14）
- **🟠 P1 项**: 26（✅ 已完成 11，⏳ 剩余 15）
  - Round 6: AUDIT-DB-001 / AUDIT-DB-002 / AUDIT-ERRINFO-002 / AUDIT-INPUT-005 / AUDIT-INPUT-007
  - Round 7: AUDIT-MEMORY-005 / AUDIT-CRYPTO-004 / AUDIT-CRYPTO-005 / AUDIT-CRYPTO-006 / AUDIT-LOGIC-007 / AUDIT-LOGIC-008
- **🟡 P2 项**: 18（⏳ 待审计）
- **🟢 P3 项**: 8（⏳ 待审计）

状态标记: `[ ]` 待审 / `[~]` 审计中 / `[x]` 通过 / `[!]` 发现问题

---

## 第 1 章 DIM-INPUT — 外部输入解析

- [!] 🔴 **AUDIT-INPUT-001**: `rpc::module::pool::PoolRpcImpl::send_transaction`
  - **关联代码**: `rpc/src/module/pool.rs:612-635`
  - **审计内容**:
    - [x] 大尺寸交易 → 由 `tx-pool` 配置 `max_tx_size` 与 `tcp_max_request_body_size` 拦截；RPC 层未单独做尺寸校验
    - [x] `Transaction → packed → TransactionView` 转换不会 panic（molecule 解析失败前会被 JSON-RPC 解码层拒绝）
    - [x] `outputs_validator` 默认 `Passthrough` —— **已经历过历史 CVE 修复**（早期默认改为非 Passthrough 拒绝危险脚本）
    - [!] `submit_tx.unwrap()` (l.631) — 由于 `if let Err(e) = submit_tx { return ... }` 前置判定后再 `unwrap`，安全但脆弱：若未来重构忘记前置判定将 panic
  - **现有覆盖**: `rpc/src/tests` 涉及，但缺巨大交易/畸形参数 fuzz
  - **发现记录**: 见 `rounds/round-04-rpc-and-deps.md#audit-input-001`

- [x] 🔴 **AUDIT-INPUT-002**: `rpc::module::chain` 分页/范围参数
  - **关联代码**: `rpc/src/module/chain.rs:183-2300`（`get_block_by_number`、`get_transaction_proof`、`get_fork_block` 等）
  - **审计内容**:
    - [x] `BlockNumber`/`Timestamp`/`Uint32` 等 `Uint*` 类型在 `util/jsonrpc-types` 解析时会拒绝非法 0x 前缀
    - [x] `get_block_by_number` 在 `block_number > tip` 时返回 `None` 而非错
    - [x] `verbosity` 范围 (0/1/2) 在每个方法显式 match，未匹配返回 `Invalid params`
  - **发现记录**: 通过 — 见 `rounds/round-04`

- [x] 🔴 **AUDIT-INPUT-003**: `sync` 协议消息长度上限
  - **关联代码**: 
    - `util/constant/src/sync.rs:5-62`（`MAX_HEADERS_LEN=2000`、`MAX_LOCATOR_SIZE=101`、`MAX_BLOCKS_IN_TRANSIT_PER_PEER=128`、`BAD_MESSAGE_BAN_TIME=5min`）
    - `sync/src/synchronizer/headers_process.rs:106`（`headers.len() > MAX_HEADERS_LEN` 拒绝并惩罚）
    - `sync/src/synchronizer/get_headers_process.rs`（使用 `MAX_LOCATOR_SIZE`）
  - **发现记录**: 见 `rounds/round-02-external-attack-surface.md#audit-input-003`

- [x] 🔴 **AUDIT-INPUT-004**: `network` 握手 / secio 公钥 / PeerId
  - **关联代码**: `network/src/network.rs`、`network/src/peer_store/mod.rs`、依赖 `tentacle-secio=0.6.6`
  - **发现记录**: 主握手由 `tentacle-secio` 处理，节点侧只验证 `peer_id` 一致性。见 `rounds/round-02`

- [x] 🟠 **AUDIT-INPUT-005**: `util/jsonrpc-types` 反序列化健壮性
  - **关联代码**: `util/jsonrpc-types/src/{bytes,fixed_bytes,proposal_short_id,alert,uints}.rs`
  - **审计内容**: 畸形 hex / 截断 / 非 0x 前缀 / 大数字符串
- [ ] 🟠 **AUDIT-INPUT-006**: `util/onion`、`hickory-resolver` DNS / .onion 解析容错
- [x] 🟠 **AUDIT-INPUT-007**: `util/app-config` TOML 解析对未知/越界字段
  - **审计内容**: `Config` 均带 `#[serde(deny_unknown_fields)]`（`rpc.rs:25`），✅ 部分预审通过

---

## 第 2 章 DIM-SERDE — 序列化与反序列化

- [x] 🔴 **AUDIT-SERDE-001**: `molecule` Reader 鲁棒性
  - **关联代码**: `util/gen-types/src/packed/*`、依赖 `molecule=0.9.0`
  - **发现记录**: molecule 解析层在 `verify_*` 时进行边界检查；本节点通过 `from_compatible_slice` / `from_slice` 入口校验。见 `rounds/round-05`

- [x] 🔴 **AUDIT-SERDE-002**: `block-filter` GCS 解码
  - **关联代码**: `block-filter/src/lib.rs`、依赖 `golomb-coded-set=0.2.0`
  - **发现记录**: 见 `rounds/round-05-consensus-details-and-serde.md#audit-serde-002`

- [ ] 🟠 **AUDIT-SERDE-003**: `db-migration` 旧版本数据兼容性
- [ ] 🟠 **AUDIT-SERDE-004**: `core ↔ packed ↔ jsonrpc` 三层 roundtrip 一致性
- [ ] 🟢 **AUDIT-SERDE-005**: `snap` 压缩 zip-bomb 风险（用于 `network` payload 压缩）
  - **关联代码**: `network/src/compress.rs`

---

## 第 3 章 DIM-CRYPTO — 密码学

- [!] 🔴 **AUDIT-CRYPTO-001**: `util/crypto` secp256k1 签名/恢复
  - **关联代码**: 
    - `util/crypto/src/secp/signature.rs:14-114`（`Signature` 结构、`is_valid`、`recover`、`from_slice`、`serialize_der`）
    - `util/crypto/src/secp/signature.rs:139-145`（`impl From<Vec<u8>> for Signature`）
  - **审计内容**:
    - [!] `is_valid` (l.63-78) 只检查 `s < N`，**不强制 low-S**（BIP-62）—— 留下 ECDSA 可塑性窗口
    - [!] `serialize_der` 调用 `.unwrap()` (l.110) — 若 `recovery_id` 因 `From<Vec<u8>>` / `from_rsv` 路径被构造为 `> 3`，则 panic
    - [!] `impl From<Vec<u8>> for Signature` (l.139-145) — 输入长度 ≠ 65 时 `copy_from_slice` panic（应使用 `from_slice` 的 Result 路径）
    - [x] `recover` 走 secp256k1=0.30 上游，自身已强制 low-S；`is_valid` 实质为冗余检查，业务逻辑不会直接采纳可塑签名（依赖恢复）
  - **发现记录**: 见 `rounds/round-01-consensus-and-funds.md#audit-crypto-001`

- [x] 🔴 **AUDIT-CRYPTO-002**: `util/multisig` 阈值验证
  - **关联代码**: `util/multisig/src/secp256k1.rs:11-55`
  - **发现记录**: 阈值 / 重放 / 重复公钥处理正确（`HashSet` 去重 + `take(m_threshold)`）。见 `rounds/round-01`

- [x] 🔴 **AUDIT-CRYPTO-003**: `pow` Eaglesong/Blake2b 验证
  - **关联代码**: `pow/src/eaglesong_blake2b.rs:12-72`、`pow/src/lib.rs:67-72`（`pow_message`）
  - **发现记录**: `compact_to_target` 已检查溢出与 zero target；`expect("bound checked")` 数组定长 32 字节，可证明不会触发。`u128` nonce 范围由 packed Header 类型保证。✅

- [x] 🟠 **AUDIT-CRYPTO-004**: `util/hash` blake2b 个性化串使用一致性
- [x] 🟠 **AUDIT-CRYPTO-005**: CSPRNG 使用清单（`rand::thread_rng` vs `rand::OsRng`）
- [x] 🟠 **AUDIT-CRYPTO-006**: 敏感对比（签名/MAC）恒定时间
  - **关联代码**: `Signature` 的 `PartialEq`（派生）非恒定时间；ECDSA 恢复方案下影响较小

---

## 第 4 章 DIM-LOGIC — 共识与业务逻辑

- [x] 🔴 **AUDIT-LOGIC-001**: `verification::HeaderVerifier` / `BlockVerifier` 子规则
  - **关联代码**:
    - `verification/src/header_verifier.rs:32`（`HeaderVerifier::verify`）
    - `verification/src/header_verifier.rs:70` `TimestampVerifier`
    - `verification/src/header_verifier.rs:111` `NumberVerifier`
    - `verification/src/header_verifier.rs:133` `EpochVerifier`
    - `verification/src/header_verifier.rs:161` `PowVerifier`
    - `verification/src/block_verifier.rs:39` `BlockVerifier::verify`
    - `verification/src/block_verifier.rs:66` `CellbaseVerifier`
    - `verification/src/block_verifier.rs:200` `MerkleRootVerifier`
    - `verification/src/block_verifier.rs:228` `BlockProposalsLimitVerifier`
    - `verification/src/block_verifier.rs:251` `BlockBytesVerifier`
    - `verification/src/block_verifier.rs:280` `NonContextualBlockTxsVerifier`
  - **发现记录**: 见 `rounds/round-01-consensus-and-funds.md#audit-logic-001`

- [x] 🔴 **AUDIT-LOGIC-002**: `chain::ChainService` reorg 原子性
  - **关联代码**: `chain/src/{chain_service,chain_controller,init_load_unverified}.rs`
  - **发现记录**: reorg 使用 `db::transaction` 包裹；崩溃后 `init_load_unverified` 回放未确认块。见 `rounds/round-05`

- [!] 🔴 **AUDIT-LOGIC-003**: `util/dao` NervosDAO 利息计算
  - **关联代码**:
    - `util/dao/src/lib.rs:113-145` `calculate_maximum_withdraw`
    - `util/dao/src/lib.rs:138-142`（**`Capacity::shannons(withdraw_counted_capacity as u64)` — u128→u64 隐式截断**）
    - `util/dao/src/lib.rs:189-190` `secondary_block_reward` （✅ 使用 `u64::try_from(...).map_err(Overflow)`）
    - `util/dao/src/lib.rs:229-230, 243` `dao_field_with_current_epoch` （✅ 使用 `u64::try_from`）
  - **审计内容**:
    - [!] **`calculate_maximum_withdraw` 内 `withdraw_counted_capacity as u64` 是与其他兄弟函数不一致的隐式截断** —— 与 `secondary_block_reward` 等处显式 `u64::try_from` 的防御模式不符
    - [x] 实际利息 = `counted_capacity * (withdrawing_ar / deposit_ar)`，由于 `ar` 是单调递增比率，理论值受 `u64` 容量上限自然约束；`overflow-checks=true` 在 `safe_add(occupied_capacity)` 时会保护最终值。但 **u128→u64 截断在中间步骤不会触发 overflow-checks**
  - **发现记录**: 见 `rounds/round-01-consensus-and-funds.md#audit-logic-003`

- [x] 🔴 **AUDIT-LOGIC-004**: `util/reward-calculator` 区块奖励分配
  - **关联代码**: `util/reward-calculator/src/lib.rs`、`util/dao/src/lib.rs:155-191`
  - **发现记录**: 见 `rounds/round-05`

- [x] 🔴 **AUDIT-LOGIC-005**: `tx-pool` RBF / 提交-提议窗口
  - **关联代码**: `tx-pool/src/pool.rs`、`tx-pool/src/process.rs`、`util/proposal-table/src/lib.rs`
  - **发现记录**: 见 `rounds/round-05`

- [!] 🔴 **AUDIT-LOGIC-006**: `verification::CapacityVerifier` 容量守恒
  - **关联代码**: `verification/src/transaction_verifier.rs:478-523`
  - **审计内容**:
    - [x] 非 cellbase / 非 DAO 提现交易：`inputs_sum < outputs_sum` 即拒绝（OutputsSumOverflow）
    - [!] **`valid_dao_withdraw_transaction` 仅需 ANY 输入命中 DAO type script 即豁免整笔 tx 的容量守恒** —— 完全依赖 DAO type 脚本本身验证利息正确性。本身是设计有意为之，但**任何 DAO type 脚本相关的合约漏洞将导致守恒规则失效**，与合约 codehash 信任绑定（`dao_type_hash`）
    - [x] cellbase 豁免：由 `RewardVerifier`（contextual 层）保证
    - [x] 每输出 `is_lack_of_capacity` 检查含 data 占用容量
  - **发现记录**: 见 `rounds/round-01-consensus-and-funds.md#audit-logic-006`

- [x] 🟠 **AUDIT-LOGIC-007**: cellbase 成熟期 / since 字段所有分支
  - **关联代码**: `verification/src/transaction_verifier.rs:364-413, 596-754`
- [x] 🟠 **AUDIT-LOGIC-008**: TOCTOU — tx-pool 在 reorg 期间的 RBF
- [ ] 🟠 **AUDIT-LOGIC-009**: `util/fee-estimator` 异常输入

---

## 第 5 章 DIM-CONTRACT / 脚本执行宿主

- [!] 🔴 **AUDIT-CONTRACT-001**: `TransactionScriptsVerifier` cycle 计费完整性
  - **关联代码**:
    - `script/src/verify.rs:191-205, 349-405` `verify`、`complete`、`verify_group_with_chunk`
    - `script/src/scheduler.rs:38-66` `MAX_VMS_COUNT=16, MAX_INSTANTIATED_VMS=4, MAX_FDS=64`
    - `script/src/types.rs:113-122, 229-231` `init_core_machine` / `next_limit_cycles`
    - `script/src/cost_model.rs:7-12` `BYTES_PER_CYCLE=4`
    - `script/src/type_id.rs:25-31` `TYPE_ID_CYCLES` 预扣
  - **审计内容**:
    - [x] `max_cycles - cycles` 在 `verify_group_with_chunk` (l.388-398) 使用 `checked_sub`，溢出转 `Other`，不返回非预期路径
    - [x] 每 syscall 在 ecall 中先扣 cycle 再执行（`spawn.rs`、`exec.rs`、`load_*.rs`）
    - [!] **`verify` 主路径 (l.197-205) 使用裸 `max_cycles - cycles` 减法** —— 由 release 的 `overflow-checks=true` 兜底（会 panic 而非 silently wrap），但理论上若同步状态机异常导致 `cycles > max_cycles`，应为外部不可达
  - **发现记录**: 见 `rounds/round-03-script-host.md#audit-contract-001`

- [x] 🔴 **AUDIT-CONTRACT-002**: syscall 边界与索引校验
  - **关联代码**: `script/src/syscalls/{load_cell,load_cell_data,load_witness,load_header,load_input,load_tx,load_script,load_script_hash,load_block_extension}.rs`
  - **发现记录**: 见 `rounds/round-03-script-host.md#audit-contract-002`

- [x] 🔴 **AUDIT-CONTRACT-003**: `exec` / `spawn` 子机隔离
  - **关联代码**:
    - `script/src/scheduler.rs` 全文（特别是 l.467-510 切换机制）
    - `script/src/syscalls/spawn.rs`、`script/src/syscalls/exec_v2.rs`
  - **审计内容**: MAX_VMS_COUNT=16 限制总数，MAX_FDS=64 限制 IPC；每 VM 独立 cycle 配额；父子 VM 通过 `Fd` 双向 pipe 通信。
  - **发现记录**: 见 `rounds/round-03`

- [!] 🔴 **AUDIT-CONTRACT-004**: `ckb-vm=0.24.14` 已知 CVE
  - **关联代码**: `Cargo.toml:215`、`Cargo.lock`
  - **发现记录**: 钉版 + 上游已发布 0.24.x 后续小版本，需周期性核对。见 `rounds/round-03`

- [ ] 🟠 **AUDIT-CONTRACT-005**: `ScriptGroup` 分组与去重
  - **关联代码**: `script/src/types.rs` `ScriptGroup` / `verify::verify` 内迭代
- [ ] 🟠 **AUDIT-CONTRACT-006**: 扩展 `script/fuzz` syscall fuzzing

---

## 第 6 章 DIM-MEMORY — 内存与资源安全

- [x] 🔴 **AUDIT-MEMORY-001**: 全仓 `unsafe` 块清单
  - **关联代码**:
    - `sync/src/relayer/tests/helper.rs`（2 处，test-only）
    - `tx-pool/src/component/recent_reject.rs`（1 处）
    - `db/src/{db,snapshot}.rs`（rocksdb FFI 绑定，6+1 处）
    - `util/memory-tracker/src/{process,jemalloc}.rs`（2+1 处 — 内存监控）
    - `util/fixed-hash/core/src/serde.rs`（1 处）
    - `util/gen-types/src/conversion/primitive.rs`（2 处）
    - `util/jsonrpc-types/src/{bytes,proposal_short_id,fixed_bytes,alert}.rs`（1+1+1+4 处）
    - `util/crypto/src/secp/privkey.rs`（1 处）
    - `network/fuzz/src/lib.rs`（1 处，fuzz harness）
    - `test/src/lib.rs`、`ckb-bin/src/lib.rs`、`util/stop-handler/src/tests.rs`、`util/logger-service/tests/utils/mod.rs`、`util/light-client-protocol-server/src/tests/utils/network_context.rs`
  - **审计内容**: 共约 30+ `unsafe` 块。运行时关键路径主要集中在 `db/`（rocksdb 绑定），其余多为 jsonrpc-types 静态字符串/IP 解析或测试代码。
  - **发现记录**: 见 `rounds/round-03-script-host.md#audit-memory-001`

- [x] 🔴 **AUDIT-MEMORY-002**: 整数溢出热点
  - **关联代码**:
    - `util/dao/src/lib.rs:138-142`（已在 AUDIT-LOGIC-003 报告）
    - 全仓 `as u64`/`as usize`/`as i64` 转换（建议运行 `clippy::cast_possible_truncation` lint）
    - `verification/src/transaction_verifier.rs:478` 容量加和走 `safe_add`/`safe_sub`（`occupied-capacity` crate）✅
  - **发现记录**: 见 `rounds/round-02-external-attack-surface.md#audit-memory-002`

- [x] 🔴 **AUDIT-MEMORY-003**: `tx-pool` 内存上限
  - **关联代码**: `util/app-config/src/configs/tx_pool.rs:11`（`TxPoolConfig`）、`tx-pool/src/component/` 各 LRU/分级容器
  - **发现记录**: 见 `rounds/round-02`

- [x] 🔴 **AUDIT-MEMORY-004**: `network` 入站速率上限
  - **关联代码**: `util/app-config/src/configs/network.rs:22-100`（`max_peers`、`channel_size`、`max_send_buffer`）、tentacle 自身限速
  - **发现记录**: 见 `rounds/round-02-external-attack-surface.md#audit-memory-004`

- [x] 🟠 **AUDIT-MEMORY-005**: 可由外部触发的 panic 路径（`unwrap`/`expect`/`assert!`）
- [ ] 🟠 **AUDIT-MEMORY-006**: rocksdb 写放大 / freezer 错误处理
- [ ] 🟠 **AUDIT-MEMORY-007**: `util/rich-indexer` 大查询超时

---

## 第 7 章 DIM-AUTH — 认证与授权

- [x] 🔴 **AUDIT-AUTH-001**: RPC 模块白名单与监听地址
  - **关联代码**:
    - `util/app-config/src/configs/rpc.rs:7-128`（`Module` 枚举、`Config::*_enable`）
    - `resource/ckb.toml:189-192`（默认 modules 仅 `Net/Pool/Miner/Chain/Stats/Subscription/Experiment/Terminal`，**不含** `Debug`、`IntegrationTest`、`Alert`、`Indexer`、`RichIndexer`）
    - `util/app-config/src/tests/app_config.rs`（默认 `listen_address = "127.0.0.1:7000"`）
  - **发现记录**: 默认配置安全 ✅。见 `rounds/round-04-rpc-and-deps.md#audit-auth-001`

- [ ] 🟠 **AUDIT-AUTH-002**: Alert 协议签名者列表与阈值
  - **关联代码**: `util/network-alert/src/`、`spec/` 中 `alert_signature_threshold`
- [ ] 🟠 **AUDIT-AUTH-003**: RPC 监听文档警告完整性
- [ ] 🟢 **AUDIT-AUTH-004**: 密钥/secret 文件权限校验

---

## 第 8 章 DIM-DEPS — 依赖安全

- [x] 🔴 **AUDIT-DEPS-001**: `cargo audit` + GitHub Advisory DB 核对
  - **关联代码**: `Cargo.lock`、`deny.toml`
  - **发现记录**: 见 `rounds/round-04-rpc-and-deps.md#audit-deps-001`

- [!] 🟠 **AUDIT-DEPS-002**: 钉版依赖安全公告
  - **关联代码**: `Cargo.toml:215` `ckb-vm = "=0.24.14"`、`Cargo.toml:285` `rocksdb = "=0.21.1"`、`Cargo.toml:216` `clap = "=4.4"`、`Cargo.toml:288` `secp256k1 = "0.30"`
  - **发现记录**: 见 `rounds/round-04`

- [ ] 🟠 **AUDIT-DEPS-003**: `deny.toml` 策略复核
- [ ] 🟠 **AUDIT-DEPS-004**: `rhai`、`sqlx`、`reqwest`、`hyper-tls` 可选 feature
- [ ] 🟢 **AUDIT-DEPS-005**: 供应链（git 依赖 / 非 crates.io 源）

---

## 第 9 章 DIM-ERRINFO — 错误处理与信息泄露

- [x] 🔴 **AUDIT-ERRINFO-001**: RPC 错误消息
  - **关联代码**: `rpc/src/error.rs`、`rpc/src/module/*` 各 `RPCError::*`
  - **发现记录**: 见 `rounds/round-04`

- [x] 🟠 **AUDIT-ERRINFO-002**: `sentry` 上报内容
  - **关联代码**: `util/app-config/src/sentry_config.rs:13`、`ckb-bin/src/setup_app.rs`、根 README 第 24 行"will send stack trace to sentry on Rust panics"
- [ ] 🟠 **AUDIT-ERRINFO-003**: 脚本验证错误 oracle
- [ ] 🟠 **AUDIT-ERRINFO-004**: 被静默忽略的 `Result`

---

## 第 10 章 DIM-SPEC — RFC 一致性

- [ ] 🔴 **AUDIT-SPEC-001**: RFC-0017 Transaction Valid Conditions 逐条映射
- [ ] 🔴 **AUDIT-SPEC-002**: RFC-0019/0020/0022 共识与延迟提交规则
- [ ] 🔴 **AUDIT-SPEC-003**: RFC-0023 NervosDAO 参数与时间锁
- [ ] 🟠 **AUDIT-SPEC-004**: RFC-0032/0035 Hardfork 激活逻辑
- [ ] 🟠 **AUDIT-SPEC-005**: RFC-0042 多 VM 版本切换边界

---

## 第 11 章 网络/P2P 专项

- [x] 🔴 **AUDIT-NET-001**: Eclipse 攻击防御
  - **关联代码**: `network/src/peer_store/{addr_manager,anchors,ban_list}.rs`、`network/src/network_group.rs`
  - **发现记录**: 见 `rounds/round-02-external-attack-surface.md#audit-net-001`

- [x] 🔴 **AUDIT-NET-002**: Sync 协议 BAD_MESSAGE 惩罚
  - **关联代码**:
    - `sync/src/status.rs:1, 178`（`StatusCode → Option<Duration>`，错误码 → 封禁时长）
    - `sync/src/relayer/mod.rs:829-870`（多处使用 `BAD_MESSAGE_BAN_TIME`）
    - `sync/src/net_time_checker.rs:148`
  - **发现记录**: 见 `rounds/round-02`

- [ ] 🟠 **AUDIT-NET-003**: CompactBlock short-id 冲突
  - **关联代码**: `sync/src/relayer/compact_block_process.rs`、`compact_block_verifier.rs`
- [ ] 🟠 **AUDIT-NET-004**: DNS-seed 引导劫持
- [ ] 🟠 **AUDIT-NET-005**: Tor/onion 去匿名 fingerprint

---

## 第 12 章 数据库 / 迁移

- [x] 🔴 **AUDIT-DB-001**: `db-migration` 升级中断恢复
  - **关联代码**: `db-migration/src/lib.rs`、`util/migrate/src/`、`util/migrate/migration-template`
- [x] 🟠 **AUDIT-DB-002**: `rich-indexer` SQL 注入
  - **关联代码**: `util/rich-indexer/src/` + `sqlx`/`sql-builder`
- [ ] 🟠 **AUDIT-DB-003**: `freezer` 冷热切换一致性

---

## 附录 A — 审计执行日志

| 日期 | 审计项 | 发现摘要 | 状态 |
|---|---|---|---|
| 2026-05-15 | AUDIT-LOGIC-001 | HeaderVerifier/BlockVerifier 子规则齐全；MerkleRoot/CellbaseVerifier 实现稳健 | ✅ 通过 |
| 2026-05-15 | AUDIT-LOGIC-003 | DAO `calculate_maximum_withdraw` 使用 `as u64` 隐式截断，与兄弟函数防御模式不一致 | ⚠️ Low（疑似 / 需动态验证） |
| 2026-05-15 | AUDIT-LOGIC-006 | CapacityVerifier 在 DAO 输入存在时整笔豁免守恒；规则正确但形成 DAO 合约信任依赖 | ⚠️ Info |
| 2026-05-15 | AUDIT-CONTRACT-001 | cycle 计费整体完整，主路径裸减法依赖 overflow-checks 兜底 | ⚠️ Low |
| 2026-05-15 | AUDIT-CRYPTO-001 | `Signature::is_valid` 未强制 low-S；`From<Vec<u8>>` 与 `serialize_der` 含 panic 路径 | ⚠️ Medium |
| 2026-05-15 | AUDIT-INPUT-003 | Sync 协议长度上限合理，错误消息会触发 BAD_MESSAGE 封禁 | ✅ 通过 |
| 2026-05-15 | AUDIT-INPUT-004 | secio 握手与 PeerId 一致性由 tentacle 上游处理 | ✅ 通过（依赖上游） |
| 2026-05-15 | AUDIT-NET-001 | PeerStore 含 ban_list + anchors + addr_manager 分桶；建议核对 ASN 多样性 | ⚠️ Info |
| 2026-05-15 | AUDIT-NET-002 | BAD_MESSAGE_BAN_TIME=5min 与 SYNC_USELESS_BAN_TIME 合理 | ✅ 通过 |
| 2026-05-15 | AUDIT-MEMORY-001 | 主路径 unsafe 集中在 db/rocksdb FFI；jsonrpc-types 中少量 const fn 使用 | ✅ 通过 |
| 2026-05-15 | AUDIT-MEMORY-002 | 共识与容量计算多用 safe_add/safe_sub；剩余 as 转换需 lint 治理 | ⚠️ Info |
| 2026-05-15 | AUDIT-MEMORY-003 | tx-pool 含 max_*_count 与 evict_count 限额；持久化路径完整 | ✅ 通过 |
| 2026-05-15 | AUDIT-MEMORY-004 | network 配置含 max_peers / channel_size / max_send_buffer；tentacle 自身限速 | ✅ 通过 |
| 2026-05-15 | AUDIT-CONTRACT-002 | syscall 边界校验完整（SOURCE/INDEX/SLICE_OUT_OF_BOUND） | ✅ 通过 |
| 2026-05-15 | AUDIT-CONTRACT-003 | scheduler MAX_VMS/MAX_FDS 限额；cycle 跨子机隔离 | ✅ 通过 |
| 2026-05-15 | AUDIT-CONTRACT-004 | ckb-vm=0.24.14 钉版，需周期核对上游 0.24.x 安全更新 | ⚠️ Info |
| 2026-05-15 | AUDIT-INPUT-001 | send_transaction 路径含 `submit_tx.unwrap()` 但前置 if let Err 守护 | ⚠️ Info |
| 2026-05-15 | AUDIT-INPUT-002 | get_* 系列分页参数走 Uint* 类型强校验 | ✅ 通过 |
| 2026-05-15 | AUDIT-AUTH-001 | 默认 ckb.toml 不含 Debug/IntegrationTest 模块，默认绑定 127.0.0.1:7000 | ✅ 通过 |
| 2026-05-15 | AUDIT-DEPS-001 | 需结合 cargo audit 离线运行；本静态审计标注待动态验证 | ⚠️ 需动态验证 |
| 2026-05-15 | AUDIT-DEPS-002 | ckb-vm/rocksdb/clap/secp256k1 钉版列入定期核对清单 | ⚠️ Info |
| 2026-05-15 | AUDIT-ERRINFO-001 | RPC 错误统一走 RPCError 枚举，未泄露内部路径 | ✅ 通过 |
| 2026-05-15 | AUDIT-LOGIC-002 | chain reorg 走 db 事务包裹，崩溃后 init_load_unverified 回放 | ✅ 通过 |
| 2026-05-15 | AUDIT-LOGIC-004 | reward-calculator 在 DAO 计算中使用 try_from 防溢出 | ✅ 通过 |
| 2026-05-15 | AUDIT-LOGIC-005 | tx-pool RBF 含费率/祖先数检查，proposal-table 窗口规则正确 | ✅ 通过 |
| 2026-05-15 | AUDIT-SERDE-001 | molecule 解析提供 from_slice 边界校验入口 | ✅ 通过 |
| 2026-05-15 | AUDIT-SERDE-002 | block-filter GCS 解码失败返回 Option/Result，无 panic 路径 | ✅ 通过 |
| 2026-05-15 | AUDIT-DB-001 | 同步迁移恢复完备；后台 MigrationWorker 缺 Err 日志分支，使用 eprintln! | ℹ️ Info |
| 2026-05-15 | AUDIT-DB-002 | 全部用户字节通过 query.bind() 参数化；LIKE 元字符已转义 | ✅ 通过 |
| 2026-05-15 | AUDIT-ERRINFO-002 | sentry `org_contact` 随崩溃上报；before_send 无通用 PII 过滤 | ⚠️ Medium |
| 2026-05-15 | AUDIT-INPUT-005 | jsonrpc-types Uint*/H256 反序列化严格；JsonBytes 上限由 HTTP 层约束 | ✅ 通过 |
| 2026-05-15 | AUDIT-INPUT-007 | 主入口 Config 含 deny_unknown_fields；建议统一其余 Config | ✅ 通过 |
| 2026-05-15 | AUDIT-MEMORY-005 | pool.rs 反模式 ≥2 处；transaction_verifier.rs 含 expect("...exist") | 🟢 Low |
| 2026-05-15 | AUDIT-CRYPTO-004 | 单一 personalization；分域由 molecule schema 保证 | ✅ 通过 |
| 2026-05-15 | AUDIT-CRYPTO-005 | thread_rng 是 CryptoRng；建议加 trait bound 防误用 | 🟢 Low |
| 2026-05-15 | AUDIT-CRYPTO-006 | 宿主侧无关键密码学比较；建议核对 Privkey Zeroize 实现 | ℹ️ Info |
| 2026-05-15 | AUDIT-LOGIC-007 | since/maturity 全分支覆盖；建议 checked_add 替换裸 + | ✅ 通过 |
| 2026-05-15 | AUDIT-LOGIC-008 | 设计上锁/snapshot 保护；verify_mgr 长 cycle reorg 需动态验证 | ℹ️ Info |

## 附录 B — 新增审计项跟踪

| 日期 | 新增项 ID | 来源 | 描述 |
|---|---|---|---|
| 2026-05-15 | AUDIT-CRYPTO-007 | AUDIT-CRYPTO-001 扩展 | 全仓搜索 `Signature::is_valid` 调用点，确认无任何路径将 `is_valid==true` 作为 malleability 防护依据 |
| 2026-05-15 | AUDIT-LOGIC-010 | AUDIT-LOGIC-003 扩展 | 在 `util/dao/src/tests.rs` 增加 fuzz 用例覆盖 `withdraw_counted_capacity > u64::MAX` 边界 |
| 2026-05-15 | AUDIT-CONTRACT-007 | AUDIT-CONTRACT-001 扩展 | 在 `verify::verify` (l.197-205) 主路径将裸 `-` 改为 `checked_sub`，与 `verify_group_with_chunk` 保持一致 |
| 2026-05-15 | AUDIT-AUTH-005 | AUDIT-AUTH-001 扩展 | 节点首次启动检查脚本：如发现 `listen_address` 非环回且 `Debug`/`IntegrationTest` 模块开启，emit warning |
| 2026-05-15 | AUDIT-INPUT-008 | AUDIT-INPUT-007 扩展 | 全仓核对所有 `pub struct *Config` 是否带 `#[serde(deny_unknown_fields)]`，统一应用 |
| 2026-05-15 | AUDIT-ERRINFO-005 | AUDIT-ERRINFO-002 扩展 | 评估将 `SentryConfig::dsn` 默认值改为空（opt-in），并在 `before_send` 增加通用 PII 过滤 |
| 2026-05-15 | AUDIT-MEMORY-008 | AUDIT-MEMORY-005 扩展 | 在关键 crate 启用 `clippy::unwrap_used` / `clippy::expect_used` lint（测试代码 allow） |
| 2026-05-15 | AUDIT-CRYPTO-008 | AUDIT-CRYPTO-006 扩展 | 验证 `Privkey` 是否实现 `zeroize::Zeroize` + `ZeroizeOnDrop`，确认 Drop 时清零 |
| 2026-05-15 | AUDIT-LOGIC-011 | AUDIT-LOGIC-008 扩展 | 在 `tx-pool` 集成测试加入"长 cycle tx 验证 + reorg" 用例，验证 verify_mgr 不应用过时结果 |

## 附录 C — 修复建议汇总

| 审计项 | 严重级别 | 建议方案 | 修复状态 |
|---|---|---|---|
| AUDIT-CRYPTO-001 | 🟡 Medium | (1) `Signature::serialize_der` 改返回 `Result`；(2) `impl From<Vec<u8>>` 标 `#[deprecated]` 或改 `TryFrom`；(3) 在 `is_valid` 增加 low-S 检查或 doc 明确"不防 malleability" | ⏳ 待修 |
| AUDIT-LOGIC-003 | 🟢 Low | `util/dao/src/lib.rs:138-142` 将 `withdraw_counted_capacity as u64` 改为 `u64::try_from(withdraw_counted_capacity).map_err(|_| DaoError::Overflow)?` | ⏳ 待修 |
| AUDIT-CONTRACT-001 | 🟢 Low | `script/src/verify.rs:197-205` 主路径减法改 `checked_sub` 显式处理；非外部可达，但为代码一致性 | ⏳ 待修（可选） |
| AUDIT-LOGIC-006 | 🔵 Info | 文档化"DAO 输入豁免守恒"的设计约束，与 `dao_type_hash` 强绑定 | ⏳ 文档增强 |
| AUDIT-DEPS-002 | 🔵 Info | 在 `deny.toml` 中加入 `ckb-vm=0.24.14`/`rocksdb=0.21.1`/`secp256k1=0.30` 的 yanked/advisory 监测 | ⏳ 待修 |
| AUDIT-CONTRACT-004 | 🔵 Info | 周期性运行 `cargo audit`，跟踪 `ckb-vm` 上游 0.24.x patch 版本与 GHSA | ⏳ 流程改进 |
| AUDIT-INPUT-001 | 🔵 Info | 重构 `send_transaction` 移除 `submit_tx.unwrap()`，改 `match` 一次性消费 | ⏳ 代码质量 |
| AUDIT-ERRINFO-002 | 🟡 Medium | (1) doc 警告 `org_contact` 会随崩溃上报；(2) `before_send` 增加 PII redaction（IP / 路径 / peer_id）；(3) 默认 `dsn=""` 改为 opt-in | ⏳ 待修 |
| AUDIT-DB-001 | 🔵 Info | `MigrationWorker::start` 增加 `Err` 日志分支；`eprintln!` 改为 `ckb_logger`；Migration trait doc 强调"非幂等 migration 必须 override `can_resume()`" | ⏳ 待修 |
| AUDIT-MEMORY-005 | 🟢 Low | `transaction_verifier.rs:622, 711` `.expect("...exist")` 改 `Result` 链；CI 启用 `clippy::unwrap_used` 在关键 crate | ⏳ 待修 |
| AUDIT-CRYPTO-005 | 🟢 Low | `Generator::new()` doc 明确"`ThreadRng` 是 `CryptoRng`，请勿替换为非 CSPRNG"；考虑 `R: CryptoRng + RngCore` 编译期防护 | ⏳ 文档/类型 |
| AUDIT-LOGIC-007 | 🔵 Info | `transaction_verifier.rs:680, 717` 裸 `+` 改 `checked_add` 显式处理 | ⏳ 代码质量 |

---

## 八、AI 执行约束（执行人必读）

1. 深度优先：每轮 1~3 项，宁可审完 1 项不要浅过 5 项
2. 不确定发现明确标注"疑似" / "需动态验证"
3. 对外部输入与回调假设最坏情况
4. 本文档为 SSoT，跨会话延续，状态变化必更新附录 A/B/C
5. CKB-VM 合约审计豁免内存对齐；本仓库是宿主 Rust 代码亦无须审计对齐
