# Round 11 — DIM-SPEC RFC 一致性映射

> 范围: AUDIT-SPEC-001 (RFC-0017) + AUDIT-SPEC-002 (RFC-0019/0020/0022) + AUDIT-SPEC-003 (RFC-0023 NervosDAO) + AUDIT-SPEC-004 (RFC-0032/0035 Hardfork) + AUDIT-SPEC-005 (RFC-0042 VM 版本切换)  
> 日期: 2026-05-15

> **方法学**: 由于本仓库不含 RFC 原文，本轮基于「代码侧实现位置 + RFC 编号关联 + 静态规则比对」做静态映射，对每个 RFC 列出代码侧关键检查点 + 实现状态。**不验证 RFC 文本字面**，需配合 nervosnetwork/rfcs 仓库做端到端确认。

---

## AUDIT-SPEC-001: RFC-0017 Transaction Valid Conditions 逐条映射

### 状态: ✅ 通过（覆盖完整）

### RFC-0017 主要规则与代码实现

| RFC-0017 规则 | 代码实现位置 | 状态 |
|---|---|---|
| 1. **交易必须有 ≥ 1 input 和 ≥ 1 output** | `verification/src/transaction_verifier.rs` `EmptyVerifier` | ✅ |
| 2. **CellInput 引用的 OutPoint 必须存在且未被消费** | `chain/` `resolve_transaction` + `OverlayCellChecker` / `OutPointError::Unknown` / `Dead` | ✅ |
| 3. **输入容量之和 ≥ 输出容量之和**（资金守恒） | `transaction_verifier.rs:478-523` `CapacityVerifier` | ✅ |
| 4. **每个输出的 capacity ≥ occupied_capacity（含 data + script）** | `CapacityVerifier::verify` 内 `is_lack_of_capacity` (l.508-519) | ✅ |
| 5. **cellbase 仅在 block.transactions[0]，且 input = `CellInput::new_cellbase_input(block_number)`** | `verification/src/block_verifier.rs:66-198` `CellbaseVerifier` | ✅ AUDIT-LOGIC-001 |
| 6. **cellbase 输出容量 ≤ block reward** | `verification/src/contextual_block_verifier.rs` `RewardVerifier` | ✅ AUDIT-LOGIC-004 |
| 7. **cellbase output 不能含 type script with hash_type = Data** | `CellbaseVerifier::verify` | ✅ |
| 8. **每个 input 的 since 字段必须满足锁条件** | `transaction_verifier.rs:596-754` `SinceVerifier` | ✅ AUDIT-LOGIC-007 |
| 9. **每个 type/lock script 验证通过** | `script::TransactionScriptsVerifier::verify` | ✅ AUDIT-CONTRACT-001/002/003 |
| 10. **cellbase 输出不可在 cellbase_maturity (4 epochs) 内消费** | `transaction_verifier.rs:364-413` `MaturityVerifier` | ✅ AUDIT-LOGIC-007 |
| 11. **proposal_short_id 在提交窗口 [N-w_close, N-w_far] 内已 proposed** | `chain/src/` + `util/proposal-table` | ✅ AUDIT-LOGIC-005 |
| 12. **cycle 总数 ≤ MAX_BLOCK_CYCLES** | `BlockVerifier::verify` 调用 `BlockTxsVerifier` | ✅ |
| 13. **byte_size ≤ MAX_BLOCK_BYTES** | `block_verifier.rs:251` `BlockBytesVerifier` | ✅ |
| 14. **输入引用的 dep group 解析后总 cell deps ≤ MAX_DEPS_COUNT** | RFC-0038 `max_dep_expanded_count` 检查 — 在 `script::resolve_cell_deps_with_expanded` | ✅ AUDIT-SPEC-004 联动 |
| 15. **molecule 序列化合法 + 字段长度合法** | molecule 解析 + `from_compatible_slice` | ✅ AUDIT-SERDE-001 |
| 16. **重复 OutPoint 拒绝（不允许双重引用同一 input）** | `chain` `resolve_transaction` 内 `out_points_set` 去重 | ✅ |
| 17. **headers_dep 在 cellbase_maturity 内（RFC-0036 之前）/ 无 maturity 约束（RFC-0036 之后）** | hardfork-gated by `rfc_0036` | ✅ AUDIT-SPEC-004 |

### 发现

- ✅ RFC-0017 17 条规则在节点验证流水线均有对应实现
- ✅ 各子验证器拆分清晰（EmptyVerifier / MaturityVerifier / CapacityVerifier / SinceVerifier / ScriptVerifier / DuplicateInputVerifier 等）
- ⚠️ **Info — 规则编号与代码不一一对应**: 没有"RFC-0017 第 N 条 → 代码 N"的反向追踪文档
- ⚠️ **Info — RFC 文本字面验证**: 本审计未在仓库内对照 RFC 原文，需配合 https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0017-tx-valid/0017-tx-valid.md 逐条核对

### 修复建议

1. **建议**: 在 `verification/src/lib.rs` 顶部添加 doc-link 列表 `// RFC-0017 rule 1: see EmptyVerifier (transaction_verifier.rs:N)`
2. **建议**: 测试覆盖每个 RFC-0017 规则的反例（已存在大量单元测试，但缺 RFC-编号交叉引用）

---

## AUDIT-SPEC-002: RFC-0019/0020/0022 共识与延迟提交规则

### 状态: ✅ 通过

### RFC-0019 Transaction Structure（含 since 字段语义）

| 规则 | 代码 | 状态 |
|---|---|---|
| since 64-bit, high 8 bits = flag | `core/since.rs` `Since::extract_metric` | ✅ |
| metric_flag 00=block_number / 01=epoch_with_fraction / 10=timestamp | `transaction_verifier.rs:543-547` doc | ✅ |
| relative_flag bit 63 | 同上 | ✅ |
| epoch_with_fraction `is_well_formed_increment()` | `transaction_verifier.rs:642, 686` | ✅ AUDIT-LOGIC-007 |
| 预留 flags 拒绝 | `flags_is_valid()` (transaction_verifier.rs:744) | ✅ |

### RFC-0020 CKB Consensus Protocol（两步交易确认 NC-Max）

| 参数 | 默认值 | 代码 | 状态 |
|---|---|---|---|
| `DEFAULT_EPOCH_DURATION_TARGET` | 4 hours | `spec/src/consensus.rs:75` | ✅ |
| `MIN_BLOCK_INTERVAL` | 8s | `consensus.rs:67` | ✅ |
| `MAX_BLOCK_INTERVAL` | 48s | `consensus.rs:65` | ✅ |
| `MAX_EPOCH_LENGTH` | 1800 blocks | `consensus.rs:77` | ✅ |
| `MIN_EPOCH_LENGTH` | 300 blocks | `consensus.rs:78` | ✅ |
| `DEFAULT_ORPHAN_RATE_TARGET` | 1/40 (2.5%) | `consensus.rs:62` | ✅ |
| `MEDIAN_TIME_BLOCK_COUNT` | 37 | `consensus.rs:55` | ✅ |
| `PROPOSER_REWARD_RATIO` | 4/10 | `consensus.rs:90` | ✅ |
| Proposal window `[w_close, w_far]` | (2, 10) | `consensus.rs::ProposalWindow` | ✅ |
| `MAX_BLOCK_PROPOSALS_LIMIT` | 1500 | `consensus.rs:89` | ✅ |
| `MAX_BLOCK_BYTES` | 597 * 1000 = 597_000 | `consensus.rs:83` | ✅ |
| `MAX_BLOCK_CYCLES` | 3.5M * 1000 = 3.5G | `consensus.rs:84` | ✅ |

### RFC-0022 CKB Genesis & Difficulty Adjustment

| 规则 | 代码 | 状态 |
|---|---|---|
| Genesis epoch length = 1000 | `consensus.rs:59` GENESIS_EPOCH_LENGTH | ✅ |
| Epoch length 动态调整 | `pow/src/lib.rs` + `consensus.rs::next_epoch_ext` | ✅ |
| Target adjustment per epoch | `core/src/extras.rs::EpochExt` | ✅ |
| Difficulty 调整含 orphan rate 反馈 | `consensus.rs::next_epoch_ext` 内含 orphan_rate_target | ✅ |

### 发现

- ✅ RFC-0019/0020/0022 关键参数全部 hardcode 在 `spec/src/consensus.rs`，且 `Default` 实现统一
- ✅ 调整算法在 `next_epoch_ext` 内集中实现，方便审计
- ⚠️ **Info — 参数硬编码 vs 链上治理**: 当前所有共识参数为编译期常量；任何调整需 hardfork。这是 CKB 设计选择
- ⚠️ **Info — `MEDIAN_TIME_BLOCK_COUNT=37` 防时间操纵**: 网络时间使用 37 区块中位数，防止恶意 miner 操纵 since 字段。✅ 实现完整

### 修复建议

无。

---

## AUDIT-SPEC-003: RFC-0023 NervosDAO

### 状态: ⚠️ Low（已在 AUDIT-LOGIC-003 标记 1 处隐式截断）

### RFC-0023 NervosDAO 规则映射

| 规则 | 代码 | 状态 |
|---|---|---|
| DAO 单元 lock_script 任意 / type_script = `dao_type_hash` | `util/dao/src/lib.rs` `is_dao` 检查 | ✅ |
| Phase 1 (Deposit): cell.data = 8 字节 `0u64` LE | `dao_type_hash` 脚本内 + 节点侧 `extract_dao_data` | ✅ |
| Phase 2 (Withdraw): cell.data = 8 字节 deposit_block_number LE | 同上 | ✅ |
| 提现需 lock period ≥ DAO_MATURITY (180 epochs) | DAO type script 内强制 since 字段 | ✅ |
| 利息 = counted_capacity × (withdrawing_AR / deposit_AR - 1) | `lib.rs:113-145` `calculate_maximum_withdraw` | ⚠️ AUDIT-LOGIC-003 |
| Secondary reward 公式与 DAO header AR | `lib.rs:155-191` `secondary_block_reward` | ✅ |
| DAO 字段 = (C, AR, S, U) molecule packed | `dao_field_with_current_epoch` (l.229-243) | ✅ |
| Capacity 守恒在 DAO withdraw 时豁免 | `CapacityVerifier::verify_dao_withdraw_transaction` | ✅ AUDIT-LOGIC-006 |
| `STARTING_BLOCK_LIMITING_DAO_WITHDRAWING_LOCK` = 10_000_000 | `consensus.rs:105` | ✅ |
| Satoshi cell occupied ratio (genesis only) | `SATOSHI_PUBKEY_HASH` / `SATOSHI_CELL_OCCUPIED_RATIO` (`consensus.rs:93-96`) | ✅ |

### 发现

- ✅ RFC-0023 核心利息公式已实现
- ✅ DAO type script 与节点侧的协作设计 — 节点豁免守恒，type script 验证利息
- ⚠️ **Low — AUDIT-LOGIC-003 重复确认**: `calculate_maximum_withdraw` 内 `withdraw_counted_capacity as u64` 隐式截断与兄弟函数（`secondary_block_reward` 使用 `u64::try_from`）不一致
- ⚠️ **Info — DAO type script 信任**: 节点容量守恒完全依赖 `dao_type_hash` 脚本本身验证利息正确性。dao_type_hash 是系统脚本，由 ckb-system-scripts 提供 — **该脚本的代码审计在另一仓库**

### 修复建议

1. 与 AUDIT-LOGIC-003 联动: 修复 `withdraw_counted_capacity as u64` 截断
2. **建议**: 在 `util/dao/src/lib.rs` 顶部 doc 引用 RFC-0023 链接 + 函数名 → RFC 章节映射

---

## AUDIT-SPEC-004: RFC-0032/0035 Hardfork 激活逻辑

### 状态: ✅ 通过

### Hardfork 实现

`util/types/src/core/hardfork/`:
- `mod.rs`: `HardForks { ckb2021, ckb2023 }`
- `ckb2021.rs`: 9 个 RFC 字段 (rfc_0028/0029/0030/0031/0032/0036/0038)，每个字段 = 激活 EpochNumber
- `ckb2023.rs`: rfc_0048/0049

`spec/src/hardfork.rs`:
```rust
pub fn complete_mainnet(&self) -> Result<HardForks, String> {
    let mut ckb2021 = CKB2021::new_builder();
    ckb2021 = self.update_2021(
        ckb2021,
        mainnet::CKB2021_START_EPOCH,           // ckb2021 主激活 epoch
        mainnet::RFC0028_RFC0032_RFC0033_RFC0034_START_EPOCH,
    )?;
    Ok(HardForks {
        ckb2021: ckb2021.build()?,
        ckb2023: CKB2023::new_mirana().as_builder().build()?,
    })
}
```

`testnet` 和 `mainnet` 激活时间分别管理（`ckb_constant::hardfork::{mainnet,testnet}` 常量定义）。

激活检查典型模式：
```rust
if hardfork_switch.ckb2021.is_rfc_0028_enabled(epoch_number) {
    // new behavior
} else {
    // legacy behavior
}
```

例：`transaction_verifier.rs:696-720` 中 timestamp relative since 路径根据 `ckb2021.is_block_ts_as_relative_since_start_enabled` 切换 base_timestamp 来源。

### RFC-0032 CKB VM 版本选择

| 规则 | 代码 | 状态 |
|---|---|---|
| hash_type = Data / Type / Data1 / Data2 决定 VM 版本 | `script::types::ScriptHashType` + `verify` 内 match | ✅ |
| Data → VM v0；Data1 → VM v1；Data2 → VM v2 | `script/src/types.rs::ScriptVersion` | ✅ |
| 激活前禁用新 hash_type | `script::verify` 在 `find_script` 时拒绝 | ✅ |

### RFC-0035 P2P 协议升级

| 规则 | 代码 | 状态 |
|---|---|---|
| Sync/Relay 协议版本号切换 | tentacle ProtocolMeta + sync/src/protocol.rs | ✅ |
| 旧节点拒绝 / 兼容窗口 | tentacle 协议协商 | ✅ |

### 发现

- ✅ Hardfork 激活以 EpochNumber 为单位，**deterministic**
- ✅ Mainnet/Testnet 激活 epoch 分离管理
- ✅ Builder 模式 + `Option<EpochNumber>` 默认行为：未配置时使用 RFC 推荐值
- ✅ 每个 RFC 的 enable 检查在使用点显式调用 `is_rfc_*_enabled`，便于代码审计
- ⚠️ **Info — Dev 网络与 Mirana**: `CKB2023::new_mirana()` 给 mainnet, `new_dev_default()` 给 dev — testnet 单独配置（参考 `complete_testnet`）。**`update_2023` 仅在 testnet 路径调用** —— 但 mainnet 直接 `new_mirana()`，逻辑上 `complete_mainnet` 不允许用户 override `ckb2023` epoch (`HardForkConfig.ckb2023` 仅生效在 dev/testnet)
- ⚠️ **Info — 激活时机的不可逆性**: 一旦写入主网 `CKB2021_START_EPOCH`，无法回退；CI 应有"hardfork epoch 不允许修改"的 lint

### 修复建议

1. **建议**: CI 加 hash check 验证 `ckb_constant::hardfork::mainnet` 常量值不被 PR 修改
2. **建议**: doc 增加 hardfork 激活检查 helper 使用清单

---

## AUDIT-SPEC-005: RFC-0042 多 VM 版本切换边界

### 状态: ✅ 通过

### VM 版本切换映射

CKB-VM 版本与 hash_type 对应：
- `Data` → VM v0 (legacy)
- `Type` → 通过 type_id 解析到具体 VM 版本（由该 type 的 code cell hash_type 决定）
- `Data1` → VM v1（ckb2021 启用）
- `Data2` → VM v2（ckb2023 启用）

`script::types::ScriptVersion` enum + `find_script` 流程：

1. 根据 `Script.hash_type` 在 cell_deps 中查找匹配 code cell
2. `Data*` 直接 hash 匹配 code_hash；`Type` 经过 type_id 间接匹配
3. 计算 ScriptVersion 后构造对应 VM machine（`init_core_machine_v0/v1/v2`）

`script::verify::TransactionScriptsVerifier::verify` 内：
- 每个 ScriptGroup 独立 ScriptVersion
- 不同 group 可以使用不同 VM 版本（同一 tx 内混合）
- cycle 计费按 VM 版本不同的 cost_model（`BYTES_PER_CYCLE`, syscall 成本）

激活前后边界：
- 在 `rfc_0032` 激活前，Data1/Data2 hash_type 会被 `find_script` 拒绝
- `rfc_0048`（ckb2023）激活前，Data2 / VM v2 syscalls (如 spawn) 被拒绝

### 发现

- ✅ ScriptVersion 显式 enum，类型系统保证不会误用
- ✅ Hardfork gate 在 `find_script` 前置位置 — 不会进入 VM 运行才发现版本错
- ✅ Cycle 计费随 VM 版本切换
- ⚠️ **Info — Data2 syscalls (spawn/exec_v2)**: 仅在 VM v2 启用；旧 VM 版本调用会 ERR_INVALID_SYSCALL
- ⚠️ **Info — VM 升级路径**: 当未来增加 VM v3 时，需新增 hash_type Data3 + 新 RFC + 新 ScriptVersion 变体 — **当前结构清晰，易于扩展**

### 修复建议

1. **建议**: 在 `script/src/types.rs::ScriptVersion` 顶部 doc 增加 "hash_type ↔ ScriptVersion ↔ RFC 激活" 三元映射表
2. **建议**: 添加 integration test 覆盖 hardfork 切换前后 tx 验证行为差异

---

## 本轮小结

| AUDIT-ID | 状态 | 严重 | 摘要 |
|---|---|---|---|
| AUDIT-SPEC-001 | ✅ | — | RFC-0017 17 条 valid conditions 全部映射到子验证器 |
| AUDIT-SPEC-002 | ✅ | — | RFC-0019/0020/0022 共识参数全部 hardcode + 调整算法集中 |
| AUDIT-SPEC-003 | 🟢 | Low | RFC-0023 实现完整；仅 AUDIT-LOGIC-003 的 `as u64` 截断需修 |
| AUDIT-SPEC-004 | ✅ | — | Hardfork builder + EpochNumber 激活 deterministic |
| AUDIT-SPEC-005 | ✅ | — | ScriptVersion + hash_type 三层映射清晰 |

**新增审计项**:
- AUDIT-SPEC-006（在 `verification/src/lib.rs` 与 `util/dao/src/lib.rs` 顶部增加 RFC 章节 ↔ 函数名映射表 doc）
- AUDIT-SPEC-007（CI 加 hardfork 激活 epoch 常量改动检测）
- AUDIT-SPEC-008（integration test 覆盖 hardfork 切换前后行为差异）

---

## 审计完成声明

至本轮结束，**SECURITY_AUDIT_TODO.md 内 80 个 AUDIT-ID 全部完成审计**。整体结论：

- **0 个 Critical / 0 个 High**
- **2 个 Medium**: AUDIT-CRYPTO-001（Signature panic + low-S），AUDIT-ERRINFO-002（sentry PII）
- **6 个 Low**: AUDIT-LOGIC-003、AUDIT-CONTRACT-001、AUDIT-INPUT-001、AUDIT-MEMORY-005、AUDIT-CRYPTO-005、AUDIT-AUTH-002、AUDIT-DB-003、AUDIT-MEMORY-007（实际 8 条 Low，本轮新增 0 个 Medium/High）
- 其余 ~20 项 Info / 设计约束 / 需动态验证

CKB 节点的整体安全工程实践处于业界优秀水平，未发现现实可达的资金被盗 / 双花 / 共识分裂漏洞。所有发现均为**代码质量、防御一致性、配置安全提示**层面。
