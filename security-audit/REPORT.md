# Nervos CKB 安全审计报告

> **审计对象**: gpBlockchain/ckb（Nervos CKB Layer-1 区块链节点 Rust 实现）  
> **审计方法**: 基于 [`security-audit` SKILL](https://github.com/gpBlockchain/ckb-test-skills/blob/main/.claude/skills/security-audit/SKILL.md) 四阶段静态代码审计 + 配置审视  
> **审计范围**: 仓库内 ~70 Cargo workspace crates / ~809 Rust 源文件  
> **审计深度**: P0 全部完成（28 项）；P1/P2/P3 待续  
> **报告日期**: 2026-05-15

---

## 1. 执行摘要

CKB 节点的整体安全工程实践处于**业界优秀水平**。核心共识、容量守恒、密码学验证、脚本执行环境等关键安全路径均有：

1. **检查算术**（`occupied-capacity::Capacity::safe_*`、`u64::try_from`、`safe_add`/`safe_sub`/`checked_*`）
2. **资源上限**（`MAX_VMS_COUNT=16`、`MAX_FDS=64`、`MAX_HEADERS_LEN=2000`、`MAX_LOCATOR_SIZE=101`、`max_peers`、`max_tx_size` 等）
3. **错误码标准化**（RPC `RPCError` 枚举、sync `StatusCode` 枚举与 `BAD_MESSAGE_BAN_TIME` 联动）
4. **`overflow-checks=true`** 在 release profile 启用整数溢出 panic
5. **`#[serde(deny_unknown_fields)]`** 在配置文件层防止字段拼写错误静默忽略
6. **默认配置安全**（`listen_address=127.0.0.1:7000`、生产 modules 不含 `Debug`/`IntegrationTest`）
7. **细粒度子验证器**（HeaderVerifier / BlockVerifier / TransactionVerifier 拆分为 10+ 个独立小验证器，便于审计与组合）

P0 阶段共计审计 28 项，发现 **0 个 Critical / High**、**1 个 Medium**、**3 个 Low**、**多个 Info / 待动态验证**。无任何会直接导致资金被盗、双花、共识分裂的现实可达漏洞；所发现问题主要为**代码质量、防御一致性、配置流程**层面，已记录修复建议。

---

## 2. 风险评级总览

| 严重级 | 数量 | AUDIT-ID 列表 |
|---|---|---|
| 🔴 Critical | 0 | — |
| 🟠 High | 0 | — |
| 🟡 Medium | 1 | AUDIT-CRYPTO-001 |
| 🟢 Low | 3 | AUDIT-LOGIC-003 / AUDIT-CONTRACT-001 / AUDIT-INPUT-001 |
| 🔵 Info / 设计约束 | 7 | AUDIT-LOGIC-006 / AUDIT-CONTRACT-004 / AUDIT-NET-001 / AUDIT-MEMORY-002 / AUDIT-DEPS-002 / AUDIT-AUTH-001（建议增强）/ AUDIT-ERRINFO-001（与 ERRINFO-002 联动） |
| ⚠️ 需动态验证 | 1 | AUDIT-DEPS-001（cargo audit）|
| ✅ 通过 | 16 | 其余 P0 项 |

---

## 3. 关键发现详情

### 3.1 🟡 Medium — `Signature` API panic 路径与缺 low-S 检查（AUDIT-CRYPTO-001）

**文件**: `util/crypto/src/secp/signature.rs:63-114, 139-145`

三个相关问题：

1. **`is_valid` (l.63-78)** 仅检查 `s < N`，未强制 low-S（`s ≤ N/2`）—— 不防 ECDSA 签名可塑性
2. **`serialize_der` (l.108-114)** 内部 `.unwrap()` —— 当 `Signature` 通过 `From<Vec<u8>>` / `from_rsv` 携带非法 `v` 字节时 panic
3. **`impl From<Vec<u8>> for Signature` (l.139-145)** —— 输入长度 ≠ 65 时 `copy_from_slice` panic（应使用已存在的安全 `from_slice` Result 路径）

**实际影响**: CKB 链上签名验证由 system script 在 ckb-vm 中调用 `secp256k1` crate，独立于本 API；且 tx_hash 包含 witness 内容，可塑签名对应不同 tx_hash 无法重放为同一交易。**链层资金不受影响**。但 `util/crypto` 是公开 API，被 `ckb-cli`、第三方 SDK 调用 —— 若调用方将 `is_valid` 误用作 normalization 判定、或将外部 65 字节 buffer 传入 `From<Vec<u8>>`，会出现 malleability 误判或 panic。

**修复建议**:
- 在 `is_valid` 增加 `s ≤ N/2` 检查或明确 doc"不防 malleability"
- 将 `serialize_der` 改为返回 `Result<Vec<u8>, Error>`
- 将 `impl From<Vec<u8>>` 标 `#[deprecated]`，引导用户使用已有的 `Signature::from_slice`

详见 [`rounds/round-01-consensus-and-funds.md#audit-crypto-001`](rounds/round-01-consensus-and-funds.md#audit-crypto-001)

---

### 3.2 🟢 Low — DAO 提款利息计算的隐式截断（AUDIT-LOGIC-003）

**文件**: `util/dao/src/lib.rs:138-142`

```rust
let withdraw_counted_capacity = u128::from(counted_capacity.as_u64())
    * u128::from(withdrawing_ar)
    / u128::from(deposit_ar);
let withdraw_capacity =
    Capacity::shannons(withdraw_counted_capacity as u64).safe_add(occupied_capacity)?;
//                                                ^^^^^^  u128→u64 隐式截断
```

**对比**: 同文件 `secondary_block_reward` (l.189-190)、`dao_field_with_current_epoch` (l.229-230, 243) 均使用 `u64::try_from(...).map_err(|_| DaoError::Overflow)?` 显式检查。

**实际影响**: `counted_capacity ≤ u64::MAX`，`withdrawing_ar / deposit_ar` 是单调递增比率（主网历史值远低于 2^64），算式结果在现实场景下**远小于 u64::MAX**。但 `overflow-checks=true` 不兜底 `as` cast，截断为 silent。若未来某种边界条件触发，提款人会获得小于应得的金额（链上不会印钱，但用户受损）。

**修复建议**: 改用 `u64::try_from(...).map_err(|_| DaoError::Overflow)?`，与同文件其他位置保持一致。

详见 [`rounds/round-01-consensus-and-funds.md#audit-logic-003`](rounds/round-01-consensus-and-funds.md#audit-logic-003)

---

### 3.3 🟢 Low — 脚本验证主路径 cycle 减法不一致（AUDIT-CONTRACT-001）

**文件**: `script/src/verify.rs:197-205`

主路径 `verify` 使用 `max_cycles - cycles` 裸减法；同文件 `verify_group_with_chunk` (l.388) 使用 `checked_sub`。两条路径模式不一致。

**实际影响**: 由于 `cycles` 单调累加且每次 `verify_script_group` 已使用 `max_cycles - cycles` 作为上限，状态机正确性下 `cycles ≤ max_cycles` 始终成立。`overflow-checks=true` 兜底，underflow 触发 panic 而非 silent。**生产路径下不可达**。

**修复建议**: 改为 `checked_sub` 保持代码一致性。

详见 [`rounds/round-01-consensus-and-funds.md#audit-contract-001`](rounds/round-01-consensus-and-funds.md#audit-contract-001)

---

### 3.4 🟢 Low — `send_transaction` 含 `submit_tx.unwrap()` 反模式（AUDIT-INPUT-001）

**文件**: `rpc/src/module/pool.rs:625-635`

前置 `if let Err(e) = submit_tx { return ... }` 已守护，但后续 `submit_tx.unwrap()` 易在未来重构中破坏。

**修复建议**: 改为单次 `match`：见 [`rounds/round-04-rpc-and-deps.md#audit-input-001`](rounds/round-04-rpc-and-deps.md#audit-input-001)

---

### 3.5 🔵 Info — DAO 提款豁免容量守恒（AUDIT-LOGIC-006）

**文件**: `verification/src/transaction_verifier.rs:478-523`

`valid_dao_withdraw_transaction` 返回 `true`（任一输入命中 `dao_type_hash`）即豁免整笔 tx 的 `inputs_sum >= outputs_sum` 守恒检查。

这是 RFC-0023 设计：DAO 提款金额由 DAO type script 自身验证（utxoset-level 校验）。**正确实现下安全**。但形成对 `dao_type_hash` 钉死值的强信任：任何 DAO 系统脚本未来变更必须严格保持利息守恒不变量。

**建议**: 在 `CapacityVerifier::verify` 顶部增加 doc 注释，明确"DAO 豁免依赖 DAO type script 的正确性"。

---

### 3.6 🔵 Info — 依赖钉版需自动安全订阅（AUDIT-DEPS-002 / 004）

钉版依赖列表（`Cargo.toml`）：
- `ckb-vm = "=0.24.14"` (l.215)
- `clap = "=4.4"` (l.216)
- `rocksdb (ckb-rocksdb) = "=0.21.1"` (l.285)

**风险**: 钉版本身好（确定性 + 防供应链），但 patch 版本中的安全修复**不会自动**进入。当前未确定是否已建立"pinned dependency security watchlist"流程。

**建议**:
1. CI 中加入 `cargo audit --deny warnings` 作为 required check
2. 周期性（每月）评估钉版的上游公告
3. GitHub Watch（Releases only）订阅 `nervosnetwork/ckb-vm` 等关键仓库
4. 在 `deny.toml` 中开启 `[advisories] vulnerability = "deny"`

---

## 4. 审计覆盖矩阵

| 维度 | 已审 P0 项 | 通过 | 发现 | 占覆盖率 |
|---|---|---|---|---|
| DIM-INPUT | 4 / 7 | 3 ✅ | 1 ℹ️ | 57% |
| DIM-SERDE | 2 / 5 | 2 ✅ | 0 | 40% |
| DIM-CRYPTO | 3 / 6 | 2 ✅ | 1 🟡 | 50% |
| DIM-LOGIC | 6 / 9 | 4 ✅ | 2 (1🟢 1ℹ️) | 67% |
| DIM-CONTRACT | 4 / 6 | 3 ✅ | 1 🟢 | 67% |
| DIM-MEMORY | 4 / 7 | 4 ✅ | 0 | 57% |
| DIM-AUTH | 1 / 4 | 1 ✅ | 0 | 25% |
| DIM-DEPS | 2 / 5 | 0 | 2 (1⚠️ 1ℹ️) | 40% |
| DIM-ERRINFO | 1 / 4 | 1 ✅ | 0 | 25% |
| DIM-SPEC | 0 / 5 | — | — | 0% |
| NET 专项 | 2 / 5 | 2 ✅ | 0 | 40% |
| DB 专项 | 0 / 3 | — | — | 0% |

**总计**: 29 / 66 项（44%）。**P0 全部完成（28 项）**，剩余为 P1/P2/P3 项。

---

## 5. 依赖状态

| 依赖 | 版本 | 钉版？ | 备注 |
|---|---|---|---|
| ckb-vm | 0.24.14 | ✅ `=` | 需周期对照上游 patch |
| rocksdb (ckb-rocksdb) | 0.21.1 | ✅ `=` | 较老，建议评估升级 |
| secp256k1 | 0.30 | ❌ caret | 自动获取 0.30.x patch ✅ |
| tokio | 1.35.0 | 准钉版 | 自动获取 1.35.x |
| tentacle | 0.7.1 | 默认 | CKB 自维护 |
| tentacle-secio | 0.6.6 | 默认 | CKB 自维护 |
| molecule | 0.9.0 | 默认 | CKB 自维护 |
| sentry | 0.34.0 | 默认 | 注意 PII 上报 |
| rhai | 1.16.0 | 默认 | 嵌入式脚本 |
| sqlx | 0.8.2 | 默认 | rich-indexer 用，需参数化查询 |
| clap | =4.4 | ✅ `=` | 较老 |
| hyper | 1 | 默认 | 1.x 稳定 |
| axum | 0.8 | 默认 | 较新 |

**结论**: 整体依赖状态健康，钉版策略需配合自动安全订阅。**未实际运行 `cargo audit`，最终漏洞清单需 CI 动态产出**。

---

## 6. 优先改进建议

按修复价值/成本比排序：

### P0（建议本季度内完成）

1. **AUDIT-CRYPTO-001**: 修复 `Signature` 三处 panic 路径与 low-S 检查
2. **AUDIT-DEPS-001**: CI 加入 `cargo audit` 强制 check
3. **AUDIT-LOGIC-003**: `util/dao/src/lib.rs:142` 改为 `u64::try_from + Overflow`

### P1（建议下季度内完成）

4. **AUDIT-CONTRACT-001**: `script/src/verify.rs:197` 改为 `checked_sub`
5. **AUDIT-INPUT-001**: 重构 `send_transaction` 移除 `unwrap()`
6. **AUDIT-LOGIC-006**: 为 `CapacityVerifier::verify` 增加 doc 说明 DAO 豁免设计约束
7. **AUDIT-AUTH-001 + AUDIT-AUTH-005**: 启动期检测非环回 listen + Debug 模块开启时发 WARN

### P2（流程改进）

8. **AUDIT-DEPS-002**: 建立 pinned 依赖 watchlist + 季度 review
9. **AUDIT-MEMORY-002**: 在关键 crate (`util/dao`, `util/reward-calculator`, `script`, `verification`) 开启 `clippy::cast_possible_truncation`
10. **AUDIT-CONTRACT-006**: 扩展 `script/fuzz` 覆盖 syscall 端到端 fuzzing
11. 在 PR 模板要求"新增 unsafe 块必须 doc SAFETY 注释"

---

## 7. 未完成项与下一步

P1/P2/P3 阶段共 **37 项**待审，重点项：

- **DIM-SPEC（5 项 / 0% 覆盖）**: 与 Nervos RFC-0017/0019/0020/0022/0023/0032/0042 的逐条代码映射 — 需消耗较多深度审计 budget
- **AUDIT-DB-001/002/003**: 数据库迁移可恢复性、rich-indexer SQL 注入、freezer 一致性
- **AUDIT-MEMORY-005**: 外部可触发 panic 路径（`unwrap`/`expect`/`assert!`）全仓扫描
- **AUDIT-CRYPTO-005/006**: CSPRNG 使用清单、敏感对比恒定时间
- **AUDIT-ERRINFO-002**: sentry 上报内容审视
- **AUDIT-NET-003/004/005**: CompactBlock short-id 冲突、DNS-seed 劫持、Tor fingerprint

完整待审列表见 [`SECURITY_AUDIT_TODO.md`](SECURITY_AUDIT_TODO.md) 第 1-12 章中所有未带 `[x]`/`[!]` 标记的条目。

---

## 8. 附录

### 附录 A — 各轮审计记录

- [`rounds/round-01-consensus-and-funds.md`](rounds/round-01-consensus-and-funds.md) — AUDIT-LOGIC-001/003/006 + AUDIT-CONTRACT-001 + AUDIT-CRYPTO-001
- [`rounds/round-02-external-attack-surface.md`](rounds/round-02-external-attack-surface.md) — AUDIT-INPUT-003/004 + AUDIT-NET-001/002 + AUDIT-MEMORY-002/004
- [`rounds/round-03-script-host.md`](rounds/round-03-script-host.md) — AUDIT-CONTRACT-002/003/004 + AUDIT-MEMORY-001
- [`rounds/round-04-rpc-and-deps.md`](rounds/round-04-rpc-and-deps.md) — AUDIT-INPUT-001/002 + AUDIT-AUTH-001 + AUDIT-DEPS-001/002 + AUDIT-ERRINFO-001
- [`rounds/round-05-consensus-details-and-serde.md`](rounds/round-05-consensus-details-and-serde.md) — AUDIT-LOGIC-002/004/005 + AUDIT-SERDE-001/002

### 附录 B — SSoT 文档

- [`SECURITY_AUDIT_TODO.md`](SECURITY_AUDIT_TODO.md) — 含项目概况、信任边界、80 项 AUDIT-ID 列表、执行日志（附录 A）、新增项跟踪（附录 B）、修复建议汇总（附录 C）

### 附录 C — 审计方法学

本审计严格遵循 [`security-audit` SKILL](https://github.com/gpBlockchain/ckb-test-skills/blob/main/.claude/skills/security-audit/SKILL.md)：

- **Phase 0 侦察建档** → 完成项目技术栈识别、模块/数据流/信任边界绘制、AUDIT-ID 行号化
- **Phase 1 逐项审计** → 5 轮 P0 深度审计，每轮 5-6 项
- **Phase 2 TODO 文档更新** → 附录 A 执行日志、附录 B 新增项、附录 C 修复建议持续同步
- **Phase 3 输出报告** → 本文件

**约束遵循**:
- ✅ 深度优先（每轮 ≤ 6 项）
- ✅ 不确定项明确标注"疑似" / "需动态验证"
- ✅ 对外部输入与回调假设最坏情况
- ✅ `SECURITY_AUDIT_TODO.md` 作为 SSoT 跨会话延续
- ✅ 每轮含"本轮完成 / 下轮建议"
- ✅ CKB-VM 合约审计豁免内存对齐；本仓库宿主 Rust 代码亦无须审计对齐

---

> **声明**: 本审计为静态代码审查 + 配置审视。所有标 "需动态验证" 的发现需通过 fuzz / 集成测试 / 测试网部署进一步核实。报告不替代由专业安全公司提供的全面有偿审计，亦不构成对 CKB 主网部署的安全担保。
