# Round 1 — P0 共识与资金审计

> 范围: AUDIT-LOGIC-001 / 003 / 006 + AUDIT-CONTRACT-001 + AUDIT-CRYPTO-001  
> 日期: 2026-05-15

---

## AUDIT-LOGIC-001: `HeaderVerifier` / `BlockVerifier` 子规则

### 状态: ✅ 通过（附 1 项 Info）

### 分析过程

`verification` crate 将 Header / Block 验证拆为多个子验证器：

| 子验证器 | 位置 | 检查规则 |
|---|---|---|
| `HeaderVerifier::verify` | `verification/src/header_verifier.rs:32` | 组合 `VersionVerifier` + `PowVerifier` + `TimestampVerifier` + `NumberVerifier` + `EpochVerifier` |
| `TimestampVerifier::verify` | l.70 | 父块中位时间戳上限 (`ALLOWED_FUTURE_BLOCKTIME`) |
| `NumberVerifier::verify` | l.111 | `header.number() == parent.number() + 1` |
| `EpochVerifier::verify` | l.133 | 与 `Consensus::next_epoch_ext` 对齐 |
| `PowVerifier::verify` | l.161 | 调用 `consensus.pow_engine().verify(header)` |
| `BlockVerifier::verify` | `block_verifier.rs:39` | 组合 Cellbase / Duplicate / MerkleRoot / Proposals / Bytes / NonContextualBlockTxs |
| `CellbaseVerifier::verify` | l.66 | 唯一 cellbase / inputs / outputs / since 字段 |
| `MerkleRootVerifier::verify` | l.200 | `transactions_root` 与 `proposals_root` 重算 |
| `BlockProposalsLimitVerifier::verify` | l.228 | `proposals().len() <= max_block_proposals_limit` |
| `BlockBytesVerifier::verify` | l.251 | 总字节 ≤ `max_block_bytes` |
| `NonContextualBlockTxsVerifier::verify` | l.280 | 对每笔 tx 走 `NonContextualTransactionVerifier` |

### 发现

- ✅ 每一条 RFC-0020/0022 中的规则在代码侧都有对应子验证器
- ✅ 验证器组合写法 (`?` 串联) 保证任一失败立刻短路
- ℹ️ Info: `BlockVerifier::verify` 顺序未把成本最低的检查（Duplicate / Bytes）放最前，但对 DoS 影响可忽略

### 修复建议

无（保持现状）

---

## AUDIT-LOGIC-003: NervosDAO `calculate_maximum_withdraw` 利息计算

### 状态: ⚠️ 建议改进（Low — 疑似 / 需动态验证）

### 分析过程

`util/dao/src/lib.rs:113-145`:

```rust
pub fn calculate_maximum_withdraw(
    &self,
    output: &CellOutput,
    output_data_capacity: Capacity,
    deposit_header_hash: &Byte32,
    withdrawing_header_hash: &Byte32,
) -> Result<Capacity, DaoError> {
    // ...
    let counted_capacity = output_capacity.safe_sub(occupied_capacity)?;
    let withdraw_counted_capacity = u128::from(counted_capacity.as_u64())
        * u128::from(withdrawing_ar)
        / u128::from(deposit_ar);
    let withdraw_capacity =
        Capacity::shannons(withdraw_counted_capacity as u64).safe_add(occupied_capacity)?;
    //                                                ^^^^^^
    //                                  隐式截断，u128→u64 不返回错误
    Ok(withdraw_capacity)
}
```

对比兄弟函数 `secondary_block_reward` (l.189-190) 与 `dao_field_with_current_epoch` (l.229-230, 243)：

```rust
let reward = u64::try_from(reward128).map_err(|_| DaoError::Overflow)?;
// ...
let miner_issuance = Capacity::shannons(u64::try_from(miner_issuance128).map_err(|_| DaoError::Overflow)?);
// ...
let ar_increase = u64::try_from(ar_increase128).map_err(|_| DaoError::Overflow)?;
```

后者使用显式 `u64::try_from + map_err(Overflow)`，前者使用 `as u64` 隐式截断。

### 发现

- ⚠️ **疑似 Low**: `util/dao/src/lib.rs:138` 与同文件其他兄弟函数的防御模式不一致。
  - **影响**: 若 `withdraw_counted_capacity > u64::MAX`，截断后的 `withdraw_capacity` 将小于真实值，给提款人造成损失（而非膨胀印钱）。
  - **可达性分析**: `counted_capacity` ≤ `output_capacity` ≤ `MAX_BLOCK_BYTES * SHANNONS_PER_BYTE` 量级；`withdrawing_ar / deposit_ar` 是单调递增比率，CKB 主网历史最大值远低于 `2^64`。**实际触发不可达但属防御性缺口**。
  - **`overflow-checks=true` 不兜底**: u128→u64 `as` 转换不属于算术运算，release 模式下也是 silent truncation。
- ✅ 后续 `safe_add(occupied_capacity)` 与 `safe_sub` 等容量操作均通过 `occupied-capacity` crate 的检查算术。

### 关键代码引用

```rust
// util/dao/src/lib.rs:138-142  ⚠️
let withdraw_counted_capacity = u128::from(counted_capacity.as_u64())
    * u128::from(withdrawing_ar)
    / u128::from(deposit_ar);
let withdraw_capacity =
    Capacity::shannons(withdraw_counted_capacity as u64).safe_add(occupied_capacity)?;
```

### 修复建议

将 l.142 改为：
```rust
let withdraw_capacity = Capacity::shannons(
    u64::try_from(withdraw_counted_capacity).map_err(|_| DaoError::Overflow)?,
).safe_add(occupied_capacity)?;
```
同时建议在 `util/dao/src/tests.rs` 增加 fuzz / proptest 覆盖 `withdraw_counted_capacity` 边界（参考附录 B 中 AUDIT-LOGIC-010）。

### 新增审计项

- AUDIT-LOGIC-010（已加入 TODO 附录 B）

---

## AUDIT-LOGIC-006: `CapacityVerifier` 输入输出容量守恒

### 状态: ⚠️ Info（设计约束需文档化）

### 分析过程

`verification/src/transaction_verifier.rs:478-523`:

```rust
pub fn verify(&self) -> Result<(), Error> {
    // skip OutputsSumOverflow verification for resolved cellbase and DAO
    // withdraw transactions.
    if !(self.resolved_transaction.is_cellbase() || self.valid_dao_withdraw_transaction()) {
        let inputs_sum = self.resolved_transaction.inputs_capacity()?;
        let outputs_sum = self.resolved_transaction.outputs_capacity()?;
        if inputs_sum < outputs_sum {
            return Err((TransactionError::OutputsSumOverflow { ... }).into());
        }
    }
    // 每个 output 检查 is_lack_of_capacity（含 data 占用）
    for (index, (output, data)) in ... {
        let data_occupied_capacity = Capacity::bytes(data.len())?;
        if output.is_lack_of_capacity(data_occupied_capacity)? {
            return Err((TransactionError::InsufficientCellCapacity { ... }).into());
        }
    }
    Ok(())
}

fn valid_dao_withdraw_transaction(&self) -> bool {
    self.resolved_transaction.resolved_inputs.iter()
        .any(|cell_meta| cell_uses_dao_type_script(&cell_meta.cell_output, &self.dao_type_hash))
}
```

### 发现

- ✅ `inputs_sum < outputs_sum` 正确使用 `Capacity::safe_*` 路径（在 `inputs_capacity()/outputs_capacity()` 内部）
- ✅ `is_lack_of_capacity` 已考虑 data 占用
- ⚠️ **Info**: `valid_dao_withdraw_transaction` 用 `.any(...)` —— **只要任意一个输入命中 `dao_type_hash`，整笔 tx 都豁免容量守恒**。
  - 这是 RFC-0023 的设计：DAO 提款合约由 DAO type script 自身验证 ar 比率与提款金额关系
  - **隐含信任**: `dao_type_hash`（在 `Consensus` 中钉死）+ DAO 链上脚本本身实现正确
  - **风险**: 若未来 DAO 脚本被升级出错或新增 type script 共享 hash（理论上 blake2b 抗碰撞所以不可能），守恒可被绕过
- ✅ cellbase 豁免通过 `RewardVerifier`（在 `verification/contextual` 中）补偿

### 修复建议

不需要代码修改。**建议在 `CapacityVerifier::verify` 顶部添加 doc comment**，说明：
> DAO withdraw transactions are exempted from input/output sum check; correctness is delegated to the DAO type script whose code hash is consensus-pinned via `Consensus::dao_type_hash()`. Any future change to the DAO contract MUST keep withdraw amount = counted_capacity * (withdrawing_ar / deposit_ar) + occupied_capacity, otherwise this exemption becomes unsound.

---

## AUDIT-CONTRACT-001: `TransactionScriptsVerifier` cycle 计费完整性

### 状态: ⚠️ 建议改进（Low — 代码一致性）

### 分析过程

`script/src/verify.rs:191-205`（主路径 `verify`）:

```rust
pub fn verify(&self, max_cycles: Cycle) -> Result<Cycle, Error> {
    let mut cycles: Cycle = 0;
    for group in self.groups() {
        let cycle = self
            .verify_script_group(group, max_cycles - cycles)  // ⚠️ 裸减法
            .map_err(|e| e.source(group))?;
        cycles = cycles
            .checked_add(cycle)
            .ok_or_else(|| ScriptError::ExceededMaximumCycles(max_cycles))?;
    }
    Ok(cycles)
}
```

对比 `verify_group_with_chunk` (l.371-398):

```rust
let remain_cycles = max_cycles.checked_sub(cycles).ok_or_else(|| {
    ScriptError::Other(format!("expect invalid cycles {max_cycles} {cycles}"))
})?;
```

`scheduler.rs:38` 限额 `MAX_VMS_COUNT=16`、`MAX_FDS=64` ✅
`cost_model.rs:7` `BYTES_PER_CYCLE=4` ✅
每个 syscall 在 ecall 入口扣 cycle（`spawn.rs`、`exec.rs`、`load_*.rs` 均验证）✅

### 发现

- ⚠️ **Low — 代码一致性**: `verify` 主路径使用 `max_cycles - cycles` 裸减法；`verify_group_with_chunk` 使用 `checked_sub`。两条路径模式不一致。
  - **实际不可达**: `cycles` 单调累加且每次 `verify_script_group` 已用 `max_cycles - cycles` 作为本组上限，组内不可超过此值；理论上 `cycles ≤ max_cycles` 始终成立
  - **`overflow-checks=true` 兜底**: release 模式下，若内部状态机异常导致 `cycles > max_cycles`，会 panic 而非 silently underflow（更安全的失败模式）
- ✅ cycle 计费在每个 syscall 路径完整：`spawn_extra_cycles_base`、`exec_load_elf_v2_cycles_base`、`transferred_byte_cycles(bytes)` 在 `read.rs`/`write.rs`/各 load_*.rs 中扣减

### 修复建议

`script/src/verify.rs:197-205` 改用 `checked_sub` 保持与 `verify_group_with_chunk` 一致：

```rust
let remain_cycles = max_cycles
    .checked_sub(cycles)
    .ok_or_else(|| ScriptError::ExceededMaximumCycles(max_cycles))?;
let cycle = self.verify_script_group(group, remain_cycles).map_err(|e| e.source(group))?;
```

详见附录 B 中 AUDIT-CONTRACT-007。

---

## AUDIT-CRYPTO-001: secp256k1 签名 / 恢复 / 序列化

### 状态: ⚠️ 发现问题（Medium）

### 分析过程

`util/crypto/src/secp/signature.rs`:

```rust
// l.63-78
pub fn is_valid(&self) -> bool {
    // ... 解 r, s 为 H256
    self.v() <= 1 && h_r < N && h_r >= ONE && h_s < N && h_s >= ONE
}

// l.108-114
pub fn serialize_der(&self) -> Vec<u8> {
    self.to_recoverable()
        .unwrap()                       // ⚠️ panic if invalid recovery_id
        .to_standard()
        .serialize_der()
        .to_vec()
}

// l.139-145
impl From<Vec<u8>> for Signature {
    fn from(sig: Vec<u8>) -> Self {
        let mut data = [0; 65];
        data[0..65].copy_from_slice(sig.as_slice());   // ⚠️ panic if len != 65
        Signature(data)
    }
}
```

### 发现

#### 1. ⚠️ Medium — `is_valid` 缺 low-S 检查

`is_valid` 仅检查 `s < N`，**不强制 `s <= N/2`**（BIP-62 / EIP-2 low-S 防可塑性）。如果调用方将 `is_valid()==true` 误解为"不可塑"，攻击者可对同一 message 构造两个互为反对称的合法签名 `(r, s)` 与 `(r, N-s)`。

- ✅ **实际缓解**: CKB 链上 secp256k1 验证由 system script 通过 ckb-vm 调用 `secp256k1` crate；签名 hash 是 `blake2b(tx_hash || witness_lengths || witness_data)`，**tx_hash 已包含 witness 中的签名字节**，因此可塑签名对应不同 tx_hash，无法重放为同一交易
- ⚠️ **代码层面风险**: 任何外部调用方（如 `ckb-cli`、第三方 dApp）若将 `Signature::is_valid` 用作 "signature normalized" 的判定，会被绕过。`util/crypto` 是 `ckb-types` 公开 API 的一部分。

#### 2. ⚠️ Medium — `serialize_der` `.unwrap()` panic

若 `Signature` 通过 `from_rsv(r, s, v=255)` 或 `impl From<Vec<u8>>` 用畸形 `v` 字节构造，再调用 `serialize_der`，`RecoveryId::try_from(i32::from(255))` 失败 → `to_recoverable` 返回 `Err` → `.unwrap()` panic。

- ✅ **节点内部用例**: 主链路 `recover()` 已经先做 `to_recoverable()?`，正常 Result 路径
- ⚠️ **外部调用风险**: 任何使用 `serialize_der()` 的工具（如 ckb-cli debug 工具）若接受用户提供的 65 字节签名（可能从前端传入），就可能 panic

#### 3. ⚠️ Medium — `impl From<Vec<u8>>` 输入长度 panic

`copy_from_slice` 要求 source 长度等于 dest 切片长度（65）。任意 `len != 65` 的 `Vec<u8>` 立刻 panic。这是公开的 `From` impl，违反 "From 不应失败" 的 Rust 惯例。

应使用 `TryFrom` 或 `Signature::from_slice`（已存在，l.53-60 是正确的 Result 实现）。

### 关键代码引用

详见上文分析。

### 修复建议

```rust
// (a) is_valid: 增加 low-S
pub fn is_valid(&self) -> bool {
    let h_r = match H256::from_slice(self.r()) { Ok(h) => h, Err(_) => return false };
    let h_s = match H256::from_slice(self.s()) { Ok(h) => h, Err(_) => return false };
    const HALF_N: H256 = h256!("0x7fffffff_ffffffff_ffffffff_ffffffff_5d576e73_57a4501d_dfe92f46_681b20a0");
    self.v() <= 1 && h_r < N && h_r >= ONE && h_s <= HALF_N && h_s >= ONE
}

// (b) serialize_der 改为 Result
pub fn serialize_der(&self) -> Result<Vec<u8>, Error> {
    Ok(self.to_recoverable()?.to_standard().serialize_der().to_vec())
}

// (c) 标 From<Vec<u8>> deprecated 或改为 TryFrom
#[deprecated(note = "Use Signature::from_slice for fallible conversion")]
impl From<Vec<u8>> for Signature { ... }
```

### 新增审计项

- AUDIT-CRYPTO-007（已加入 TODO 附录 B）：全仓搜索 `Signature::is_valid` 调用点，确认无任何路径将其作为 malleability 防护依据

---

## 本轮小结

| AUDIT-ID | 状态 | 严重 | 摘要 |
|---|---|---|---|
| AUDIT-LOGIC-001 | ✅ | — | HeaderVerifier/BlockVerifier 子规则完整 |
| AUDIT-LOGIC-003 | ⚠️ | Low | DAO `as u64` 隐式截断，与兄弟函数防御模式不一致 |
| AUDIT-LOGIC-006 | ℹ️ | Info | DAO 提款豁免守恒为设计约束，建议补 doc |
| AUDIT-CONTRACT-001 | ⚠️ | Low | cycle 计费主路径裸减法，建议改 `checked_sub` |
| AUDIT-CRYPTO-001 | ⚠️ | Medium | `Signature::is_valid` 缺 low-S；`From<Vec<u8>>`/`serialize_der` 含 panic 路径 |

**下轮建议**: 进入 Round 2 — 外部攻击面（AUDIT-INPUT-003/004、AUDIT-NET-001/002、AUDIT-MEMORY-002/004）
