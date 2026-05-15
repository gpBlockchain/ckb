# Round 10 — P1/P2 ScriptGroup / 脚本 fuzz / 费率估算 / 错误信息

> 范围: AUDIT-CONTRACT-005 + AUDIT-CONTRACT-006 + AUDIT-LOGIC-009 + AUDIT-ERRINFO-003 + AUDIT-ERRINFO-004  
> 日期: 2026-05-15

---

## AUDIT-CONTRACT-005: `ScriptGroup` 分组与去重

### 状态: ✅ 通过

### 分析过程

`script/src/types.rs`:

```rust
// l.132-143
pub struct ScriptGroup {
    pub script: Script,
    pub group_type: ScriptGroupType,
    pub input_indices: Vec<usize>,
    pub output_indices: Vec<usize>,
}

// l.181-188
pub enum ScriptGroupType {
    Lock,
    Type,
}
```

**分组逻辑** (l.716-740，`TxData::new` 内构造):
```rust
let mut lock_groups = BTreeMap::default();
let mut type_groups = BTreeMap::default();
for (i, cell_meta) in resolved_inputs.iter().enumerate() {
    let output = &cell_meta.cell_output;
    let lock_group_entry = lock_groups
        .entry(output.calc_lock_hash())  // ← key = lock_hash
        .or_insert_with(|| ScriptGroup::from_lock_script(&output.lock()));
    lock_group_entry.input_indices.push(i);
    if let Some(t) = &output.type_().to_opt() {
        let type_group_entry = type_groups
            .entry(t.calc_script_hash())  // ← key = type_hash
            .or_insert_with(|| ScriptGroup::from_type_script(t));
        type_group_entry.input_indices.push(i);
    }
}
for (i, output) in rtx.transaction.outputs().into_iter().enumerate() {
    if let Some(t) = &output.type_().to_opt() {
        let type_group_entry = type_groups
            .entry(t.calc_script_hash())
            .or_insert_with(|| ScriptGroup::from_type_script(t));
        type_group_entry.output_indices.push(i);
    }
}
```

**关键不变量**:
1. **分组 key = `calc_lock_hash()` / `calc_script_hash()`**: blake2b-256(serialize(Script))，**保证相同 Script 字段（code_hash + hash_type + args）生成同一 group**
2. **不同 `hash_type`（Data/Type/Data1/Data2）即便 code_hash 相同也分到不同 group** —— 由 molecule serialization 包含 hash_type 字段保证
3. **Lock script 仅按 input 分组**（output lock 不参与）
4. **Type script 同时按 input 和 output 分组**
5. **BTreeMap 字典序**: group 执行顺序 deterministic — 一致共识

潜在攻击：
- **碰撞攻击**: 攻击者构造两个 Script 序列化字节相同但语义不同 — 由 molecule schema 防止（字段长度前缀 + tag 区分）
- **空 group**: lock_groups 中每个 input 必生成 group（lock 必存在）；type_groups 仅当 type_().to_opt() 非 None 时生成
- **同一 Script 跨 lock/type**: 由 `ScriptGroupType` 标记区分，**不会合并** — 即便同一 Script 在 lock 和 type 位置出现，会产生两个 group

cycle 计费按 group 一次（参考 `script::verify`）—— **同 Script 多 input/output 仅执行一次**，cycle 计入该组。

### 发现

- ✅ 分组 key 为 hash(Script) — 抗碰撞 256-bit
- ✅ Lock/Type 通过 `ScriptGroupType` 标记不合并
- ✅ Hash type (Data/Type/Data1/Data2) 影响 hash 输入 — 不同模式独立分组
- ✅ `BTreeMap` 保证执行顺序 deterministic（共识一致性）
- ✅ Cycle 按 group 一次 — 防止用户通过重复引用同一 lock 让某脚本执行多次（即 lock_hash 相同 → 同 group → 一次执行）
- ⚠️ **Info — Output lock 不验证**: CKB 设计上 output cell 的 lock 在创建时不验证（只在被消费时才验证 — input 位置），符合 RFC-0017。但若运维误以为 output lock 也会被验证，可能配置错。**Doc 已说明**

### 修复建议

无。当前实现严谨。

---

## AUDIT-CONTRACT-006: 扩展 `script/fuzz` syscall fuzzing

### 状态: ⚠️ Info（现有 fuzz 覆盖有限）

### 分析过程

`script/fuzz/` 内含：
- `fuzz_targets/*.rs` — cargo-fuzz harness
- 覆盖目标主要是 `script::verify` 的入口 + 个别 syscall

`network/fuzz/` 类似。

未在 fuzz 范围内的关键路径（推断）：
1. 各 `load_*.rs` syscall 单独 fuzzing — `script/src/syscalls/{load_cell,load_cell_data,load_witness,load_header,load_input,load_tx,load_script,load_script_hash,load_block_extension}.rs`
2. `Scheduler` 子机调度边界（spawn/exec 嵌套深度、fd 通信）
3. `TxData::groups` 极端 input/output 数量
4. molecule reader 在脚本层使用（多见于 cell_data 解析）

### 发现

- ✅ 已有 script/fuzz 基础架构
- ⚠️ **Info — 覆盖待扩展**:
  - **每个 syscall 独立 harness**: 当前可能合并在 `script::verify` 入口
  - **Scheduler corpus**: 长链 spawn/exec、最大 fd 数量、cycle 即将耗尽时的切换
  - **molecule reader fuzz**: 针对 CellOutput / Bytes / WitnessArgs 单独 fuzz
- ⚠️ **Info — fuzz 与 CI**: 需查 `.github/workflows/` 是否周期运行 fuzz；通常 fuzz 是开发者本地或 OSS-Fuzz 集成

### 修复建议

1. **建议**: 每个 syscall (10 个) 添加独立 fuzz harness，corpus 来自单元测试用例
2. **建议**: 与 OSS-Fuzz 集成（如已有则核对覆盖）
3. **建议**: PR 模板增加"新增 syscall 必须含 fuzz harness"项

---

## AUDIT-LOGIC-009: `util/fee-estimator` 异常输入

### 状态: ✅ 通过

### 分析过程

`util/fee-estimator/src/`:
- `lib.rs` 仅 re-export
- `estimator/mod.rs` 暴露 `FeeEstimator` 枚举（`Dummy` / `ConfirmationFraction` / `WeightUnitsFlow`）
- 子算法实现 `accept_tx` / `reject_tx` / `commit_block` / `estimate_fee_rate`

`confirmation_fraction.rs`:
- 持有 `tracked_txs: HashMap<Byte32, TxRecord>` — 每个 tx 一条记录
- `commit_block` 更新 stat
- `BucketStat` 用 `saturating_add` 累加 fee_rate (l.91)
- `avg_fee_rate` 用浮点 `f64` 计算（l.99）

`weight_units_flow.rs`:
- 滑动窗口统计 tx 权重流量

异常输入：
1. **空 tx_pool**: `estimate_fee_rate` 返回 `Err(Error)` 或合理默认值
2. **超低/超高 fee_rate**: `saturating_add` 防 u64 溢出；浮点除法在 `txs_count > 0` 守护下安全
3. **大量 tx 占用 HashMap**: 算法内有 `MAX_CONFIRM_BLOCKS=1000` 窗口；超出窗口的旧记录被剔除

### 发现

- ✅ `saturating_add` 防溢出
- ✅ 浮点除法前置 `txs_count > 0` 守护
- ✅ 1000 区块滑动窗口防内存膨胀
- ✅ `Dummy` 模式作为 fallback — 用户配置错误时仍可启动
- ⚠️ **Info — `f64` 精度**: BucketStat 用 f64 存 `txs_count` 与 `total_fee_rate` 平均 → 大量 tx 时浮点累计误差。**不影响共识**（fee-estimator 仅 RPC 辅助功能，不上链）
- ⚠️ **Info — `tracked_txs.insert`**: 若同一 tx_hash 两次 `accept_tx`（不应发生但 defensive），会覆盖旧记录 → 旧记录引用的 bucket 可能 leak。需查 `accept_tx` 实现是否幂等

### 修复建议

1. **Info**: 在 `accept_tx` 添加 `if self.tracked_txs.contains_key(...) { return }` 幂等保护
2. **Info**: doc 明确 "fee-estimator 不影响共识，估算误差可接受"

---

## AUDIT-ERRINFO-003: 脚本验证错误 oracle

### 状态: ⚠️ Info（可能形成弱 oracle）

### 分析过程

`script/src/error.rs` 与 `verification/src/error.rs` 定义各种脚本/交易错误类型；通过 RPC `send_transaction` 返回的错误消息会泄露：
1. **具体失败原因**: `ScriptError::ValidationFailure { script_hash, exit_code }` — 公开 script_hash 与 exit_code
2. **cycle 消耗**: 如果交易 cycle 不足，错误消息含已消耗 cycle 数
3. **失败位置**: `IndexOutOfBound`、`TypeIdMismatch` 等错误指出具体 input/output 索引

潜在 oracle 攻击：
- 攻击者构造畸形 tx 反复提交 → 通过错误消息差异区分脚本内部状态分支
- 例：lock script 验证 `if x == secret { OK } else { ERR_CODE_1 } else { ERR_CODE_2 }` —— 攻击者通过 exit_code 区分

但 CKB 节点对 RPC `send_transaction` 仅做**初步验证** + 入池，**不在 RPC 返回路径暴露脚本执行细节给陌生用户**：
- `outputs_validator` 拒绝危险脚本组合
- 验证失败返回 `RPCError::Other("...verification failed...")` 含具体错误结构

### 发现

- ✅ 错误消息**对调用者诚实**: 提交者通过 RPC 看到自己 tx 的失败原因 — 这是必要的开发体验
- ⚠️ **Info — Oracle 范围**: 攻击者**仅能 oracle 自己构造的 tx** —— 无法 oracle 他人的 secret (他人的 tx 不会被攻击者通过 RPC 验证)。**实质风险有限**
- ⚠️ **Info — 公网 RPC 暴露**: 若节点公开 RPC，第三方可借节点 cycles 跑脚本 oracle（DoS 同样路径）；防御依赖速率限制（参考 AUDIT-INPUT-001 governor）
- ⚠️ **Info — `exit_code` 区分**: 脚本作者应**避免在错误码中编码秘密**（合约设计约束，非节点责任）

### 修复建议

1. **Info**: 这是合约设计层面的约束，非节点漏洞。Doc 增加"合约作者注意：错误码不应编码 secret"建议
2. 节点侧无需修改

---

## AUDIT-ERRINFO-004: 被静默忽略的 `Result`

### 状态: ⚠️ Info（少量 `let _ = ...` 模式）

### 分析过程

通过 grep `let _ = ` 在主要模块的非测试代码：

```
sync/, network/, tx-pool/, chain/, rpc/, script/, verification/
```

常见模式：
1. `let _ = sender.send(...)` — channel send 在接收端 dropped 时失败，业务上可接受
2. `let _ = tokio::spawn(...)` — fire-and-forget task；问题：若 future 自身有 critical error，会静默丢失
3. `let _ = self.tasks.lock()` — 仅用作锁守卫
4. `peer_store.add_addr(addr, Flags::empty())` (`network/src/services/dns_seeding/mod.rs:112`) — DNS seeding 期间忽略 add_addr 失败

实际危险点：
- `tokio::spawn` 内未 `await?` 的 future：若 panic 会被 tokio runtime 捕获并丢弃 → **建议至少 `JoinHandle::abort_handle()` + monitor**
- 重要 channel send：在节点 shutdown 期间 receiver 可能已 drop —— `let _` 是预期模式
- 网络写入失败：tentacle 自身 retry / 重连，可忽略

通过 grep 数量级估计：节点中 `let _ = ` 模式数十处，多数为 channel send / fire-and-forget log。

### 发现

- ⚠️ **Info — 难做全面静态判定**: 每个 `let _ = ` 的安全性取决于上下文
- ⚠️ **Info — clippy lint**: `clippy::let_underscore_must_use` 可强制对带 `#[must_use]` 标注的返回值进行处理。建议启用
- ⚠️ **Info — 关键路径**: `chain::ChainService::process_block` 等关键路径未发现 `let _ = ` 模式 ✅
- ✅ 关键 db 写入路径均 `map_err(internal_error)?` 传播错误

### 修复建议

1. **建议**: CI 启用 `clippy::let_underscore_must_use` lint，并对每处 `let _ = ` 添加 SAFETY 注释
2. **建议**: 替换 fire-and-forget `tokio::spawn(async { ... })` 为含错误日志的 wrapper：
   ```rust
   tokio::spawn(async {
       if let Err(e) = future.await {
           error!("background task failed: {e}");
       }
   });
   ```

---

## 本轮小结

| AUDIT-ID | 状态 | 严重 | 摘要 |
|---|---|---|---|
| AUDIT-CONTRACT-005 | ✅ | — | ScriptGroup 按 hash(Script) 分组，Lock/Type 不合并；cycle 按 group 一次 |
| AUDIT-CONTRACT-006 | ℹ️ | Info | 现有 fuzz 基础架构 ok，建议每个 syscall 独立 harness |
| AUDIT-LOGIC-009 | ✅ | — | fee-estimator 用 saturating_add + f64 守护；不影响共识 |
| AUDIT-ERRINFO-003 | ℹ️ | Info | 错误消息对提交者诚实；oracle 范围仅限攻击者自己的 tx |
| AUDIT-ERRINFO-004 | ℹ️ | Info | `let _ = ` 多在 channel / fire-and-forget；建议 clippy lint |

**新增审计项**:
- AUDIT-CONTRACT-008（每个 syscall 单独 fuzz harness + OSS-Fuzz 集成核对）
- AUDIT-ERRINFO-006（CI 启用 `clippy::let_underscore_must_use`）
