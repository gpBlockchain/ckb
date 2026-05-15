# Round 16 — P2P 消息处理路径 panic 审计

> 日期: 2026-05-15
> 角色: 安全审计（不改动代码）
> 范围: 远端 P2P 消息可达的 `.unwrap()` / `.expect()` / `panic!` / `unreachable!` / 索引越界路径
> 结论: **发现 1 个真实代码缺陷 AUDIT-PANIC-001（Medium，mainnet 由 PoW 屏蔽 → Low），1 个纵深防御建议 AUDIT-PANIC-002（Info）；其余可疑点经过逐一验证均被前置检查门控。**

## 审计方法

CKB 节点是单进程：**任何 panic = 进程崩溃 = 100% DoS**。远端攻击者只需一条精心构造的消息让节点 panic，即可在 `BAD_MESSAGE_BAN_TIME` 起作用之前直接 crash 整个节点。

逐一审视以下文件中 `.unwrap() / .expect() / panic!() / unreachable!()`：

- `sync/src/relayer/**.rs`（28 处生产代码）
- `sync/src/synchronizer/**.rs`（11 处生产代码）
- `network/src/protocols/**.rs`（含 ping/identify/discovery/hole_punching）

判定标准：

1. **不可达**：被前置类型/范围检查门控（如 `is_empty()` → `get(0)`）✅
2. **协议契约保护**：tentacle 框架保证生命周期（`connected` → `received` → `disconnected`）✅
3. **本地不可触发**：设施 token / 初始化路径 ✅
4. **远端可触发但代价 ≥ PoW header**：mainnet 经济不可行 → Info/Low
5. **远端廉价可触发**：High/Critical

---

## 🟡 AUDIT-PANIC-001 — `BlockUnclesVerifier` 缺 `return` 导致远端可触发 panic

### 严重度

- **mainnet 评级: Low**（由 PoW header 验证屏蔽，每次触发需要攻击者挖出一个真实有效的 header）
- **dev/test chain (`pow=Dummy`) 评级: High**（零成本远程 crash 节点）
- **代码缺陷严重度: Medium**（明确的代码 bug，与同模块 sibling 行为不一致）

### 缺陷位置

`sync/src/relayer/block_uncles_verifier.rs:18-24`：

```rust
if expected_ids.len() != uncles.len() {
    StatusCode::BlockUnclesLengthIsUnmatchedWithPendingCompactBlock.with_context(format!(
        "Expected({}) != actual({})",
        expected_ids.len(),
        uncles.len(),
    ));
    // 👆 缺少 `return` —— Status 被构造后丢弃，函数继续
}

for (expected_id, uncle) in expected_ids.into_iter().zip(uncles) {
    let hash = uncle.hash();
    if hash != expected_id {
        return StatusCode::BlockUnclesAreUnmatchedWithPendingCompactBlock
            .with_context(format!("Expected({expected_id}) != actual({hash})"));
    }
}

Status::ok()
```

**对比 sibling**：同目录 `block_transactions_verifier.rs:23-30` 在同一处长度不匹配检查上正确使用 `return`：

```rust
if missing_short_ids.len() != transactions.len() {
    return StatusCode::BlockTransactionsLengthIsUnmatchedWithPendingCompactBlock
        .with_context(format!(...));
}
```

显然作者预期 uncles verifier 也 return —— 这是一处遗漏的 `return` 关键字。

### 触发路径（攻击链）

1. **攻击者**发送一个 `CompactBlock` 消息（`sync/src/relayer/compact_block_process.rs`）
   - 必须通过 `non_contextual_check`（uncles_num/proposals_limit/height）
   - 必须通过 `contextual_check`（含 `HeaderVerifier::verify` → **PoW header 难度门槛**）
   - CompactBlock 中至少包含 1 个 uncle，其 `BlockStatus::UNKNOWN` 或 `HEADER_VALID`
2. **节点**经过 `reconstruct_block` 发现缺失 uncle（`mod.rs:434, 469`），返回 `ReconstructionResult::Missing(_, [missing_uncle_idx])`
3. **节点**调用 `missing_or_collided_post_process`（`compact_block_process.rs:354-361`），将 `expected_uncle_indexes = [missing_uncle_idx]` 写入 `pending_compact_blocks`，并向 peer 发送 `GetBlockTransactions{ uncle_indexes: [missing_uncle_idx] }`
4. **攻击者**响应 `BlockTransactions { uncles: [] }` —— **空 uncles 列表**
5. **节点** `BlockTransactionsProcess::execute`（`block_transactions_process.rs:85-89`）调用 `BlockUnclesVerifier::verify(compact_block, expected_uncle_indexes=[1], &received_uncles=[])`：
   - `expected_ids.len() == 1`, `uncles.len() == 0`
   - 长度不匹配，**Status 被构造后丢弃**（缺 return）
   - `zip` 产生 0 个 pair，循环不执行
   - 返回 `Status::ok()` ❌
6. **节点**继续执行 `reconstruct_block(received_uncles=[], uncles_index=&[1])`（`mod.rs:420-425`）：
   ```rust
   for (i, uncle_hash) in compact_block.uncles().into_iter().enumerate() {
       if uncles_index.contains(&(i as u32)) {  // i == 1 命中
           uncles.push(
               received_uncles
                   .get(position)            // position == 0, received_uncles.len() == 0
                   .expect("have checked the indexes")  // 💥 PANIC
                   .clone()
                   .data(),
           );
           position += 1;
   ```
7. `Option::None.expect("have checked the indexes")` → **进程 abort**

### 当前防御

唯一防御是 `HeaderVerifier::verify` 中的 PoW 难度检查，要求攻击者持有一个有效 header：

- **mainnet (`pow = Eaglesong`)**：实际挖矿成本（>13 EH/s 全网算力分母），单次触发约等于一次完整出块的算力成本。即便如此，**单个 header 可同时发给 N 个 peer**，因此一次挖矿可 crash 多节点
- **testnet (`pow = Eaglesong`)**：测试币 + 较低难度，攻击成本明显降低但仍非零
- **dev/staging (`pow = Dummy`)**：**零 PoW 成本**，可被任何对等节点立即触发

### 影响

- 单条恶意消息 → 节点进程 abort → DoS
- panic 发生在 `received` 异步消息处理中，**`BAD_MESSAGE_BAN_TIME` 来不及生效**
- 攻击者节点本身不会因此被 ban（因为 ban 流程根本没机会执行）

### 修复建议（开发团队实施）

最小修复：在 `block_uncles_verifier.rs:18` 加 `return`：

```rust
if expected_ids.len() != uncles.len() {
    return StatusCode::BlockUnclesLengthIsUnmatchedWithPendingCompactBlock.with_context(...);
}
```

纵深防御：将 `reconstruct_block:425` 的 `.expect(...)` 改为返回 `ReconstructionResult::Error(...)`，使得即使将来又出现类似上游漏检 bug，节点也不会 panic，而是降级为 ban peer + 重新请求。

### 评级理由

| 维度 | 评估 |
|------|------|
| 漏洞性质 | 真实的代码缺陷（确认遗漏 `return`） |
| 远端可达 | 是 |
| mainnet 触发成本 | ≥ 1 个有效 header PoW（极高） |
| testnet/dev 触发成本 | 显著降低 / 零 |
| 影响 | 进程 abort = DoS |
| 综合 | **Low（mainnet）/ Medium（多链综合）** |

---

## ⚪ AUDIT-PANIC-002 — `received_uncles.get(position).expect(...)` 的纵深防御（**Info**）

### 位置

- `sync/src/relayer/mod.rs:425` — `expect("have checked the indexes")`
- `sync/src/relayer/mod.rs:477` — `expect("missing checked, should not fail")`

### 描述

即使 PANIC-001 被修复，`reconstruct_block` 仍依赖**上游验证器的不变式**：

- line 425 依赖 `BlockUnclesVerifier` 已确保 `received_uncles.len() ≥ count(i ∈ uncles_index)`
- line 477 依赖 `block_transactions` 中所有 `Option` 都是 `Some` —— 由 `missing = ... .any(Option::is_none)` 检查后 `if !missing` 守护

这两处 `expect` 是合理的"防御性 unwrap"，但它们将**安全性建立在跨函数的契约上**——一旦上游检查在重构中改变（如 PANIC-001 那种漏写 `return`），下游立刻 panic。

### 建议

将 `expect` 改为返回 `ReconstructionResult::Error(StatusCode::Internal.with_context(...))`，把"上游契约失败"降级为 protocol error 而不是 process abort。

不构成可利用漏洞，仅作纵深防御提示。

---

## 经验证安全的可疑 panic 列表（false positives）

下列点在 round 16 中被验证为**有合理前置检查**，不构成漏洞：

| # | 位置 | 表面风险 | 验证结论 |
|---|------|---------|---------|
| 1 | `sync/src/relayer/compact_block_verifier.rs:31,38,49,50` | `prefilled_transactions.get(...).unwrap()` | 由 line 27 `is_empty()` 检查 + len-1 循环范围门控 ✅ |
| 2 | `sync/src/relayer/get_block_proposal_process.rs:65` | `fetch_txs.unwrap()` | 由 line 57-64 `if let Err(e) = fetch_txs { return; }` 门控 ✅ |
| 3 | `sync/src/relayer/get_transactions_process.rs:75` | `.unwrap()` | tx_pool fetch_txs 已检查 Err 提前 return ✅ |
| 4 | `sync/src/relayer/mod.rs:388, 566` | `fetch_txs.unwrap()` | 同上模式 ✅ |
| 5 | `sync/src/relayer/mod.rs:796,799,802` | `expect("set_notify at init is ok")` | 初始化路径，本地 ✅ |
| 6 | `sync/src/relayer/mod.rs:91` | `NonZeroU32::new(30).unwrap()` | 编译期常量 ✅ |
| 7 | `sync/src/synchronizer/headers_process.rs:184` | `headers.last().expect("empty checked")` | 由 line 183 `if headers.len() == MAX_HEADERS_LEN (2000)` 门控 ✅ |
| 8 | `sync/src/synchronizer/mod.rs:148` | `expect("assume valid target must exist")` | 仅在 `CanStart::AssumeValidNotFound` 分支可达，该状态隐含 `assume_valid_targets` 非空 ✅ |
| 9 | `sync/src/synchronizer/mod.rs:276` | `expect("has checked targets is not empty")` | 由 line 269 `if targets.is_empty() { return; }` 门控 ✅ |
| 10 | `sync/src/synchronizer/mod.rs:875-887` | 5 处 `expect("set_notify at init is ok")` | 初始化路径，本地 ✅ |
| 11 | `network/src/protocols/identify/mod.rs:112,132,166,242,304` | 5 处 `expect("RemoteInfo must exists")` | 由 tentacle 协议契约保证 `connected` 先于 `received`/`disconnected`，且 `RemoteInfo` 在 `connected` 中无条件 `insert` ✅ |
| 12 | `network/src/protocols/discovery/mod.rs:66` + `hole_punching/mod.rs:55` | `expect("set discovery notify fail")` | 初始化路径 ✅ |
| 13 | `network/src/protocols/hole_punching/mod.rs:251,256` | `NonZeroU32::new(30).unwrap()` | 编译期常量 ✅ |
| 14 | `network/src/protocols/ping.rs:269` | `panic!("unknown token {token}")` | token 来自 `set_notify` 注册，非 peer 控制 ✅ |
| 15 | `sync/src/synchronizer/headers_process.rs:303` | `panic!("header ... with HEADER_VALID should exist")` | 由本节点 status 标记控制；非 peer 直接控制 ✅ |
| 16 | `sync/src/types/mod.rs:1784` | `panic!("index calculated in get_locator")` | 本节点构造 locator 的数学不变式 ✅ |
| 17 | `sync/src/relayer/mod.rs:949` | `_ => unreachable!()` | match 中前面分支覆盖了所有 `RelayMessageUnionReader` 变体；molecule schema 保证穷尽 ✅ |

---

## Round 16 结论

1. **新发现 1 个代码缺陷**：`AUDIT-PANIC-001` — `BlockUnclesVerifier` 缺 `return`，远端可触发 panic（mainnet 由 PoW 屏蔽 → Low；dev/staging 链 High）
2. **新发现 1 个 Info 纵深防御建议**：`AUDIT-PANIC-002` — `reconstruct_block` 的 `.expect` 降级为 protocol error
3. **17 处可疑 panic 经验证均有合理保护**

### 累计统计（v3.2 终态）

| 严重度 | 数量 | 新增项 |
|--------|------|--------|
| Critical | 0 | — |
| High | 1 | AUDIT-MEMORY-009 |
| Medium | 2 | AUDIT-CRYPTO-001 / AUDIT-ERRINFO-002 |
| Low | ~9 | + **AUDIT-PANIC-001**（Round 16 新增） |
| Info | ~24 | + **AUDIT-PANIC-002**（Round 16 新增）/ AUDIT-MEMORY-010（Round 15） |

### 备注

PANIC-001 虽然 mainnet 等级评 Low，但**修复成本极小**（增加一个 `return` 关键字），强烈建议开发团队优先纳入下个 patch release。dev/staging 链上的 CI/integration test 在此 bug 下确实存在被任意对等节点 crash 的风险。
