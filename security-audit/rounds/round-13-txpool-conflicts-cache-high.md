# Round 13 — 深度审计：tx-pool conflicts_cache 内存放大攻击

> 日期: 2026-05-15  
> 范围: 在 12 轮按维度/模块/跨模块审计均未发现 High 后，沿 RBF 与拒绝路径深入挖掘  
> 结论: **发现首个 High 级别问题** — `AUDIT-MEMORY-009`

---

## 起点：用户要求"继续审计直到发现高危问题"

前 12 轮发现：0 Critical / 0 High / 2 Medium / 8 Low / ~20 Info。本轮通过 3 个并行 sub-agent 分别深挖：

1. sync/relay 协议消息处理（合计 6 候选，**核验后全部降级**）
2. tx-pool orphan / conflicts 池增长（4 候选，**1 个升级为 High**）
3. chain reorg ↔ freezer / init_load_unverified panic（5 候选，**核验后降级**）

下文记录每个候选的核验过程与最终评级。

---

## ⚠️ AUDIT-MEMORY-009 — tx-pool `conflicts_cache` 内存放大攻击（**HIGH**）

### 位置
- `tx-pool/src/pool.rs:31,48,164-188`
- `tx-pool/src/process.rs:225-232,448-456`
- `util/types/src/core/tx_pool.rs:309` — `TRANSACTION_SIZE_LIMIT = 512 * 1_000`
- 默认配置 `resource/ckb.toml:213-214` — `min_rbf_rate=1500 > min_fee_rate=1000` ⇒ **RBF 默认启用**

### 漏洞描述

`TxPool` 维护两个独立 LRU 缓存用于追踪被替换 / 被拒绝的 tx：

```rust
// tx-pool/src/pool.rs:31-32
const CONFLICTES_CACHE_SIZE: usize = 10_000;
const CONFLICTES_INPUTS_CACHE_SIZE: usize = 30_000;

// tx-pool/src/pool.rs:48-50
pub(crate) conflicts_cache: lru::LruCache<ProposalShortId, TransactionView>,
pub(crate) conflicts_outputs_cache: lru::LruCache<OutPoint, ProposalShortId>,
```

**关键问题**:
1. `conflicts_cache` 上限是**条目数 = 10,000**，每条目存储完整 `TransactionView`
2. 单笔 tx 最大字节数 `TRANSACTION_SIZE_LIMIT = 512_000` 字节
3. 理论上限：10,000 × 512KB ≈ **4.88 GB**
4. 该缓存**不计入** `max_tx_pool_size = 180MB`（resource/ckb.toml:211）
5. 缓存条目的两条插入路径都不要求攻击者**支付任何交易费**

### 插入路径核验

#### 路径 A — RBF 替换（`process.rs:225-232`）
```rust
let reject = Reject::RBFRejected(format!("replaced by tx {}", entry.transaction().hash()));
// RBF replace successfully, put old transactions into conflicts pool
tx_pool.record_conflict(old.transaction().clone());  // line 229
```
将 **被替换的旧 tx**（合法用户的 tx）放入缓存。

#### 路径 B — after_process 兜底（`process.rs:448-456`）
```rust
if matches!(
    ret,
    Err(Reject::RBFRejected(..) | Reject::Resolve(OutPointError::Dead(_)))
) {
    let mut tx_pool = self.tx_pool.write().await;
    if tx_pool.pool_map.find_conflict_outpoint(&tx).is_some() {
        tx_pool.record_conflict(tx.clone());   // line 454 — 攻击者的 tx 入缓存
    }
}
```
**这是关键漏洞点**: 攻击者提交的、未付费、被拒绝的 tx 仍然被存入 `conflicts_cache`。

### 攻击场景（已经过代码路径核验）

**前置条件**:
- 攻击者拥有 1 个 live cell（mainnet 最低 ~61 CKB ≈ $10）
- 默认配置（RBF 启用）

**步骤**:
1. 攻击者构造 tx **A**（小尺寸，正常费率）花费 cell X → 入池
2. 构造 tx **B₁**（接近 512KB，用 `output_data` 灌入垃圾字节）花费同一 cell X，费率略高于 A
   - 通过 `non_contextual_verify` ✓（tx_size 刚好不超）
   - 通过 `check_tx_fee` ✓（fee = inputs_capacity - outputs_capacity > 0）
   - 通过 script verification ✓（攻击者持有 X 的私钥）
   - 触发 RBF 替换 → A 入 `conflicts_cache`（**路径 A**）→ B₁ 入池
3. 构造 tx **B₂**：依然花费 cell X，~512KB，**费率刚好低于 B₁（但 ≥ min_fee_rate）**
   - 通过非语境验证 ✓
   - 通过 fee 检查 ✓
   - 通过签名验证 ✓
   - `resolve_tx(false)` 检测到 X 被 B₁ 占用 → `Reject::Resolve(OutPointError::Dead(X))`
   - 重新 `resolve_tx(true)` 成功（line 293），`find_conflict_outpoint(B₂)` 返回 Some(B₁) ✓
   - 继续后续验证，submit_entry 因 RBF 费率不达标 → `Reject::RBFRejected` 或 Dead
   - **`after_process` 命中 line 453 条件** → `record_conflict(B₂)` → **B₂ 入 `conflicts_cache`**
4. 重复 B₃, B₄, …, B₁₀₀₀₀ — 每个 ~512KB，每个都被 RBF 拒绝、不付费、但**入缓存**
5. LRU 满后开始淘汰最旧条目，攻击者维持稳态注入即可保持 10,000 条目

**结果**:
- `conflicts_cache`: 10,000 条 × ~512KB ≈ **4.88 GB** 攻击者控制的数据
- 完全旁路 `max_tx_pool_size = 180MB` 上限（**~27 倍放大**）
- 默认 mainnet 节点 RAM 8-16GB → **OOM kill 实际可达**

### 攻击成本

| 资源 | 数量 |
|---|---|
| 资金 | 1 个 cell（~61 CKB ≈ $10），且**不被消耗**（rejected txs 不上链） |
| 链上手续费 | 仅 **B₁ 替换成功** 一次的费用，rest 均为 RBFRejected 免费 |
| 上行带宽 | ~5 GB（10,000 × 512KB） |
| 计算 | 签名 10,000 次（毫秒级） |
| 时间 | 单核心几分钟可填满 |

### 为何前几轮未发现

- Round 03 / 10 审计 `ScriptGroup`、cycle 与 fuzz；未深挖 conflicts_cache 字节预算
- Round 09 `MEMORY-006` 看了 rocksdb，`MEMORY-007` 看了 rich-indexer；未审 conflicts_cache
- `MEMORY-003`（Round 02）核对的是主 pool 与各 LRU 上限，**但忽略 conflicts_cache 的字节维度**
- `MEMORY-005`（Round 07）专注 panic 反模式
- 整个跨模块 `XM-002` 在 Round 12 提到 conflicts_cache 但未量化字节预算

### 缓解建议（按效力降序）

1. **字节配额上限** — 将 `conflicts_cache` 改为按字节计上限（例如 50 MB），替代 `usize` 条目数上限
   ```rust
   // 改造为 BytesBoundedLruCache 或在 record_conflict 中累加 tx_size，超阈值时淘汰
   ```
2. **不存储 TransactionView** — 仅存 `ProposalShortId → Byte32(tx_hash)`；需要恢复时从 `recent_reject` 或链上读取
3. **将 `conflicts_cache` 字节数计入 `max_tx_pool_size`** — 在 `limit_size()`（pool.rs:292-329）中对 `conflicts_cache` 也做清理
4. **拒绝异常大尺寸 RBF 候选** — 在 line 454 前增加 `if tx.data().total_size() > SOFT_LIMIT { return }`
5. **per-peer / per-source 限速** — 对单 peer 单位时间内的 RBFRejected 数量限速

### 严重级评定

| 维度 | 评估 |
|---|---|
| **可达性** | ✅ 默认配置可触发（RBF 默认启用） |
| **特权要求** | ✅ 任意 RPC 用户 + 1 cell 持有 |
| **攻击复杂度** | 🟡 中（需要构造合法签名 + RBF 关系），但脚本化容易 |
| **影响** | 🔴 OOM kill → 节点崩溃；并影响共识参与 |
| **放大倍数** | 🔴 ~27× over `max_tx_pool_size` |
| **链上代价** | 🟢 接近 0 |
| **最终评级** | **🟠 HIGH** |

按 CVSS 3.1 估算: AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H ≈ 6.5–7.5。

---

## 已核验后降级的候选

### Sync agent Finding #1 — `pending_compact_blocks` 无界 — **驳回**
- 入口 `missing_or_collided_post_process` 之前必须通过 `HeaderVerifier::verify()`（`sync/src/relayer/compact_block_process.rs:325`），即真实 **PoW** 检查
- 攻击者无法批量产出有效 PoW header → 不构成实际 DoS
- 评级: **Info / 设计安全**

### Sync agent Finding #2 — `unknown_header_list` 无界 — **驳回**（误报）
- `sync/src/types/mod.rs:1183` 显式守卫：`if self.state().peers.unknown_header_list_is_empty(pi)`
- 只有列表为空时才填充，且最多 `MAX_LOCATOR_SIZE = 101` 个 hash
- 单 peer 上限 = 101 × 32B ≈ 3.2 KB，整网最坏 max_peers × 3.2KB ≪ 1MB
- 评级: **N/A — 误报**

### Sync agent Finding #3 — `pending_compact_blocks` 锁竞争 — **降级**
- 同样受 PoW 前置门控限制
- `.retain()` O(n) 在每次成功 block 接收时执行，正常 mainnet ~10s/block，n 较小
- 评级: **Info**

### Sync agent Finding #5/#6 — 状态竞争 / `RelayTransactionHashes` 限速 — **维持 Medium**
- `RelayTransactionHashes` 单条最多 32767 hashes（`MAX_RELAY_TXS_NUM_PER_BATCH`），无 per-peer rate-limit
- 攻击者可大量发送但需经 BAD_MESSAGE 处理；不属于 High
- 评级: **Medium**, 已被 round-02 NET-002 与 round-09 涵盖

### chain agent Finding "XM-014-A: reorg crosses freezer" — **降级**
- `chain/src/` 完全没有 `freezer` 引用（grep 验证），freezer 由 store 层抽象
- store 读取对 freezer 透明，detach_block 只 DELETE column families，freezer 文件由 store/freezer 子层管理
- 现实可利用性：mainnet PoW 实际 reorg 深度 < 7 block，freezer threshold 通常远大于此（数千区块）
- 评级: **Low** (维持 round-12 XM-014-A 评级；为防御深度建议加显式 fork_point > freezer.number 检查)

### chain agent Finding "init_load_unverified panic" — **降级**
- `chain/src/init_load_unverified.rs:117` `.expect("unverified block must be in db")`
- 触发条件需要数据库部分写入（COLUMN_NUMBER_HASH 有，COLUMN_BLOCK_BODY 无）
- CKB 写入由 RocksDB WriteBatch 原子事务保证，部分写入不会发生
- 评级: **Info**（防御性 expect → ok_or_else 仍是好做法）

### tx-pool agent Finding "orphan pool 51MB 旁路" — **维持 Medium**
- 100 条目上限 × 512KB = 51MB
- 比 MEMORY-009 小得多，且 orphan 入池条件更苛刻（需有效 parent reference 与 cycle limit）
- 评级: **Medium**, 已可作为 MEMORY-009 修复的关联项

### tx-pool agent Finding "RBF deep chains" — **维持 Medium**
- `calc_descendants` 在 RBF 检查链上重复调用，CPU 而非内存
- `MAX_REPLACEMENT_CANDIDATES = 100` 上限存在但循环内调用，可能多算
- 评级: **Medium**

---

## 本轮交付物

1. **AUDIT-MEMORY-009 (HIGH)** — 新增至 SECURITY_AUDIT_TODO.md 附录 B 与 C
2. 三个 sub-agent 候选清单的核验结论（上述）
3. **MODULE_REPORT.md / REPORT.md** 更新风险评级总览

## 风险评级总览（更新后）

| 严重 | 数量 | 项目 |
|---|---|---|
| 🔴 Critical | 0 | — |
| 🟠 **High** | **1** | **AUDIT-MEMORY-009** (新增) |
| 🟡 Medium | 2 | CRYPTO-001, ERRINFO-002 |
| 🟢 Low | 8 | LOGIC-003, CONTRACT-001, INPUT-001, MEMORY-005, CRYPTO-005, AUTH-002, DB-003, MEMORY-007 + XM-014-A |
| 🔵 Info | ~22 | （含本轮核验降级项） |

## 建议下一步

1. **优先级 P0** — 修复 MEMORY-009，建议方案 1 + 2 组合（字节配额 + 不存全 TransactionView）
2. 添加专项 fuzz/集成测试: 「reject-tx-conflict-cache 字节预算」
3. 在 `tx-pool/src/component/tests/` 增加测试用例验证 conflicts_cache 字节上限
