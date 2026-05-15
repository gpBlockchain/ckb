# Round 15 — 横向同源扫描：全仓远程可达缓存数据结构

> 日期: 2026-05-15
> 触发: Round 13 发现 `AUDIT-MEMORY-009`（tx-pool conflicts_cache 内存放大）。专业审计在确认一处 High 后必做的同源横向扫描——查找全仓库是否有相同范式（远程可触发 + 按条目数而非字节计费 + 缺乏总量上限）的其他容器。
> 结论: **未发现新 High/Medium**；新增 1 个 Info 级别纵深防御建议 `AUDIT-MEMORY-010`（pending_compact_blocks），当前由 PoW 检查屏蔽，不构成可利用漏洞。

---

## 审计范围

枚举所有满足以下条件的容器：

1. `LruCache::new` / `lru::LruCache` 全仓实例（含 `util/*`、`shared/*`、`tx-pool/*`、`sync/*`、`store/*`、`verification/*`、`miner/*`、`rpc/*`、`freezer/*`、`util/network-alert/*`）
2. 通过 P2P/RPC 入口可被远程触发插入的 `HashMap` / `HashSet` / `VecDeque`

针对每个容器评估 4 个维度：

- **上限维度**：条目数 / 字节 / TTL / 无
- **value 大小**：固定 / 受协议限定 / 攻击者可控可变
- **触发路径**：远程廉价 / 远程已计费 / 远程 PoW 门槛 / 我方发起 / 本地
- **同源风险**：与 `AUDIT-MEMORY-009` 相似度

---

## 全仓 LRU 缓存清单与评估

| # | 位置 | 类型 | 上限 | Value 大小 | 触发路径 | 评级 |
|---|------|------|------|-----------|---------|------|
| 1 | `tx-pool/src/pool.rs:48` | `conflicts_cache: LruCache<ProposalShortId, TransactionView>` | 10 K 条目 | ≤ 512 KB/tx (可变) | 远程廉价（RBF/dead-cell reject 不计费） | 🟠 **HIGH — AUDIT-MEMORY-009（已记录）** |
| 2 | `tx-pool/src/pool.rs:50` | `conflicts_outputs_cache: LruCache<OutPoint, ProposalShortId>` | 30 K 条目 | 固定 ~64 B → ~1.9 MB 上限 | 同上 | ✅ Safe |
| 3 | `tx-pool/src/pool.rs:40` | `committed_txs_hash_cache: LruCache<ProposalShortId, Byte32>` | 100 K 条目 | 固定 ~42 B → ~4 MB 上限 | 仅由本节点确认 block 路径填充 | ✅ Safe |
| 4 | `verification/src/cache.rs:11` | `TxVerificationCache: LruCache<Byte32, Completed{cycles,fee}>` | 30 K 条目 | 固定 ~48 B → ~1.4 MB 上限 | 仅已通过完整验证的 tx | ✅ Safe |
| 5 | `sync/src/types/mod.rs:340` (`TtlFilter`) | `LruCache<T, u64>` (tx_filter) | 50 K 条目 + 4h TTL | 固定 ~40 B → ~2 MB 上限 | 远程廉价（tx hash 广播） | ✅ Safe（条目固定大小 + TTL） |
| 6 | `sync/src/types/mod.rs:1025` | `pending_get_headers: LruCache<(PeerIndex, Byte32), Instant>` | 10 K 条目 | 固定 ~56 B → ~560 KB 上限 | 我方主动发起 | ✅ Safe |
| 7 | `store/src/cache.rs:13-25` (7 张表) | `headers/cell_data/cell_data_hash/block_proposals/block_tx_hashes/block_uncles/block_extensions` | config 控制（默认 header=4096, cell_data=128, proposals=30） | 已确认链上数据，受 `MAX_BLOCK_BYTES` 限定 | 间接（链上付费数据） | ✅ Safe |
| 8 | `freezer/src/freezer_files.rs:475` | `LruCache<index, File>` | `open_files_limit` (config) | 文件句柄 | 本地 | ✅ Safe |
| 9 | `util/network-alert/src/alert_relayer.rs:44` | `known_lists: LruCache<PeerIndex, HashSet<u32>>` | 64 peer | `HashSet<u32>` 大小受**官方多签发布的 alert 数量**限制（line 151 `verify_signatures` 在 `mark_as_known` 前） | 远程但必须通过 BIP-style 多签 | ✅ Safe（多签密钥硬编码于 chain spec） |
| 10 | `util/network-alert/src/notifier.rs:38` | `cancel_filter: LruCache<u32, ()>` | `CANCEL_FILTER_SIZE` 固定 | 固定 | 同上（多签验证后） | ✅ Safe |
| 11 | `rpc/src/module/terminal.rs:112-116` | 5 个 `LruCache::new(1)`（sys/mining/tx_pool/cells/network info） | 1 条目 | 单次 RPC 响应 | 本地终端 | ✅ Safe |
| 12 | `miner/src/miner.rs:75` | `legacy_work: LruCache<…>` | `WORK_CACHE_SIZE` 固定 | mining work | 本地 miner | ✅ Safe |

**LRU 小结**：12 个 LRU 缓存中仅 #1（`conflicts_cache`）满足"远程廉价触发 + 攻击者可控可变 value + 仅条目数上限"三件套，与 `AUDIT-MEMORY-009` 同源——其余 11 个均通过以下机制之一缓解：

- **固定大小 value**（#2 #3 #4 #5 #6）
- **链上付费**（#7 #11 间接）
- **官方多签门槛**（#9 #10）
- **本地不可远程**（#8 #11 #12）

---

## 远程可达 HashMap / 非 LRU 容器

| # | 位置 | 类型 | 上限 | Value 大小 | 触发门槛 | 评级 |
|---|------|------|------|-----------|---------|------|
| A | `sync/src/types/mod.rs:980,1332` `PendingCompactBlockMap` | `HashMap<Byte32, (CompactBlock, HashMap<PeerIndex,(Vec<u32>,Vec<u32>)>, u64)>` | **无显式条目数上限** | `CompactBlock` 含 prefilled_transactions，理论可达 block 大小量级（数百 KB） | **必须通过 `non_contextual_check` + `contextual_check`（含 `HeaderVerifier::verify`）→ PoW 难度门槛** | ⚪ **Info — AUDIT-MEMORY-010（新）** |
| B | `util/network-alert/src/notifier.rs:16` `received_alerts: HashMap<u32, Alert>` | 同左 | 由官方多签数量限定（已签发 alert 总量） | Alert 元数据（≤ 数 KB） | 多签验证后 | ✅ Safe |
| C | `sync/src/types/mod.rs:1335` `inflight_proposals: DashMap<ProposalShortId, BlockNumber>` | 同左 | 由当前 inflight 协议消息限定 | 固定 ~14 B | Round 12 已审计 | ✅ Safe |
| D | `sync/src/types/mod.rs:1019` `unknown_tx_hashes: KeyedPriorityQueue` | 同左 | 已有 per-peer + 全局上限 | 固定 hash | Round 13 已审计 | ✅ Safe |
| E | `sync/src/types/mod.rs:1024` `InflightBlocks` | 含 `download_schedulers`/`inflight_states`/`trace_number` | Round 12/13 已审计有上限 | 固定 | — | ✅ Safe |

---

## ⚪ AUDIT-MEMORY-010 — pending_compact_blocks 缺纵深防御上限（**Info**）

### 位置

- `sync/src/types/mod.rs:980-987` — `PendingCompactBlockMap` 类型定义
- `sync/src/types/mod.rs:1332` — 字段声明
- `sync/src/relayer/compact_block_process.rs:358-359` — 唯一生产插入点 `entry().or_insert_with(...)`
- `sync/src/relayer/compact_block_process.rs:107-117` — 清理（`remove` + `retain by epoch` + `shrink_to_fit!(_,20)`）

### 描述

`PendingCompactBlockMap = HashMap<Byte32, (CompactBlock, HashMap<PeerIndex, (Vec<u32>, Vec<u32>)>, u64)>` 用于缓存远端发来的 compact block 在等待补全 missing tx/uncles 期间的状态。该 `HashMap`：

1. **没有显式条目数上限**。`shrink_to_fit!(_, 20)` 只是 capacity 回收的提示，不限制 `len()`。
2. **每个 entry 的 value 包含完整 `CompactBlock`**，其中 `prefilled_transactions` 可包含完整 tx，理论上一个 compact block 可接近 block 大小（数百 KB）。
3. 清理依赖 epoch 推进（`retain` 仅在成功接受新 block 时调用，line 112-116）。

### 当前防御

进入 `pending_compact_blocks` 之前必须通过：

- `non_contextual_check`（`compact_block_process.rs:190-228`）：uncles_num、proposals_limit、height ≥ tip - epoch_length 范围
- `contextual_check`（line 230-339）：parent 存在 + `HeaderVerifier::verify` —— 此处对 header 做 **PoW 验证**（mainnet ~13 EH/s 难度门槛）

**因此当前不是可利用漏洞**：要触发一条插入即需要伪造一个有效 PoW 的 header，攻击成本 ≥ 真正挖矿，远远超过经济收益。

### 风险情境（为何仍归档）

`pending_compact_blocks` 的安全完全依赖一处显式 PoW 检查。这是单点防御：

1. **未来引入轻验证模式**：若节点配置支持 trust-anchor + 跳过完整 PoW（如某些 light validator 提案），立即失去保护
2. **dev/test chain**：`pow = { Dummy = {} }` 配置下无 PoW 难度，本地多节点测试可写入大量条目（仅影响开发体验，非 mainnet）
3. **header_verifier 重构 bug**：若有人重构 `HeaderVerifier::verify` 误将 PoW 改为条件检查，缺乏纵深防御会直接放大事故
4. **`shrink_to_fit!(_, 20)` 的存在表明设计者预期 `len() ≤ 20`** —— 但未通过类型/容器层固化这一约束

### 建议（开发团队实施）

在 `missing_or_collided_post_process` 中插入前增加显式上限检查，例如：

- `if pending_compact_blocks.len() >= MAX_PENDING_COMPACT_BLOCKS { return; }`（建议常量 ≤ 64，与 `INIT_BLOCKS_IN_TRANSIT_PER_PEER` × 典型 peer 数同量级）
- 或将 `HashMap` 改为 `LruCache::new(64)`，让插入自动淘汰
- 同时对 entry 的 inner `HashMap<PeerIndex, …>` 限制为 `MAX_PEERS` 量级，防止同一 block_hash 下被多 peer 重复占位

### 评级理由

| 维度 | 评估 |
|------|------|
| 可达性 | 远程协议消息触发 |
| 攻击成本 | **≥ 挖出一个有效 header**（mainnet 极高，dev chain 极低） |
| 影响 | 内存放大（理论上每条目数百 KB × 无上限） |
| 触发难度 | mainnet 不可行；dev/test 局部 |
| 现实评级 | **Info**（纵深防御建议） |

---

## Round 15 结论

1. **横向同源扫描收敛**：全仓 12 个 LRU + 5 个远程可达 HashMap，仅 `tx-pool conflicts_cache` 满足 MEMORY-009 同源条件——其他容器均通过 value 固定大小、链上付费、多签门槛、PoW 门槛、本地隔离之一缓解。
2. **新候选 1 个**：`AUDIT-MEMORY-010 (Info)` — `pending_compact_blocks` 受 PoW 单点防御，建议增加纵深上限。
3. **MEMORY-009 仍是 v3 审计的唯一 High**；Round 14 + Round 15 联合核验给出**充分信心**该评级稳定。

### 累计统计（v3 终态）

| 严重度 | 数量 | 项目 |
|--------|------|------|
| Critical | 0 | — |
| High | 1 | AUDIT-MEMORY-009 |
| Medium | 2 | （见 SECURITY_AUDIT_TODO.md）|
| Low | ~11 | （见 SECURITY_AUDIT_TODO.md）|
| Info | ~25 | 含本轮新增 AUDIT-MEMORY-010 |

下一步建议交由开发团队实施 MEMORY-009 修复（修复方向见 round-13 报告"建议修复"小节）+ MEMORY-010 纵深防御。
