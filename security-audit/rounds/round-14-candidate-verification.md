# Round 14 — High 复盘与候选核验

> 日期: 2026-05-15 (T+1h)  
> 触发: 用户"继续"指令，要求在 Round 13 之后继续寻找更多 High  
> 结论: **未发现新增 High**。本轮 7 个候选经源码核验后全部降级；AUDIT-MEMORY-009 (Round 13) 仍是唯一 High。

---

## 触发动机

Round 13 找到首个 High (AUDIT-MEMORY-009：tx-pool `conflicts_cache` 内存放大)。用户希望"继续"，故继续沿相邻路径深挖：

1. **tx-pool 其他缓存** — 是否存在与 `conflicts_cache` 类似"条目数 cap + 大字节负载"模式
2. **notify / RPC subscription** — 是否存在订阅者放大 task spawn 或慢消费者反压
3. **sync 中其余无界 map** — `pending_compact_blocks` / `pending_get_block_proposals` / `inflight_proposals`

通过 2 个并行 sub-agent + 主线核验。

---

## 候选清单与核验结论

### 候选 A: `pending_compact_blocks` 无界 (sync agent #1)
- **声称**: HashMap 无上限，攻击者可注入 1M compact block 头部 → ~570 MB
- **核验**: `sync/src/relayer/compact_block_process.rs:325` 在 `missing_or_collided_post_process` 之前调用 `HeaderVerifier::verify()`，包含 **PoW 检查**。攻击者必须为每个 hash 产出有效 PoW header，经济上不现实（mainnet 每个 header PoW ≈ 数秒-分钟 ASIC 工作量）
- **降级为**: Info（设计安全）

### 候选 B: `pending_get_block_proposals` 无界 (sync agent #2)
- **声称**: `DashMap<ProposalShortId, HashSet<PeerIndex>>` 无上限，单条消息攻击者可注入大量 unique ids
- **核验**: `sync/src/relayer/get_block_proposal_process.rs:38-44` 显式校验：
  ```rust
  let limit = shared.consensus().max_block_proposals_limit() * (shared.consensus().max_uncles_num() as u64);
  if message_len as u64 > limit {
      return StatusCode::ProtocolMessageIsMalformed.with_context(...);
  }
  ```
  Mainnet 上限 ≈ 1500 × 2 = 3000 项/消息；每项 ProposalShortId = 10B + HashSet<PeerIndex> ≈ 8B/peer。每条消息净增 ~30KB。结合 relayer 全局限速 (round-02 NET-002) 与 1 分钟 drain 周期，最坏内存 < 10 MB
- **降级为**: Low（建议加 per-peer cap，已建议但非 High）

### 候选 C: `inflight_proposals` 无界 (sync agent #3)
- **声称**: `DashMap<ProposalShortId, BlockNumber>`，攻击者通过 block header PoW 注入
- **核验**: 入库路径需通过完整 block 接收 (`block_proposal_process.rs:27` 上限 `max_block_proposals_limit * max_uncles_num`)，且 `clear_expired_inflight_proposals` 在 block tip 推进时清理。攻击者必须为每个 block 提供 PoW
- **降级为**: Info

### 候选 D: notify subscriber HashMap 放大 N×task spawn (notify agent #1)
- **声称**: 每个 RPC 订阅在 `NotifyService.new_block_subscribers` 创建唯一 entry；N 订阅 → 每 block N task spawn
- **核验**: `rpc/src/module/subscription.rs:259-273` `SubscriptionRpcImpl::new` 在 RPC server 启动时**只调用一次**，使用固定 key:
  ```rust
  const SUBSCRIBER_NAME: &str = "TcpSubscription";
  handle.block_on(notify_controller.subscribe_new_block(SUBSCRIBER_NAME.to_string()));
  ```
  `NotifyService.new_block_subscribers` HashMap 实际只有 **1 个 entry**（key = `"TcpSubscription"`）。每 block 只 spawn 1 个 task。WebSocket 客户端经 `broadcast::channel(128)` 订阅（line 275-280），broadcast 内部共享 128 msg 环形缓冲，N 个 receiver 共享同一 buffer
- **降级为**: 误报 (N/A)

### 候选 E: broadcast channel lagging 数据丢失 (notify agent #2)
- **声称**: 慢消费者会丢失消息且只 log 不断开
- **核验**: 确实如此 (`subscription.rs:223-237`)，但这是 **设计选择**（broadcast channel 语义），不是漏洞。慢客户端被静默丢消息，但不影响其他客户端或服务端
- **降级为**: Info（建议在 doc 中明确这一语义）

### 候选 F: RPC batch request × max_request_body_size 放大 (notify agent #3)
- **声称**: 1000 batch × 20MB body = 20GB 内存
- **核验**: `max_request_body_size` 是 HTTP body **总**长度限制（jsonrpsee 在 hyper 层强制），20MB 是请求体上限，**不是每个 call**。`rpc_batch_limit: 1000` 限制的是 batch 中 call 数量。实际最大单请求内存 ≤ 20MB
- **降级为**: Low（已被 round-04 RPC-001 涵盖）

### 候选 G: tx-pool `verify_queue` 字节预算超 max_tx_pool_size (tx-pool agent)
- **位置**: `tx-pool/src/component/verify_queue.rs:18` `DEFAULT_MAX_VERIFY_QUEUE_TX_SIZE = 256_000_000`
- **核验**: 实测 verify_queue 256MB 上限 vs max_tx_pool_size 180MB，超出 ~42% **是事实**。但 verify_queue 仅短期持有待验证 tx，验证完即出队进入主池或拒绝；不是持续放大
- **降级为**: Low / 设计审查（建议对齐到 ≤ max_tx_pool_size 以保持总账一致）

---

## 评级表（与 Round 13 一致，无变动）

| 严重 | 数量 | 项目 |
|---|---|---|
| 🔴 Critical | 0 | — |
| 🟠 **High** | **1** | **AUDIT-MEMORY-009** (Round 13) |
| 🟡 Medium | 2 | AUDIT-CRYPTO-001, AUDIT-ERRINFO-002 |
| 🟢 Low | 8 + XM-014-A + **本轮新增 2 (B, G)** ≈ 11 | … |
| 🔵 Info | ~24 (本轮 +4: A, D, E, candidate notes) | … |

---

## 收敛判断

经过 14 轮静态审计（含 4 个跨模块 + 候选验证轮次），CKB 节点的剩余攻击面主要集中在：

1. **资源边界放大**: AUDIT-MEMORY-009 是仍未修复的真实 High，**P0 必修**
2. **设计可观察性不足**: 多处 `verify_queue`/notify/broadcast 行为依赖运维感知（建议 metrics 强化）
3. **运维侧依赖**: TLS termination / 部署侧 hardening 不在审计范围

无新增 High。进一步深挖收益递减，建议优先推进 MEMORY-009 修复 PR。

---

## 经验沉淀（已写入 store_memory 类似领域笔记的检查点）

- 对"N 个订阅者放大"声明，**先查 register 的 key 来源** — 固定 key vs 唯一 key 决定 N
- 对"Map 无上限"声明，**先查入口消息的 `len()` 校验** — molecule 反序列化前/后是否有大小检查
- 对"HashMap+TtlFilter"组合，按 LRU 字节而非条目数估算上限，再与 `max_tx_pool_size` / 共识 byte limit 比对
