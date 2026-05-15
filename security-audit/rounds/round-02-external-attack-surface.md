# Round 2 — P0 外部攻击面审计

> 范围: AUDIT-INPUT-003 / 004 + AUDIT-NET-001 / 002 + AUDIT-MEMORY-002 / 004  
> 日期: 2026-05-15

---

## AUDIT-INPUT-003: Sync 协议消息长度上限与字段范围

### 状态: ✅ 通过

### 分析过程

`util/constant/src/sync.rs` 定义了主要边界常量：

| 常量 | 值 | 含义 |
|---|---|---|
| `MAX_TIP_AGE` | 24 * 3600 * 1000 ms | IBD 判定阈值 |
| `MAX_HEADERS_LEN` | `2000` | 单次 `SendHeaders` 消息最大 header 数 |
| `MAX_BLOCKS_IN_TRANSIT_PER_PEER` | `128` | 单 peer 在途块数 |
| `CHECK_POINT_WINDOW` | `512` | 检查点窗口 |
| `MAX_LOCATOR_SIZE` | `101` | `GetHeaders` locator 最大长度 |
| `BAD_MESSAGE_BAN_TIME` | `5min` | 错误消息封禁时长 |

`sync/src/synchronizer/headers_process.rs:106`:
```rust
if headers.len() > MAX_HEADERS_LEN {
    return StatusCode::HeadersIsTooLarge.with_context(...);
}
```

`sync/src/synchronizer/get_headers_process.rs` 使用 `MAX_LOCATOR_SIZE` 约束 locator。

`sync/src/relayer/compact_block_process.rs`、`block_transactions_process.rs` 等使用 `IndexTransaction.index` 索引校验。

### 发现

- ✅ 所有协议消息均有 `MAX_*` 上限，超限 → 返回 `StatusCode::BAD_MESSAGE` 子类 → `BAD_MESSAGE_BAN_TIME` 封禁
- ✅ `MAX_HEADERS_LEN=2000` 与 Bitcoin Core 一致，每 header 约 220 字节，单消息上限 ≈ 440KB，合理
- ✅ `MAX_LOCATOR_SIZE=101` 对应 `log2(2^64)` 几何级数 + 10，足够覆盖全链
- ✅ `MAX_BLOCKS_IN_TRANSIT_PER_PEER=128` 限制单 peer 在途请求，配合 `IBD_BLOCK_FETCH_TOKEN_COUNTDOWN_THRESHOLD` 防止单 peer 滥用带宽

### 修复建议

无。

---

## AUDIT-INPUT-004: tentacle 握手 / secio 公钥 / PeerId 解析

### 状态: ✅ 通过（依赖上游）

### 分析过程

CKB 网络层基于 `tentacle=0.7.1` 与 `tentacle-secio=0.6.6`：

- 握手协议（密钥协商、key exchange、加密通道）由 `tentacle-secio` 实现，未在本仓库再次封装
- 节点侧 `network/src/network.rs`、`peer_registry.rs`、`peer_store/` 仅消费 `tentacle::SessionContext::remote_pubkey` 提取 PeerId
- `PeerId` 派生 = `multihash(SHA256(pubkey))`，已规范化

本仓库可控的部分：
- `network/src/peer_registry.rs` 在握手完成回调中校验：是否已封禁、是否在白名单、是否超过 `max_peers`
- `network/src/peer_store/mod.rs` `PeerStore::add_addr` 校验入站地址格式（`Multiaddr` 解析）

### 发现

- ✅ 握手与公钥验证由 `tentacle-secio` 上游负责，未在本仓库引入额外解析路径
- ⚠️ **依赖上游**: `tentacle-secio=0.6.6` 与 `tentacle=0.7.1` 的安全公告需在 AUDIT-DEPS-002 中跟踪
- ✅ 节点侧对入站 `Multiaddr` 解析依赖 `tentacle-multiaddr=0.3.6`，错误返回不会 panic

### 修复建议

无（已为上游审计跟踪项）。

---

## AUDIT-NET-001: Eclipse 攻击防御

### 状态: ⚠️ Info（建议加强 ASN/子网多样性核对）

### 分析过程

`network/src/peer_store/` 子模块：

| 文件 | 作用 |
|---|---|
| `addr_manager.rs` | 已知地址管理与评分 |
| `anchors.rs` | 锚定节点列表（确保有稳定回路） |
| `ban_list.rs` | 封禁列表（IP + 时间） |
| `browser.rs` | wasm 浏览器节点专用 |
| `peer_store_db.rs` | 持久化 |
| `peer_store_impl.rs` | 主实现 |
| `types.rs` | 数据结构 |

`network/src/network_group.rs` 提供按 `Multiaddr` 提取 "network group"（一般为 IP /16 或 ASN）的工具，用于：
- 出站连接选择时避免同一 group 占主导
- 入站连接驱逐时优先保留多样性

### 发现

- ✅ 节点持久化 `anchors` —— 即便 PeerStore 被污染重启后仍能连接已知好节点（参考 Bitcoin Core 同名机制）
- ✅ `ban_list` 与 `BAD_MESSAGE_BAN_TIME` 联动
- ⚠️ **Info — 需动态验证**: network_group 当前是否按 ASN（更强多样性）还是 /16 子网（较弱）分组？需查 `network_group.rs` 实现详情
- ⚠️ **Info**: `Config.bootnodes` 与 `Config.dns_seeds` 是引导期信任锚；若 DNS 被劫持且 `bootnodes` 数量不足，可在冷启动时被 eclipse —— 这属于 AUDIT-NET-004 范畴

### 修复建议

1. 文档化 network_group 的具体定义（ASN vs 子网）以方便用户评估
2. 启动时若 `peer_store_db` 为空且 `bootnodes.len() < 3`，输出 warning

---

## AUDIT-NET-002: Sync 协议 BAD_MESSAGE 惩罚

### 状态: ✅ 通过

### 分析过程

`sync/src/status.rs:1, 178`:
```rust
use ckb_constant::sync::{BAD_MESSAGE_BAN_TIME, SYNC_USELESS_BAN_TIME};
// ...
pub fn ban_time(&self) -> Option<Duration> {
    match self.code {
        // ... 部分轻量级警告返回 None
        _ => Some(BAD_MESSAGE_BAN_TIME),
    }
}
```

`sync/src/relayer/mod.rs` 多个位置在消息验证失败处显式 ban：
- l.829, 851, 870: `BAD_MESSAGE_BAN_TIME`

`sync/src/net_time_checker.rs:148`: 时间漂移过大 → ban

### 发现

- ✅ 所有 `StatusCode::BAD_MESSAGE_*` 变体均映射到 `BAD_MESSAGE_BAN_TIME=5min` 的封禁
- ✅ `SYNC_USELESS_BAN_TIME` 用于"非恶意但拖累"的对端（如长期 stalling）
- ✅ `relayer` 与 `synchronizer` 均统一通过 `Status` 返回封禁请求，避免散落在各处的 `.disconnect()` 调用

### 修复建议

无。

---

## AUDIT-MEMORY-002: 整数溢出热点

### 状态: ⚠️ Info

### 分析过程

CKB 已采取以下整数安全措施：

1. **Release `overflow-checks = true`**（`Cargo.toml:319`）— 整数 `+`、`-`、`*` 溢出 panic 而非 wrap
2. **`occupied-capacity` crate** 提供 `Capacity::safe_add/safe_sub/safe_mul` 检查算术，全仓 capacity 计算均使用
3. **`numext-fixed-uint`** 用于 `U256` PoW target 计算

剩余热点：

| 位置 | 风险 | 缓解 |
|---|---|---|
| `util/dao/src/lib.rs:138` | u128 → u64 `as` 截断 | ❌ 已在 AUDIT-LOGIC-003 报告 |
| `util/dao/src/lib.rs:189, 230, 243` | u128 → u64 | ✅ 使用 `u64::try_from` |
| `pow/src/eaglesong_blake2b.rs:30` | U256 from_big_endian | ✅ 数组定长 32 字节 |
| `script/src/verify.rs:197-205` | `max_cycles - cycles` 裸减法 | ⚠️ 已在 AUDIT-CONTRACT-001 报告 |
| `verification/src/transaction_verifier.rs` 各处 | capacity 加和 | ✅ 全部 `safe_*` |
| 各处 `data.len() as u64` 类转换 | 通常 usize→u64 安全 | ✅ 64-bit 平台支持 |

### 发现

- ✅ 核心共识/资金路径使用 `safe_*` 显式算术
- ✅ `overflow-checks=true` 提供二级防护
- ⚠️ **Info**: 仍存在零散的 `as u64`/`as usize` 转换。建议在 CI 中加入 `clippy::cast_possible_truncation` 告警 lint（默认 allow，需显式开启）

### 修复建议

考虑在仓库根 `clippy.toml` 增加：
```toml
# 高风险 cast lint（建议至少在 util/dao、util/reward-calculator、script、verification 中开启）
```
或在新代码 review 时强制要求 `try_from` 替代 `as` 用于跨宽度转换。

---

## AUDIT-MEMORY-004: 网络入站速率上限

### 状态: ✅ 通过

### 分析过程

`util/app-config/src/configs/network.rs:22-100`:

| 字段 | 类型 | 作用 |
|---|---|---|
| `max_peers` | u32 | 总连接上限 |
| `max_outbound_peers` | u32 | 出站上限 |
| `max_send_buffer` | Option<usize> | 单连接发送缓冲上限 |
| `channel_size` | Option<usize> | tentacle 内部通道大小 |
| `ping_interval_secs` / `ping_timeout_secs` | u64 | 死连接清理 |
| `whitelist_only` | bool | 仅白名单模式 |

`Cargo.toml:236-240` `governor=0.10` 用于速率限制（feature `std`, `jitter`, `quanta`）。

### 发现

- ✅ 多维度限额齐备
- ✅ tentacle 框架自身在协议层强制 max_send_buffer
- ⚠️ **Info — 需动态验证**: `governor` 实际限速点是否覆盖所有协议入口？建议在 `network/src/protocols/` 各模块核对
- ✅ `ban_list` + `BAD_MESSAGE_BAN_TIME` 形成主动断开机制

### 修复建议

无（建议跟进 governor 实际限速点的动态验证）。

---

## 本轮小结

| AUDIT-ID | 状态 | 严重 | 摘要 |
|---|---|---|---|
| AUDIT-INPUT-003 | ✅ | — | sync 协议长度上限齐备并联动封禁 |
| AUDIT-INPUT-004 | ✅ | — | 握手依赖 tentacle-secio 上游 |
| AUDIT-NET-001 | ℹ️ | Info | PeerStore 多样性机制完备，建议核对 ASN |
| AUDIT-NET-002 | ✅ | — | BAD_MESSAGE 封禁机制统一 |
| AUDIT-MEMORY-002 | ℹ️ | Info | safe_* + overflow-checks 双重防护到位 |
| AUDIT-MEMORY-004 | ✅ | — | 网络速率限制配置完整 |

**下轮建议**: 进入 Round 3 — 脚本执行宿主（AUDIT-CONTRACT-002/003/004 + AUDIT-MEMORY-001）
