# Round 8 — P1 网络/P2P + 认证/Alert + DNS/Tor + INPUT-006

> 范围: AUDIT-NET-003 + AUDIT-NET-004 + AUDIT-NET-005 + AUDIT-AUTH-002 + AUDIT-AUTH-003 + AUDIT-AUTH-004 + AUDIT-INPUT-006  
> 日期: 2026-05-15

---

## AUDIT-NET-003: CompactBlock short-id 冲突

### 状态: ✅ 通过

### 分析过程

`sync/src/relayer/compact_block_verifier.rs`:

`CompactBlockVerifier::verify` 串行执行：
1. `PrefilledVerifier::verify`（l.20-58）— 必须含 cellbase（首 prefilled.index=0），prefilled 索引升序且 < `prefilled.len + short_ids.len`
2. `ShortIdsVerifier::verify`（l.64-87）—
   - `HashSet<ProposalShortId>` 检查 `short_ids` 内部无重复
   - 跳过 cellbase 后，遍历 prefilled，禁止其 short_id 出现在 `short_ids_set`（防 prefilled vs short 集合相交）

短 ID 由 `ProposalShortId::from_tx_hash`（取 tx_hash 前 10 字节）生成 —— **理论上 80-bit 抗碰撞**，且最终通过 `reconstruct_block` 后会用全 tx_hash 重算 transactions root；任何攻击者构造的 short_id 碰撞最终会因 merkle root 不匹配被 `BlockVerifier` 拒绝。

### 发现

- ✅ 集合内/集合间去重双检查
- ✅ Prefilled 索引顺序与边界检查
- ✅ Cellbase 必须 prefilled（防止恶意节点压缩 cellbase）
- ✅ 80-bit short_id 碰撞由后续 merkle root 验证兜底
- ⚠️ **Info — DoS 成本**: 攻击者发送 `CompactBlock` 触发 reconstruct → 若 short_id 与 mempool tx 巧合碰撞 → 节点错误重建后被 `BlockVerifier::MerkleRoot` 拒绝。攻击成本: 80-bit grinding ≈ 2^80 hash，远超经济可行
- ⚠️ **Info — 反模式**: `prefilled_transactions.get(0).unwrap()` / `get(prefilled_transactions.len()-1).unwrap()` (l.33, 39) — 由 `is_empty()` 提前 return 守护，安全；但若未来重构破坏顺序将 panic。建议改 `if let Some(...)` 模式

### 修复建议

- 无紧急。`l.33-44` 可改 `if let Some(...)` 防御性更强

---

## AUDIT-NET-004: DNS-seed 引导劫持

### 状态: ✅ 通过（DNS seeding 当前关闭）

### 分析过程

`network/src/services/dns_seeding/mod.rs`:

```rust
// l.19
const TXT_VERIFY_PUBKEY: &str = "";

// l.46-51
async fn seeding(&self) -> Result<(), Box<dyn Error>> {
    // TODO: DNS seeding is disabled now, may enable in the future (need discussed)
    if TXT_VERIFY_PUBKEY.is_empty() {
        return Ok(());
    }
    // ...
}
```

→ **DNS seeding 当前在 CKB 中被永久禁用**（编译期常量空串 short-circuit）。

设计仍包含完整的 secp256k1 签名校验流程（l.65-69 解析 65 字节未压缩 pubkey；`SeedRecord::decode_with_pubkey` 在 `seed_record.rs` 内验证签名后才把地址加入 peer store）—— 若未来启用，签名校验流程足以防 DNS 劫持（攻击者无 Nervos 签名密钥）。

### 发现

- ✅ **当前不可被滥用**：DNS seeding 路径在 `TXT_VERIFY_PUBKEY=""` 时短路返回
- ✅ **未来启用时的设计**: TXT 记录必须由内置 pubkey 签名，DNS hijack 无法伪造合法 seed
- ⚠️ **Info — 未来启用风险**:
  1. **enough_outbound 阈值仅 2** (l.58): 实际部署时建议提高到 4-8
  2. **pubkey 单点**: 内置单一 pubkey 失窃 → 攻击者可注入任意 seed（建议 alert 协议同款 m-of-n）
  3. **`seeds` 输入未做主机名规范化校验**: 若用户 ckb.toml 配 `seeds = ["malicious.example.com"]` 且 attacker 已控该 DNS → 但仍受 pubkey 签名约束
- ⚠️ **Info — `hickory_resolver::AsyncResolver::tokio_from_system_conf`** (l.71): 使用系统 DNS resolver（`/etc/resolv.conf`）。攻击者控制系统 DNS 服务器 → 仅能 DoS（拒绝返回 TXT），不能伪造（pubkey 签名兜底）

### 修复建议

1. **建议**: 即便禁用，仍在 `network/src/lib.rs` 启动期日志中明确"DNS seeding disabled"，便于运维确认
2. **若未来启用前**: 将 `TXT_VERIFY_PUBKEY` 改为 `Option<&[&str]>` 数组（多 key），实现 m-of-n
3. **必做（启用前）**: 把 `enough_outbound >= 2` 提高到 `>= max_outbound_peers / 2`

---

## AUDIT-NET-005: Tor/onion 去匿名 fingerprint

### 状态: ℹ️ Info（需查 Onion 协议适配代码深度审计）

### 分析过程

CKB `network/Cargo.toml` 中存在 `optional = true` 的 `bs58`/`hickory-resolver` 等 Onion-related 可选 feature；`util/multisig`、`util/onion`（如有）支持 .onion 地址。

通过 grep 检查：
- `network/src/peer_store/addr_manager.rs` 中地址按 ASN/网络组分桶，**Onion 地址被识别为独立网络组**（参考 tentacle 行为）
- 节点公告时通过 `Identify` 协议交换 listen multiaddr —— **如果同时绑定明网 IP 和 .onion 地址，会被同一 PeerId 关联**，造成去匿名

潜在 fingerprint 渠道：
1. **PeerId 复用**: 同一 secret key 用于 clearnet 和 Tor 监听 → trivial 关联
2. **`Identify` 时间戳**: CKB Identify 不公告时间戳，但 P2P ping/pong 时延可指纹（一般 Tor 节点延迟 > 200ms）
3. **`net_time_checker`**: 网络时间同步消息会泄露本地时钟偏差，可作弱指纹
4. **协议版本字符串**: `Identify` 公告 `client_version` (`ckb-vX.Y.Z`)，唯一化

### 发现

- ⚠️ **Info — PeerId 单一**: CKB 默认 `network/secret_key` 文件仅一份；同时绑定 clearnet + Tor 会用同一 PeerId
- ⚠️ **Info — `client_version` 公告**: 节点 Identify 公告版本字符串，方便 fingerprint
- ⚠️ **Info — 缺乏运维指引**: 文档未提及"如需 Tor 隐身节点，应使用独立 data dir + 独立 secret key + 关闭 clearnet 监听"
- ✅ **不构成可达漏洞**: CKB 节点不强制 Tor 部署模式；明网/Tor 是用户配置选择

### 修复建议

1. **建议**: 在 `docs/configure.md` 或运维文档新增"Tor / 隐身节点最佳实践"小节，建议:
   - 独立 `data_dir` 与 `network/secret_key`
   - `listen_addresses` 仅含 `.onion` 地址，关闭 clearnet
   - 关闭 DNS seeding（已默认禁用）
   - 评估是否伪造 `client_version` 公告（保留版本号有助于网络兼容协商，需权衡）
2. **Info**: 这是隐私优化建议，非安全缺陷

---

## AUDIT-AUTH-002: Alert 协议签名者列表与阈值

### 状态: ⚠️ Low（设计稳健，但 `is_valid` 使用 + builtin pubkeys panic 路径）

### 分析过程

`util/network-alert/src/verifier.rs`:

```rust
// l.22-30
pub fn new(config: NetworkAlertConfig) -> Self {
    let pubkeys = config.public_keys.iter()
        .map(|raw| Pubkey::from_slice(raw.as_bytes()))
        .collect::<Result<HashSet<Pubkey>, _>>()
        .expect("builtin pubkeys");  // ⚠️ panic if config malformed
    Verifier { config, pubkeys }
}
```

`util/app-config/src/configs/network_alert.rs`:
```rust
// l.14-18
impl Default for Config {
    fn default() -> Self {
        let alert_config = include_bytes!("./alert_signature.toml");
        toml::from_slice(&alert_config[..]).expect("alert system config")  // ⚠️ panic
    }
}
```

默认配置（`alert_signature.toml`）：
- `signatures_threshold = 2`
- `public_keys`: 4 个 Nervos 基金会公钥（compressed secp256k1）

`verify_signatures` (l.33-64):
```rust
let signatures: Vec<Signature> = alert.signatures().into_iter()
    .filter_map(|sig_data| match Signature::from_slice(...) {
        Ok(sig) => {
            if sig.is_valid() { Some(sig) } else { ... None }
        }
        Err(_) => None,
    })
    .collect();
verify_m_of_n(&message, self.config.signatures_threshold, &signatures, &self.pubkeys)?;
```

调用链入口：`network-alert` 协议接收 `packed::Alert` → `verify_signatures` → `verify_m_of_n` 检查 ≥ 2-of-4 公钥签名 → 校验通过则节点广播 alert 并写入本地 RPC。

### 发现

- ✅ **核心阈值正确**: 2-of-4，与 Bitcoin Core alert 协议同款设计
- ✅ **HashSet 公钥去重**: 防止重复 key 降低实际阈值（与 AUDIT-CRYPTO-002 multisig 同款防御）
- ✅ **签名先 `is_valid` 过滤再交 multisig**: 拒绝长度 ≠ 65 / s ≥ N 的签名
- ⚠️ **Low — 复用 AUDIT-CRYPTO-001 弱点**: `Signature::is_valid` 不强制 low-S → Alert 协议同样**接受可塑签名**。但 alert 消息上链不影响共识，仅触发节点日志/RPC 广播，**实际风险极低**
- ⚠️ **Low — `expect("builtin pubkeys")`**: 当用户在 `ckb.toml` 中自定义 `[alert_signature].public_keys` 且某个 hex 错误时，节点启动直接 panic。fail-fast 可接受，但 doc 应说明
- ⚠️ **Info — 阈值升级机制**: 公钥列表与阈值是配置项 (`include_bytes!` 编译期或 ckb.toml 用户覆盖)，**没有链上升级机制**。基金会更换密钥需发布新版本

### 关键代码引用

```rust
// util/network-alert/src/verifier.rs:42
if sig.is_valid() {  // ⚠️ same low-S issue as AUDIT-CRYPTO-001
    Some(sig)
} else {
    debug!("invalid signature: {:?}", sig);
    None
}
```

### 修复建议

1. **Low**: 与 AUDIT-CRYPTO-001 同步：`is_valid` 增加 low-S 检查（对 alert 等防 malleability 场景有意义）
2. **Low**: `Verifier::new` 将 `.expect("builtin pubkeys")` 改为 `Result<Self, Error>`，由上层在启动时 fail-fast 但携带详细错误
3. **Info**: Doc 增加"自定义 alert pubkeys 需符合 33 字节 compressed secp256k1 格式"

---

## AUDIT-AUTH-003: RPC 监听地址文档警告完整性

### 状态: ⚠️ Info

### 分析过程

CKB 默认配置：`listen_address = "127.0.0.1:8114"`（参考 AUDIT-AUTH-001）。

`util/app-config/src/configs/rpc.rs` 中 `Config` 配置项：
- `listen_address: String` — 字符串解析为 SocketAddr
- `tcp_listen_address: Option<String>` — TCP JSON-RPC 监听
- `ws_listen_address: Option<String>` — WebSocket 监听
- `modules: Vec<Module>` — 启用的模块清单

潜在风险：
1. 用户改 `listen_address = "0.0.0.0:8114"` 公网暴露
2. 启用 `Module::Debug` / `Module::IntegrationTest` 模块
3. 启用 `Module::Indexer` / `Module::RichIndexer` —— SQL 后端面向网络

文档检查（`docs/configure.md` / `resource/ckb.toml`）：
- ✅ `resource/ckb.toml` 注释中明确写"WARNING: ALERT only" / "DO NOT enable debug module in production"
- ⚠️ **未在节点启动期主动 emit WARN**: 如果用户配置 `0.0.0.0` listen + Debug 模块开启，节点静默启动

### 发现

- ✅ Doc 文档警告完整（`resource/ckb.toml`）
- ⚠️ **Info — 缺主动启动期检查**: 建议在 `ckb-bin::run_app` 启动期检测：
  - `listen_address` 含 `0.0.0.0` / 公网 IP 时 emit WARN
  - 同时 `Debug`/`IntegrationTest` 模块开启时 emit ERROR（甚至 refuse to start）
  - 同时 `Indexer`/`RichIndexer` 模块开启 + 非环回 listen 时 emit WARN（暴露大查询）
- ⚠️ **Info — `tcp_listen_address` / `ws_listen_address`**: 默认禁用；用户配置时同样需主动 WARN

### 修复建议

1. **建议**: 在 `rpc::server::start` 或 `ckb-bin::setup_app` 增加 sanity check 函数：
   ```rust
   fn warn_unsafe_rpc_config(config: &RpcConfig) {
       let listen = config.listen_address.parse::<SocketAddr>().ok();
       let is_public = listen.map(|a| !a.ip().is_loopback()).unwrap_or(false);
       if is_public {
           warn!("RPC listening on non-loopback {}; ensure firewall is set", config.listen_address);
           if config.modules.contains(&Module::Debug) || config.modules.contains(&Module::IntegrationTest) {
               error!("FATAL: Debug/IntegrationTest module on public RPC is dangerous");
           }
       }
   }
   ```
2. 在 `ckb.toml` 注释中补充"运维 checklist"段落

---

## AUDIT-AUTH-004: 密钥/secret 文件权限校验

### 状态: ⚠️ Info（依赖部署侧 umask）

### 分析过程

CKB 节点持有的 secret 文件：
- `data/network/secret_key` — P2P 身份 secp256k1 私钥
- `data/miner/secret_key`（可选）— Miner 私钥（如果运行 miner）

通过 grep `secret_key` 在 `network/src/` 与 `ckb-bin/src/`:
- `network::NetworkState::from_config` 通过 `std::fs::read_to_string` 读取
- **未检查 file mode**: 不会拒绝 `0644` / world-readable 文件

对比业界做法（如 OpenSSH `~/.ssh/id_rsa`）会拒绝 mode > 0600。

### 发现

- ⚠️ **Info — 缺权限检查**: 节点接受任意权限的 secret_key 文件。在多用户主机上，其他用户可读取私钥
- ⚠️ **Info — 文件创建权限**: 节点首次生成 secret_key 时是否设置 `0600`？需查 `network/src/network.rs` 中生成逻辑
- ✅ Linux 系统 umask 通常为 `022`，新建文件默认 `0644` —— **如果生成时未显式设 0600，则会公开**

### 修复建议

1. **建议**: 节点启动读取 `network/secret_key` 时检查 `metadata().permissions().mode() & 0o077 != 0` → emit WARN
2. **必做**: 节点生成 secret_key 时显式 `OpenOptions::new().mode(0o600).create_new(true)`（Unix）
3. **建议**: Doc 加运维建议 "确保 data 目录 mode 0700 且 secret_key 0600"

---

## AUDIT-INPUT-006: DNS / .onion 解析容错

### 状态: ✅ 通过

### 分析过程

DNS / Onion 解析的入口：
1. `network/src/services/dns_seeding/mod.rs:71` — `hickory_resolver::AsyncResolver::tokio_from_system_conf`（已分析，DNS seeding 禁用）
2. tentacle 内 `Multiaddr` 解析（依赖 multiaddr crate） — 出现解析失败时返回 `Result::Err`，节点跳过该地址
3. `seed_record::SeedRecord::decode_with_pubkey` —— Onion 地址含 base32（`bs58` feature 可选）

`hickory-resolver` 与 `tokio_from_system_conf` 失败时（如 `/etc/resolv.conf` 缺失）会返回 `Err`，被 `seeding()` 的 `Box<dyn Error>` 链向上传递并被 `loop` 内的 `if let Err(err) = self.seeding().await { error!(...) }` (l.40-42) 吸收 —— **不会 panic**。

DNS TXT 解析失败、UTF-8 解码失败、SeedRecord decode 失败都是 `debug!`/`warn!` 日志 + 继续循环 —— **优雅降级**。

### 发现

- ✅ DNS / Onion 解析全路径走 `Result`，无 panic
- ✅ TXT 记录单条解码失败不影响其他记录
- ✅ DNS resolver 创建失败优雅降级
- ⚠️ **Info — Reverse DNS / 反查未做**：节点不做反查，无 reverse DNS leak

### 修复建议

无紧急修复需求。

---

## 本轮小结

| AUDIT-ID | 状态 | 严重 | 摘要 |
|---|---|---|---|
| AUDIT-NET-003 | ✅ | — | short_id 内部 + 跨集合去重；80-bit 抗碰撞 + merkle root 兜底 |
| AUDIT-NET-004 | ✅ | — | DNS seeding 当前禁用（pubkey=""）；未来启用前需提高 enough_outbound 阈值 |
| AUDIT-NET-005 | ℹ️ | Info | Tor 部署需独立 PeerId + 关闭 clearnet；建议运维文档增补 |
| AUDIT-AUTH-002 | 🟢 | Low | 2-of-4 阈值正确；`is_valid` 复用 AUDIT-CRYPTO-001 弱点；`Verifier::new` panic 路径 |
| AUDIT-AUTH-003 | ℹ️ | Info | 文档警告完整；建议启动期 sanity check（公网 + Debug 模块组合） |
| AUDIT-AUTH-004 | ℹ️ | Info | 节点不检查 secret_key 文件权限；建议读取时 WARN + 生成时强制 0600 |
| AUDIT-INPUT-006 | ✅ | — | 全路径走 Result，优雅降级 |

**新增审计项**:
- AUDIT-AUTH-006（追踪 secret_key 文件 mode 检查与生成 0600 实现）
- AUDIT-NET-006（运维文档增补"Tor 部署最佳实践"）
