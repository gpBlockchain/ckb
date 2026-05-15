# Round 4 — P0 RPC 与依赖审计

> 范围: AUDIT-INPUT-001 / 002 + AUDIT-AUTH-001 + AUDIT-DEPS-001 / 002 + AUDIT-ERRINFO-001  
> 日期: 2026-05-15

---

## AUDIT-INPUT-001: `send_transaction` 参数与执行路径

### 状态: ⚠️ Info

### 分析过程

`rpc/src/module/pool.rs:612-635`:
```rust
fn send_transaction(
    &self,
    tx: Transaction,
    outputs_validator: Option<OutputsValidator>,
) -> Result<H256> {
    let tx: packed::Transaction = tx.into();
    let tx: core::TransactionView = tx.into_view();

    self.check_output_validator(outputs_validator, &tx)?;

    let tx_pool = self.shared.tx_pool_controller();
    let submit_tx = tx_pool.submit_local_tx(tx.clone());

    if let Err(e) = submit_tx {
        error!("Send submit_tx request error {}", e);
        return Err(RPCError::ckb_internal_error(e));
    }

    let tx_hash = tx.hash();
    match submit_tx.unwrap() {   // ⚠️ 前置 if let Err 已守护
        Ok(_) => Ok(tx_hash.into()),
        Err(reject) => Err(RPCError::from_submit_transaction_reject(&reject)),
    }
}
```

完整数据流：
1. JSON-RPC 解码（hyper + axum）受 `Config.max_request_body_size` 限制
2. `Transaction → packed::Transaction` 是 molecule 编码转换，过大/截断在 jsonrpc-types 层被拒
3. `outputs_validator` 默认从 `OutputsValidator::Passthrough` 起步，但 `check_output_validator` 对 main/testnet 应用更严格的 well-known scripts 白名单
4. `submit_local_tx` 进入 tx-pool 异步处理（receiver/sender 模式）
5. tx-pool 自身有：`max_tx_size`（kB）、`max_pending_size`、`max_ancestors_count`、`min_fee_rate`、`max_ancestors_count_limit`、`max_tx_verify_cycles`

### 发现

- ✅ **大尺寸防御层次**: 
  1. HTTP 层 `max_request_body_size`
  2. JSON-RPC 解码层
  3. tx-pool `max_tx_size`
- ✅ `outputs_validator` 在 mainnet/testnet 应用默认 well-known 白名单（已经历过历史 CVE 修复）
- ⚠️ **Info — 代码质量**: l.631 `submit_tx.unwrap()` 是反模式 —— 虽然前置 `if let Err(e) = submit_tx { return ... }` 保证安全，但易在未来重构中破坏。建议改为 `match submit_tx { Ok(x) => match x { ... }, Err(e) => Err(...) }` 单次消费
- ⚠️ **Info — 需动态验证**: 巨型 witness（如单 witness 几 MB）是否被 `max_tx_size` 充分覆盖？需结合 tx-pool 配置默认值核对

### 修复建议

重构 `send_transaction` 为单次 `match`：
```rust
match tx_pool.submit_local_tx(tx.clone()) {
    Err(e) => {
        error!("Send submit_tx request error {}", e);
        Err(RPCError::ckb_internal_error(e))
    }
    Ok(Err(reject)) => Err(RPCError::from_submit_transaction_reject(&reject)),
    Ok(Ok(_)) => Ok(tx.hash().into()),
}
```

---

## AUDIT-INPUT-002: `chain` RPC 范围/分页参数

### 状态: ✅ 通过

### 分析过程

`rpc/src/module/chain.rs` 多处 `get_*` 方法：

| 方法 | 关键参数 | 校验 |
|---|---|---|
| `get_block_by_number` (l.317) | `block_number: BlockNumber` | `block_number > tip` 返回 `Ok(None)` |
| `get_block` (l.183) | `block_hash: H256, verbosity, with_cycles` | `verbosity` 显式 match 0/2，越界返 `Invalid params` |
| `get_block_hash` (l.705) | `block_number` | 同上 |
| `get_transaction` (l.657) | `tx_hash: H256, verbosity` | `verbosity` 0/1/2 显式 match |
| `get_transaction_proof` (l.1060) | `tx_hashes: Vec<H256>, block_hash: Option<H256>` | 内部限制 tx_hashes 数量与 block 范围 |
| `get_fork_block`, `get_header` 等 | 同样模式 | |

`BlockNumber` 类型来自 `util/jsonrpc-types`，是 `Uint64` newtype，要求 `0x` 前缀十六进制：
```rust
// 简化形式
impl<'de> Deserialize<'de> for Uint64 {
    // 解析 "0x..." 失败 → SerdeError → JSON-RPC 返回 Invalid params
}
```

### 发现

- ✅ 所有 `Uint*` 类型走严格反序列化路径，畸形数字直接被 JSON-RPC 框架拒
- ✅ 越界 block_number 返回 `Ok(None)` 而非错（符合 RPC 文档"may return null"）
- ✅ verbosity 仅接受白名单枚举
- ✅ 大范围扫描类（如 `get_transaction_proof`）在内部有数量上限

### 修复建议

无。

---

## AUDIT-AUTH-001: RPC 模块白名单与监听地址

### 状态: ✅ 通过（默认配置安全）

### 分析过程

`util/app-config/src/configs/rpc.rs:7-21`:
```rust
pub enum Module {
    Net, Chain, Miner, Pool, Experiment, Stats,
    IntegrationTest, Alert, Subscription, Debug,
    Indexer, RichIndexer, Terminal,
}
```

`resource/ckb.toml:189-192`（生产默认）:
```toml
modules = ["Net", "Pool", "Miner", "Chain", "Stats", "Subscription", "Experiment", "Terminal"]
# dev =>   modules = [..., "Debug", "Terminal"]
# integration => modules = [..., "IntegrationTest", "Terminal"]
```

监听地址（`util/app-config/src/tests/app_config.rs`）:
```rust
assert_eq!(ckb_config.rpc.listen_address, "127.0.0.1:7000");
```

### 发现

- ✅ **生产默认不包含**: `Debug`、`IntegrationTest`、`Alert`、`Indexer`、`RichIndexer`
- ✅ **默认监听 127.0.0.1**（仅本机），需用户显式改为 `0.0.0.0:7000` 才暴露公网
- ✅ `dev` / `integration` profile 在模板中明确标注 "仅供开发"
- ✅ `enable_deprecated_rpc` 默认 `false`
- ✅ `reject_ill_transactions` 默认 `false`，但 mainnet/testnet 应用 well-known 脚本白名单
- ✅ Config 使用 `#[serde(deny_unknown_fields)]` 防止配置文件错字静默忽略

### 修复建议

1. **建议增强**: 启动时若检测到 `listen_address` 绑定非环回地址（如 `0.0.0.0:*` 或公网 IP）且 `Debug`/`IntegrationTest` 模块开启，输出 `WARN` 级日志（已加入附录 B 中 AUDIT-AUTH-005）
2. 在 `ckb.toml` 注释中加粗强调"将 listen_address 改为 0.0.0.0 前，请先审视 modules 列表"

---

## AUDIT-DEPS-001: cargo audit + GHSA 核对

### 状态: ⚠️ 需动态验证

### 分析过程

本静态审计无法实时调用 `cargo audit`（需 RustSec advisory DB），但可对关键依赖做基本检查：

| 依赖 | 版本 | 风险关注点 |
|---|---|---|
| `ckb-vm` | =0.24.14 | RISC-V VM 解释器，历史曾有 unsafe / 算术修复 |
| `rocksdb` (=ckb-rocksdb) | =0.21.1 | C++ FFI，rocksdb 自身偶有 CVE |
| `secp256k1` | 0.30 | 上游成熟，主要历史 CVE 早期修复 |
| `tokio` | 1.35.0 | 较新，CVE 偶发但通常补丁 |
| `hyper` | 1 | 1.x 系列已稳定 |
| `axum` | 0.8 | 较新，无重大公告 |
| `tentacle` | 0.7.1 | CKB 自维护，需对照其 git 历史 |
| `tentacle-secio` | 0.6.6 | 同上 |
| `rhai` | 1.16.0 | 嵌入式脚本引擎；如开放给用户输入需审 RhaiAST 注入 |
| `sqlx` | 0.8.2 | `rich-indexer` 使用，需 parametrized query |
| `reqwest`, `hyper-tls` | 0.12, 0.6 | TLS 栈，根据 OS 不同 |
| `sentry` | 0.34.0 | 崩溃上报，注意 PII 泄露 |
| `clap` | =4.4 | 钉版较老（当前 4.5.x），无重大公告但建议升级 |

`deny.toml` 仓库已包含（`Cargo.toml:40` 工作区文件列表中），用于：
- 许可证白名单
- 重复版本检测
- yanked 版本检测

### 发现

- ⚠️ **需动态验证**: 必须运行 `cargo audit` 才能给出确定性结论。本审计标注以下为重点跟踪项：
  - `ckb-vm=0.24.14`（钉版，需对照 0.24.x patch 与 0.25+ 系列）
  - `rocksdb=0.21.1`（钉版较老，当前上游 ckb-rocksdb 可能已有新版本）
  - `clap=4.4`（钉版较老）
- ✅ 仓库已使用 `deny.toml` 做策略约束（具体内容未在本轮审视，列入 AUDIT-DEPS-003）

### 修复建议

1. **必做**: 在 CI 中加入：
   ```yaml
   - run: cargo install cargo-audit && cargo audit
   ```
   并设为 required check
2. 周期性（每月）评估 `ckb-vm`/`rocksdb`/`clap` 钉版的安全公告
3. 对 `Cargo.lock` 加入 `dependabot.yml` 或 `renovate.json` 自动 PR 通知

---

## AUDIT-DEPS-002: 钉版依赖安全公告核对

### 状态: ⚠️ Info（流程改进）

### 分析过程

钉版列表（来自 `Cargo.toml`）：
- `Cargo.toml:215` `ckb-vm = { version = "=0.24.14", default-features = false }`
- `Cargo.toml:216` `clap = "=4.4"`
- `Cargo.toml:285` `rocksdb = { version = "=0.21.1", package = "ckb-rocksdb", ... }`
- `Cargo.toml:288` `secp256k1 = "0.30"`（非 `=` 钉版，会接受 0.30.x patch）

### 发现

- ⚠️ **Info**: 钉版本身是好的（确定性 + 防止 supply-chain），但需配合自动安全公告订阅，否则 patch 版本中的修复无法获得
- ✅ `secp256k1 = "0.30"`（caret 语义）会自动获取 0.30.x patch
- ⚠️ `ckb-vm` / `rocksdb` / `clap` 严格钉版，patch 不自动接受

### 修复建议

1. 建立内部 "pinned dependency security watchlist"：
   - GitHub Watch（Releases only）跟踪 `nervosnetwork/ckb-vm`、`nervosnetwork/rust-rocksdb`、`clap-rs/clap`
2. 每季度发起 patch 升级 PR
3. 在 `deny.toml` 中可考虑：
   ```toml
   [advisories]
   vulnerability = "deny"
   unmaintained = "warn"
   yanked = "deny"
   ```

---

## AUDIT-ERRINFO-001: RPC 错误消息信息泄露

### 状态: ✅ 通过

### 分析过程

`rpc/src/error.rs` 定义 `RPCError` 枚举，每个变体有固定的错误码（如 `-1102 PoolRejectedTransactionByOutputsValidator`）与对外消息。

各 `module/*.rs` 通过：
```rust
.map_err(|e| RPCError::custom(RPCError::Invalid, err.to_string()))
.map_err(|e| RPCError::ckb_internal_error(e))
.map_err(|reject| RPCError::from_submit_transaction_reject(&reject))
```

### 发现

- ✅ 错误码集中在枚举中，对外接口稳定
- ✅ `ckb_internal_error` 不暴露 stack trace
- ✅ `from_submit_transaction_reject` 将 tx-pool 内部拒绝原因映射为标准化错误码（不直接暴露内部状态字段）
- ⚠️ **Info**: `error!("...")` 日志输出（如 `pool.rs:626, 650, 657, 666, 675` 等多处）会写入本地日志，含完整 error 链。若运维将日志公开（如 Sentry），可能泄露内部细节 —— 这属于 AUDIT-ERRINFO-002 范畴

### 修复建议

无（在 AUDIT-ERRINFO-002 中跟进 sentry 上报内容）。

---

## 本轮小结

| AUDIT-ID | 状态 | 严重 | 摘要 |
|---|---|---|---|
| AUDIT-INPUT-001 | ℹ️ | Info | send_transaction 含 `submit_tx.unwrap()` 反模式但已有前置守护 |
| AUDIT-INPUT-002 | ✅ | — | chain RPC 范围参数走严格 Uint* 反序列化 |
| AUDIT-AUTH-001 | ✅ | — | 默认 modules 不含 Debug/IntegrationTest；默认 127.0.0.1 绑定 |
| AUDIT-DEPS-001 | ⚠️ | 需动态验证 | 必须 CI 跑 cargo audit 才能定论；关键钉版列入 watchlist |
| AUDIT-DEPS-002 | ℹ️ | Info | ckb-vm/rocksdb/clap 钉版需自动安全订阅 |
| AUDIT-ERRINFO-001 | ✅ | — | RPC 错误统一通过 `RPCError` 枚举，不暴露内部状态 |

**下轮建议**: 进入 Round 5 — 共识细节 + 序列化（AUDIT-LOGIC-002/004/005 + AUDIT-SERDE-001/002）
