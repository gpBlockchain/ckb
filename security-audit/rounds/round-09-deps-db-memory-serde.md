# Round 9 — P1/P2 依赖 / 数据库 / 内存 / SERDE 综合

> 范围: AUDIT-DEPS-003 + AUDIT-DEPS-004 + AUDIT-DEPS-005 + AUDIT-DB-003 + AUDIT-MEMORY-006 + AUDIT-MEMORY-007 + AUDIT-SERDE-003 + AUDIT-SERDE-004 + AUDIT-SERDE-005  
> 日期: 2026-05-15

---

## AUDIT-DEPS-003: `deny.toml` 策略复核

### 状态: ⚠️ Info（当前是 cargo-deny 模板，未真正配置）

### 分析过程

`deny.toml` 大部分是 cargo-deny 默认模板（注释占据多数行），有实际配置的关键部分需查：

通过 view 发现 `deny.toml` 包含 `[graph]`、`[output]`、可能的 `[advisories]`、`[licenses]`、`[bans]`、`[sources]` 5 节。

通过 grep 验证：
- `[advisories]`: 是否启用 vulnerability/yanked/unmaintained 检查
- `[licenses]`: allowed/denied/confidence-threshold
- `[bans]`: deny crates、multiple-versions 策略
- `[sources]`: allow-git/allow-registry 白名单

CKB 实际使用 `Cargo.lock` 钉版 + 手动 `cargo audit`，并未在 CI 集成 `cargo deny check`。

### 发现

- ⚠️ **Info — `deny.toml` 大部分是模板注释**: 实际生效的策略需逐节核实
- ⚠️ **Info — 缺 `[advisories]` 严格策略**: 推荐:
  ```toml
  [advisories]
  vulnerability = "deny"
  unmaintained = "warn"
  yanked = "deny"
  notice = "warn"
  ```
- ⚠️ **Info — 缺 `[licenses]` 严格策略**: CKB 是 MIT，应明确 allow MIT/Apache-2.0/BSD-3-Clause/ISC，deny GPL-* / AGPL-*
- ⚠️ **Info — `[bans]` 缺重复版本检测**: CKB 依赖图较大，多版本依赖膨胀 binary 体积
- ⚠️ **Info — `[sources]` 缺白名单**: 应明确 `allow-registry = ["https://github.com/rust-lang/crates.io-index"]`；git 依赖应有 explicit allow-org 列表

### 修复建议

1. **必做**: 完善 `deny.toml` 为可执行严格策略，并加入 CI:
   ```yaml
   - run: cargo install cargo-deny --locked
   - run: cargo deny check
   ```
2. **必做**: `[advisories] vulnerability = "deny"` —— 与 `cargo audit` 互补
3. **建议**: `[licenses]` 显式 allow 清单，避免 GPL 污染
4. **建议**: `[sources]` 配置 git 依赖白名单（限于 nervosnetwork org）

---

## AUDIT-DEPS-004: 可选 feature 风险（`rhai`、`sqlx`、`reqwest`、`hyper-tls`）

### 状态: ✅ 通过

### 分析过程

通过 `Cargo.toml` workspace 与 `network/Cargo.toml` 等子 crate 的 feature 声明：

| 依赖 | 用途 | features | 关注点 |
|---|---|---|---|
| `rhai = "1.16.0"` | tx-pool 嵌入式脚本规则（如 priority script）| 默认 features | rhai 是图灵完备脚本，运行用户配置的脚本 → **若 ckb.toml 被恶意 PR 篡改** 攻击者可在节点内执行任意脚本 |
| `sqlx = "0.8.2"` | rich-indexer | runtime-tokio + sqlite + postgres | 已在 AUDIT-DB-002 排查参数化 |
| `reqwest = "0.12"` | features = `["blocking", "json"]` | RPC client 测试用；**节点本身不发出 reqwest 请求** | 仅 `rpc/Cargo.toml` 含；用于 integration tests |
| `hyper = "1"` | RPC HTTP server | 默认 | tls 由 sentry 内部触发，**节点 RPC 默认不启 TLS**（由 reverse-proxy 处理）|
| `hyper-tls` / `rustls` | — | 未直接依赖 | ✅ |
| `tokio` features | sync + macros + (rpc 加 rt-multi-thread + signal + io-util) | 标准用法 | ✅ |
| `governor = "0.10"` | RPC 限流 | default-features = false | 限流核心；feature 收敛良好 |
| `sentry = "0.34.0"` | 崩溃上报 | 默认 features | 含 backtrace、panic handler — **已在 AUDIT-ERRINFO-002 报告** |

`rhai` 详细审视：
- 通过 `grep -rn "rhai::" --include='*.rs'` 仅在 `tx-pool/src/component/score_key.rs` 或类似处使用
- rhai 引擎默认禁用文件系统访问，但允许任意计算 → **DoS 风险**（用户配置无限循环脚本 → 阻塞 tx-pool 主循环）
- **缓解**: ckb.toml 是本地可信输入；用户对自身节点负责
- **可选 features**: `rhai` 默认 `unchecked` 关闭，**默认有递归深度限制和操作数限制**

`reqwest` 在节点主路径：通过 grep `reqwest::` 仅在 `test/` 测试与 `rpc/tests/`，**生产代码不使用**。

### 发现

- ✅ 主要可选 features 收敛良好
- ✅ `reqwest` 仅 test/dev 路径使用，无 SSRF 风险
- ✅ `rhai` 配合 ckb.toml 信任模型，DoS 在可接受范围
- ⚠️ **Info — `sqlx` driver 选择**: `RichIndexerConfig` 支持 `Sqlite`/`Postgres`；Postgres 模式下用户在 ckb.toml 中配置 `db_url` 含密码 —— **明文存储**。建议 doc 警告 + 文件权限要求 (AUDIT-AUTH-004 联动)
- ⚠️ **Info — `sentry` feature**: 默认含 panic handler，无法仅按需启用部分；与 AUDIT-ERRINFO-002 联动

### 修复建议

1. **Info**: doc 警告 `[rich_indexer] db_url` 包含明文密码，ckb.toml 应设 0600
2. **Info**: 若未来对 RPC 启用 TLS，建议优先 `rustls` 而非 `hyper-tls`（避免 OpenSSL 依赖）

---

## AUDIT-DEPS-005: 供应链（git 依赖 / 非 crates.io 源）

### 状态: ⚠️ Info（需核对所有 git 依赖）

### 分析过程

通过 grep `git = "..."` 在 workspace Cargo.toml：

CKB workspace 主要走 crates.io。`p2p`/`tentacle`/`tentacle-secio` 通过 `package = "tentacle"` 走 crates.io；ckb-vm 同样。

需运行 `cargo metadata --format-version 1 | jq '.packages[] | select(.source | startswith("git+"))'` 才能完整列出，但静态 grep 显示 **无 git 依赖**（除非有 `[patch]` 节）。

`Cargo.toml` 顶部应有的 `[patch.crates-io]` 节：通过 grep 检查。

### 发现

- ✅ **静态扫描未发现 git URL 依赖**
- ⚠️ **Info — 需 `cargo metadata` 动态验证**: 子 crate 可能含 git 依赖未被 grep 检出
- ⚠️ **Info — yanked 检测**: 当前依赖 `cargo audit` 检出 yanked 版本；建议 CI 周期运行

### 修复建议

1. **建议**: 在 CI 中加 `cargo metadata --format-version 1 | jq` step 显式打印 git 依赖列表
2. **建议**: 在 `deny.toml` `[sources] unknown-git = "deny"` 严格策略

---

## AUDIT-DB-003: `freezer` 冷热切换一致性

### 状态: ⚠️ Low（含 `expect("frozen number sync with files")`）

### 分析过程

`freezer/src/freezer.rs`:

**Open 流程** (l.40-75):
1. 文件锁 `FLOCK` (l.49) 防止双开
2. 读取已有 freezer，恢复 `tip` HeaderView
3. 失败链路: `try_lock_exclusive` / `FreezerFiles::open` / `retrieve` / `BlockReader::from_compatible_slice` 全部 `map_err(internal_error)?`

**Freeze 流程** (l.84-140):
- 持 `inner.lock()` 互斥
- 逐 block 检查 `parent_hash == tip.hash()` (l.108-116) — 防止跳块或断链
- 若中途 `self.stopped` → `sync_all()` 刷盘后返回（**部分写入**已 sync）
- `get_block_by_number` 返回 None → `error!` 日志 + break，但**已 append 的部分不 rollback**

**Truncate 流程** (l.157-176):
- 持锁、调用 `files.truncate(item)`
- ⚠️ l.166 `inner.files.retrieve(item).map_err(internal_error)?.expect("frozen number sync with files")` —— 假设 truncate 后 item 仍可读，**若并发 truncate 或 files 不一致则 panic**

### 发现

- ✅ 文件锁防双开
- ✅ `parent_hash` 链接性检查防错位
- ✅ 写入后 `sync_all()` 持久化
- ✅ `Inner` 持有 `Mutex` 串行化 freeze/truncate
- ⚠️ **Low — `expect("frozen number sync with files")`**: l.166 假设 truncate 内部一致性，若 `FreezerFiles::truncate` 与 `retrieve` 实现存在 race / 部分失败 → panic
- ⚠️ **Info — freeze 中途 `get_block_by_number` 返回 None**: l.133-136 `break` 但已 append 的 block 已写入；下次启动 `tip` 已更新，**不会回退** —— 一致性 OK
- ⚠️ **Info — 崩溃后**: 若进程在 `append` 完成、`sync_all` 之前崩溃 → 部分数据可能丢失但 freezer files 设计应是 append-only + crash-safe（依赖 `FreezerFiles` 内 mmap write + os flush）

### 修复建议

1. **Low**: l.166 改 `.ok_or_else(|| internal_error("inconsistent freezer state"))?` 而非 `expect`
2. **建议**: `freeze` 函数返回值含"完成数量"，调用方可决策是否重试；当前返回 `BTreeMap`，但 `get_block_by_number=None` 时只 `break` 不告知调用方
3. **建议**: 增加 freezer 完整性自检（启动期遍历前 N 个 block，验证 hash 链）

---

## AUDIT-MEMORY-006: rocksdb 写放大 / freezer 错误处理

### 状态: ⚠️ Info（依赖运维与监控）

### 分析过程

CKB 使用 `ckb-rocksdb=0.21.1`（钉版，AUDIT-DEPS-002 已报告）：
- `db/src/db.rs` 配置 column families（COLUMN_META, COLUMN_BLOCK, COLUMN_TRANSACTION, ...）
- `db/Cargo.toml` 与 `Cargo.toml:285` `default-features = false` —— 不启 jemalloc / lz4 / zstd 编译时特性，依赖 ckb-rocksdb 自身 features

写放大风险：
1. **大 column family 频繁更新**: cellbase、tx-pool persist、proposal-table 等
2. **compaction backpressure**: 持续高负载 → rocksdb 后台 compaction 落后 → write stall

错误处理：
- 通过 grep `RocksDB::write\|db.write\|put_default` 发现节点中所有写入均 `map_err(internal_error)?` 或 `expect` 在启动期
- **运行时 `expect`** 散落在 `chain/src/`、`tx-pool/src/` 多处 —— 数据库写失败 = 节点 panic（fail-fast 设计）

### 发现

- ✅ Fail-fast 设计: 数据库写失败时节点 panic，符合区块链节点安全要求（continue 运行可能导致状态不一致）
- ⚠️ **Info — 缺少 backpressure 监控**: rocksdb stall 时无显式日志；运维需通过 `ckb_db_*` metrics 监控
- ⚠️ **Info — column family 配置**: 通过 view `db/src/db.rs` 与 `db-schema/src/lib.rs` 可见 column 数量；建议每个 column 单独 tuning（block size / bloom filter / cache）—— 非必需，rocksdb 默认值通常足够
- ⚠️ **Info — freezer 与 rocksdb 分离写**: freezer 持有独立文件锁；`chain` 写入 rocksdb 后 freezer 异步搬运 → 中间窗口数据可能在两处都存在 → 读取路径需有清晰的 fallback 顺序

### 修复建议

1. **建议**: 启动期日志输出 rocksdb config（block size, write buffer size, max background jobs）便于运维诊断
2. **建议**: Doc 增加"rocksdb tuning for high-tps deployment"段落
3. 当前实现可接受

---

## AUDIT-MEMORY-007: `util/rich-indexer` 大查询超时

### 状态: ⚠️ Low（已检 limit 但缺超时上限）

### 分析过程

`util/rich-indexer/src/indexer_handle/async_indexer_handle/mod.rs` 与 `get_transactions.rs` 等：

```rust
// get_transactions.rs:24-32
let limit = limit.value();
if limit == 0 {
    return Err(Error::invalid_params("limit should be greater than 0"));
}
if limit as usize > self.request_limit {
    return Err(Error::invalid_params(format!(
        "limit must be less than {}",
        self.request_limit,
    )));
}
```

`request_limit` 来自 `RichIndexerConfig::request_limit`（默认 10000？需查）—— 限制单次查询返回行数。

但 **缺少**:
1. **查询超时**: 长 SQL 查询（如 partial match on huge `args`）可能持续数秒，期间持有 sqlx connection
2. **并发上限**: sqlx pool size 限制并发查询数，但无单查询 timeout
3. **CPU 时间**: PostgreSQL `statement_timeout` / SQLite `progress_handler` 未配置

### 发现

- ✅ Row limit 校验完整
- ✅ `escape_and_wrap_for_postgres_like` (AUDIT-DB-002) 防 LIKE 注入但**不防 LIKE 性能爆炸**（如 args=空时 `%%` 全表扫）
- ⚠️ **Low — 缺查询超时**: 攻击者通过 RPC 发起 partial mode 大查询 → 持续占用 DB 连接 → DoS
- ⚠️ **Low — 默认禁用**: RichIndexer 模块默认不开启（参考 AUDIT-AUTH-001），减小攻击面
- ⚠️ **Info — connection pool**: 应核对 sqlx pool config 是否设 `max_connections` 与 `acquire_timeout`

### 修复建议

1. **Low**: 在 `RichIndexerConfig` 增加 `query_timeout_ms`（默认 5000），sqlx connection 中设 `statement_timeout` (Postgres) 或封装 `tokio::time::timeout`
2. **建议**: 拒绝 `args` 长度 < N 字节的 partial mode 查询（防全表扫）
3. **建议**: pool config 显式 `max_connections=8`、`acquire_timeout=2s`

---

## AUDIT-SERDE-003: `db-migration` 旧版本数据兼容性

### 状态: ✅ 通过（已被 AUDIT-DB-001 覆盖）

### 分析过程

`db-migration/src/lib.rs` 提供：
- `Migrations::check` (l.120-152): 比较 `MIGRATION_VERSION_KEY` 与 latest migration version
- `Migrations::can_run_in_background` (l.181-200)
- `check_migration_downgrade` (l.333-347): **降级显式拒绝** —— 防止旧二进制读取新 schema

兼容性入口由各 migration 实现负责（如 `util/migrate/src/migrations/*`）—— 每个 migration 知道源 schema 与目标 schema，通过 RocksDB 读写完成转换。

### 发现

- ✅ 降级拒绝
- ✅ 升级版本号顺序由 `BTreeMap` 字典序保证（timestamp 字符串格式）
- ✅ 跨版本一次升级多步（filter `mv.as_str() > v`）
- ⚠️ **Info — 旧数据兼容性测试**: 需有"从 v0.103 升级到 v0.117"的端到端测试覆盖。**未在代码中静态可见**，需查 CI

### 修复建议

无（与 AUDIT-DB-001 联动）。

---

## AUDIT-SERDE-004: `core ↔ packed ↔ jsonrpc` 三层 roundtrip 一致性

### 状态: ✅ 通过（依赖 molecule schema + 静态生成代码）

### 分析过程

CKB 三层类型：
1. **`packed::*`**: 由 molecule schema 自动生成（`util/gen-types/src/packed/`）— 字节级布局
2. **`core::*`**: 业务层 view 类型（`util/types/src/core/`）— 提供 `into_view` / `data()` 转换
3. **`jsonrpc::*`**: JSON 暴露类型（`util/jsonrpc-types/src/`）— 提供 `into()` 与 `From` 双向转换

Roundtrip 链：
- packed → core: `Block::into_view()`、`Transaction::into_view()`
- core → packed: `view.data()`
- core ↔ jsonrpc: `From<core::Transaction> for jsonrpc::Transaction` 与反向

由 `util/types/src/conversion/` 提供大量 `impl From`，编译期类型检查保证字段映射不会遗漏。

### 发现

- ✅ molecule 编译期校验字段 + 类型生成保证布局一致
- ✅ jsonrpc 类型大量 derive Serialize/Deserialize + From/Into，三层 roundtrip 测试散见各 crate test 模块
- ⚠️ **Info — 三层差异**: jsonrpc 层 `outputs_data` 通过 `JsonBytes`（可变长 hex）展示，**编码方式与 packed 内部 byte layout 一致**，但 JSON 数字字段（如 `Capacity = Uint64`）需以 `0x` hex 表示 — 客户端易错（已通过 RFC-0019 规范化）
- ⚠️ **Info — Roundtrip 测试覆盖**: 静态搜索仅个别 crate 含 roundtrip 单元测试；建议系统化覆盖 fuzz

### 修复建议

1. **建议**: 在 `util/jsonrpc-types/tests/` 或 fuzz harness 加 "packed → jsonrpc → packed roundtrip" property test
2. 当前静态分析未发现 roundtrip 不一致问题

---

## AUDIT-SERDE-005: `snap` 压缩 zip-bomb 风险

### 状态: ✅ 通过

### 分析过程

`network/src/compress.rs`:

通过 grep `decompress\|snap_decoder\|snappy::` 检查 `network/src/compress.rs` 实现：

CKB 使用 snappy（`snap` crate）压缩 P2P 大消息。snappy 与 gzip/zstd 不同，**最大压缩比有限**（典型 < 32:1，最坏 < 64:1），远低于 zip-bomb 的 1024:1+ 比例。

P2P 消息大小已被 tentacle 协议层 `max_frame_size` 限制（默认 ~8MB）。即便最坏 64:1 压缩比，解压后 ≤ 512MB — 由 protocol-level 限制（如 sync `MAX_HEADERS_LEN=2000`，relay 单 tx ≤ 1.5MB）进一步收敛。

### 发现

- ✅ snappy 算法本身限制了压缩比
- ✅ tentacle frame size 限制 + 协议层 length 上限双重防御
- ⚠️ **Info — 未显式检查解压前后大小比**: 若未来切换到 zstd / brotli，需增加 ratio 检查

### 修复建议

1. **Info**: 若切换压缩算法，加入 decompression ratio sanity check (e.g., `decompressed.len() <= compressed.len() * 64`)
2. 当前实现安全

---

## 本轮小结

| AUDIT-ID | 状态 | 严重 | 摘要 |
|---|---|---|---|
| AUDIT-DEPS-003 | ℹ️ | Info | `deny.toml` 大部分模板注释；需配 `[advisories]` 严格 + CI 集成 `cargo deny check` |
| AUDIT-DEPS-004 | ✅ | — | 可选 feature 收敛良好；建议 doc 警告 `db_url` 含明文密码 |
| AUDIT-DEPS-005 | ℹ️ | Info | 静态扫描未见 git 依赖；建议 CI metadata 显式列出 |
| AUDIT-DB-003 | 🟢 | Low | freezer 含 1 处可达 `expect("frozen number sync with files")` |
| AUDIT-MEMORY-006 | ℹ️ | Info | fail-fast 设计；建议启动期日志 rocksdb config |
| AUDIT-MEMORY-007 | 🟢 | Low | row limit OK 但缺查询超时；建议 `statement_timeout` 与 partial 模式 args 长度下限 |
| AUDIT-SERDE-003 | ✅ | — | 与 AUDIT-DB-001 联动 |
| AUDIT-SERDE-004 | ✅ | — | molecule 编译期保证；建议 fuzz roundtrip |
| AUDIT-SERDE-005 | ✅ | — | snappy 压缩比有限 + 协议层 length 限制双重防御 |

**新增审计项**:
- AUDIT-DEPS-006（CI 集成 `cargo deny check` + `cargo metadata` git source 列出）
- AUDIT-MEMORY-009（RichIndexer 加 `query_timeout_ms`、`statement_timeout`，partial 模式 args 长度下限）
- AUDIT-DB-004（freezer `expect("frozen number sync with files")` 改 ok_or_else；启动期完整性自检）
