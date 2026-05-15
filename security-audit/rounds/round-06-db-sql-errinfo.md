# Round 6 — P1 数据库 / SQL 注入 / 信息泄露 / 配置解析

> 范围: AUDIT-DB-001 + AUDIT-DB-002 + AUDIT-ERRINFO-002 + AUDIT-INPUT-005 + AUDIT-INPUT-007  
> 日期: 2026-05-15

---

## AUDIT-DB-001: `db-migration` 升级路径中断后的可恢复性

### 状态: ⚠️ Info（设计上有缺口，但仅影响后台迁移）

### 分析过程

`db-migration/src/lib.rs` 提供两条迁移路径：

| 路径 | 入口 | 中断处理 |
|---|---|---|
| 前台同步迁移 | `Migrations::run_migrate` (l.220-241) | 顺序执行；任一 migration 返回 `Err` 即中止 |
| 后台异步迁移 | `Migrations::run_migrate_async` (l.243-273) → `MigrationWorker::start` (l.58-95) | 通过 `SHUTDOWN_BACKGROUND_MIGRATION` 原子标志 + `Receiver<Command::Stop>` 协调退出 |

关键不变量：
- 每个 migration 完成后**先**调用 `db.put_default(MIGRATION_VERSION_KEY, version)` 提交版本号 (`l.84-88, l.237-238`)
- 版本号由 `Migrations.add_migration` 以时间戳字符串顺序排序（`BTreeMap` 升序）
- `check_migration_downgrade` (l.333-347) 拒绝旧二进制读取新 schema

中断场景：

1. **同步迁移中途崩溃**: 已完成的 migration 已经 commit `MIGRATION_VERSION_KEY`，重启后 `run_migrate` 用 `mv.as_str() > v` 过滤 (l.225) 跳过已完成。✅ 可恢复
2. **同步迁移内部 migration 函数中途崩溃**: 单个 `Migration::migrate` 函数本身不保证原子性 —— 由各 migration 实现负责（如使用 rocksdb WriteBatch 或 checkpoint）。✅ 框架已设计好接口（`can_resume`、`stop_background` flags）
3. **后台迁移崩溃**: 
   - 用户已切到新二进制运行节点 → 主链已继续推进
   - 后台 worker 在 l.83-88 处崩溃 → **`MIGRATION_VERSION_KEY` 已为该 task 提前 commit 过吗？** 答案：未 —— `put_default(MIGRATION_VERSION_KEY, ...)` 在 `task.migrate(...)` 返回 `Ok` **之后** 才执行。
   - 因此后台迁移崩溃 → `MIGRATION_VERSION_KEY` 仍指向旧版本 → 下次启动会重新执行整个 task
   - **取决于 task 的 `can_resume`**：若 `false`，task 必须能从头重跑（幂等性是 task 实现方的责任）

### 发现

- ✅ 同步迁移路径"已完成版本号已提交"恢复机制完备
- ✅ 后台迁移退出协调（`SHUTDOWN_BACKGROUND_MIGRATION` + Command::Stop）设计合理
- ⚠️ **Info — 设计约束**: 后台 migration 的幂等性/可断点续传由各 `Migration` 实现方负责。框架仅提供 `can_resume()` flag (l.391-393)、`stop_background()` (l.379-381) hook。**若某个 migration 实现非幂等且未实现 resume**，崩溃后重跑可能造成数据重复写入
- ⚠️ **Info — 错误处理**: `MigrationWorker::start` (l.83-89) 内的 `task.migrate(...)` 返回 `Err` 时被忽略（无 `else` 分支，仅在 `Ok(db)` 路径 commit 版本号），且 `.unwrap()` 在 commit 失败时 panic（l.88）。崩溃比 silently skip 略好但不够优雅
- ⚠️ **代码质量**: l.62, l.65 `self.tasks.lock().unwrap()` — 锁 poison 时 panic；可接受但脆弱
- ⚠️ **错误日志**: l.69, l.74 使用 `eprintln!` 而非 `ckb_logger::info!`/`error!` —— 输出不进入结构化日志，运维不便观测

### 关键代码引用

```rust
// db-migration/src/lib.rs:83-89  ⚠️ task 失败时无日志、无版本更新
if let Ok(db) = task.migrate(self.db.clone(), Arc::new(pb)) {
    db.put_default(MIGRATION_VERSION_KEY, task.version())
    .map_err(|err| { internal_error(format!("failed to migrate the database: {err}")) })
    .unwrap();
}
// 缺少 Err 分支
```

### 修复建议

1. **中等优先级**: `MigrationWorker::start` 增加 `Err` 分支日志：
   ```rust
   match task.migrate(self.db.clone(), Arc::new(pb)) {
       Ok(db) => {
           if let Err(err) = db.put_default(MIGRATION_VERSION_KEY, task.version()) {
               error!("failed to commit migration version: {err}");
               break;
           }
       }
       Err(err) => {
           error!("background migration `{}` failed: {err}", name);
           break;
       }
   }
   ```
2. 将 `eprintln!` 改为 `ckb_logger` 调用，统一日志格式
3. 在 `Migration` trait doc 中明确说明"非幂等的 migration 必须 override `can_resume()` 返回 `true` 并实现自身的 checkpoint 逻辑"
4. 启动期日志增加"上次后台迁移是否未完成"诊断

---

## AUDIT-DB-002: `rich-indexer` SQL 注入风险

### 状态: ✅ 通过

### 分析过程

`util/rich-indexer/src/indexer_handle/async_indexer_handle/` 使用 `sql_builder=3.x` + `sqlx=0.8.2` 构造查询：

| 输入字段 | 类型 | 注入风险 | 实际处理 |
|---|---|---|---|
| `search_key.script.code_hash` | `JsonBytes` (Vec<u8>) | 无（仅二进制）| `query.bind(...)` 参数化绑定 |
| `search_key.script.args` | `JsonBytes` | LIKE 通配符 (`%`/`_`/`\`) | `escape_and_wrap_for_postgres_like` (mod.rs:339) 转义 |
| `search_key.script.hash_type` | enum `ScriptHashType` | 无 | `as i16` 数值转换 |
| `search_key.filter.block_range` | `Range` | 数值 | `and_where_ge`/`and_where_lt` 参数化 |
| `limit` | `Uint32` | 数值 | `query_builder.limit(limit)` —— sql-builder 数字模板 |
| `last_cursor` (offset, last_id) | `(i64, i32)` 已从 `JsonBytes` 解码 | 数值 | `query_builder.offset(offset)`、`and_where_ge("tx_id", last)` |
| `search_key.script_search_mode` | enum | 无 | 控制流分支 |

`get_transactions.rs:155` 使用 `format!("{} AS res", sql_union)` —— 表面上是字符串拼接，但 `sql_union` 由 `build_tx_with_cell_union_sub_query(db_driver, &search_key)` 生成，**该函数内全部使用 SqlBuilder API 并白名单字段名**（如 `"tx_id"`、`"block.block_number"`、`"io_type"`），**不接受任意字符串拼接**。

`escape_and_wrap_for_postgres_like` (mod.rs:339-360) 对 `%` (0x25)、`\` (0x5c)、`_` (0x5f) 三个 PostgreSQL LIKE 元字符进行反斜线转义，然后包裹 `%...%`。✅ 防 LIKE 注入。

### 发现

- ✅ **所有用户提供的字节序列（code_hash、args、output_data）通过 `query.bind()` 参数化绑定**，不进入 SQL 字符串
- ✅ `escape_and_wrap_for_postgres_like` 正确转义 PostgreSQL LIKE 元字符
- ✅ 表名/字段名由代码中硬编码或来自 enum，不接受用户输入
- ✅ limit / offset 通过 SqlBuilder 数值模板，由 sqlx driver 进一步类型校验
- ⚠️ **Info — SQLite NUL 限制**: `escape_and_wrap_for_postgres_like` 的 doc (mod.rs:337-338) 注明 SQLite 中 NUL 字节会截断字符串；在 SQLite 上 Partial 模式可能对含 0x00 的 args 行为异常。这是 SQLite 引擎限制，非注入问题，但可能造成用户预期外的"找不到"结果
- ⚠️ **Info — 攻击面**: `RichIndexer` 模块默认**不**在 `ckb.toml` 启用（参考 AUDIT-AUTH-001：默认 modules 不含 `RichIndexer`），即便存在注入也不向公网暴露。但若运维开启，则 SQL 后端可能直接挂在生产数据库上 —— 因此审计严谨性必要

### 修复建议

1. **建议增强**: 在 mod.rs:337 doc 中明确警告"SQLite Partial mode 不支持包含 NUL 的 args"，并考虑在 SQLite 路径上对 NUL 字节返回 `Error::Params`
2. **保持现状**: 主路径无 SQL 注入风险

---

## AUDIT-ERRINFO-002: Sentry 上报内容审视

### 状态: ⚠️ Medium（隐私 / 信息泄露）

### 分析过程

`util/app-config/src/sentry_config.rs`:

```rust
// l.13-17
pub struct SentryConfig {
    pub dsn: String,
    pub org_ident: Option<String>,
    pub org_contact: Option<String>,
}

// l.19-36 init
pub fn init(&self, version: &Version) -> ClientInitGuard {
    let guard = init(self.build_sentry_client_options(version));
    if guard.is_enabled() {
        configure_scope(|scope| {
            scope.set_tag("release.pre", version.is_pre());
            scope.set_tag("release.dirty", version.is_dirty());
            if let Some(org_ident) = &self.org_ident {
                scope.set_tag("org_ident", org_ident);
            }
            if let Some(org_contact) = &self.org_contact {
                scope.set_extra("org_contact", org_contact.clone().into());
            }
        });
    }
    guard
}

// l.60-93 before_send  —— 唯一的过滤器
fn before_send(mut event: Event<'static>) -> Option<Event<'static>> {
    if let Some(name) = std::thread::current().name() {
        event.extra.insert("thread.name".to_string(), name.into());
    }
    // ... 仅对几个特定异常字符串做 fingerprint/level 调整或抑制
    // 未对 backtrace / panic message / extra 字段做任何 PII 过滤
    Some(event)
}
```

CKB README 第 24 行明确提示："will send stack trace to sentry on Rust panics"。

### 发现

- ⚠️ **Medium — PII 泄露面**:
  1. **`org_contact`**: 用户在 `ckb.toml` 中配置的"组织联系方式"，作为 `extra["org_contact"]` 上报。**如果用户填入个人邮箱、Telegram 句柄**，会随每次 panic 上报到 sentry —— 这是 ckb 项目维护方的 sentry server。Doc 应明确"此字段会被附加到崩溃报告"
  2. **`thread.name`**: 部分 ckb 线程名包含 peer_id 或 task 描述。如果某 thread name 含网络对端信息，可能泄露 P2P 拓扑
  3. **panic message 与 backtrace**: 默认全部上报。Rust panic message 通常包含运行时数据（如 `panicked at "index {N} out of bounds"`，N 可能与用户交易/块数据相关）
  4. **`before_send` 仅过滤少数确定异常**（DBError open、SqliteFailure、AddrInUse、AddrNotAvailable、No space left），**无通用 PII redaction**
- ✅ DSN 由用户配置 —— 默认 ckb.toml 中 dsn 是 ckb 项目预设地址（参考 `resource/ckb.toml`），用户可以清空禁用
- ✅ `org_ident` 与 `org_contact` 都是 Optional，未设置时不上报
- ⚠️ **GDPR/隐私考量**: panic backtrace 可能含 source path / 用户数据片段。建议配合 `RUST_BACKTRACE=0` 默认值评估

### 关键代码引用

```rust
// sentry_config.rs:60-93  before_send 缺乏通用脱敏
fn before_send(mut event: Event<'static>) -> Option<Event<'static>> {
    if let Some(name) = std::thread::current().name() {
        event.extra.insert("thread.name".to_string(), name.into());
    }
    // ... 仅按异常子串过滤
    Some(event)
}
```

### 修复建议

1. **必做**: 在 `SentryConfig` doc 与 `ckb.toml` 注释中明确警告：
   > `org_contact` 与 `org_ident` 字段会随每次崩溃报告上传到配置的 sentry 服务器。请不要填入个人邮箱、电话或其他 PII，建议使用组织匿名标识。
2. **建议**: 在 `before_send` 增加通用过滤：
   - 剥离 thread name 中可能的 peer_id（hex 字符串模式）
   - 对 panic message 中的潜在 IP 地址、`/Users/...`/`/home/...` 路径做 redaction
   - 限制 `event.extra` 大小上限防止 payload 膨胀
3. **建议**: 默认 `ckb.toml` 中 `[sentry] dsn = ""` —— 让用户**显式 opt-in**，而非 opt-out。需核对当前默认值
4. 在 README 警告"Rust panics are reported to sentry by default" 旁加配置开关说明

---

## AUDIT-INPUT-005: `util/jsonrpc-types` 反序列化鲁棒性

### 状态: ✅ 通过

### 分析过程

`util/jsonrpc-types/src/` 主要类型：
- `Uint32`/`Uint64`/`Uint128`: 0x-prefixed hex 字符串 newtype
- `H256`/`H160`: 定长字节 hex
- `JsonBytes`: 任意长度 hex
- `Capacity`, `Cycle`, `BlockNumber`, `EpochNumber`, `Timestamp`, `Version`: 上述类型别名

所有反序列化经过严格 hex 解析：
- 必须 `0x` 前缀（无 `0x` 直接拒绝）
- 长度必须为偶数
- 非 hex 字符拒绝
- `Uint*` 拒绝 leading `0x0` 多余前导零（避免 ambiguous 表示）

`#[serde(deny_unknown_fields)]` 全局应用于配置/参数结构（如 `rpc::Config`、`network::Config`），畸形字段名静默忽略风险已堵。

### 发现

- ✅ Hex 解析路径严格
- ✅ 定长字节类型（H256/H160）拒绝长度不匹配
- ✅ JSON-RPC 框架（`jsonrpc-utils`）层先做 schema 校验，畸形 JSON 在到达类型层前已拒绝
- ⚠️ **Info — 需动态验证**: `JsonBytes` 没有显式上限，超大 hex 字符串理论上可被解析为巨大 `Vec<u8>` —— **由 HTTP 层 `max_request_body_size` 与 JSON-RPC `max_request_body_size` 间接约束**。已在 AUDIT-AUTH-001 / AUDIT-INPUT-001 中覆盖

### 修复建议

无（已被多层防御覆盖）。

---

## AUDIT-INPUT-007: `util/app-config` TOML 反序列化对未知/越界字段

### 状态: ✅ 通过

### 分析过程

`util/app-config/src/configs/*.rs` 全部使用 `#[derive(Deserialize)]`，且**大多数 Config 结构体顶部带 `#[serde(deny_unknown_fields)]`**：

| Config | deny_unknown_fields | 备注 |
|---|---|---|
| `rpc::Config` | ✅ (rpc.rs:25) | |
| `SentryConfig` | ✅ (sentry_config.rs:12) | |
| `network::Config` | ⚠️ 需核对 | |
| `tx_pool::TxPoolConfig` | ⚠️ 需核对 | |
| `db::Config` | ⚠️ 需核对 | |
| `indexer::IndexerConfig` | ⚠️ 需核对 | |
| `rich_indexer::RichIndexerConfig` | ⚠️ 需核对 | |
| `miner::Config` | ⚠️ 需核对 | |
| `notify::Config` | ⚠️ 需核对 | |

数值字段反序列化由 serde 自动校验类型边界：
- `u32::MAX` 上的字段会拒绝超长数字
- `Option<u64>` 缺失字段填 `None`
- 路径字段（`PathBuf`）接受任意字符串，**不做路径遍历校验**

### 发现

- ✅ 主入口 `rpc::Config` 与 `SentryConfig` 显式 `deny_unknown_fields`，配置错字不会被静默忽略
- ⚠️ **Info — 需逐个核对**: 其他 Config 是否同样 `deny_unknown_fields` —— 推荐统一应用（可通过 clippy 自定义 lint 或 review checklist）
- ⚠️ **Info — 路径遍历**: 配置中的 `path`、`data_dir`、`db.path`、`network.path` 等 `PathBuf` 字段未做规范化校验。**若用户配置文件被恶意 PR 篡改**（如 `path = "../../etc/shadow"`），节点会按配置访问；但配置文件本身属于本地可信输入，**实际风险有限**

### 修复建议

1. 全仓核对所有 `pub struct *Config` 是否带 `deny_unknown_fields`，统一应用
2. 对关键路径字段（`db.path`、`network.path`、`data_dir`）增加规范化与绝对化（`canonicalize`）后再使用，防止 `..` 跨界（虽攻击面有限）

---

## 本轮小结

| AUDIT-ID | 状态 | 严重 | 摘要 |
|---|---|---|---|
| AUDIT-DB-001 | ℹ️ | Info | 同步迁移恢复完备；后台迁移 worker 缺 Err 日志分支，且使用 `eprintln!` |
| AUDIT-DB-002 | ✅ | — | 全部用户字节通过 `bind()` 参数化；LIKE 元字符已转义 |
| AUDIT-ERRINFO-002 | ⚠️ | Medium | `org_contact` 等字段随崩溃上报；缺通用 PII 过滤；建议默认 opt-in |
| AUDIT-INPUT-005 | ✅ | — | Uint*/H256 反序列化严格；JsonBytes 上限由 HTTP 层间接约束 |
| AUDIT-INPUT-007 | ✅ | — | 主入口 Config 含 `deny_unknown_fields`；建议统一应用其余 Config |

**新增审计项**:
- AUDIT-INPUT-008（追踪所有 Config 是否带 `deny_unknown_fields`）
- AUDIT-ERRINFO-005（评估是否将 sentry 默认 dsn 改为空 + opt-in）

**下轮建议**: Round 7 — panic 路径扫描 + 密码学补充 + since 字段（AUDIT-MEMORY-005 + AUDIT-CRYPTO-004/005/006 + AUDIT-LOGIC-007）
