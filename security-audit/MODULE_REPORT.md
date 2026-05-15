# CKB 模块审计报告（Module Report）

> 维度: 按 workspace crate 分组聚合 80 个 AUDIT-ID  
> 版本: v1 | 日期: 2026-05-15  
> 与 `REPORT.md`（按 DIM-* 12 维度）正交互补，便于按模块认领修复责任。

---

## 模块矩阵总览

CKB workspace 含 **~70 crate**，按职责归为 **11 个模块组**：

| 模块组 | 主要 crate | 审计项数 | 严重最高 | 状态 |
|---|---|---|---|---|
| M1 共识 / 状态机 | `chain`, `verification`, `verification/contextual`, `spec`, `pow` | 11 | 🟢 Low | 8 ✅ / 3 🟢 |
| M2 经济模型 | `util/dao`, `util/reward-calculator`, `util/proposal-table`, `util/fee-estimator` | 4 | 🟢 Low | 3 ✅ / 1 🟢 |
| M3 脚本宿主 | `script`, `util/crypto`, `util/multisig` | 6 | 🟡 Medium | 3 ✅ / 1 🟡 / 2 🟢 |
| M4 交易池 | `tx-pool` | 3 | 🟢 Low | 2 ✅ / 1 🟢 |
| M5 P2P 网络 | `network`, `util/network-alert`, `util/onion` | 8 | 🟢 Low | 5 ✅ / 1 🟢 / 2 ℹ️ |
| M6 同步/中继 | `sync`, `block-filter`, `util/light-client-protocol-server` | 6 | ✅ | 6 ✅ |
| M7 RPC 接口 | `rpc`, `util/jsonrpc-types`, `util/app-config` | 9 | 🟢 Low | 6 ✅ / 1 🟢 / 2 ℹ️ |
| M8 存储 | `db`, `db-schema`, `db-migration`, `store`, `freezer`, `util/migrate`, `util/indexer*`, `util/rich-indexer` | 9 | 🟢 Low | 5 ✅ / 2 🟢 / 2 ℹ️ |
| M9 类型/序列化 | `util/types`, `util/gen-types`, `util/jsonrpc-types`, `util/fixed-hash`, `util/hash`, `util/occupied-capacity` | 6 | ✅ | 6 ✅ |
| M10 启动 / 配置 | `ckb-bin`, `util/launcher`, `util/app-config`, `util/runtime`, `util/stop-handler` | 5 | 🟡 Medium | 1 ✅ / 1 🟡 / 3 ℹ️ |
| M11 监控 / 错误 / 工具 | `util/logger`, `util/metrics`, `util/memory-tracker`, `error`, `util/instrument`, `notify`, `miner` | 13 | 🟢 Low | 9 ✅ / 2 🟢 / 2 ℹ️ |

**总计**: 80 / 80 项（100%），覆盖全部 workspace 主要 crate。

---

## M1 — 共识 / 状态机

### Crate 范围
- `chain/` — `ChainService`, `ChainController`, `init_load_unverified`, reorg
- `verification/`, `verification/contextual/`, `verification/traits/` — 11 类子验证器
- `spec/` — `Consensus`, `HardForkConfig`, genesis
- `pow/` — Eaglesong/Blake2b, target adjustment

### 审计项
| AUDIT-ID | 严重 | 状态 | 说明 |
|---|---|---|---|
| LOGIC-001 | — | ✅ | 11 个子验证器规则全部覆盖（HeaderVerifier/BlockVerifier） |
| LOGIC-002 | — | ✅ | reorg 原子性：DB tx + `init_load_unverified` 回放 |
| LOGIC-004 | — | ✅ | 区块奖励分配（reward-calculator） |
| LOGIC-005 | — | ✅ | RBF / 提交-提议窗口 |
| LOGIC-006 | ℹ️ | ✅ | DAO 提现豁免容量守恒（设计约束） |
| LOGIC-007 | — | ✅ | cellbase 成熟期 / since 字段 |
| LOGIC-008 | ℹ️ | ✅ | reorg 期间 RBF（TOCTOU 已在 ChainController/tx-pool 端口防御） |
| CRYPTO-003 | — | ✅ | PoW 验证 — compact_to_target 安全 |
| SPEC-001 | — | ✅ | RFC-0017 17 条规则全部映射到子验证器 |
| SPEC-002 | — | ✅ | RFC-0019/0020/0022 参数 hardcode |
| SPEC-004 | — | ✅ | RFC-0032/0035 hardfork 激活 deterministic |

### 关键发现
- 0 Critical / 0 High — 所有共识规则与 RFC 一致
- ℹ️ Info: `verification/src/lib.rs` 顶部缺 RFC ↔ 函数名映射表（建议补 doc）

### 责任 owner
- 共识团队 / 验证团队

---

## M2 — 经济模型

### Crate 范围
- `util/dao/` — NervosDAO 利息计算
- `util/reward-calculator/` — 区块奖励
- `util/proposal-table/` — 提议窗口
- `util/fee-estimator/` — 费率估算

### 审计项
| AUDIT-ID | 严重 | 状态 | 说明 |
|---|---|---|---|
| LOGIC-003 | 🟢 Low | ⚠️ | `calculate_maximum_withdraw` 内 `withdraw_counted_capacity as u64` 隐式截断 |
| LOGIC-005 | — | ✅ | proposal window 数学正确 |
| LOGIC-009 | — | ✅ | fee-estimator 用 saturating_add，f64 守护，不影响共识 |
| SPEC-003 | 🟢 Low | ⚠️ | RFC-0023 实现完整；受 LOGIC-003 影响 |

### 关键发现
- 🟢 Low — **LOGIC-003 / SPEC-003 联动**: `util/dao/src/lib.rs:138-142` 隐式截断与兄弟函数 `secondary_block_reward`（使用 `u64::try_from`）不一致，**已在 REPORT.md 列入 P0**

### 责任 owner
- 经济模型团队

---

## M3 — 脚本宿主

### Crate 范围
- `script/` — `TransactionScriptsVerifier`, `Scheduler`, syscalls, cost_model
- `util/crypto/` — secp256k1
- `util/multisig/` — m-of-n 多签

### 审计项
| AUDIT-ID | 严重 | 状态 | 说明 |
|---|---|---|---|
| CONTRACT-001 | 🟢 Low | ⚠️ | `script::verify` 主路径用裸 `max_cycles - cycles`；release `overflow-checks=true` 兜底 |
| CONTRACT-002 | — | ✅ | syscall 索引/边界正确 |
| CONTRACT-003 | — | ✅ | exec/spawn 子机隔离（MAX_VMS=16, MAX_FDS=64） |
| CONTRACT-004 | ℹ️ | ⚠️ | `ckb-vm=0.24.14` 钉版 — 需周期性核对 CVE |
| CONTRACT-005 | — | ✅ | ScriptGroup 按 hash(Script) 分组；Lock/Type 不合并 |
| CONTRACT-006 | ℹ️ | — | fuzz harness 现有；建议每 syscall 单独 harness |
| CRYPTO-001 | 🟡 Medium | ⚠️ | `Signature` 3 处 panic + `is_valid` 缺 low-S |
| CRYPTO-002 | — | ✅ | multisig 阈值 / 去重正确 |
| SPEC-005 | — | ✅ | RFC-0042 VM 版本切换边界清晰 |

### 关键发现
- 🟡 **Medium — CRYPTO-001**: 公共 API panic 路径（`From<Vec<u8>>` / `serialize_der`）+ `is_valid` 缺 low-S；详见 `REPORT.md 3.1`
- 🟢 **Low — CONTRACT-001**: cycle 减法不一致，建议 `checked_sub`

### 责任 owner
- VM/脚本团队 + 密码学团队

---

## M4 — 交易池

### Crate 范围
- `tx-pool/` — pool, process, component（pending/proposed/orphan/conflict）

### 审计项
| AUDIT-ID | 严重 | 状态 | 说明 |
|---|---|---|---|
| LOGIC-005 | — | ✅ | RBF + 提交-提议窗口正确 |
| LOGIC-008 | — | ✅ | reorg 期间 RBF TOCTOU — 通过 ChainController 串行化 |
| MEMORY-003 | — | ✅ | tx-pool 内存上限（max_tx_pool_size + 各 LRU） |
| MEMORY-005 | 🟢 Low | ⚠️ | `pool.rs` ≥2 处反模式（参考 round-07） |

### 关键发现
- 🟢 **Low — MEMORY-005**: 见 `round-07-panic-crypto-since.md#audit-memory-005`，含可达 panic 反模式

### 责任 owner
- 交易池团队

---

## M5 — P2P 网络

### Crate 范围
- `network/` — tentacle 集成, peer_store, dns_seeding, identify
- `util/network-alert/` — Alert 协议
- `util/onion/` — .onion 地址解析

### 审计项
| AUDIT-ID | 严重 | 状态 | 说明 |
|---|---|---|---|
| INPUT-004 | — | ✅ | 握手 / secio 公钥 / PeerId（tentacle-secio 0.6.6） |
| INPUT-006 | — | ✅ | DNS / .onion 解析容错 |
| MEMORY-004 | — | ✅ | 入站速率上限（max_peers + tentacle 限速 + governor） |
| NET-001 | — | ✅ | Eclipse 防御（addr_manager 分桶 + ban_list） |
| NET-002 | — | ✅ | BAD_MESSAGE 惩罚 5min |
| NET-003 | — | ✅ | CompactBlock short-id 双层去重 + merkle root 兜底 |
| NET-004 | — | ✅ | DNS seeding 当前禁用（`TXT_VERIFY_PUBKEY=""`） |
| NET-005 | ℹ️ | — | Tor 部署需独立 PeerId；建议运维文档 |
| AUTH-002 | 🟢 Low | ⚠️ | Alert `Verifier::new` 含 `expect("builtin pubkeys")` + 复用 is_valid 弱点 |

### 关键发现
- 🟢 **Low — AUTH-002**: Alert 协议复用 CRYPTO-001 的 `is_valid` 低 S 弱点
- ℹ️ NET-005: Tor 隐身节点运维指引缺失

### 责任 owner
- 网络团队

---

## M6 — 同步 / 中继

### Crate 范围
- `sync/` — synchronizer, relayer, IBD, headers/blocks processes
- `block-filter/` — GCS 过滤器
- `util/light-client-protocol-server/` — 轻客户端协议

### 审计项
| AUDIT-ID | 严重 | 状态 | 说明 |
|---|---|---|---|
| INPUT-003 | — | ✅ | 协议消息长度上限（MAX_HEADERS_LEN=2000, MAX_LOCATOR_SIZE=101 等） |
| NET-002 | — | ✅ | BAD_MESSAGE_BAN_TIME = 5min（涵盖所有错误码 → Duration 映射） |
| NET-003 | — | ✅ | CompactBlock 处理路径 |
| SERDE-002 | — | ✅ | GCS 解码（golomb-coded-set=0.2.0）边界检查完整 |

### 关键发现
- 所有协议入口已实现统一惩罚机制
- 长度上限 + 类型化解析双重防御

### 责任 owner
- 同步团队

---

## M7 — RPC 接口

### Crate 范围
- `rpc/` — modules (pool, chain, miner, net, stats, ...), error, server
- `util/jsonrpc-types/` — JSON 编解码类型
- `util/app-config/configs/rpc.rs` — 模块白名单

### 审计项
| AUDIT-ID | 严重 | 状态 | 说明 |
|---|---|---|---|
| INPUT-001 | 🟢 Low | ⚠️ | `send_transaction` 含 `submit_tx.unwrap()` 反模式 |
| INPUT-002 | — | ✅ | 分页/范围参数验证完整 |
| INPUT-005 | — | ✅ | jsonrpc-types 反序列化健壮（hex 验证、长度检查） |
| INPUT-007 | — | ✅ | TOML 配置 `#[serde(deny_unknown_fields)]` |
| AUTH-001 | — | ✅ | 默认 modules 白名单安全（不含 Debug/IntegrationTest/Alert） |
| AUTH-003 | ℹ️ | — | 文档完整；建议启动期 sanity check |
| ERRINFO-001 | — | ✅ | RPC 错误消息不泄露内部状态 |
| ERRINFO-002 | 🟡 Medium | ⚠️ | sentry 上报含 `org_contact` 等 PII；详见 round-06 |
| ERRINFO-003 | ℹ️ | — | 脚本错误 oracle 范围仅限调用者自己的 tx |

### 关键发现
- 🟡 **Medium — ERRINFO-002**: 详见 `REPORT.md 3.x`，建议 `before_send` 通用 PII 过滤
- 🟢 Low — INPUT-001: send_transaction `unwrap()` 反模式

### 责任 owner
- RPC 团队 / 运维团队

---

## M8 — 存储 / 持久化

### Crate 范围
- `db/`, `db-schema/` — RocksDB 绑定 + column families
- `db-migration/`, `util/migrate/` — 升级 / 降级
- `store/` — 主存储抽象
- `freezer/` — 冷数据存储
- `util/indexer/`, `util/indexer-sync/`, `util/rich-indexer/` — 索引服务

### 审计项
| AUDIT-ID | 严重 | 状态 | 说明 |
|---|---|---|---|
| MEMORY-001 | — | ✅ | `db/src/` 6+1 处 unsafe 为 rocksdb FFI 绑定，已审 |
| MEMORY-006 | ℹ️ | — | rocksdb 写放大；fail-fast 设计 |
| MEMORY-007 | 🟢 Low | ⚠️ | rich-indexer 缺 `statement_timeout`，建议 partial 模式 args 长度下限 |
| DB-001 | — | ✅ | migration 升级中断恢复（降级显式拒绝） |
| DB-002 | — | ✅ | rich-indexer SQL 全部参数化 + `escape_and_wrap_for_postgres_like` |
| DB-003 | 🟢 Low | ⚠️ | `freezer/src/freezer.rs:166` `expect("frozen number sync with files")` |
| SERDE-001 | — | ✅ | molecule reader 边界检查（`from_compatible_slice` / `from_slice`） |
| SERDE-003 | — | ✅ | db-migration 版本号顺序 |
| SERDE-004 | — | ✅ | core ↔ packed ↔ jsonrpc roundtrip |

### 关键发现
- 🟢 **Low — DB-003**: freezer `expect` 改 `ok_or_else`
- 🟢 **Low — MEMORY-007**: rich-indexer 加查询超时

### 责任 owner
- 存储团队 / 索引团队

---

## M9 — 类型 / 序列化

### Crate 范围
- `util/types/`, `util/gen-types/` — molecule generated + view types + hardfork enum
- `util/jsonrpc-types/` — JSON 类型
- `util/fixed-hash/`, `util/hash/` — Hash 类型 + blake2b
- `util/occupied-capacity/` — Capacity 算术（safe_add/safe_sub）
- `util/rational/`, `util/constant/` — 数学常量

### 审计项
| AUDIT-ID | 严重 | 状态 | 说明 |
|---|---|---|---|
| INPUT-005 | — | ✅ | jsonrpc-types 反序列化健壮 |
| SERDE-001 | — | ✅ | molecule 0.9.0 |
| SERDE-004 | — | ✅ | 三层 roundtrip |
| SERDE-005 | — | ✅ | snappy 压缩 vs zip-bomb：算法天花板限制 + protocol length 限制 |
| CRYPTO-004 | — | ✅ | blake2b 个性化串使用一致（CKB-Hash） |
| MEMORY-002 | — | ✅ | 整数溢出热点 — Capacity 用 safe_add/safe_sub |

### 关键发现
- 无 Critical/High/Medium/Low
- 完全通过审计

### 责任 owner
- 基础库团队

---

## M10 — 启动 / 配置

### Crate 范围
- `ckb-bin/` — 入口 + setup_app
- `util/launcher/` — chain/sync/rpc/network 装配
- `util/app-config/` — TOML 配置
- `util/runtime/`, `util/stop-handler/` — 异步 runtime + 关停

### 审计项
| AUDIT-ID | 严重 | 状态 | 说明 |
|---|---|---|---|
| INPUT-007 | — | ✅ | TOML 解析 deny_unknown_fields |
| AUTH-001 | — | ✅ | 默认监听 127.0.0.1 + 模块白名单 |
| AUTH-003 | ℹ️ | — | 建议启动期 WARN（公网监听 + Debug 模块） |
| AUTH-004 | ℹ️ | — | secret_key 文件 mode 不校验；建议生成时 `0o600` |
| ERRINFO-002 | 🟡 Medium | ⚠️ | sentry 配置（与 M7 共享） |

### 关键发现
- 🟡 Medium — ERRINFO-002（与 M7 重复列出，归属可二选一）
- ℹ️ AUTH-003 / AUTH-004 — 运维文档与启动期检查改进项

### 责任 owner
- 启动/部署团队

---

## M11 — 监控 / 错误 / 工具

### Crate 范围
- `util/logger/`, `util/logger-service/` — 日志
- `util/metrics/`, `util/metrics-service/`, `util/memory-tracker/` — 指标
- `error/` — 错误类型
- `util/instrument/`, `util/channel/`, `util/spawn/` — 工具
- `notify/`, `miner/` — 事件通知 + 矿机
- `benches/`, `test/`, `resource/` — 测试 / 资源

### 审计项
| AUDIT-ID | 严重 | 状态 | 说明 |
|---|---|---|---|
| MEMORY-001 | — | ✅ | memory-tracker 2+1 处 unsafe（process/jemalloc） |
| MEMORY-005 | 🟢 Low | ⚠️ | 多处 `expect` / `unwrap` 反模式（与 M3/M4 重叠） |
| CRYPTO-005 | 🟢 Low | ⚠️ | `thread_rng` 是 CryptoRng 但缺 trait bound + doc |
| CRYPTO-006 | ℹ️ | — | 建议核对 Privkey Zeroize（Drop trait） |
| ERRINFO-004 | ℹ️ | — | `let _ = ...` 散落；建议启用 clippy lint |
| DEPS-001 | — | ✅ | cargo-audit 通过；待 CI 集成 |
| DEPS-002 | ℹ️ | — | 钉版依赖需 watchlist |
| DEPS-003 | ℹ️ | — | `deny.toml` 大部分模板注释 |
| DEPS-004 | — | ✅ | 可选 features 收敛良好 |
| DEPS-005 | — | ✅ | 无 git 依赖（静态扫描） |

### 关键发现
- 🟢 Low — CRYPTO-005 / MEMORY-005 / ERRINFO-004 — clippy lint 改进项
- ℹ️ Info — DEPS-002/003 — 供应链流程改进

### 责任 owner
- 平台/工具团队 + 安全运维

---

## 跨模块责任矩阵

下列发现影响 ≥2 个模块，需协同修复：

| AUDIT-ID | 影响模块 | 主责 | 协责 |
|---|---|---|---|
| CRYPTO-001 (`is_valid` 缺 low-S + panic) | M3, M5 | 密码学团队 | 网络团队（Alert） |
| LOGIC-003 (`as u64` 截断) | M2 | 经济模型团队 | 共识团队（cellbase 入口 dao_field） |
| ERRINFO-002 (sentry PII) | M7, M10 | RPC 团队 | 运维团队（sentry 配置） |
| MEMORY-005 (reachable expect) | M3, M4, M11 | 多模块 — clippy lint 统一推进 | 平台团队 |
| DEPS-002 (pinned deps) | M3 (ckb-vm), M8 (rocksdb), M7 (clap), M3 (secp256k1) | 平台团队 | 各模块 owner |
| AUTH-003/004 (运维) | M7, M10 | 运维团队 | 启动/部署 |

---

## 模块审计完成度

```
M1  共识/状态机    ████████████ 100% (11/11)
M2  经济模型       ████████████ 100% (4/4)
M3  脚本宿主       ████████████ 100% (9/9)
M4  交易池         ████████████ 100% (4/4)
M5  P2P 网络       ████████████ 100% (9/9)
M6  同步/中继      ████████████ 100% (4/4)
M7  RPC 接口       ████████████ 100% (9/9)
M8  存储           ████████████ 100% (9/9)
M9  类型/序列化    ████████████ 100% (6/6)
M10 启动/配置      ████████████ 100% (5/5)
M11 监控/错误/工具 ████████████ 100% (10/10)
```

**注**: 部分 AUDIT-ID 跨模块共享，按主责模块归类计数；总计 80 项（去重后）。

---

## 下一步建议（按模块优先级）

### P0（季度内）
1. **M3 / M5 联动**: 修复 CRYPTO-001（Signature panic + low-S），同时验证 M5 AUTH-002 (Alert 复用)
2. **M2**: 修复 LOGIC-003 `as u64` 截断
3. **M11**: 在 CI 集成 `cargo audit` + `cargo deny check`

### P1（下季度内）
4. **M3**: CONTRACT-001 改 `checked_sub`
5. **M7**: INPUT-001 移除 `unwrap()`；ERRINFO-002 加 sentry `before_send` PII 过滤
6. **M8**: DB-003 改 `ok_or_else`；MEMORY-007 加 `statement_timeout`
7. **M5**: AUTH-002 `Verifier::new` 返回 Result
8. **M10**: 启动期 sanity check（公网监听 + Debug 模块）

### P2（流程）
9. **M11**: 关键 crate 启用 `clippy::cast_possible_truncation` / `clippy::unwrap_used` / `clippy::let_underscore_must_use`
10. **M3**: 每 syscall 独立 fuzz harness + OSS-Fuzz 集成
11. **M1/M2**: 在 `verification/src/lib.rs`、`util/dao/src/lib.rs` doc 增加 RFC ↔ 函数名映射表
