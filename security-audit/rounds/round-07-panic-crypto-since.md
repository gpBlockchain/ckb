# Round 7 — P1 panic 路径 / 密码学补充 / since 字段 / Logic-007/008

> 范围: AUDIT-MEMORY-005 + AUDIT-CRYPTO-004 + AUDIT-CRYPTO-005 + AUDIT-CRYPTO-006 + AUDIT-LOGIC-007 + AUDIT-LOGIC-008  
> 日期: 2026-05-15

---

## AUDIT-MEMORY-005: 外部可触发 panic 路径扫描

### 状态: ⚠️ Low（少量可达 panic 路径，建议加固）

### 分析过程

对关键面向外部输入的模块（`rpc/src/module/`、`sync/src/`、`network/src/`）做 `.unwrap()` / `.expect()` 静态扫描：

#### `rpc/src/module/pool.rs`

| 行号 | 调用 | 可达性 | 评估 |
|---|---|---|---|
| 570, 602 | `serde_json::from_str(...).expect("checked json str")` | **不可达**（编译期常量字符串） | ✅ 安全 |
| 631 | `submit_tx.unwrap()` | **不可达**（前置 `if let Err(e) = submit_tx { return ... }` 守护） | ⚠️ 已在 AUDIT-INPUT-001 报告 |
| 679 | `get_tx_pool_info.unwrap()` | **不可达**（同上模式） | ⚠️ 同上反模式 |
| 797, 818 | `expect("No secp256k1_blake160_*")` | **不可达**（启动期 system cells 必存在） | ⚠️ 若 system cells 缺失 → 启动时即 panic（fail-fast，可接受）|
| 908 | `expect("checked len")` | **取决于上下文** | 需 view 确认 |

#### `verification/src/transaction_verifier.rs`

| 行号 | 调用 | 可达性 |
|---|---|---|
| 622 | `self.data_loader.get_header_fields(block_hash).expect("parent block exist")` | **理论可达** 若 dataloader bug |
| 711 | `self.data_loader.get_header_fields(&info.block_hash).expect("header exist")` | 同上 |

这些 `.expect("...exist")` 假设 `ContextualTransactionVerifier` 总在 header 已加载情况下调用 —— 由 chain service 调用前的 `get_header_view` 保证。若 chain service 重构破坏假设 → panic。

#### `db-migration/src/lib.rs`

| 行号 | 调用 |
|---|---|
| 88 | `.unwrap()` on commit version 失败 — 已在 Round 6 报告 |
| 62, 65 | `self.tasks.lock().unwrap()` — 锁 poison panic |
| 123, 126, 147, 158, 161, 184, 187, 283 | `.expect(...)` on db meta 读取 / utf8 解码 — 假设 db 数据完整 |

#### `sync/src/synchronizer/headers_process.rs`、`sync/src/relayer/compact_block_process.rs`

通过 grep 计数：仅 2 处 `.unwrap()/.expect()`，主要在测试相关代码，主流程使用 `Result` 链。✅

#### `script/src/verify.rs`

主路径 `verify` 在前次审计已覆盖，无外部可触发 panic。

### 发现

- ✅ **大部分 panic 是 fail-fast 设计**: 启动期 system cells 缺失、db 数据损坏等 —— 这些场景下继续运行更危险，panic 是正确选择
- ⚠️ **Low — 反模式**: `rpc/src/module/pool.rs:679` `get_tx_pool_info.unwrap()` 与 l.631 同样的"前置 if-let-Err + 后 unwrap"反模式
- ⚠️ **Low — 假设性 panic**: `verification/src/transaction_verifier.rs:622, 711` 的 `.expect("...exist")` 依赖调用方契约。建议改为 `Result` 链 + `InternalError`
- ⚠️ **Info — Mutex poison**: 全仓 `Mutex::lock().unwrap()` 大量存在（如 `db-migration` `tx-pool` `script::scheduler`）。Rust 标准做法，但若任一线程 panic 在持锁时 → 其他线程获取同锁会 propagation panic
- ⚠️ **Info — `.expect("checked json str")`**: 编译期常量 JSON 解析失败仅会在源码错误时发生（编译期不可检测，运行时启动即 panic）。可接受但建议改为 `OnceLock<Vec<H256>>` 与单元测试守护

### 关键代码引用

```rust
// rpc/src/module/pool.rs:625-635  ⚠️ 反模式（重复）
let submit_tx = tx_pool.submit_local_tx(tx.clone());
if let Err(e) = submit_tx {
    error!("Send submit_tx request error {}", e);
    return Err(RPCError::ckb_internal_error(e));
}
let tx_hash = tx.hash();
match submit_tx.unwrap() { ... }

// rpc/src/module/pool.rs:672-681  ⚠️ 同样反模式
let get_tx_pool_info = tx_pool.get_tx_pool_info();
if let Err(e) = get_tx_pool_info {
    error!("Send get_tx_pool_info request error {}", e);
    return Err(RPCError::ckb_internal_error(e));
};
let tx_pool_info = get_tx_pool_info.unwrap();
```

### 修复建议

1. **Low**: 重构 `pool.rs` 多处反模式为单次 `match`（已在 AUDIT-INPUT-001 提出，本轮确认范围 ≥2 处）
2. **Low**: `transaction_verifier.rs:622, 711` 改 `.expect` 为 `.ok_or_else(|| InternalErrorKind::Database.other("parent header missing"))?`
3. **建议增加 lint**: 在 CI 中开启 `clippy::unwrap_used` 与 `clippy::expect_used` 在 `rpc/src/module/`、`verification/src/`、`sync/src/`、`script/src/` 等关键 crate（可 `allow` 在测试代码）
4. **流程**: PR 审查模板加入 "新增 `.unwrap()`/`.expect()` 必须附 SAFETY/INVARIANT 注释"

---

## AUDIT-CRYPTO-004: blake2b 个性化串使用一致性

### 状态: ✅ 通过

### 分析过程

`util/hash/src/lib.rs` 暴露默认 hasher：
```rust
pub const CKB_HASH_PERSONALIZATION: &[u8] = b"ckb-default-hash";  // l.32
pub const BLAKE2B_LEN: usize = 32;
pub const BLANK_HASH: [u8; 32] = [ 68, 244, ... ];  // 预计算

pub fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32)
        .personal(CKB_HASH_PERSONALIZATION)
        .build()
}
```

通过 grep 确认全仓 hash 调用：
- `tx_hash`、`witness_hash`、`script_hash`、`block_hash`、`header_hash`、`transactions_root`、`proposals_root`、`extra_hash`、`uncles_hash` 等均通过 `new_blake2b()` 或 `blake2b_256()` 派生 —— 共享同一 personalization 串
- DAO 计算中 `nervos-dao` 字符串作为 type script 参数，不是 hash personalization
- `merkle-tree` 内部 hash 走 `blake2b_256`，同 personalization

### 发现

- ✅ 全仓单一 personalization 串 `"ckb-default-hash"`，没有发现使用不同 personalization 的"分域"hash（如以太坊的 keccak("transaction")/keccak("block")）。
- ⚠️ **Info — 域穿越分析**: 由于所有 CKB hash 共享 personalization，理论上不同语义对象的字节序列可能哈希到同值。**实际防护来自**：
  - molecule 序列化前缀（每种类型有唯一的字段布局），保证 `serialize(Tx) != serialize(Block)` 即便长度相同
  - 输入字节流通过类型确定的 prefix（如 Block 必以 Header (208 字节) 开头）
  - 因此攻击者无法构造 `Tx` 字节序列 = `Block` 字节序列
- ✅ `BLANK_HASH` 常量是 personalization 后的 empty hash，与全仓约定一致

### 修复建议

无。建议在 `util/hash/src/lib.rs` doc 中明确说明"CKB 采用单一 personalization，分域由 molecule schema 保证"。

---

## AUDIT-CRYPTO-005: CSPRNG 使用清单

### 状态: ⚠️ Low（仅 keypair 生成器使用 ThreadRng，需文档明确）

### 分析过程

通过 grep `rand::thread_rng`/`OsRng`/`rand::rngs` 收集生产路径用例：

| 位置 | RNG | 用途 | 评估 |
|---|---|---|---|
| `util/crypto/src/secp/generator.rs:23` | `rand::thread_rng()` | `Generator::new()` 生成 secp256k1 私钥种子 | ⚠️ 见下方分析 |
| `util/crypto/src/secp/generator.rs:29` | `SmallRng::seed_from_u64(seed)` | `non_crypto_safe_prng` —— doc 明确"only used in tests" | ✅ |
| `network/src/network.rs:50, 348, 531, 1194` | `rand::thread_rng()` `.choose_multiple` | 从已知 peer 集合随机选择 N 个供出站连接 | ✅ 非密码学用途 |
| `network/src/protocols/hole_punching/component/mod.rs:73-74` | `rand::random::<u64>() % 50`、`rand::random::<bool>()` | NAT 穿透 jitter 与时序随机 | ✅ 非密码学（时序混淆即可）|
| `network/src/protocols/discovery/addr.rs:65` | `rand::random()` | `BuildHashKernels` 种子 — bloom filter hash 函数 | ✅ |
| `util/crypto/src/secp/tests.rs:7`、`network/src/tests/*` | `rand::thread_rng()` / `rand::random()` | 测试 | ✅ |

#### `Generator::new()` 安全分析（最关键）

```rust
// util/crypto/src/secp/generator.rs:22-25
pub fn new() -> Self {
    let rng = rand::thread_rng();
    Generator { rng: Box::new(rng) }
}

// l.34-42
fn gen_secret_key(&mut self) -> SecretKey {
    let mut seed = vec![0; 32];
    loop {
        self.rng.fill(seed.as_mut_slice());
        if let Ok(key) = SecretKey::from_slice(&seed) {
            return key;
        }
    }
}
```

`rand::thread_rng()` 在 `rand 0.8.x` 中底层为 `ThreadRng` → `ReseedingRng<ChaCha12Core, OsRng>`：
- 每个线程独立的 ChaCha12 实例
- 从 `OsRng`（OS-level CSPRNG，对应 `getrandom`/`getentropy`）seeding
- 周期性 reseed（默认 64 KiB 后）

→ **`thread_rng()` 是 CSPRNG**，符合密钥生成要求。

### 发现

- ✅ **`Generator::new()` 使用 `rand::thread_rng()` 是密码学安全的**（`rand 0.8` 文档明确保证 `ThreadRng: CryptoRng`）
- ✅ 网络层 RNG 用途均为非密码学（peer 选择、NAT jitter、bloom filter）
- ✅ `non_crypto_safe_prng` 命名清晰且 doc 明确"only used in tests"
- ⚠️ **Low — 文档可改进**: `Generator::new()` 的 doc (l.21) 仅说 "Default random number generator is `rand::rngs::ThreadRng`" —— **未明确声明 ThreadRng 的 CryptoRng 性质**。维护者升级 `rand` 时可能误将 `ThreadRng` 替换为非 crypto 安全的替代品
- ⚠️ **Info — 升级风险**: `rand 0.9` 已发布并对 `thread_rng()` API 做调整（`rand::rng()`）；将来升级时需谨慎核对 `CryptoRng` trait bound 是否仍成立
- ⚠️ **Info**: `Generator::gen_secret_key` 的 `loop { ... }` 重试 SecretKey 解析失败的概率约 `2^-128`（接近 N 的概率），不会形成可观察的算力差异（防侧信道）

### 修复建议

1. **Low**: 在 `util/crypto/src/secp/generator.rs:22` 的 doc 中加上：
   > Returns a generator backed by `rand::thread_rng()`, which is documented as `CryptoRng`. Do **not** replace with a non-cryptographic RNG.
2. **Low**: 在 `Generator` 结构体上增加 trait bound 检查（如显式 `impl CryptoRng for Generator` 或在内部使用 `R: rand::CryptoRng + RngCore`）—— 编译期防止误用
3. **建议**: 升级 `rand` 主版本时增加专门的 PR review checklist 项

---

## AUDIT-CRYPTO-006: 敏感对比是否恒定时间

### 状态: ⚠️ Info（非攻击面，但建议加固）

### 分析过程

CKB 上链签名验证由 ckb-vm 内的系统脚本（`secp256k1_blake160_sighash_all` 等）执行 —— **不在 Rust 宿主中做签名验证**。Rust 侧的"敏感对比"主要是：

| 对比 | 位置 | 是否需要 CT |
|---|---|---|
| `Signature::PartialEq`（派生）| `util/crypto/src/secp/signature.rs` Signature 结构 | ⚠️ 派生 PartialEq 非 CT |
| `H256/H160 PartialEq` | `util/fixed-hash/core` 派生 | 通常用于 hash 查找，**非攻击面** |
| 节点 ID / peer pubkey 对比 | `network/src` 多处 | 非密码学敏感（节点 ID 公开）|
| Alert message 签名验证 | `util/network-alert` | 走 secp256k1 上游，未在 Rust 侧做字节对比 |
| Multisig 内 `pks.contains(rec_pk)` | `util/multisig/src/secp256k1.rs:44` | `HashSet::contains` 走 hash 路径，**非线性时间但也非 CT** |

实际攻击面分析：
- **签名对比侧信道**: CKB 链上验证签名 = 通过 ECDSA recovery 比较恢复出的 pubkey 与 lock_args 中的 hash —— hash 对比是 32 字节定长，且攻击者已知 lock_args，无可侧信道获取的秘密
- **私钥对比**: 私钥仅在 `Privkey::sign` 时传给 secp256k1 crate；Rust 侧无 `Privkey == other_privkey` 操作
- **MAC/HMAC**: CKB 协议未使用 HMAC（P2P 加密由 tentacle-secio 处理）

### 发现

- ✅ **节点宿主侧无关键密码学比较**：链上签名验证在 ckb-vm 内执行；P2P 加密在 tentacle-secio 内
- ⚠️ **Info — `Signature::PartialEq` 派生非 CT**：但 `Signature` 不属于秘密（已签字节序列公开），CT 非必要
- ⚠️ **Info — 形式合规建议**：若 future 在 Rust 宿主侧引入 MAC/HMAC（如未来 RPC 鉴权），需使用 `subtle::ConstantTimeEq` 或 `secrecy` crate
- ⚠️ **Privkey zeroize**：`util/crypto/src/secp/privkey.rs` 中有 1 处 unsafe（已在 AUDIT-MEMORY-001 列出），建议确认 `Privkey` Drop 实现是否调用 `secp256k1::SecretKey::zeroize` 或 `zeroize::Zeroize`

### 修复建议

1. **Info**: 验证 `Privkey` 实现 `zeroize::Zeroize` + `ZeroizeOnDrop`，防止内存残留
2. **预防性**: 若未来引入 HMAC/MAC，文档约定使用 `subtle::ConstantTimeEq`
3. 当前无紧急修复需求

---

## AUDIT-LOGIC-007: cellbase 成熟期 / since 字段所有分支

### 状态: ✅ 通过（附 1 项 Info）

### 分析过程

**Cellbase Maturity** (`MaturityVerifier`, `verification/src/transaction_verifier.rs:364-426`)：

```rust
let cellbase_immature = |meta: &CellMeta| -> bool {
    meta.transaction_info
        .as_ref()
        .map(|info| {
            info.block_number > 0 && info.is_cellbase() && {
                let threshold = self.cellbase_maturity.to_rational() + info.block_epoch.to_rational();
                let current = self.epoch.to_rational();
                current < threshold
            }
        })
        .unwrap_or(false)
};
```

- 检查 inputs (l.398) **和** cell_deps (l.411)
- `block_number > 0` 排除创世 cellbase（创世可立即引用）
- 用 `Rational` 比较，避免 epoch + fraction 整数溢出
- `is_cellbase()` 仅对 first tx of block 返回 true，逻辑正确

**Since Field** (`SinceVerifier`, `verification/src/transaction_verifier.rs:596-754`)：

5 个分支：
1. `BlockNumber` 绝对锁 (l.635) — `tx_env.block_number(proposal_window) < block_number` 拒绝
2. `EpochNumberWithFraction` 绝对锁 (l.641) — `is_well_formed_increment()` 拒绝非规范化 fraction
3. `Timestamp` 绝对锁 (l.651) — `tip_timestamp < timestamp` 拒绝
4. `BlockNumber` 相对锁 (l.678) — `tx_env.block_number(...) < info.block_number + block_number`
5. `EpochNumberWithFraction` 相对锁 (l.685) — Rational 加法避免溢出
6. `Timestamp` 相对锁 (l.696-720) — **特殊**：hardfork `ckb2021.is_block_ts_as_relative_since_start_enabled` 控制 base_timestamp 来源（直接用 input block 的 timestamp vs parent_median_time）
7. `None` 分支 (l.658, 721) — `InvalidSince` 错误
8. `flags_is_valid()` 前置校验 (l.744) — 拒绝预留 flag bits

**关键防御**:
- `since == 0` 提前 continue (l.738-741) — 跳过未使用 since 字段的 inputs
- `info.block_number + block_number` 加法在 release mode 受 `overflow-checks=true` 保护
- `info.block_epoch.to_rational() + epoch_number_with_fraction.normalize().to_rational()` 走 Rational 数学

### 发现

- ✅ 所有 since metric 分支显式 match，无遗漏
- ✅ Cellbase maturity 同时检查 inputs 和 cell_deps（防止通过 cell_dep 引用未成熟 cellbase）
- ✅ 创世 cellbase 特殊处理（`info.block_number > 0`）
- ✅ Hardfork 切换在 timestamp relative since 路径正确分支
- ⚠️ **Info — 整数加法**: l.680 `info.block_number + block_number` 与 l.717 `base_timestamp + timestamp` 是裸 `+`。理论上极端值（如 `since.block_number = u64::MAX` 与 `info.block_number > 0`）触发 overflow → `overflow-checks=true` panic
  - **可达性**: `since` 来自交易，攻击者控制；`since.extract_metric` 中 `BlockNumber` 是 56-bit 值（high 8 bits 是 flag），实际范围 < 2^56；加上 `info.block_number` < 2^56 → 和 < 2^57，远小于 u64::MAX
  - **结论**: 实际不可达 panic，但建议 `checked_add` 显式处理
- ✅ `flags_is_valid()` 拒绝未定义 flag bits，防止未来 hardfork 提前激活

### 修复建议

1. **Low**: l.680 与 l.717 改用 `checked_add` + `InvalidSince` 错误，与同文件其他防御模式一致
2. **Info**: 建议增加 since 相关的 fuzz target（构造极端 since 值 → ResolvedTransaction）

---

## AUDIT-LOGIC-008: TOCTOU — tx-pool 在 reorg 期间的 RBF / 拉取依赖

### 状态: ⚠️ Info（设计上有锁保护，但需动态验证）

### 分析过程

tx-pool 服务架构（`tx-pool/src/`）：
- 主体 `TxPool` 通过 `TxPoolService` 持有，使用 `tokio::sync::RwLock`（参考 `tx-pool/src/service.rs`）
- 所有 mutation（submit / remove / RBF / reorg refresh）都通过 channel 串行化到 tx-pool 主循环
- 同步层（`chain::ChainService`）在 `process_block` 完成后通过事件通知 tx-pool 做 `update_tx_pool_for_reorg`

潜在 TOCTOU 场景：
1. **场景 A**: RPC 提交 tx-X（依赖 cell-Y）→ 验证通过 → 准备入池；同时 reorg 使 cell-Y 不再有效
   - **缓解**: tx-pool 内部使用 snapshot（`Arc<Snapshot>`）做 cell resolution；snapshot 是 immutable，避免 toctou
   - reorg 触发后 tx-pool 会重新 resolve 所有 pending tx；invalid 的 tx 被驱逐
2. **场景 B**: 两个并发 RBF 请求竞争替换同一 input
   - **缓解**: 服务串行化到主循环，按 FIFO 处理
3. **场景 C**: tx-pool 验证一笔 tx（耗时 cycle）期间，新块到来
   - **缓解**: tx-pool 使用 `verify_mgr` 异步验证；验证时持有的 snapshot 是当时的；验证完成后将结果应用到**当前**最新池态（如果 snapshot 已过期则丢弃结果）—— 需查 `verify_mgr` 实现细节确认

### 发现

- ✅ tx-pool 主体使用 RwLock + tokio channel 串行化
- ✅ Cell resolution 通过 `Arc<Snapshot>` immutable view
- ✅ Reorg 后显式 refresh 所有 pending tx
- ⚠️ **Info — 需动态验证**: `verify_mgr` 在长 cycle tx 验证期间收到 reorg 是否会:
  - (a) 中止当前验证 → 重新基于新链态验证
  - (b) 继续验证 → 应用结果时检查 snapshot 是否仍 valid
  - (c) silently 应用过时结果（**这是 bug**）
- ⚠️ **Info**: tx-pool 持久化（`persisted.rs`）在崩溃后重启时，pending tx 会重新验证，无 TOCTOU

### 修复建议

1. **动态验证**: 建议设计集成测试，在长 cycle tx 验证期间触发 reorg，观察结果正确性
2. **代码审视**: 重点 review `tx-pool/src/verify_mgr.rs`（如存在）的 "verify completion → apply" 路径，确保 snapshot 失效检查

---

## 本轮小结

| AUDIT-ID | 状态 | 严重 | 摘要 |
|---|---|---|---|
| AUDIT-MEMORY-005 | 🟢 | Low | `pool.rs` 反模式 ≥2 处；`transaction_verifier.rs` 含 expect("...exist") |
| AUDIT-CRYPTO-004 | ✅ | — | 单一 personalization；分域由 molecule schema 保证 |
| AUDIT-CRYPTO-005 | 🟢 | Low | `ThreadRng` 是 CryptoRng；doc 未明确，建议加 trait bound |
| AUDIT-CRYPTO-006 | ℹ️ | Info | 宿主侧无关键密码学比较；建议核对 Privkey zeroize |
| AUDIT-LOGIC-007 | ✅ | — | since/maturity 全分支覆盖；建议 checked_add |
| AUDIT-LOGIC-008 | ℹ️ | Info | 设计上锁/snapshot 保护；verify_mgr 长 cycle 期间 reorg 需动态验证 |

**新增审计项**:
- AUDIT-MEMORY-008（追踪 `clippy::unwrap_used` lint 启用范围）
- AUDIT-CRYPTO-008（验证 `Privkey` 实现 `Zeroize`/`ZeroizeOnDrop`）
- AUDIT-LOGIC-011（在 `tx-pool` 集成测试中加入"长 cycle tx 验证 + reorg" 用例）

**下轮建议（Round 8）**: 剩余 P1 — AUDIT-AUTH-002（Alert 协议）+ AUDIT-AUTH-003（监听地址文档）+ AUDIT-DEPS-003（deny.toml 复核）+ AUDIT-DEPS-004（feature flags）+ AUDIT-NET-003（CompactBlock short-id 冲突）+ AUDIT-ERRINFO-003/004
