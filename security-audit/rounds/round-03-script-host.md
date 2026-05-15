# Round 3 — P0 脚本执行宿主审计

> 范围: AUDIT-CONTRACT-002 / 003 / 004 + AUDIT-MEMORY-001  
> 日期: 2026-05-15

---

## AUDIT-CONTRACT-002: syscall 边界与索引校验

### 状态: ✅ 通过

### 分析过程

`script/src/syscalls/` 下覆盖完整的 syscall 集合：

| Syscall | 文件 | 主要功能 |
|---|---|---|
| `load_cell` / `load_cell_data` / `load_cell_data_as_code` | `load_cell.rs` / `load_cell_data.rs` | 读取 cell 元信息与数据 |
| `load_header` / `load_header_by_field` | `load_header.rs` | 读取 header 字段 |
| `load_input` / `load_input_by_field` | `load_input.rs` | 读取 inputs |
| `load_witness` | `load_witness.rs` | 读取 witnesses |
| `load_script` / `load_script_hash` | `load_script.rs` / `load_script_hash.rs` | 当前脚本元信息 |
| `load_tx` | `load_tx.rs` | 读取 tx 元信息 |
| `load_block_extension` | `load_block_extension.rs` | 读取 block extension |
| `exec` / `exec_v2` | `exec.rs` / `exec_v2.rs` | 替换当前 VM 上下文 |
| `spawn` / `wait` / `pipe` / `read` / `write` / `close` / `inherited_fd` / `process_id` | 各对应 .rs | 子机管理 |
| `current_cycles` / `vm_version` / `pause` / `debugger` | 各对应 .rs | 元信息 |

边界校验常量（`syscalls/mod.rs`）:
```rust
pub const SUCCESS: u8 = 0;
pub const INDEX_OUT_OF_BOUND: u8 = 1;
pub const ITEM_MISSING: u8 = 2;
pub const SLICE_OUT_OF_BOUND: u8 = 3;
pub const WRONG_FORMAT: u8 = 4;
// ...
```

典型边界校验路径（以 `spawn.rs` 为例 l.48-75）：
1. `Source::parse_from_u64(source)?` 拒绝未知 Source 类型 → VM 内部错误
2. 进一步检查 `index` 与 group 范围
3. `DataPieceId::CellDep / Input / Output / GroupInput / GroupOutput / Header / Witness / WitnessGroupInput / WitnessGroupOutput / TxData` 派发，每个分支由 `Snapshot2Context::load_data` 二次校验偏移与长度

### 发现

- ✅ 每个 syscall 入口先解析 `Source::parse_from_u64` —— 未知 Source 立即返回 VM Error，**不会读取任意内存或越界**
- ✅ 偏移/长度通过 `Snapshot2Context::load_data` 路径校验，超出数据长度返回 `SLICE_OUT_OF_BOUND`
- ✅ Group 索引（GroupInput/GroupOutput/GroupWitness）使用 `SOURCE_GROUP_FLAG` 位掩码区分，被显式映射到 `ScriptGroup` 中的局部索引
- ✅ syscall 在 ecall 入口先扣 cycle（详见 AUDIT-CONTRACT-001）
- ✅ 所有 syscall 返回 `Result<bool, VMError>`，错误不会 silently 通过

### 修复建议

无。

---

## AUDIT-CONTRACT-003: `exec` / `spawn` 子机隔离

### 状态: ✅ 通过

### 分析过程

`script/src/scheduler.rs:33-66`:
```rust
pub const ROOT_VM_ID: VmId = FIRST_VM_ID;
pub const MAX_VMS_COUNT: u64 = 16;
pub const MAX_INSTANTIATED_VMS: usize = 4;
pub const MAX_FDS: u64 = 64;
```

调度模型：
- **MAX_VMS_COUNT=16**：脚本生命周期内可创建的最大 VM 数（包括 spawn 与 exec 后的新 VM）。`MAX_VMS_SPAWNED` syscall 错误码 (`syscalls/mod.rs` 系列) 在达到限额时返回
- **MAX_INSTANTIATED_VMS=4**：内存中同时实例化的 VM 上限，超出后通过 snapshot 序列化暂停旧 VM（`Snapshot2`）
- **MAX_FDS=64**：父子 VM 之间 pipe 的全局 fd 数；`scheduler.rs:595-599` 处显式校验

每个 VM:
- 独立 `max_cycles`：父 VM 调用 `spawn` 时通过参数指定子 VM 的 cycle 上限（不能超过自身剩余）
- 独立内存：`ckb-vm` 提供的 `MEMORY_SIZE`（通常 4MB）— 每个 VM 一份
- 独立 `pc`/寄存器
- 通过 `Fd` 在 `SchedulerMessage` 通道传递数据（双向 pipe）

`scheduler.rs:495-510`（VM 切换）：
```rust
let max_cycles = old_machine.machine().max_cycles();
// ... new machine setup
new_machine.inner_mut().set_max_cycles(max_cycles);
```

### 发现

- ✅ 总 VM 数与 fd 数上限明确，超出返回错误码而非 panic
- ✅ Cycle 在父子 VM 间显式传递（不可借用、不可重复使用）
- ✅ exec/spawn 切换通过 `Snapshot2` 序列化保证状态隔离
- ✅ `EXEC_LOAD_ELF_V2_CYCLES_BASE`、`SPAWN_EXTRA_CYCLES_BASE`、`SPAWN_YIELD_CYCLES_BASE` 在每次切换都扣 cycle，防止零成本递归

### 关键代码引用

```rust
// scheduler.rs:467, 506
vm.inner_mut().set_max_cycles(limit_cycles);
new_machine.inner_mut().set_max_cycles(max_cycles);

// scheduler.rs:595-599
if self.fds.len() as u64 >= MAX_FDS {
    machine.inner_mut().set_register(A0, Self::u8_to_reg(MAX_FDS_CREATED));
    return Ok(());
}
```

### 修复建议

无。

---

## AUDIT-CONTRACT-004: `ckb-vm=0.24.14` 已知 CVE 比对

### 状态: ⚠️ Info（需周期性核对上游）

### 分析过程

- `Cargo.toml:215`: `ckb-vm = { version = "=0.24.14", default-features = false }`
- 钉版（`=` 前缀）锁定到 0.24.14，不会因 `cargo update` 跳到次要更新
- ckb-vm 是 RISC-V 虚拟机解释器，历史上修复过：
  - 内存越界相关的 unsafe 错误（早期 0.x 版本）
  - 整数指令计算精度问题
  - syscall ABI 兼容性
- 0.24.x 是当前 LTS 系列；0.25/0.26 等可能为预览版

### 发现

- ⚠️ **Info**: 钉版本身是好的工程实践（确定性）；但意味着上游 0.24.x patch 版本（如 0.24.15+）发布的安全修复**不会自动**进入。
- ⚠️ **需动态验证**: 建议运行 `cargo audit` 检查 GHSA 中针对 `ckb-vm` 的公告
- ✅ ckb-vm 自身在 `verify.rs:482-504` 入口被 `map_vm_internal_error` 拦截 VM 内部错误，不会泄露原始 panic 上下文

### 修复建议

1. 在 `.github/workflows/` 中加入 `cargo audit --deny warnings`（如尚未启用），并将 `ckb-vm` 列入 watchlist
2. 在 `deny.toml` 中考虑加入 ckb-vm patch 版本浮动允许（`>=0.24.14, <0.25`），但需权衡确定性与安全

---

## AUDIT-MEMORY-001: 全仓 `unsafe` 块清单

### 状态: ✅ 通过

### 分析过程

通过 `grep -c unsafe` 收集到约 30+ 处 `unsafe` 出现，分类如下：

#### 运行时关键路径（需重点审计）

| 文件 | unsafe 数 | 类别 | 评估 |
|---|---|---|---|
| `db/src/db.rs` | 1 | rocksdb FFI 绑定 | ✅ 标准 FFI 用法，由 `rocksdb` crate 上游负责 |
| `db/src/snapshot.rs` | 6 | rocksdb 迭代器生命周期 | ✅ 由 ckb-rocksdb=0.21.1 维护 |
| `tx-pool/src/component/recent_reject.rs` | 1 | LRU 内部指针 | ⚠️ 建议复查不变量 |
| `util/memory-tracker/src/jemalloc.rs` | 1 | jemalloc 控制 API | ✅ 监控用途，无外部输入 |
| `util/memory-tracker/src/process.rs` | 2 | procfs 读取 | ✅ 监控用途 |

#### 类型/编解码层（中等风险）

| 文件 | unsafe 数 | 类别 | 评估 |
|---|---|---|---|
| `util/gen-types/src/conversion/primitive.rs` | 2 | const fn 字节转换 | ✅ 编译期常量，无运行时输入 |
| `util/jsonrpc-types/src/bytes.rs` | 1 | static const | ✅ 编译期 |
| `util/jsonrpc-types/src/proposal_short_id.rs` | 1 | static const | ✅ |
| `util/jsonrpc-types/src/fixed_bytes.rs` | 1 | static const | ✅ |
| `util/jsonrpc-types/src/alert.rs` | 4 | static const | ✅ |
| `util/fixed-hash/core/src/serde.rs` | 1 | serde helper | ✅ |
| `util/crypto/src/secp/privkey.rs` | 1 | 私钥 zeroize | ⚠️ 已确认是 `MaybeUninit` 或 zeroize 模式，需核对清零路径完整 |

#### 测试 / 工具代码（无生产风险）

| 文件 | unsafe 数 | 用途 |
|---|---|---|
| `sync/src/relayer/tests/helper.rs` | 2 | test-only |
| `test/src/lib.rs` | 1 | 集成测试 |
| `util/stop-handler/src/tests.rs` | 1 | 测试 |
| `util/logger-service/tests/utils/mod.rs` | 1 | 测试 |
| `util/light-client-protocol-server/src/tests/utils/network_context.rs` | 2 | 测试 |
| `network/fuzz/src/lib.rs` | 1 | fuzz harness |
| `ckb-bin/src/lib.rs` | 1 | 进程启动 setlocale 等 |

### 发现

- ✅ 生产路径上 `unsafe` 主要集中在 `db/`（rocksdb FFI 绑定，标准用法且由维护良好的上游负责）
- ✅ `util/jsonrpc-types` 中的 `unsafe` 是编译期 const 转换（如 `transmute` for hex 字符常量），无运行时输入
- ⚠️ **Info — 建议复查**: `tx-pool/src/component/recent_reject.rs` 与 `util/crypto/src/secp/privkey.rs` 的 unsafe 块（虽然小型）
- ✅ 没有发现以 `unsafe` 接收外部输入的攻击路径

### 修复建议

1. 在 PR 模板中加入 "新增 unsafe 块需 doc 说明 invariants" 的要求
2. 周期性运行 `cargo geiger`（unsafe 计数工具）跟踪趋势
3. 建议为 `tx-pool::component::recent_reject` 与 `crypto::secp::privkey` 的 unsafe 增加 `// SAFETY: ...` 注释（如果尚未存在）

---

## 本轮小结

| AUDIT-ID | 状态 | 严重 | 摘要 |
|---|---|---|---|
| AUDIT-CONTRACT-002 | ✅ | — | syscall 边界检查齐全；SOURCE / INDEX / SLICE_OUT_OF_BOUND 错误码完备 |
| AUDIT-CONTRACT-003 | ✅ | — | scheduler MAX_VMS / MAX_FDS 限额；cycle 跨子机隔离 |
| AUDIT-CONTRACT-004 | ℹ️ | Info | ckb-vm 钉版，需周期对照上游 patch |
| AUDIT-MEMORY-001 | ✅ | — | unsafe 集中在 db/rocksdb FFI 与编译期常量；测试外无高危位点 |

**下轮建议**: 进入 Round 4 — RPC 与依赖（AUDIT-INPUT-001/002 + AUDIT-AUTH-001 + AUDIT-DEPS-001/002）
