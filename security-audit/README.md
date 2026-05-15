# CKB 安全审计资料目录

本目录承载基于 [`security-audit` SKILL](https://github.com/gpBlockchain/ckb-test-skills/blob/main/.claude/skills/security-audit/SKILL.md) 工作流为 Nervos CKB 节点定制的完整审计资料，分四个阶段交付：

| 阶段 | 产出文件 | 状态 |
|---|---|---|
| Phase 0 — 侦察建档 | [`SECURITY_AUDIT_TODO.md`](./SECURITY_AUDIT_TODO.md) v3（含项目概况 / 数据流 / 信任边界 / 80 个 AUDIT-ID 全部完成） | ✅ 完成 |
| Phase 1 — 逐项深度审计 | [`rounds/round-01-consensus-and-funds.md`](./rounds/round-01-consensus-and-funds.md)<br>[`rounds/round-02-external-attack-surface.md`](./rounds/round-02-external-attack-surface.md)<br>[`rounds/round-03-script-host.md`](./rounds/round-03-script-host.md)<br>[`rounds/round-04-rpc-and-deps.md`](./rounds/round-04-rpc-and-deps.md)<br>[`rounds/round-05-consensus-details-and-serde.md`](./rounds/round-05-consensus-details-and-serde.md)<br>[`rounds/round-06-db-sql-errinfo.md`](./rounds/round-06-db-sql-errinfo.md)<br>[`rounds/round-07-panic-crypto-since.md`](./rounds/round-07-panic-crypto-since.md)<br>[`rounds/round-08-network-auth-dns.md`](./rounds/round-08-network-auth-dns.md)<br>[`rounds/round-09-deps-db-memory-serde.md`](./rounds/round-09-deps-db-memory-serde.md)<br>[`rounds/round-10-scriptgroup-fuzz-fee-errinfo.md`](./rounds/round-10-scriptgroup-fuzz-fee-errinfo.md)<br>[`rounds/round-11-dim-spec-rfc.md`](./rounds/round-11-dim-spec-rfc.md)<br>[`rounds/round-12-cross-module-cases.md`](./rounds/round-12-cross-module-cases.md) — **跨模块用例**<br>[`rounds/round-13-txpool-conflicts-cache-high.md`](./rounds/round-13-txpool-conflicts-cache-high.md) — 🟠 **首个 HIGH (AUDIT-MEMORY-009)**<br>[`rounds/round-14-candidate-verification.md`](./rounds/round-14-candidate-verification.md) — 7 候选核验，全部降级；MEMORY-009 仍唯一 High | ✅ **14 轮完成 (80 + 6 XM + 1 HIGH + 候选复盘)** |
| Phase 2 — TODO 文档更新 | `SECURITY_AUDIT_TODO.md` 附录 A/B/C/D 同步更新 | ✅ 完成 |
| Phase 3 — 最终报告 | [`REPORT.md`](./REPORT.md)（维度视角）+ [`MODULE_REPORT.md`](./MODULE_REPORT.md)（模块视角） | ✅ 完成 |

## 阅读顺序

1. 先看 `SECURITY_AUDIT_TODO.md` 顶部"项目概况 / 审计进度"快览
2. 浏览 `REPORT.md` 第 1~3 节获取**按维度**的关键发现的执行摘要
3. 浏览 `MODULE_REPORT.md` 获取**按模块/crate**的审计完成度与责任矩阵
4. 需要详细分析时，根据 `REPORT.md` / `MODULE_REPORT.md` 中的 AUDIT-ID 跳转到对应的 `rounds/round-NN-*.md`
5. 关注**跨模块路径**时阅读 `rounds/round-12-cross-module-cases.md`（14 个端到端用例）
6. **审计已 100% 完成**，所有 80 个 AUDIT-ID + 6 个跨模块 AUDIT-XM 项均已闭环

## 重要说明

- **状态**: 本次审计为 **代码静态审计 + 配置审视**，所有标注 "需动态验证" 的发现需配合 fuzz / 集成测试 / 测试网部署进一步核实。
- **作用域**: `ckb` 节点本身（Rust 工作区 ~70 个 crate）。**不包括** `ckb-vm`、`tentacle`、`secp256k1` 等上游依赖的代码审计 —— 仅核对其调用方式与版本公告。
- **CKB-VM 合约审计豁免**: 依 SKILL 第 5 节，CKB 合约审计豁免内存对齐项；本仓库是宿主 Rust 代码，对齐由 Rust 编译器/语言层面保证，同样无需审计。
