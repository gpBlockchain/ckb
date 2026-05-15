# CKB 安全审计资料目录

本目录承载基于 [`security-audit` SKILL](https://github.com/gpBlockchain/ckb-test-skills/blob/main/.claude/skills/security-audit/SKILL.md) 工作流为 Nervos CKB 节点定制的完整审计资料，分四个阶段交付：

| 阶段 | 产出文件 | 状态 |
|---|---|---|
| Phase 0 — 侦察建档 | [`SECURITY_AUDIT_TODO.md`](./SECURITY_AUDIT_TODO.md) v0（含项目概况 / 数据流 / 信任边界 / 80 个 AUDIT-ID） | ✅ 完成 |
| Phase 1 — 逐项深度审计 | [`rounds/round-01-consensus-and-funds.md`](./rounds/round-01-consensus-and-funds.md)<br>[`rounds/round-02-external-attack-surface.md`](./rounds/round-02-external-attack-surface.md)<br>[`rounds/round-03-script-host.md`](./rounds/round-03-script-host.md)<br>[`rounds/round-04-rpc-and-deps.md`](./rounds/round-04-rpc-and-deps.md)<br>[`rounds/round-05-consensus-details-and-serde.md`](./rounds/round-05-consensus-details-and-serde.md)<br>[`rounds/round-06-db-sql-errinfo.md`](./rounds/round-06-db-sql-errinfo.md)<br>[`rounds/round-07-panic-crypto-since.md`](./rounds/round-07-panic-crypto-since.md) | ✅ 5 轮 P0 + 2 轮 P1 完成 |
| Phase 2 — TODO 文档更新 | `SECURITY_AUDIT_TODO.md` 附录 A/B/C 同步更新 | ✅ 完成 |
| Phase 3 — 最终报告 | [`REPORT.md`](./REPORT.md) | ✅ 完成 |

## 阅读顺序

1. 先看 `SECURITY_AUDIT_TODO.md` 顶部"项目概况 / 审计进度"快览
2. 浏览 `REPORT.md` 第 1~3 节获取关键发现的执行摘要
3. 需要详细分析时，根据 `REPORT.md` 中的 AUDIT-ID 跳转到对应的 `rounds/round-NN-*.md`
4. P1/P2/P3 项目仍在 TODO 中，由后续审计会话延续

## 重要说明

- **状态**: 本次审计为 **代码静态审计 + 配置审视**，所有标注 "需动态验证" 的发现需配合 fuzz / 集成测试 / 测试网部署进一步核实。
- **作用域**: `ckb` 节点本身（Rust 工作区 ~70 个 crate）。**不包括** `ckb-vm`、`tentacle`、`secp256k1` 等上游依赖的代码审计 —— 仅核对其调用方式与版本公告。
- **CKB-VM 合约审计豁免**: 依 SKILL 第 5 节，CKB 合约审计豁免内存对齐项；本仓库是宿主 Rust 代码，对齐由 Rust 编译器/语言层面保证，同样无需审计。
