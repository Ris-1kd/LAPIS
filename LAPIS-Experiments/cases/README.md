# LAPIS CVE Case Dataset

本目录按断链类型组织 CVE case 数据集。

```text
connectivity_gap/
  缺失调用边。source frontier 到达调用点，但 CG 没有连接到真实 callee。

propagation_gap/
  缺失数据流。调用上下文基本可达，但 taint/value/access-path 没有继续传播。

mixed_case/
  调用边和数据流都缺失。先补 CCEC，重跑后再决定是否补 CTPC。

control/
  对照组。baseline 已经完整命中，不进入修复流程。
```

## 当前 Case

| 分类目录 | CVE | 项目 | 修复分支 |
|---|---|---|---|
| `connectivity_gap/` | CVE-2024-27758 | RPyC | CCEC |
| `connectivity_gap/` | CVE-2023-24816 | IPython | CCEC |
| `propagation_gap/` | CVE-2024-36039 | PyMySQL | CTPC |
| `mixed_case/` | CVE-2026-24486 | python-multipart | CCEC -> CTPC |
| `mixed_case/` | CVE-2025-55156 | pyLoad | CCEC -> CTPC |
| `control/` | CVE-2023-4033 | MLflow | no repair |

每个 case 至少包含：

```text
case.json   case 元数据、断链分类、source/sink、baseline 位置、预期修复顺序
README.md   case 简述和产物目录说明
```

后续生成的证据、契约和验证产物按 case 内目录放置：

```text
evidence/
ccec/
ctpc/
validation/
repaired-runs/
```
