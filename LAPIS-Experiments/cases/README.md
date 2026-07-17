# LAPIS CVE Case Dataset

本目录按断链类型组织 LAPIS case 元数据和实验产物。

原始输入数据集不要放在这里。源码、PoC 和 YASA rule 应放在：

```text
../benchmarks/<gap_type>/<case_id>/
```

```text
connectivity_gap/
  缺失调用边。source frontier 到达调用点，但 CG 没有连接到真实 callee。

propagation_gap/
  缺失数据流。调用上下文基本可达，但 taint/value/access-path 没有继续传播。

mixed_case/
  benchmark 评估分组。baseline 阶段不能直接确认混合缺口；只能先按
  connectivity_gap 补 CCEC，重跑后若仍存在 propagation_gap，再确认混合缺口。

control/
  对照组。baseline 已经完整命中，不进入修复流程。
```

## 当前 Case

| 分类目录 | CVE | 项目 | 修复分支 |
|---|---|---|---|
| `connectivity_gap/` | CVE-2024-27758 | RPyC | CCEC |
| `connectivity_gap/` | CVE-2023-24816 | IPython | CCEC |
| `propagation_gap/` | CVE-2024-36039 | PyMySQL | CTPC |
| `mixed_case/` | CVE-2026-24486 | python-multipart | CCEC -> rerun -> CTPC if confirmed |
| `mixed_case/` | CVE-2025-55156 | pyLoad | CCEC -> rerun -> CTPC if confirmed |
| `control/` | CVE-2023-4033 | MLflow | no repair |

每个 case 至少包含：

```text
case.json   case 元数据、baseline 位置、benchmark 路径、扫描规则路径
README.md   oracle-blind case 简述和产物目录说明
```

`case.json` 不应包含人工 breakpoint、frontier、完整 source-to-sink 链路、
预期修复顺序或历史候选契约。候选推断只能读取 baseline 静态产物和代码上下文。

后续生成的证据、契约和验证产物按 case 内目录放置：

```text
evidence/
ccec/
ctpc/
validation/
repaired-runs/
e2e/
```

`e2e/` 是完整闭环产物目录：baseline 复扫、CCEC 复扫、post-CCEC 复诊、
可选 CTPC 复扫和最终评估都写在这里。hidden oracle 只允许在
`end_to_end_report.json` 的 final evaluation 阶段读取。

## CCEC 三类补调用边机制

```text
easy
  direct_static_edge。baseline 暴露一个明确 callsite，静态证据只有一个
  唯一 callee。规则可直接生成候选边，LLM 只允许格式化/解释，不负责发散候选。

middle
  top_k_static_edges_then_llm_ranking。baseline 暴露 callsite，但存在多个
  静态候选 callee、分支、重绑定、callback 或 receiver 不确定性。规则先生成
  top-k，LLM 只根据 evidence 排序、选择和补 guard。

hard
  llm_synthesized_virtual_or_materialized_edge。baseline 只暴露动态/反射/
  factory/callback-table 证据，没有直接 materialized callee。LLM 根据多源静态
  证据合成 guarded dynamic/virtual/materialized call-edge contract。
```

三类机制都必须 oracle-blind：不能读取 hidden oracle、人工完整链路、旧
candidate_edges 或旧 repaired-runs。修复并复扫后，才允许和隐藏答案对照。

## CCEC / CTPC 三分局部验证

```text
CCEC
  build-ccec-validation-prompt
  -> materialize-ccec-validation
  -> validate-ccec-local
  -> 后续带 --lapisCcecFile 跑 callgraph/YASA 复扫

  ccec-validation/must-link/case.py       edge_present
  ccec-validation/must-not-link/case.py   edge_absent
  ccec-validation/must-kill/case.py       edge_suppressed

CTPC
  build-validation-prompt
  -> materialize-validation
  -> validate-ctpc
  -> build-validation-rules
  -> run-yasa-validation

  validation/must-flow/case.py      finding
  validation/must-not-flow/case.py  no_finding
  validation/must-kill/case.py      no_finding
```

局部样例只验证候选契约本身是否按 guard 生效/不生效/被抑制，不得包含完整
CVE source-to-sink oracle 链路。

## End-to-End 闭环

```text
run-end-to-end-case
  -> baseline full-case rerun
  -> initial Evidence Gate / Gap Diagnosis
  -> CCEC candidate generation and structural validation
  -> full-case rerun with CCEC
  -> post-CCEC Evidence Gate / Gap Diagnosis
  -> if propagation_gap remains and ctpc/ctpc*.json exists, rerun with CCEC+CTPC
  -> final evaluation, optionally compare hidden oracle
```

如果 post-CCEC 复诊需要 CTPC，但当前 case 没有 `ctpc/ctpc.v2.json` 或
`ctpc/ctpc.json`，闭环报告会标记 `ctpc_rerun=blocked`。这表示需要先通过
oracle-blind 的 CTPC prompt/LLM/三分验证生成数据流契约，再继续复扫。

## 与 benchmarks/ 的关系

```text
benchmarks/
  source/  被分析项目源码
  poc/     安全 PoC / driver
  rules/   YASA rule config

cases/
  case.json 引用 benchmark 路径
  evidence/ccec/ctpc/validation/repaired-runs 保存 LAPIS 产物
```

推荐 `case.json` 中使用相对路径指向 benchmark：

```json
{
  "dataset_dir": "../../benchmarks/mixed_case/cve-2026-24486-python-multipart/source",
  "rule_file": "../../benchmarks/mixed_case/cve-2026-24486-python-multipart/rules/final-sink-only.json"
}
```
