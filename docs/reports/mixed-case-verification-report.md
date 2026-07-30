# Mixed Case Verification Report

本文记录当前 LAPIS mixed-case 实验的最新工程闭环结果。mixed case 的判断不是简单看
baseline 是否匹配 sink，而是看：

```text
1. CCEC 是否让调用图/边界继续前进；
2. CCEC 后是否仍然 no_finding 或出现 FACT TRACE GAP；
3. 是否需要 CTPC 补充参数传播 / access-path / container / string-flow fact；
4. CCEC + CTPC 被 LAPIS-Tool 消费后，YASA 是否报告 finding；
5. ordered_source_to_sink_chain 是否按参数传播顺序可供人工审查。
```

## 当前实现

Mixed workflow 已接入工程代码：

```text
LAPIS-Core/src/lapis/cli.py
  run-yasa-case 输出 contract status、finding_trace、ordered_source_to_sink_chain。

LAPIS-Core/src/lapis/yasa_runner.py
  汇总 CCEC/CTPC 消费诊断，判断 trace_status / needs_ctpc，
  并编排审查用 source-to-sink 链路。

LAPIS-Tool/src/engine/analyzer/python/common/python-analyzer.ts
  消费 materialized CCEC call edge。

LAPIS-Tool/src/checker/taint/python/lapis-ctpc.ts
  消费 CTPC v2 facts，支持 force/suppress finding 和 diagnostics。
```

## CVE-2026-24486 / python-multipart

分类：

```text
gap_type: mixed_case
repair route: CCEC first, then CTPC
```

最新产物：

```text
case:
LAPIS-Experiments/cases/mixed_case/cve-2026-24486-python-multipart/case.json

LLM CCEC:
LAPIS-Experiments/reports/python-multipart-llm-auto-mixed-latest/ccec/candidate_edges.llm.json

LLM CTPC:
LAPIS-Experiments/reports/python-multipart-llm-auto-mixed-latest/ctpc/ctpc/ctpc.json

validation:
LAPIS-Experiments/reports/python-multipart-llm-auto-mixed-latest/validation/validation_response.auto.json
```

复扫结果：

| 阶段 | report | 结果 |
|---|---|---|
| baseline | `runs/baseline/baseline_full_cve_report.json` | `finding=0`, `sources=2`, `sinks=4` |
| post CCEC | `runs/post-ccec/post-ccec_full_cve_report.json` | `finding=0`, `sources=2`, `sinks=4` |
| CCEC + CTPC | `runs/final-ccec-ctpc/final-ccec-ctpc_full_cve_report.json` | `reported`, `finding=1`, `sources=2`, `sinks=4` |

解释：

```text
CCEC 修复 callback/event dispatch 类调用连接问题；
但 CCEC 后仍未形成完整 taint finding。

CTPC 继续补充 file_name / closure / constructor / path/open 相关传播 fact；
最终 LAPIS-Tool 消费 CCEC+CTPC 后，YASA 输出 reported finding。
```

## CVE-2025-55156 / pyLoad

分类：

```text
gap_type: mixed_case
repair route: CCEC first, then CTPC
```

最新产物：

```text
case:
LAPIS-Experiments/cases/mixed_case/cve-2025-55156-pyload/case.json

LLM CCEC:
LAPIS-Experiments/reports/pyload-llm-auto-mixed-latest/ccec/candidate_edges.llm.json

LLM CTPC:
LAPIS-Experiments/reports/pyload-llm-auto-mixed-latest/ctpc/ctpc/ctpc.json
```

复扫结果：

| 阶段 | report | 结果 |
|---|---|---|
| baseline | `runs/baseline/baseline_full_cve_report.json` | `finding=0`, `sources=2`, `sinks=0` |
| post CCEC | `runs/post-ccec-after-callsite-match-fix/post-ccec-after-callsite-match-fix_full_cve_report.json` | `finding=0`, `sources=2`, `sinks=2` |
| CCEC + CTPC | `runs/final-ccec-ctpc-clean-trace/final-ccec-ctpc-clean-trace_full_cve_report.json` | `reported`, `finding=1`, `sources=2`, `sinks=2` |

解释：

```text
CCEC 让 YASA 从 db.update_link_info(data) 进入真实 receiver 方法体附近，
因此 post-CCEC 阶段 sink 从 0 前进到 2，但 taint 仍没有闭合。

CTPC 补充 data[*][3]、generator tuple index、join、f-string SQL 拼接传播；
最终形成 ordered source-to-sink chain 并 reported。
```

## 如何审查 Mixed 结果

推荐命令形态：

```bash
PYTHONPATH=LAPIS-Core/src python3 -m lapis run-yasa-case \
  --tool-dir LAPIS-Tool \
  --case LAPIS-Experiments/cases/mixed_case/cve-2026-24486-python-multipart/case.json \
  --out-dir LAPIS-Experiments/reports/reproduce-python-multipart/final-ccec-ctpc \
  --uast-sdk-path /path/to/YASA-Engine-upstream/uast4py-linux-amd64 \
  --label final-ccec-ctpc \
  --timeout-seconds 180 \
  --ccec-file LAPIS-Experiments/reports/python-multipart-llm-auto-mixed-latest/ccec/candidate_edges.llm.json \
  --ctpc-file LAPIS-Experiments/reports/python-multipart-llm-auto-mixed-latest/ctpc/ctpc/ctpc.json
```

终端输出中重点看：

```text
status=reported
result=finding
ccec_status=materialized_call_edge_consumed 或 progress_observed
ctpc_status=fact_forced_finding
trace_status=ctpc_fact_closed / reported_trace
ordered_source_to_sink_chain
```

`finding_trace` 是 YASA/SARIF 风格结果；`ordered_source_to_sink_chain` 是
LAPIS 在 YASA 消费 CCEC/CTPC 后，根据 case、源码、diagnostics、已消费契约编排出的
人工审查链路。它不是人工参考答案，也不是直接把 oracle 链路复制进报告。
