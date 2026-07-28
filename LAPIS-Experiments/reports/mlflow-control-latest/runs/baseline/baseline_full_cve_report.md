# LAPIS Full-CVE YASA Report

- Label: `baseline`
- Case: `cve-2023-4033-mlflow`
- Status: `not_reported`
- Result: `no_finding`
- Return code: `0`
- Tool: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool`
- Source path: `/home/ubuntu/llm-yasa-repair/py-bench/cve-2023-4033-mlflow`
- Rule: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/control/cve-2023-4033-mlflow/rules/final-sink-only.json`
- CTPC: `None`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/mlflow-control-latest/runs/baseline/baseline`

## Summary

- Findings: `0`
- Sources marked: `0`
- Sinks matched: `0`
- Entry points: `0`
- Files analyzed: `413`
- Lines analyzed: `103168`

## Trace Quality

- Trace status: `no_finding_trace`
- CCEC virtual sink: `False`
- CTPC fact trace: `False`
- FACT TRACE GAP: `False`
- Needs CTPC: `False`
- Needs trace review: `False`

## Interpretation

This is a full original-CVE run. A finding here is evidence that the enhanced analyzer connected the case entrypoint, interprocedural execution context, CTPC access-path facts, and final sink rule on the original dataset.

## Ordered Source-To-Sink Chain

```text
Step 0: SOURCE poc/poc_cve_2023_4033_mlflow.py:15  input_path = cve_2023_4033_source() [case.source]
```

## Next Debug Target

The local CTPC validation may still pass while the full CVE run does not report. That means the remaining gap is in full-program execution context, cross-function fact propagation, receiver/argument binding, or final sink reachability.
