# LAPIS Full-CVE YASA Report

- Label: `baseline`
- Case: `cve-2025-55156-pyload`
- Status: `not_reported`
- Result: `no_finding`
- Return code: `0`
- Tool: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool`
- Source path: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/benchmarks/mixed_case/cve-2025-55156-pyload`
- Rule: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/mixed_case/cve-2025-55156-pyload/rules/final-sink-only.json`
- CTPC: `None`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/pyload-llm-auto-mixed-latest/runs/baseline/baseline`

## Summary

- Findings: `0`
- Sources marked: `2`
- Sinks matched: `0`
- Entry points: `1`
- Files analyzed: `570`
- Lines analyzed: `61479`

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
Step 0: SOURCE poc/poc_cve_2025_55156_pyload.py:16  url = cve_2025_55156_source() [case.source]
Step 1: SINK src/pyload/core/database/file_database.py:271  self.c.execute(f"SELECT id FROM links WHERE url IN ('{statuses}')") [case.sink]
```

## Next Debug Target

The local CTPC validation may still pass while the full CVE run does not report. That means the remaining gap is in full-program execution context, cross-function fact propagation, receiver/argument binding, or final sink reachability.
