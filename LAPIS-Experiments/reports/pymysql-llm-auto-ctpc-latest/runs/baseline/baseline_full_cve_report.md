# LAPIS Full-CVE YASA Report

- Label: `baseline`
- Case: `cve-2024-36039-pymysql`
- Status: `not_reported`
- Result: `no_finding`
- Return code: `0`
- Tool: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool`
- Source path: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/dataset`
- Rule: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/rules/final-sink-only.json`
- CTPC: `None`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc-latest/runs/baseline/baseline`

## Summary

- Findings: `0`
- Sources marked: `1`
- Sinks matched: `2`
- Entry points: `1`
- Files analyzed: `20`
- Lines analyzed: `4367`

## Trace Quality

- Trace status: `no_finding_trace`
- CCEC virtual sink: `False`
- CTPC fact trace: `False`
- FACT TRACE GAP: `False`
- Needs CTPC: `False`
- Needs trace review: `False`

## Interpretation

This is a full original-CVE run. A finding here is evidence that the enhanced analyzer connected the case entrypoint, interprocedural execution context, CTPC access-path facts, and final sink rule on the original dataset.

## Next Debug Target

The local CTPC validation may still pass while the full CVE run does not report. That means the remaining gap is in full-program execution context, cross-function fact propagation, receiver/argument binding, or final sink reachability.
