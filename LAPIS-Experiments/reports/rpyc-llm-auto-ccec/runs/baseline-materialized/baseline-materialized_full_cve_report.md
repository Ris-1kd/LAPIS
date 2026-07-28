# LAPIS Full-CVE YASA Report

- Label: `baseline-materialized`
- Case: `cve-2024-27758-rpyc-final-sink-only`
- Status: `not_reported`
- Result: `no_finding`
- Return code: `0`
- Tool: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool`
- Source path: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/benchmarks/connectivity_gap/cve-2024-27758-rpyc`
- Rule: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/connectivity_gap/cve-2024-27758-rpyc/rules/final-sink-only.json`
- CTPC: `None`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/rpyc-llm-auto-ccec/runs/baseline-materialized/baseline-materialized`

## Summary

- Findings: `0`
- Sources marked: `1`
- Sinks matched: `0`
- Entry points: `1`
- Files analyzed: `30`
- Lines analyzed: `6497`

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
