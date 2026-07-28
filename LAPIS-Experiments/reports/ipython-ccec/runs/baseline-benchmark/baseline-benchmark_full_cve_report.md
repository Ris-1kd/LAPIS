# LAPIS Full-CVE YASA Report

- Label: `baseline-benchmark`
- Case: `cve-2023-24816-ipython`
- Status: `not_reported`
- Result: `no_finding`
- Return code: `0`
- Tool: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool`
- Source path: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/benchmarks/connectivity_gap/cve-2023-24816-ipython`
- Rule: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/connectivity_gap/cve-2023-24816-ipython/rules/final-sink-only.json`
- CTPC: `None`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/ipython-ccec/runs/baseline-benchmark/baseline-benchmark`

## Summary

- Findings: `0`
- Sources marked: `1`
- Sinks matched: `2`
- Entry points: `1`
- Files analyzed: `295`
- Lines analyzed: `73363`

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
