# LAPIS Full-CVE YASA Report

- Label: `baseline`
- Case: `cve-2026-24486-python-multipart`
- Status: `not_reported`
- Result: `no_finding`
- Return code: `0`
- Tool: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool`
- Source path: `/home/ubuntu/llm-yasa-repair/py-bench/cve-2026-24486-python-multipart`
- Rule: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/mixed_case/cve-2026-24486-python-multipart/rules/final-sink-only.json`
- CTPC: `None`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/python-multipart-llm-auto-mixed/runs/baseline/baseline`

## Summary

- Findings: `0`
- Sources marked: `2`
- Sinks matched: `4`
- Entry points: `1`
- Files analyzed: `12`
- Lines analyzed: `3724`

## Interpretation

This is a full original-CVE run. A finding here is evidence that the enhanced analyzer connected the case entrypoint, interprocedural execution context, CTPC access-path facts, and final sink rule on the original dataset.

## Next Debug Target

The local CTPC validation may still pass while the full CVE run does not report. That means the remaining gap is in full-program execution context, cross-function fact propagation, receiver/argument binding, or final sink reachability.
