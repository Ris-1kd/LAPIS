# LAPIS YASA Validation Report

- Label: `ctpc-yasa-validation`
- Status: `needs_revision`
- Tool: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool`
- Rules: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/python-multipart-llm-auto-mixed/ctpc-validation/rules`

## Samples

### must-flow - PASS

- Expected: `finding`
- YASA result: `finding`
- Return code: `0`
- Findings: `3`
- Sources marked: `1`
- Sinks matched: `8`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/python-multipart-llm-auto-mixed/ctpc-validation/yasa/ctpc-yasa-validation/must-flow`

### must-not-flow - FAIL

- Expected: `no_finding`
- YASA result: `finding`
- Return code: `0`
- Findings: `2`
- Sources marked: `1`
- Sinks matched: `8`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/python-multipart-llm-auto-mixed/ctpc-validation/yasa/ctpc-yasa-validation/must-not-flow`

### must-kill - FAIL

- Expected: `no_finding`
- YASA result: `finding`
- Return code: `0`
- Findings: `1`
- Sources marked: `1`
- Sinks matched: `4`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/python-multipart-llm-auto-mixed/ctpc-validation/yasa/ctpc-yasa-validation/must-kill`

## Feedback

- must-not-flow expected no_finding but YASA produced finding
- must-kill expected no_finding but YASA produced finding
