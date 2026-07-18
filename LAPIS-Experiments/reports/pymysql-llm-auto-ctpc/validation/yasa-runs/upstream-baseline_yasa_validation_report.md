# LAPIS YASA Validation Report

- Label: `upstream-baseline`
- Status: `needs_revision`
- Tool: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool`
- Rules: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/validation/yasa-rules`

## Samples

### must-flow - FAIL

- Expected: `finding`
- YASA result: `no_finding`
- Return code: `0`
- Findings: `0`
- Sources marked: `1`
- Sinks matched: `2`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/validation/yasa-runs/upstream-baseline/must-flow`

### must-not-flow - PASS

- Expected: `no_finding`
- YASA result: `no_finding`
- Return code: `0`
- Findings: `0`
- Sources marked: `0`
- Sinks matched: `0`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/validation/yasa-runs/upstream-baseline/must-not-flow`

### must-kill - PASS

- Expected: `no_finding`
- YASA result: `no_finding`
- Return code: `0`
- Findings: `0`
- Sources marked: `0`
- Sinks matched: `0`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/validation/yasa-runs/upstream-baseline/must-kill`

## Feedback

- must-flow expected finding but YASA produced no_finding
