# LAPIS YASA Validation Report

- Label: `llm-ctpc-enhanced`
- Status: `accepted`
- Tool: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool`
- Rules: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/validation/yasa-rules`

## Samples

### must-flow - PASS

- Expected: `finding`
- YASA result: `finding`
- Return code: `0`
- Findings: `1`
- Sources marked: `1`
- Sinks matched: `2`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/validation/yasa-runs/llm-ctpc-enhanced/must-flow`

### must-not-flow - PASS

- Expected: `no_finding`
- YASA result: `no_finding`
- Return code: `0`
- Findings: `0`
- Sources marked: `1`
- Sinks matched: `2`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/validation/yasa-runs/llm-ctpc-enhanced/must-not-flow`

### must-kill - PASS

- Expected: `no_finding`
- YASA result: `no_finding`
- Return code: `0`
- Findings: `0`
- Sources marked: `1`
- Sinks matched: `2`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/validation/yasa-runs/llm-ctpc-enhanced/must-kill`

## Feedback

- All YASA validation samples matched expected results.
