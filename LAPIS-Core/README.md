# LAPIS-Core

LAPIS-Core contains the reusable implementation of the access-path propagation
gap workflow.

Planned modules:

```text
src/lapis/
  locator/      forward frontier, backward dependency, convergence location
  evidence/     local structure extraction and Evidence Pack construction
  candidates/   access-path edge generation and ranking
  ctpc/         CTPC schema and lowering logic
  validate/     YASA runner and validation result checking
```

The core package should avoid hard-coding a specific CVE. Case-specific rules,
baseline artifacts, and reports belong in `../LAPIS-Experiments`.

## Prototype Command

From the workspace root:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis build-evidence \
  --case /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/case.json \
  --out /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/evidence/evidence_pack.json
```

Build a CTPC prompt:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis build-ctpc-prompt \
  --evidence /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/evidence/evidence_pack.json \
  --out /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/llm/ctpc_prompt.md
```

Materialize a CTPC response:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis materialize-ctpc \
  --response /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/llm/ctpc_response.seed.json \
  --out-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql
```

Build a validation-sample prompt:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis build-validation-prompt \
  --evidence /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/evidence/evidence_pack.json \
  --ctpc /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/ctpc/ctpc.json \
  --out /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/llm/validation_prompt.md
```

Upgrade a legacy CTPC into the structured CTPC v2 schema:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis upgrade-ctpc-v2 \
  --ctpc /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/ctpc/ctpc.json \
  --out /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/ctpc/ctpc.v2.json
```

`ctpc.v2` replaces free-form edge conditions with structured fields:

```text
applies_to.risk_kind
fact_types[].shape
propagation_edges[].event
propagation_edges[].pattern.kind
propagation_edges[].from / propagation_edges[].to
function_summaries[].pattern.kind
function_summaries[].from / function_summaries[].to
kill_conditions[].pattern / kill_conditions[].effect
```

`function_summaries` are the structured hook for cross-function access-path
semantics. The first supported summary kind is `return_fact_from_argument`,
which maps an actual argument fact, for example `$arg0.keys()[*]`, to a call
return fact that later propagation edges can consume.

Materialize validation samples:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis materialize-validation \
  --response /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/llm/validation_response.seed.json \
  --out-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql
```

Build YASA rules for the three validation samples:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis build-validation-rules \
  --validation-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/validation \
  --out-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/validation/yasa-rules
```

Run the current CTPC validation loop:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis validate-ctpc \
  --ctpc /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/ctpc/ctpc.json \
  --validation-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/validation \
  --out-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/validation/reports
```

This validation loop is local CTPC semantic validation. It checks whether the
candidate contract explains the access-path breakpoint on generated
must-flow/must-not-flow/must-kill samples. It is not the final proof that the
original CVE source-to-final-sink chain is reported.

Run upstream YASA on the same validation set:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis run-yasa-validation \
  --tool-dir /home/ubuntu/llm-yasa-repair/YASA-Engine-upstream \
  --validation-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/validation \
  --rules-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/validation/yasa-rules \
  --out-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/validation/yasa-runs \
  --uast-sdk-path /home/ubuntu/llm-yasa-repair/YASA-Engine-upstream/uast4py-linux-amd64 \
  --label upstream-baseline
```

Run YASA on the original full CVE case:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis run-yasa-case \
  --tool-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool \
  --case /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/case.json \
  --out-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/full-cve-runs \
  --uast-sdk-path /home/ubuntu/llm-yasa-repair/YASA-Engine-upstream/uast4py-linux-amd64 \
  --label lapis-tool-ctpc-v2 \
  --ctpc-file /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/ctpc/ctpc.v2.json
```

This is the final acceptance direction for a case: the enhanced analyzer should
report the complete original CVE chain through the real dataset entrypoint and
final sink rule.

Build the feasibility closure report:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis build-feasibility-report \
  --ctpc-validation /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/validation/reports/validation_report.json \
  --baseline-yasa /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/validation/yasa-runs/upstream-baseline_yasa_validation_report.json \
  --out /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/reports/feasibility_closure.json
```

Run LAPIS-Tool with a CTPC file:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis run-yasa-validation \
  --tool-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool \
  --validation-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/validation \
  --rules-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/validation/yasa-rules \
  --out-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/validation/yasa-runs \
  --uast-sdk-path /home/ubuntu/llm-yasa-repair/YASA-Engine-upstream/uast4py-linux-amd64 \
  --label lapis-tool-ctpc \
  --ctpc-file /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/ctpc/ctpc.json
```

Run LAPIS-Tool with the structured CTPC v2 file:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis run-yasa-validation \
  --tool-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool \
  --validation-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/validation \
  --rules-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/validation/yasa-rules \
  --out-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/validation/yasa-runs \
  --uast-sdk-path /home/ubuntu/llm-yasa-repair/YASA-Engine-upstream/uast4py-linux-amd64 \
  --label lapis-tool-ctpc-v2 \
  --ctpc-file /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/ctpc/ctpc.v2.json
```

Build a closed feasibility report:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis build-feasibility-report \
  --ctpc-validation /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/validation/reports/validation_report.json \
  --baseline-yasa /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/validation/yasa-runs/upstream-baseline_yasa_validation_report.json \
  --enhanced-yasa /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/validation/yasa-runs/lapis-tool-ctpc_yasa_validation_report.json \
  --out /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/cve-2024-36039-pymysql/reports/feasibility_closure.json
```
