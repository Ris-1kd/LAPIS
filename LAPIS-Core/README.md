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

## Three-Class CVE Workflow

List the current CVE case dataset:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis list-cases \
  --cases-root /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases \
  --out /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/case_index.json
```

Run the front-door repair workflow for all cases:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis run-repair-workflow \
  --cases-root /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases \
  --out /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/repair_workflow_report.json
```

This command writes, per case:

```text
evidence/evidence_gate.json
evidence/gap_diagnosis.json
ccec/candidate_edges.json       for connectivity_gap and suspected post-CCEC cases
ccec/validation_report.json     structural CCEC validation
```

Run the full end-to-end loop for one case:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis run-end-to-end-case \
  --tool-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool \
  --case /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/mixed_case/cve-2026-24486-python-multipart/case.json \
  --out-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/mixed_case/cve-2026-24486-python-multipart/e2e \
  --uast-sdk-path /home/ubuntu/llm-yasa-repair/YASA-Engine-upstream/uast4py-linux-amd64
```

This command writes:

```text
e2e/runs/baseline/
e2e/runs/post-ccec/
e2e/runs/post-ccec-ctpc/     only when CTPC is confirmed and ctpc/ctpc*.json exists
e2e/evidence/initial_evidence_gate.json
e2e/evidence/initial_gap_diagnosis.json
e2e/evidence/post_ccec_evidence_gate.json
e2e/evidence/post_ccec_gap_diagnosis.json
e2e/ccec/candidate_edges.json
e2e/end_to_end_report.json
e2e/end_to_end_report.md
```

Run the same loop for every case:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis run-end-to-end-cases \
  --tool-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool \
  --cases-root /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases \
  --out-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/e2e \
  --uast-sdk-path /home/ubuntu/llm-yasa-repair/YASA-Engine-upstream/uast4py-linux-amd64
```

Hidden oracle files are optional and are read only by the final evaluation block
through `--oracle` or `--oracle-root`. If no oracle exists, the report records
`reported_without_oracle` or `not_reported_without_oracle` based on the final
full-case YASA result.

Optional LLM automation uses any OpenAI-compatible chat-completions API. Keep
API keys out of the repository:

```bash
export LAPIS_LLM_BASE_URL=https://your-openai-compatible-provider.example/v1
export LAPIS_LLM_MODEL=your-model-name
export LAPIS_LLM_API_KEY=...

PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis llm-smoke-test
```

For one-off tests without exporting a key:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis llm-smoke-test \
  --base-url https://your-openai-compatible-provider.example/v1 \
  --model your-model-name \
  --api-key-stdin
```

With `--llm-auto`, the E2E runner calls the configured LLM when CCEC/CTPC
synthesis is needed:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis run-end-to-end-case \
  --tool-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool \
  --case /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/mixed_case/cve-2026-24486-python-multipart/case.json \
  --out-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/mixed_case/cve-2026-24486-python-multipart/e2e \
  --uast-sdk-path /home/ubuntu/llm-yasa-repair/YASA-Engine-upstream/uast4py-linux-amd64 \
  --llm-auto
```

Expected routing:

```text
connectivity_gap:
  CVE-2023-24816 / IPython -> CCEC
  CVE-2024-27758 / RPyC    -> CCEC

propagation_gap:
  CVE-2024-36039 / PyMySQL -> CTPC

mixed_case benchmark group:
  CVE-2025-55156 / pyLoad           -> CCEC first, then CTPC if still broken
  CVE-2026-24486 / python-multipart -> CCEC first, then CTPC if still broken

control:
  CVE-2023-4033 / MLflow -> stop, already reported
```

Generate and structurally validate CCEC candidates for one case:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis generate-ccec-candidates \
  --case /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/connectivity_gap/cve-2024-27758-rpyc/case.json \
  --out /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/connectivity_gap/cve-2024-27758-rpyc/ccec/candidate_edges.json

PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis validate-ccec-candidates \
  --candidates /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/connectivity_gap/cve-2024-27758-rpyc/ccec/candidate_edges.json \
  --out /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/connectivity_gap/cve-2024-27758-rpyc/ccec/validation_report.json
```

## Prototype Command

From the workspace root:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis build-evidence \
  --case /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/case.json \
  --out /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/evidence/evidence_pack.json
```

Build a CTPC prompt:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis build-ctpc-prompt \
  --evidence /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/evidence/evidence_pack.json \
  --out /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/llm/ctpc_prompt.md
```

Run the overall repair workflow front door:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis evidence-gate \
  --case /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/case.json \
  --evidence /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/evidence/evidence_pack.json \
  --out /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/gate/evidence_gate_report.json

PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis diagnose-gap \
  --gate /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/gate/evidence_gate_report.json \
  --out /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/diagnosis/gap_diagnosis.json
```

`evidence-gate` implements Step 1 of the repair workflow. It classifies a
no-finding case as `candidate_fn`, `true_negative`, `safe_killed`,
`infeasible`, `deferred`, or `already_reported`. `diagnose-gap` implements
Step 2 and routes a `candidate_fn` to `connectivity_gap` or
`propagation_gap`. When both connectivity and propagation evidence appear in
baseline, it still reports `connectivity_gap` with
`secondary_gap=possible_propagation_gap` and
`needs_post_ccec_rediagnosis=true`; the mixed case is confirmed only after
CCEC repair, rerun, and rediagnosis.

Materialize a CTPC response:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis materialize-ctpc \
  --response /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/llm/ctpc_response.seed.json \
  --out-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql
```

Build a validation-sample prompt:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis build-validation-prompt \
  --evidence /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/evidence/evidence_pack.json \
  --ctpc /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/ctpc/ctpc.json \
  --out /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/llm/validation_prompt.md
```

Upgrade a legacy CTPC into the structured CTPC v2 schema:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis upgrade-ctpc-v2 \
  --ctpc /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/ctpc/ctpc.json \
  --out /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/ctpc/ctpc.v2.json
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
  --response /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/llm/validation_response.seed.json \
  --out-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql
```

Build YASA rules for the three validation samples:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis build-validation-rules \
  --validation-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/validation \
  --out-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/validation/yasa-rules
```

Run the current CTPC validation loop:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis validate-ctpc \
  --ctpc /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/ctpc/ctpc.json \
  --validation-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/validation \
  --out-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/validation/reports
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
  --validation-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/validation \
  --rules-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/validation/yasa-rules \
  --out-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/validation/yasa-runs \
  --uast-sdk-path /home/ubuntu/llm-yasa-repair/YASA-Engine-upstream/uast4py-linux-amd64 \
  --label upstream-baseline
```

Run YASA on the original full CVE case:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis run-yasa-case \
  --tool-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool \
  --case /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/case.json \
  --out-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/full-cve-runs \
  --uast-sdk-path /home/ubuntu/llm-yasa-repair/YASA-Engine-upstream/uast4py-linux-amd64 \
  --label lapis-tool-ctpc-v2 \
  --ctpc-file /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/ctpc/ctpc.v2.json
```

This is the final acceptance direction for a case: the enhanced analyzer should
report the complete original CVE chain through the real dataset entrypoint and
final sink rule.

Build the feasibility closure report:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis build-feasibility-report \
  --ctpc-validation /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/validation/reports/validation_report.json \
  --baseline-yasa /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/validation/yasa-runs/upstream-baseline_yasa_validation_report.json \
  --out /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/reports/feasibility_closure.json
```

Run LAPIS-Tool with a CTPC file:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis run-yasa-validation \
  --tool-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool \
  --validation-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/validation \
  --rules-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/validation/yasa-rules \
  --out-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/validation/yasa-runs \
  --uast-sdk-path /home/ubuntu/llm-yasa-repair/YASA-Engine-upstream/uast4py-linux-amd64 \
  --label lapis-tool-ctpc \
  --ctpc-file /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/ctpc/ctpc.json
```

Run LAPIS-Tool with the structured CTPC v2 file:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis run-yasa-validation \
  --tool-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool \
  --validation-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/validation \
  --rules-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/validation/yasa-rules \
  --out-dir /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/validation/yasa-runs \
  --uast-sdk-path /home/ubuntu/llm-yasa-repair/YASA-Engine-upstream/uast4py-linux-amd64 \
  --label lapis-tool-ctpc-v2 \
  --ctpc-file /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/ctpc/ctpc.v2.json
```

Build a closed feasibility report:

```bash
PYTHONPATH=/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Core/src \
python3 -m lapis build-feasibility-report \
  --ctpc-validation /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/validation/reports/validation_report.json \
  --baseline-yasa /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/validation/yasa-runs/upstream-baseline_yasa_validation_report.json \
  --enhanced-yasa /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/validation/yasa-runs/lapis-tool-ctpc_yasa_validation_report.json \
  --out /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/reports/feasibility_closure.json
```
