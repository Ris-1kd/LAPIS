# LAPIS

LAPIS is the workspace for the new access-path propagation gap research line.

## Layout

```text
LAPIS-Core/
  Reusable tool implementation for locating access-path propagation gaps,
  building evidence packs, ranking candidate edges, and validating contracts.

LAPIS-Experiments/
  Experiment assets: case configs, YASA rules, baseline outputs, generated
  evidence packs, validation cases, and reports.

LAPIS-Tool/
  LAPIS-modified YASA tool tree. This is where CTPC loading, guarded
  access-path propagation, and YASA-in-the-loop validation hooks will be added.

docs/
  Project-level methodology, dataset classification, and verification reports.

paper-experiments/
  Paper-facing table templates, metric definitions, and future aggregation
  scripts for final evaluation results.
```

`YASA-Engine-upstream` remains the untouched baseline. LAPIS-specific YASA
changes should be made in `LAPIS-Tool`, not in the upstream folder.

See [docs/README.md](docs/README.md) for the organized LAPIS research
documentation index.

See [paper-experiments/README.md](paper-experiments/README.md) for paper
experiment table templates. The current templates intentionally use `TBD`
placeholders until the full dataset is collected.

## Reproduce One Experiment Case

The repository contains the LAPIS automation code, the LAPIS-modified YASA tool
tree, benchmark inputs, case metadata, generated contracts, and latest reports.
After cloning, `LAPIS-Tool` is the modified YASA tool used by the experiments.

Prerequisites:

```bash
git clone https://github.com/Ris-1kd/LAPIS.git
cd LAPIS

# Install the LAPIS-modified YASA tool dependencies.
cd LAPIS-Tool
npm install
cd ..
```

Provide the external UAST SDK path when running YASA-backed experiments. The
SDK is not committed in this repository:

```text
--uast-sdk-path /path/to/YASA-Engine-upstream/uast4py-linux-amd64
```

For LLM-backed CCEC/CTPC generation, keep the API key local and out of git:

```bash
cat > .lapis-llm.env <<'EOF'
LAPIS_LLM_BASE_URL=https://llm-api.net/v1
LAPIS_LLM_MODEL=gpt-5
LAPIS_LLM_API_KEY=your_api_key_here
EOF

PYTHONPATH=LAPIS-Core/src python3 -m lapis llm-smoke-test
```

Run a baseline scan for one case:

```bash
PYTHONPATH=LAPIS-Core/src python3 -m lapis run-yasa-case \
  --tool-dir LAPIS-Tool \
  --case LAPIS-Experiments/cases/connectivity_gap/cve-2023-24816-ipython/case.json \
  --out-dir LAPIS-Experiments/reports/reproduce-ipython/baseline \
  --uast-sdk-path /path/to/YASA-Engine-upstream/uast4py-linux-amd64 \
  --label baseline \
  --timeout-seconds 180
```

Run the same case with the latest generated CCEC contract consumed by the
modified YASA tool:

```bash
PYTHONPATH=LAPIS-Core/src python3 -m lapis run-yasa-case \
  --tool-dir LAPIS-Tool \
  --case LAPIS-Experiments/cases/connectivity_gap/cve-2023-24816-ipython/case.json \
  --out-dir LAPIS-Experiments/reports/reproduce-ipython/final-ccec \
  --uast-sdk-path /path/to/YASA-Engine-upstream/uast4py-linux-amd64 \
  --label final-ccec \
  --timeout-seconds 180 \
  --ccec-file LAPIS-Experiments/reports/ipython-ccec/ccec/candidate_edges.llm.json
```

Run a CTPC case:

```bash
PYTHONPATH=LAPIS-Core/src python3 -m lapis run-yasa-case \
  --tool-dir LAPIS-Tool \
  --case LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/case.json \
  --out-dir LAPIS-Experiments/reports/reproduce-pymysql/final-ctpc \
  --uast-sdk-path /path/to/YASA-Engine-upstream/uast4py-linux-amd64 \
  --label final-ctpc \
  --timeout-seconds 180 \
  --ctpc-file LAPIS-Experiments/reports/pymysql-llm-auto-ctpc-latest/ctpc/ctpc/ctpc.json
```

Run a mixed CCEC + CTPC case:

```bash
PYTHONPATH=LAPIS-Core/src python3 -m lapis run-yasa-case \
  --tool-dir LAPIS-Tool \
  --case LAPIS-Experiments/cases/mixed_case/cve-2026-24486-python-multipart/case.json \
  --out-dir LAPIS-Experiments/reports/reproduce-python-multipart/final-ccec-ctpc \
  --uast-sdk-path /path/to/YASA-Engine-upstream/uast4py-linux-amd64 \
  --label final-ccec-ctpc \
  --timeout-seconds 180 \
  --ccec-file LAPIS-Experiments/reports/python-multipart-llm-auto-mixed-latest/ccec/candidate_edges.llm.json \
  --ctpc-file LAPIS-Experiments/reports/python-multipart-llm-auto-mixed-latest/ctpc/ctpc/ctpc.json
```

Each run writes a JSON report, a Markdown report, YASA scan artifacts, and the
terminal summary. When a repaired run succeeds, the terminal output includes
`status=reported`, `findings=1`, contract consumption status, and an ordered
source-to-sink chain for manual review.

To regenerate contracts instead of reusing the checked-in latest outputs, use
the end-to-end LLM workflow:

```bash
PYTHONPATH=LAPIS-Core/src python3 -m lapis run-end-to-end-case \
  --tool-dir LAPIS-Tool \
  --case LAPIS-Experiments/cases/mixed_case/cve-2026-24486-python-multipart/case.json \
  --out-dir LAPIS-Experiments/reports/reproduce-python-multipart/e2e \
  --uast-sdk-path /path/to/YASA-Engine-upstream/uast4py-linux-amd64 \
  --llm-auto
```
