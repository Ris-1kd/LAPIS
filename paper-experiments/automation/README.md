# Paper Experiment Automation

This directory contains a small, reproducible aggregation loop for the current
LAPIS validation cases. It is intentionally separate from the main LAPIS
runtime code so the paper tables can evolve as the benchmark grows.

## Files

| File | Purpose |
|---|---|
| `case-manifest.json` | Declares the current small benchmark slice and points to baseline/final reports |
| `aggregate_tables.py` | Reads reports/contracts and writes table-ready CSV/Markdown drafts |
| `llm-backends.example.json` | Example backend matrix for GPT/Gemini/DeepSeek-style OpenAI-compatible APIs |
| `run_backend_matrix.py` | Builds or executes per-backend LLM generation, validation, materialization, and re-scan commands |
| `generated/` | Generated outputs from the latest aggregation run |

## Usage

Run from the repository root:

```bash
python3 paper-experiments/automation/aggregate_tables.py
```

By default the script reads `case-manifest.json` and writes generated drafts to
`paper-experiments/automation/generated/`.

The generated files are not a hand-written oracle. They are derived from:

- `*_full_cve_report.json` files emitted by `lapis run-yasa-case`;
- CCEC / CTPC JSON contract files;
- CCEC validation reports and CTPC three-way validation responses, when present.

## Extension Plan

To add a new CVE, append a case object to `case-manifest.json` with paths to the
baseline report, final LAPIS report, and generated contracts. The aggregation
logic is dataset-agnostic and can scale to the planned paper benchmark without
per-project code changes.

To compare more LLM backends, add backend entries under a case's `llm_runs`
array. Each backend should point to its generated contracts, validation files,
and final re-scan report.

## Backend Matrix Dry Run

Generate commands for one backend without calling the API:

```bash
PYTHONPATH=LAPIS-Core/src python3 paper-experiments/automation/run_backend_matrix.py \
  --backend gpt5
```

Execute the generated loop after configuring the backend API key in the
environment or `.lapis-llm.env`:

```bash
PYTHONPATH=LAPIS-Core/src python3 paper-experiments/automation/run_backend_matrix.py \
  --backend gpt5 \
  --execute
```

The execution loop is:

```text
LLM CCEC/CTPC generation
-> local CCEC validation / CTPC materialization
-> LLM CTPC three-way validation generation
-> YASA re-scan with materialized contracts
-> aggregate_tables.py records the results
```
