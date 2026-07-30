# LAPIS Paper Experiments

This directory is reserved for paper-facing experiment tables, metric
definitions, and result aggregation materials.

The current numbers in `docs/experiment/LAPIS_Experiment_Design.md` are design
examples only. Do not treat them as final experiment results. Final tables in
this directory should be populated only after the full benchmark collection and
reproduction runs are complete.

## Scope

```text
paper-experiments/
  tables/
    CSV templates for the paper's main and appendix tables.

  metrics/
    Metric definitions and counting rules.

  raw/
    Placeholders for raw exported summaries copied from reproducible runs.

  scripts/
    Future aggregation/checking scripts.
```

## Research Questions

The table templates follow the current experiment design:

| RQ | Purpose | Main Tables |
|---|---|---|
| RQ1 | Known-CVE effectiveness and path recovery | Table 1, Table 2, Table 3 |
| RQ2 | Component ablation | Table 4 |
| RQ3 | LLM backend robustness | Table 5 |
| RQ4 | Real-world project evaluation | Table 6 |

## Data Policy

- Use `TBD` or empty cells until the corresponding run has been reproduced.
- Keep example values out of final CSVs.
- Store generated scan reports under `LAPIS-Experiments/reports/`; this
  directory should contain only table-ready summaries, indices, and metric
  definitions.
- If a number is derived from a script, record the source report path and
  command in the relevant appendix CSV or raw index.

## Current Benchmark Cases

The current small validation set is not the final paper-scale dataset:

| Gap Type | Case |
|---|---|
| Connectivity Gap | CVE-2023-24816 / IPython |
| Connectivity Gap | CVE-2024-27758 / RPyC |
| Propagation Gap | CVE-2024-36039 / PyMySQL |
| Mixed Gap | CVE-2026-24486 / python-multipart |
| Mixed Gap | CVE-2025-55156 / pyLoad |
| Control | CVE-2023-4033 / MLflow |

These cases can be used to validate the aggregation format, but their current
counts should not be extrapolated to the final paper dataset.
