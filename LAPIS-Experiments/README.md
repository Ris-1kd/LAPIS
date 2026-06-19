# LAPIS-Experiments

LAPIS-Experiments stores reproducible assets for evaluating LAPIS-Core.

## Layout

```text
benchmarks/
  Raw analyzer inputs grouped by the three repair classes:
    connectivity_gap/
    propagation_gap/
    mixed_case/
  Each benchmark case contains source/, poc/, rules/, manifest.json, README.md.

cases/
  LAPIS case metadata and generated experiment artifacts grouped by gap type:
    connectivity_gap/
    propagation_gap/
    mixed_case/
    control/

rules/
  YASA and other analyzer rules used by experiments.

runs/
  Baseline and LAPIS-enhanced analyzer outputs.

evidence/
  Generated Evidence Pack files.

reports/
  Human-readable experiment reports and tables.
```

The current CVE case dataset is grouped by the three repair classes:

```text
connectivity_gap:
  CVE-2024-27758 / RPyC
  CVE-2023-24816 / IPython

propagation_gap:
  CVE-2024-36039 / PyMySQL

mixed_case:
  CVE-2026-24486 / python-multipart
  CVE-2025-55156 / pyLoad

control:
  CVE-2023-4033 / MLflow
```

## Benchmarks vs Cases

```text
benchmarks/
  Inputs uploaded by dataset maintainers:
    source/   analyzed project source
    poc/      safe PoC / driver
    rules/    YASA rule config

cases/
  LAPIS experiment metadata and outputs:
    case.json
    evidence/
    ccec/
    ctpc/
    llm/
    validation/
    repaired-runs/
```

When adding a new CVE dataset, upload raw files to `benchmarks/<gap_type>/<case_id>/`
first. Then create or update `cases/<gap_type>/<case_id>/case.json` to point to
that benchmark input.
