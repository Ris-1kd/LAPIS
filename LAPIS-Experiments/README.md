# LAPIS-Experiments

LAPIS-Experiments stores reproducible assets for evaluating LAPIS-Core.

## Layout

```text
cases/
  Per-case configuration, source/sink mapping, and expected gap metadata.

rules/
  YASA and other analyzer rules used by experiments.

runs/
  Baseline and LAPIS-enhanced analyzer outputs.

evidence/
  Generated Evidence Pack files.

reports/
  Human-readable experiment reports and tables.
```

The first planned case is the PyMySQL dict-key access-path propagation example
for CVE-2024-36039.
