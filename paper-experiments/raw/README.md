# Raw Result Index

Use this directory to index raw experiment exports that feed the paper tables.

Recommended convention:

```text
raw/
  rq1-known-cves/
  rq2-ablation/
  rq3-llm-backends/
  rq4-real-world/
```

Do not duplicate large YASA run directories here unless needed. Prefer storing
the canonical run outputs under `LAPIS-Experiments/reports/` and referencing
their paths in appendix CSV files.
