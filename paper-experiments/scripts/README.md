# Aggregation Scripts

The active paper-table automation now lives in
`paper-experiments/automation/`. This directory is kept for future helper
scripts that are not part of the main aggregation loop.

Expected responsibilities:

- read `*_full_cve_report.json` files from `LAPIS-Experiments/reports/`;
- extract finding/source/sink counts and contract consumption summaries;
- verify ordered trace availability;
- produce or update CSV files in `paper-experiments/tables/`.

For the current small closed loop, use:

```bash
python3 paper-experiments/automation/aggregate_tables.py
```
