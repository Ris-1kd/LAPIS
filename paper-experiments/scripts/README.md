# Aggregation Scripts

This directory is reserved for future scripts that convert reproducible
experiment reports into paper table CSVs.

Expected responsibilities:

- read `*_full_cve_report.json` files from `LAPIS-Experiments/reports/`;
- extract finding/source/sink counts and contract consumption summaries;
- verify ordered trace availability;
- produce or update CSV files in `paper-experiments/tables/`.

No aggregation script is committed yet because the final paper-scale dataset is
still being collected.
