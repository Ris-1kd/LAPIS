# Paper Table Templates

The CSV files in this directory are templates for paper-facing tables. Their
current values are intentionally blank or `TBD`.

Do not copy sample values from `docs/experiment/LAPIS_Experiment_Design.md`.
Populate these tables only from reproducible experiment runs and record source
report paths in appendix tables when possible.

## Main Tables

| File | Paper Table |
|---|---|
| `main-tables.md` | Markdown rendering of the five main paper tables |
| `table1_dataset_statistics.csv` | Dataset statistics |
| `table2_overall_detection_results.csv` | Overall detection results |
| `table3_ablation_study.csv` | Component ablation |
| `table4_llm_backend_comparison.csv` | LLM backend robustness |
| `table5_real_world_evaluation.csv` | Real-world evaluation |

## Appendix Tables

| File | Purpose |
|---|---|
| `appendix_cve_detail_results.csv` | Per-CVE detailed results |
| `appendix_contract_accuracy.csv` | Per-contract validation and consumption results |
| `appendix_gap_type_recovery.csv` | Gap-type recovery details, if needed |
| `appendix_llm_outputs_index.csv` | LLM output, prompt, and raw response index |
