# Main Paper Table Templates

These Markdown tables mirror the five main CSV templates. All values are
intentionally left as `TBD` until the full benchmark collection and reproduction
runs are complete.

## Table 1 Dataset Statistics

| Vulnerability Type | CWE | Projects | CVEs | Connectivity Gap | Propagation Gap | Mixed Gap | Safe / Control | Notes |
|---|---|---|---|---|---|---|---|---|
| SQL Injection | CWE-89 | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| Command Injection | CWE-78 | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| Path Traversal | CWE-22 | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| Deserialization | CWE-502 | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| Other | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| Total | - | TBD | TBD | TBD | TBD | TBD | TBD | TBD |

CSV source: `table1_dataset_statistics.csv`

## Table 2 Overall Detection Results

| Method | Detected CVEs | Recall | Precision | F1 | Path Recovery | False Positives | Notes |
|---|---|---|---|---|---|---|---|
| YASA | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| LAPIS | TBD | TBD | TBD | TBD | TBD | TBD | TBD |

CSV source: `table2_overall_detection_results.csv`

## Table 3 Ablation Study

| Configuration | Removed Component | Recall | Precision | F1 | Path Recovery | False Positives | LLM Calls | Notes |
|---|---|---|---|---|---|---|---|---|
| Full LAPIS | None | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| w/o Evidence | Static Evidence | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| w/o CCEC | Call-edge Contract | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| w/o CTPC | Propagation Contract | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| w/o Validation | Three-way Validation | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| w/o Stage Repair | Staged Repair | TBD | TBD | TBD | TBD | TBD | TBD | TBD |

CSV source: `table3_ablation_study.csv`

## Table 4 LLM Backend Comparison

| Model | Provider | Contract Accuracy | Triple Pass Rate | Path Recovery | Token Cost | Latency Seconds | Notes |
|---|---|---|---|---|---|---|---|
| GPT | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| Gemini | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| DeepSeek | TBD | TBD | TBD | TBD | TBD | TBD | TBD |

CSV source: `table4_llm_backend_comparison.csv`

## Table 5 Real-World Evaluation

| Project | LOC | YASA Findings | LAPIS Findings | New Findings | Confirmed | Valid Risky Flow | Sanitized | False Positives | Unknown | Precision | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| Total | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD |

CSV source: `table5_real_world_evaluation.csv`
