# Table 3 Ablation Study

Values are placeholders until the final benchmark collection is complete. The
main ablation uses only components that can be disabled independently in the
pipeline. Stage ordering and ordered-trace rendering are reported in text or
appendix diagnostics instead of being treated as standalone repair components.

| Configuration | Recall | Precision | F1 | Path Recovery | FP | Notes |
|---|---:|---:|---:|---:|---:|---|
| Full LAPIS | TBD | TBD | TBD | TBD | TBD | None removed |
| w/o Evidence | TBD | TBD | TBD | TBD | TBD | Static evidence removed from LLM generation |
| w/o CCEC | TBD | TBD | TBD | TBD | TBD | Call-edge contract disabled |
| w/o CTPC | TBD | TBD | TBD | TBD | TBD | Propagation contract disabled |
| w/o Validation | TBD | TBD | TBD | TBD | TBD | Three-way validation disabled |

CSV source: `table3_ablation_study.csv`
