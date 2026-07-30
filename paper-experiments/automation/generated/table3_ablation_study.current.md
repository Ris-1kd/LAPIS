# Table 3 Current Ablation Study

Draft values combine measured full LAPIS runs with manifest-derived lower bounds where explicit ablation runs are not yet available.

| Configuration | Recall | Precision | F1 | Path Recovery | FP | Notes |
|---|---|---|---|---|---|---|
| Full LAPIS | 1.00 | TBD | TBD | 1.00 | TBD | Current small-sample upper-bound |
| w/o Evidence | not_run | not_run | not_run | not_run | not_run | Requires explicit prompt ablation runs |
| w/o CCEC | 0.20 | TBD | TBD | 0.20 | TBD | Derived lower bound: only cases not requiring CCEC remain recoverable |
| w/o CTPC | 0.40 | TBD | TBD | 0.40 | TBD | Derived lower bound: only CCEC-only cases remain recoverable |
| w/o Validation | not_run | not_run | not_run | not_run | not_run | Requires validation-bypass re-scan and manual/oracle audit |
