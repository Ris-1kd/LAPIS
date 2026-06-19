# LAPIS Repair Workflow Report

- Cases root: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases`
- Case count: 6

| Case | Project | Category | Gate | Diagnosis | Next step |
|---|---|---|---|---|---|
| cve-2023-24816-ipython | IPython | 缺失调用边 | candidate_fn | connectivity_gap | run_ccec |
| cve-2024-27758-rpyc | RPyC | 缺失调用边 | candidate_fn | connectivity_gap | run_ccec |
| cve-2024-36039-pymysql | PyMySQL | 缺失数据流 | candidate_fn | propagation_gap | run_ctpc |
| cve-2025-55156-pyload | pyLoad | 调用边和数据流都缺失 | candidate_fn | mixed_case | run_ccec_first |
| cve-2026-24486-python-multipart | python-multipart | 调用边和数据流都缺失 | candidate_fn | mixed_case | run_ccec_first |
| cve-2023-4033-mlflow | MLflow | 对照组 | already_reported | not_repair_candidate | stop |
