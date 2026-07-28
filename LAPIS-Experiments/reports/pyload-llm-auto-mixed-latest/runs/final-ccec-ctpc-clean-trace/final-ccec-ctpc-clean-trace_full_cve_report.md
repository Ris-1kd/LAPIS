# LAPIS Full-CVE YASA Report

- Label: `final-ccec-ctpc-clean-trace`
- Case: `cve-2025-55156-pyload`
- Status: `reported`
- Result: `finding`
- Return code: `0`
- Tool: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool`
- Source path: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/benchmarks/mixed_case/cve-2025-55156-pyload`
- Rule: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/mixed_case/cve-2025-55156-pyload/rules/final-sink-only.json`
- CTPC: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/pyload-llm-auto-mixed-latest/ctpc/ctpc/ctpc.json`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/pyload-llm-auto-mixed-latest/runs/final-ccec-ctpc-clean-trace/final-ccec-ctpc-clean-trace`

## Summary

- Findings: `1`
- Sources marked: `2`
- Sinks matched: `2`
- Entry points: `1`
- Files analyzed: `570`
- Lines analyzed: `61479`

## Trace Quality

- Trace status: `ctpc_fact_closed`
- CCEC virtual sink: `False`
- CTPC fact trace: `True`
- FACT TRACE GAP: `False`
- Needs CTPC: `False`
- Needs trace review: `False`

## Contract Consumption

- CCEC status: `materialized_call_edge_consumed`
- CCEC candidate edges: `5`
- CCEC materialized matches: `1`
- CCEC checker matches: `0`
- Post-CCEC source+sink reached: `True`
- CTPC status: `fact_forced_finding`
- CTPC rules: `4`
- CTPC forced findings: `2`

## Interpretation

This is a full original-CVE run. A finding here is evidence that the enhanced analyzer connected the case entrypoint, interprocedural execution context, CTPC access-path facts, and final sink rule on the original dataset.

## Findings

```text
Finding 1
  sinkRule: self.c.execute
  sinkAttribute: CVE-2025-55156-pyload-sql-injection
  primary: /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/benchmarks/mixed_case/cve-2025-55156-pyload/src/pyload/core/database/file_database.py:271:9
  Step 0: file:///src/pyload/core/database/file_database.py:270:1
    node: LAPIS CTPC fs1_join_returns_argument_taint: "','".join(x[3] for x in data)
    snippet:
      src/pyload/core/database/file_database.py
        AffectedNodeName: LAPIS CTPC fs1_join_returns_argument_taint: "','".join(x[3] for x in data)
        270:  Return Value:      "','".join(x[3] for x in data)
  Step 1: file:///poc/poc_cve_2025_55156_pyload.py:17:1
    node: LAPIS CTPC e1_url_to_list_tuple_index3: Propagate taint from url into the list literal element at tuple index 3 within data.
    snippet:
      poc/poc_cve_2025_55156_pyload.py
        AffectedNodeName: LAPIS CTPC e1_url_to_list_tuple_index3: Propagate taint from url into the list literal element at tuple index 3 within data.
        17:  Var Pass:      data = [("name", 1, 2, url)]
  Step 2: file:///src/pyload/core/database/file_database.py:270:1
    node: LAPIS CTPC e2_data_index3_to_statuses_via_gen: Propagate taint from each tuple's element at index 3 in 'data' into the joined string 'statuses'.
    snippet:
      src/pyload/core/database/file_database.py
        AffectedNodeName: LAPIS CTPC e2_data_index3_to_statuses_via_gen: Propagate taint from each tuple's element at index 3 in 'data' into the joined string 'statuses'.
        270:  Var Pass:      statuses = "','".join(x[3] for x in data)
  Step 3: file:///src/pyload/core/database/file_database.py:271:1
    node: LAPIS CTPC e3_statuses_into_execute_fstring: Capture embedding of the tainted 'statuses' into the SQL f-string passed to self.c.execute.
    snippet:
      src/pyload/core/database/file_database.py
        AffectedNodeName: LAPIS CTPC e3_statuses_into_execute_fstring: Capture embedding of the tainted 'statuses' into the SQL f-string passed to self.c.execute.
        271:  ARG PASS:      self.c.execute(f"SELECT id FROM links WHERE url IN ('{statuses}')")
  Step 4: file:///src/pyload/core/database/file_database.py:271:9
    node: self.c.execute
    snippet:
       /src/pyload/core/database/file_database.py
        AffectedNodeName: self.c.execute
        271: SINK:          self.c.execute(f"SELECT id FROM links WHERE url IN ('{statuses}')")
```

## Ordered Source-To-Sink Chain

```text
Step 0: SOURCE poc/poc_cve_2025_55156_pyload.py:16  url = cve_2025_55156_source() [case.source]
Step 1: CTPC direct_assignment poc/poc_cve_2025_55156_pyload.py:17  data = [("name", 1, 2, url)] [e1_url_to_list_tuple_index3]
Step 2: CCEC CALL EDGE poc/poc_cve_2025_55156_pyload.py:18  return db.update_link_info(data) [edge-1-db.update_link_info]
Step 3: ARG PASS src/pyload/core/database/file_database.py:261  def update_link_info(self, data): [edge-1-db.update_link_info]
Step 4: CTPC direct_assignment src/pyload/core/database/file_database.py:270  statuses = "','".join(x[3] for x in data) [e2_data_index3_to_statuses_via_gen]
Step 5: SINK src/pyload/core/database/file_database.py:271  self.c.execute(f"SELECT id FROM links WHERE url IN ('{statuses}')") [case.sink]
```

## Reconstructed CCEC Chain

```text
source: poc/poc_cve_2025_55156_pyload.py:16  url = cve_2025_55156_source()
CCEC edge 1: edge-1-db.update_link_info
  from: poc/poc_cve_2025_55156_pyload.py:cve_2025_55156_driver
  at: poc/poc_cve_2025_55156_pyload.py:18 db.update_link_info(data)
  to: src.pyload.core.database.file_database.update_link_info#line_261
  calleeKind: real_function
  evidence: poc/poc_cve_2025_55156_pyload.py:18  db.update_link_info(data)  [ast_callsite]
  evidence: src/pyload/core/database/file_database.py:261  update_link_info(self, data)  [function_signature]
  effect: add_call_edge poc/poc_cve_2025_55156_pyload.py:cve_2025_55156_driver -> src.pyload.core.database.file_database.update_link_info#line_261 at db.update_link_info(data)
sink: src/pyload/core/database/file_database.py:271  self.c.execute(f"SELECT id FROM links WHERE url IN ('{statuses}')")
```
