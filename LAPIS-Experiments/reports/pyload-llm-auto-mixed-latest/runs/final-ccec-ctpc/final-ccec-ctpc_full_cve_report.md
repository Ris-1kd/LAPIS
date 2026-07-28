# LAPIS Full-CVE YASA Report

- Label: `final-ccec-ctpc`
- Case: `cve-2025-55156-pyload`
- Status: `reported`
- Result: `finding`
- Return code: `0`
- Tool: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool`
- Source path: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/benchmarks/mixed_case/cve-2025-55156-pyload`
- Rule: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/mixed_case/cve-2025-55156-pyload/rules/final-sink-only.json`
- CTPC: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/pyload-llm-auto-mixed-latest/ctpc/ctpc/ctpc.json`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/pyload-llm-auto-mixed-latest/runs/final-ccec-ctpc/final-ccec-ctpc`

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
- CTPC rules: `2`
- CTPC forced findings: `2`

## Interpretation

This is a full original-CVE run. A finding here is evidence that the enhanced analyzer connected the case entrypoint, interprocedural execution context, CTPC access-path facts, and final sink rule on the original dataset.

## Findings

```text
Finding 1
  sinkRule: self.c.execute
  sinkAttribute: CVE-2025-55156-pyload-sql-injection
  primary: /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/benchmarks/mixed_case/cve-2025-55156-pyload/src/pyload/core/database/file_database.py:271:9
  Step 0: file:///poc/poc_cve_2025_55156_pyload.py:17:1
    node: LAPIS CTPC e1: The source URL is stored as the fourth tuple element inside the list assigned to `data`.
    snippet:
      poc/poc_cve_2025_55156_pyload.py
        AffectedNodeName: LAPIS CTPC e1: The source URL is stored as the fourth tuple element inside the list assigned to `data`.
        17:  Var Pass:      data = [("name", 1, 2, url)]
  Step 1: file:///poc/poc_cve_2025_55156_pyload.py:18:1
    node: LAPIS CTPC e2: The boundary call passes `data` into `update_link_info`, where the nested slot-3 values are joined into `statuses` and then embedded into the SQL execute call.
    snippet:
      poc/poc_cve_2025_55156_pyload.py
        AffectedNodeName: LAPIS CTPC e2: The boundary call passes `data` into `update_link_info`, where the nested slot-3 values are joined into `statuses` and then embedded into the SQL execute call.
        18:  ARG PASS:      db.update_link_info(data)
  Step 2: file:///src/pyload/core/database/file_database.py:271:9
    node: self.c.execute
    snippet:
       /src/pyload/core/database/file_database.py
        AffectedNodeName: self.c.execute
        271: SINK:          self.c.execute(f"SELECT id FROM links WHERE url IN ('{statuses}')")
```

## Ordered Source-To-Sink Chain

```text
Step 0: SOURCE poc/poc_cve_2025_55156_pyload.py:16  url = cve_2025_55156_source() [case.source]
Step 1: CTPC direct_assignment poc/poc_cve_2025_55156_pyload.py:17  data = [("name", 1, 2, url)] [e1]
Step 2: CCEC CALL EDGE poc/poc_cve_2025_55156_pyload.py:18  return db.update_link_info(data) [edge-1-db.update_link_info]
Step 3: CCEC CALL EDGE src/pyload/core/database/file_database.py:64  order = self._next_file_order(package) [edge-2-add_link._next_file_order]
Step 4: CCEC CALL EDGE src/pyload/core/database/file_database.py:76  order = self._next_file_order(package) [edge-3-add_links._next_file_order]
Step 5: CCEC CALL EDGE src/pyload/core/database/file_database.py:86  order = self._next_package_order(queue) [edge-4-add_package._next_package_order]
Step 6: CCEC CALL EDGE src/pyload/core/database/file_database.py:279  position = self._next_package_order(p.queue) [edge-5-reorder_package._next_package_order]
Step 7: ARG PASS src/pyload/core/database/file_database.py:45  def _next_package_order(self, queue=0): [edge-4-add_package._next_package_order]
Step 8: ARG PASS src/pyload/core/database/file_database.py:54  def _next_file_order(self, package): [edge-2-add_link._next_file_order]
Step 9: ARG PASS src/pyload/core/database/file_database.py:261  def update_link_info(self, data): [edge-1-db.update_link_info]
Step 10: SINK src/pyload/core/database/file_database.py:271  self.c.execute(f"SELECT id FROM links WHERE url IN ('{statuses}')") [case.sink]
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
CCEC edge 2: edge-2-add_link._next_file_order
  from: src/pyload/core/database/file_database.py:add_link
  at: src/pyload/core/database/file_database.py:64 self._next_file_order(package)
  to: src.pyload.core.database.file_database._next_file_order#line_54
  calleeKind: real_function
  evidence: src/pyload/core/database/file_database.py:64  self._next_file_order(package)  [ast_callsite]
  evidence: src/pyload/core/database/file_database.py:54  _next_file_order(self, package)  [function_signature]
  effect: add_call_edge src/pyload/core/database/file_database.py:add_link -> src.pyload.core.database.file_database._next_file_order#line_54 at self._next_file_order(package)
CCEC edge 3: edge-3-add_links._next_file_order
  from: src/pyload/core/database/file_database.py:add_links
  at: src/pyload/core/database/file_database.py:76 self._next_file_order(package)
  to: src.pyload.core.database.file_database._next_file_order#line_54
  calleeKind: real_function
  evidence: src/pyload/core/database/file_database.py:76  self._next_file_order(package)  [ast_callsite]
  effect: add_call_edge src/pyload/core/database/file_database.py:add_links -> src.pyload.core.database.file_database._next_file_order#line_54 at self._next_file_order(package)
CCEC edge 4: edge-4-add_package._next_package_order
  from: src/pyload/core/database/file_database.py:add_package
  at: src/pyload/core/database/file_database.py:86 self._next_package_order(queue)
  to: src.pyload.core.database.file_database._next_package_order#line_45
  calleeKind: real_function
  evidence: src/pyload/core/database/file_database.py:86  self._next_package_order(queue)  [ast_callsite]
  evidence: src/pyload/core/database/file_database.py:45  _next_package_order(self, queue)  [function_signature]
  effect: add_call_edge src/pyload/core/database/file_database.py:add_package -> src.pyload.core.database.file_database._next_package_order#line_45 at self._next_package_order(queue)
CCEC edge 5: edge-5-reorder_package._next_package_order
  from: src/pyload/core/database/file_database.py:reorder_package
  at: src/pyload/core/database/file_database.py:279 self._next_package_order(p.queue)
  to: src.pyload.core.database.file_database._next_package_order#line_45
  calleeKind: real_function
  evidence: src/pyload/core/database/file_database.py:279  self._next_package_order(p.queue)  [ast_callsite]
  effect: add_call_edge src/pyload/core/database/file_database.py:reorder_package -> src.pyload.core.database.file_database._next_package_order#line_45 at self._next_package_order(p.queue)
sink: src/pyload/core/database/file_database.py:271  self.c.execute(f"SELECT id FROM links WHERE url IN ('{statuses}')")
```
