# LAPIS Full-CVE YASA Report

- Label: `post-ccec-after-consumption-generalization`
- Case: `cve-2025-55156-pyload`
- Status: `not_reported`
- Result: `no_finding`
- Return code: `0`
- Tool: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool`
- Source path: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/benchmarks/mixed_case/cve-2025-55156-pyload`
- Rule: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/mixed_case/cve-2025-55156-pyload/rules/final-sink-only.json`
- CTPC: `None`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/pyload-llm-auto-mixed-latest/runs/post-ccec-after-consumption-generalization/post-ccec-after-consumption-generalization`

## Summary

- Findings: `0`
- Sources marked: `2`
- Sinks matched: `2`
- Entry points: `1`
- Files analyzed: `570`
- Lines analyzed: `61479`

## Trace Quality

- Trace status: `post_ccec_sink_reached_taint_open`
- CCEC virtual sink: `False`
- CTPC fact trace: `False`
- FACT TRACE GAP: `False`
- Needs CTPC: `True`
- Needs trace review: `True`

## Contract Consumption

- CCEC status: `materialized_call_edge_consumed`
- CCEC candidate edges: `5`
- CCEC materialized matches: `1`
- CCEC checker matches: `0`
- Post-CCEC source+sink reached: `True`
- CTPC status: `not_provided`
- CTPC rules: `0`
- CTPC forced findings: `0`

## Interpretation

This is a full original-CVE run. A finding here is evidence that the enhanced analyzer connected the case entrypoint, interprocedural execution context, CTPC access-path facts, and final sink rule on the original dataset.

## Ordered Source-To-Sink Chain

```text
Step 0: SOURCE poc/poc_cve_2025_55156_pyload.py:16  url = cve_2025_55156_source() [case.source]
Step 1: CCEC CALL EDGE poc/poc_cve_2025_55156_pyload.py:18  return db.update_link_info(data) [edge-1-db.update_link_info]
Step 2: CCEC CALL EDGE src/pyload/core/database/file_database.py:64  order = self._next_file_order(package) [edge-2-add_link._next_file_order]
Step 3: CCEC CALL EDGE src/pyload/core/database/file_database.py:76  order = self._next_file_order(package) [edge-3-add_links._next_file_order]
Step 4: CCEC CALL EDGE src/pyload/core/database/file_database.py:86  order = self._next_package_order(queue) [edge-4-add_package._next_package_order]
Step 5: CCEC CALL EDGE src/pyload/core/database/file_database.py:279  position = self._next_package_order(p.queue) [edge-5-reorder_package._next_package_order]
Step 6: ARG PASS src/pyload/core/database/file_database.py:45  def _next_package_order(self, queue=0): [edge-4-add_package._next_package_order]
Step 7: ARG PASS src/pyload/core/database/file_database.py:54  def _next_file_order(self, package): [edge-2-add_link._next_file_order]
Step 8: ARG PASS src/pyload/core/database/file_database.py:261  def update_link_info(self, data): [edge-1-db.update_link_info]
Step 9: SINK src/pyload/core/database/file_database.py:271  self.c.execute(f"SELECT id FROM links WHERE url IN ('{statuses}')") [case.sink]
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

## Next Debug Target

The local CTPC validation may still pass while the full CVE run does not report. That means the remaining gap is in full-program execution context, cross-function fact propagation, receiver/argument binding, or final sink reachability.
