# LAPIS Full-CVE YASA Report

- Label: `final-ccec-ctpc`
- Case: `cve-2026-24486-python-multipart`
- Status: `reported`
- Result: `finding`
- Return code: `0`
- Tool: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool`
- Source path: `/home/ubuntu/llm-yasa-repair/py-bench/cve-2026-24486-python-multipart`
- Rule: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/mixed_case/cve-2026-24486-python-multipart/rules/final-sink-only.json`
- CTPC: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/python-multipart-llm-auto-mixed-latest/ctpc/ctpc/ctpc.json`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/python-multipart-llm-auto-mixed-latest/runs/final-ccec-ctpc/final-ccec-ctpc`

## Summary

- Findings: `1`
- Sources marked: `2`
- Sinks matched: `4`
- Entry points: `1`
- Files analyzed: `12`
- Lines analyzed: `3724`

## Trace Quality

- Trace status: `ctpc_fact_closed`
- CCEC virtual sink: `False`
- CTPC fact trace: `True`
- FACT TRACE GAP: `False`
- Needs CTPC: `False`
- Needs trace review: `False`

## Interpretation

This is a full original-CVE run. A finding here is evidence that the enhanced analyzer connected the case entrypoint, interprocedural execution context, CTPC access-path facts, and final sink rule on the original dataset.

## Findings

```text
Finding 1
  sinkRule: open
  sinkAttribute: LAPIS CTPC virtual sink: open
  primary: /home/ubuntu/llm-yasa-repair/py-bench/cve-2026-24486-python-multipart/python_multipart/multipart.py:1765:16
  Step 0: file:///python_multipart/multipart.py:1765:16
    node: LAPIS CTPC: ctpc access-path propagation reached filesystem_path value self._file_base; final sink open
    snippet:
       /python_multipart/multipart.py
        AffectedNodeName: LAPIS CTPC: ctpc access-path propagation reached filesystem_path value self._file_base; final sink open
        9:   SOURCE:  from enum import IntEnum
  Step 1: file:///python_multipart/multipart.py:1765:16
    node: self.parser.write
    snippet:
       /python_multipart/multipart.py
        AffectedNodeName: self.parser.write
        1765: SINK:          return self.parser.write(data)
```

## Ordered Source-To-Sink Chain

```text
Step 0: SOURCE poc/poc_cve_2026_24486_python_multipart.py:9  filename = cve_2026_24486_source() [case.source]
Step 1: CTPC constructor_keyword_capture poc/poc_cve_2026_24486_python_multipart.py:20  file_name=filename, [kw_capture_formparser_file_name]
Step 2: CCEC REGISTRATION python_multipart/multipart.py:1578  parser = OctetStreamParser( [ccec_formparser_write_to_octetstream_write]
Step 3: CTPC direct_assignment python_multipart/multipart.py:379  self._file_base = base [file_name_to_file_base]
Step 4: CTPC direct_assignment python_multipart/multipart.py:380  self._ext = ext [file_name_to_file_ext]
Step 5: CTPC direct_assignment python_multipart/multipart.py:473  fname = self._file_base + self._ext if keep_extensions else self._file_base [file_base_to_fname]
Step 6: CTPC path_join_keep_filename python_multipart/multipart.py:475  path = os.path.join(file_dir, fname)  # type: ignore[arg-type] [fname_to_path_join_guarded]
Step 7: ARG PASS python_multipart/multipart.py:690  if not self._started: [ccec_formparser_write_to_octetstream_write.target]
Step 8: ARG PASS python_multipart/multipart.py:1556  def on_start() -> None: [ccec_octetstream_write_start_callback.target]
Step 9: ARG PASS python_multipart/multipart.py:1560  def on_data(data: bytes, start: int, end: int) -> None: [ccec_octetstream_write_data_callback.target]
Step 10: CTPC filesystem_sink_argument python_multipart/multipart.py:478  tmp_file = open(path, "w+b") [path_to_open_sink]
Step 11: CTPC filesystem_sink_argument python_multipart/multipart.py:1765  return self.parser.write(data) [virtual_sink_at_parser_write]
Step 12: SINK multipart.py:478  open(path, "w+b") [case.sink]
```

## Reconstructed CCEC Chain

```text
source: poc/poc_cve_2026_24486_python_multipart.py:9  filename = cve_2026_24486_source()
CCEC edge 1: ccec_formparser_write_to_octetstream_write
  from: python_multipart.multipart.FormParser.write
  at: parser.write(b"file-content")
  to: python_multipart.multipart.OctetStreamParser.write
  calleeKind: callback
  evidence: python_multipart/multipart.py:1578  parser = OctetStreamParser(  [callback_registration]
  effect: add_call_edge python_multipart.multipart.FormParser.write -> python_multipart.multipart.OctetStreamParser.write at self.parser.write(data)
CCEC edge 2: ccec_octetstream_write_start_callback
  from: python_multipart.multipart.OctetStreamParser.write
  at: self.callback("start")
  to: python_multipart.multipart.FormParser.__init__.<callback:on_start>
  calleeKind: callback
  effect: add_call_edge python_multipart.multipart.OctetStreamParser.write -> python_multipart.multipart.FormParser.__init__.<callback:on_start> at self.callback("start")
CCEC edge 3: ccec_octetstream_write_data_callback
  from: python_multipart.multipart.OctetStreamParser.write
  at: self.callback("data", data, 0, data_len)
  to: python_multipart.multipart.FormParser.__init__.<callback:on_data>
  calleeKind: callback
  effect: add_call_edge python_multipart.multipart.OctetStreamParser.write -> python_multipart.multipart.FormParser.__init__.<callback:on_data> at self.callback("data", data, 0, data_len)
sink: multipart.py:478  open(path, "w+b")
```
