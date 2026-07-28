# LAPIS Full-CVE YASA Report

- Label: `post-ccec`
- Case: `cve-2026-24486-python-multipart`
- Status: `not_reported`
- Result: `no_finding`
- Return code: `0`
- Tool: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool`
- Source path: `/home/ubuntu/llm-yasa-repair/py-bench/cve-2026-24486-python-multipart`
- Rule: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/mixed_case/cve-2026-24486-python-multipart/rules/final-sink-only.json`
- CTPC: `None`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/python-multipart-llm-auto-mixed-latest/runs/post-ccec/post-ccec`

## Summary

- Findings: `0`
- Sources marked: `2`
- Sinks matched: `4`
- Entry points: `1`
- Files analyzed: `12`
- Lines analyzed: `3724`

## Trace Quality

- Trace status: `no_finding_trace`
- CCEC virtual sink: `False`
- CTPC fact trace: `False`
- FACT TRACE GAP: `False`
- Needs CTPC: `False`
- Needs trace review: `False`

## Interpretation

This is a full original-CVE run. A finding here is evidence that the enhanced analyzer connected the case entrypoint, interprocedural execution context, CTPC access-path facts, and final sink rule on the original dataset.

## Ordered Source-To-Sink Chain

```text
Step 0: SOURCE poc/poc_cve_2026_24486_python_multipart.py:9  filename = cve_2026_24486_source() [case.source]
Step 1: CCEC REGISTRATION python_multipart/multipart.py:1578  parser = OctetStreamParser( [ccec_formparser_write_to_octetstream_write]
Step 2: ARG PASS python_multipart/multipart.py:690  if not self._started: [ccec_formparser_write_to_octetstream_write.target]
Step 3: ARG PASS python_multipart/multipart.py:1556  def on_start() -> None: [ccec_octetstream_write_start_callback.target]
Step 4: ARG PASS python_multipart/multipart.py:1560  def on_data(data: bytes, start: int, end: int) -> None: [ccec_octetstream_write_data_callback.target]
Step 5: SINK multipart.py:478  open(path, "w+b") [case.sink]
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

## Next Debug Target

The local CTPC validation may still pass while the full CVE run does not report. That means the remaining gap is in full-program execution context, cross-function fact propagation, receiver/argument binding, or final sink reachability.
