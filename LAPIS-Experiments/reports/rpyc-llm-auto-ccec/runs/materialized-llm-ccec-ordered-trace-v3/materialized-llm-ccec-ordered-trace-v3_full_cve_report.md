# LAPIS Full-CVE YASA Report

- Label: `materialized-llm-ccec-ordered-trace-v3`
- Case: `cve-2024-27758-rpyc-final-sink-only`
- Status: `reported`
- Result: `finding`
- Return code: `0`
- Tool: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool`
- Source path: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/benchmarks/connectivity_gap/cve-2024-27758-rpyc`
- Rule: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/connectivity_gap/cve-2024-27758-rpyc/rules/final-sink-only.json`
- CTPC: `None`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/rpyc-llm-auto-ccec/runs/materialized-llm-ccec-ordered-trace-v3/materialized-llm-ccec-ordered-trace-v3`

## Summary

- Findings: `2`
- Sources marked: `1`
- Sinks matched: `2`
- Entry points: `1`
- Files analyzed: `30`
- Lines analyzed: `6497`

## Trace Quality

- Trace status: `reported_trace`
- CCEC virtual sink: `False`
- CTPC fact trace: `False`
- FACT TRACE GAP: `False`
- Needs CTPC: `False`
- Needs trace review: `False`

## Interpretation

This is a full original-CVE run. A finding here is evidence that the enhanced analyzer connected the case entrypoint, interprocedural execution context, CTPC access-path facts, and final sink rule on the original dataset.

## Findings

```text
Finding 1
  sinkRule: pickle.loads
  sinkAttribute: CVE-2024-27758-rpyc-pickle-deserialization
  primary: /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/benchmarks/connectivity_gap/cve-2024-27758-rpyc/source/rpyc/core/netref.py:255:20
  Step 0: file:///poc/poc_cve_2024_27758_rpyc.py:25:15
    node: cve_2024_27758_source()
    snippet:
       /poc/poc_cve_2024_27758_rpyc.py
        AffectedNodeName: cve_2024_27758_source()
        25:  SOURCE:      payload = cve_2024_27758_source()
  Step 1: file:///poc/poc_cve_2024_27758_rpyc.py:25:5
    node: payload
    snippet:
       /poc/poc_cve_2024_27758_rpyc.py
        AffectedNodeName: payload
        25:  Var Pass:      payload = cve_2024_27758_source()
  Step 2: file:///poc/poc_cve_2024_27758_rpyc.py:27:26
    node: __init__
    snippet:
       /poc/poc_cve_2024_27758_rpyc.py
        AffectedNodeName: __init__
        27:  CALL:      proxy = netref_class(FakeConnection(payload), ("remote.module.EvilArray", 1, 2))
  Step 3: file:///poc/poc_cve_2024_27758_rpyc.py:10:24
    node: payload
    snippet:
       /poc/poc_cve_2024_27758_rpyc.py
        AffectedNodeName: payload
        10:  ARG PASS:      def __init__(self, payload):
  Step 4: file:///poc/poc_cve_2024_27758_rpyc.py:11:9
    node: self.payload
    snippet:
       /poc/poc_cve_2024_27758_rpyc.py
        AffectedNodeName: self.payload
        11:  Var Pass:          self.payload = payload
  Step 5: file:///poc/poc_cve_2024_27758_rpyc.py:27:5
    node: proxy
    snippet:
       /poc/poc_cve_2024_27758_rpyc.py
        AffectedNodeName: proxy
        27:  Var Pass:      proxy = netref_class(FakeConnection(payload), ("remote.module.EvilArray", 1, 2))
  Step 6: file:///poc/poc_cve_2024_27758_rpyc.py:28:12
    node: numpy_like_array_coercion
    snippet:
       /poc/poc_cve_2024_27758_rpyc.py
        AffectedNodeName: numpy_like_array_coercion
        28:  CALL:      return numpy_like_array_coercion(proxy)
  Step 7: file:///poc/poc_cve_2024_27758_rpyc.py:19:31
    node: obj
    snippet:
       /poc/poc_cve_2024_27758_rpyc.py
        AffectedNodeName: obj
        19:  ARG PASS:  def numpy_like_array_coercion(obj):
  Step 8: file:///poc/poc_cve_2024_27758_rpyc.py:20:5
    node: array_callback
    snippet:
       /poc/poc_cve_2024_27758_rpyc.py
        AffectedNodeName: array_callback
        20:  Var Pass:      array_callback = getattr(obj, "__array__")
  Step 9: file:///source/rpyc/core/netref.py:255:20
    node: pickle.loads
    snippet:
       /source/rpyc/core/netref.py
        AffectedNodeName: pickle.loads
        255: SINK:              return pickle.loads(syncreq(self, consts.HANDLE_PICKLE, -1))
```

## Ordered Source-To-Sink Chain

```text
Step 0: SOURCE poc/poc_cve_2024_27758_rpyc.py:25  payload = cve_2024_27758_source() [case.source]
Step 1: CALL poc/poc_cve_2024_27758_rpyc.py:26  netref_class = class_factory(("remote.module.EvilArray", 1, 0), [("__array__", "array protocol")]) [source-scan]
Step 2: CALL poc/poc_cve_2024_27758_rpyc.py:27  proxy = netref_class(FakeConnection(payload), ("remote.module.EvilArray", 1, 2)) [source-scan]
Step 3: ARG PASS poc/poc_cve_2024_27758_rpyc.py:10  def __init__(self, payload): [source-scan]
Step 4: VAR PASS poc/poc_cve_2024_27758_rpyc.py:11  self.payload = payload [source-scan]
Step 5: CALL poc/poc_cve_2024_27758_rpyc.py:28  return numpy_like_array_coercion(proxy) [source-scan]
Step 6: ARG PASS poc/poc_cve_2024_27758_rpyc.py:19  def numpy_like_array_coercion(obj): [source-scan]
Step 7: VAR PASS poc/poc_cve_2024_27758_rpyc.py:20  array_callback = getattr(obj, "__array__") [source-scan]
Step 8: CALL poc/poc_cve_2024_27758_rpyc.py:21  return array_callback() [source-scan]
Step 9: CCEC GUARD source/rpyc/core/netref.py:251  elif name == "__array__": [array-boundary-to-materialized-__array__-line-252]
Step 10: ARG PASS source/rpyc/core/netref.py:252  def __array__(self): [array-boundary-to-materialized-__array__-line-252.target]
Step 11: SINK source/rpyc/core/netref.py:255  return pickle.loads(syncreq(self, consts.HANDLE_PICKLE, -1)) [array-boundary-to-materialized-__array__-line-252]
```

## Reconstructed CCEC Chain

```text
source: poc/poc_cve_2024_27758_rpyc.py:25  payload = cve_2024_27758_source()
CCEC edge 1: array-boundary-to-materialized-__array__-line-252
  from: numpy_like_array_coercion [poc_cve_2024_27758_rpyc.py : 19_21]
  at: array_callback()
  to: rpyc.core.netref._make_method.__array__#line_252
  calleeKind: real_function
  evidence: poc/poc_cve_2024_27758_rpyc.py:20  array_callback = getattr(obj, "__array__")  [baseline_callgraph]
  evidence: poc/poc_cve_2024_27758_rpyc.py:21  array_callback()  [ast_callsite]
  evidence: poc/poc_cve_2024_27758_rpyc.py:26  class_factory(("remote.module.EvilArray", 1, 0), [("__array__", "array protocol")])  [callback_registration]
  evidence: rpyc/core/netref.py:251  name == "__array__"  [ast_control_flow_guard]
  evidence: rpyc/core/netref.py:255  pickle.loads(syncreq(self, consts.HANDLE_PICKLE, -1))  [baseline_diagnostic]
  effect: add_call_edge array_callback() -> rpyc.core.netref._make_method.__array__#line_252 at poc/poc_cve_2024_27758_rpyc.py:21
sink: source/rpyc/core/netref.py:255  pickle.loads(syncreq(...))
```
