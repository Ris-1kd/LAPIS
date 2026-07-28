# LAPIS Full-CVE YASA Report

- Label: `llm-auto-materialized-ccec-ordered-trace-v2`
- Case: `cve-2023-24816-ipython`
- Status: `reported`
- Result: `finding`
- Return code: `0`
- Tool: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool`
- Source path: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/benchmarks/connectivity_gap/cve-2023-24816-ipython`
- Rule: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/connectivity_gap/cve-2023-24816-ipython/rules/final-sink-only.json`
- CTPC: `None`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/ipython-ccec/runs/llm-auto-materialized-ccec-ordered-trace-v2/llm-auto-materialized-ccec-ordered-trace-v2`

## Summary

- Findings: `1`
- Sources marked: `1`
- Sinks matched: `4`
- Entry points: `1`
- Files analyzed: `295`
- Lines analyzed: `73363`

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
  sinkRule: os.system
  sinkAttribute: CVE-2023-24816-ipython-command
  primary: /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/benchmarks/connectivity_gap/cve-2023-24816-ipython/source/IPython/utils/terminal.py:112:23
  Step 0: file:///poc/poc_cve_2023_24816_ipython.py:9:13
    node: cve_2023_24816_source()
    snippet:
       /poc/poc_cve_2023_24816_ipython.py
        AffectedNodeName: cve_2023_24816_source()
        9:   SOURCE:      title = cve_2023_24816_source()
  Step 1: file:///poc/poc_cve_2023_24816_ipython.py:9:5
    node: title
    snippet:
       /poc/poc_cve_2023_24816_ipython.py
        AffectedNodeName: title
        9:   Var Pass:      title = cve_2023_24816_source()
  Step 2: file:///poc/poc_cve_2023_24816_ipython.py:11:12
    node: set_term_title
    snippet:
       /poc/poc_cve_2023_24816_ipython.py
        AffectedNodeName: set_term_title
        11:  CALL:      return terminal.set_term_title(title)
  Step 3: file:///source/IPython/utils/terminal.py:120:20
    node: title
    snippet:
       /source/IPython/utils/terminal.py
        AffectedNodeName: title
        120: ARG PASS:  def set_term_title(title):
  Step 4: file:///source/IPython/utils/terminal.py:124:5
    node: _set_term_title
    snippet:
       /source/IPython/utils/terminal.py
        AffectedNodeName: _set_term_title
        124: CALL:      _set_term_title(title)
  Step 5: file:///source/IPython/utils/terminal.py:104:29
    node: title
    snippet:
       /source/IPython/utils/terminal.py
        AffectedNodeName: title
        104: ARG PASS:          def _set_term_title(title):
  Step 6: file:///source/IPython/utils/terminal.py:112:23
    node: os.system
    snippet:
       /source/IPython/utils/terminal.py
        AffectedNodeName: os.system
        112: SINK:                  ret = os.system("title " + title)
```

## Ordered Source-To-Sink Chain

```text
Step 0: SOURCE poc/poc_cve_2023_24816_ipython.py:9  title = cve_2023_24816_source() [case.source]
Step 1: CALL poc/poc_cve_2023_24816_ipython.py:11  return terminal.set_term_title(title) [source-scan]
Step 2: ARG PASS source/IPython/utils/terminal.py:120  def set_term_title(title): [ccec-1]
Step 3: CCEC CALL EDGE source/IPython/utils/terminal.py:124  _set_term_title(title) [ccec-1]
Step 4: ARG PASS source/IPython/utils/terminal.py:104  def _set_term_title(title): [ccec-1]
Step 5: SINK source/IPython/utils/terminal.py:112  ret = os.system("title " + title) [case.sink]
```

## Reconstructed CCEC Chain

```text
source: poc/poc_cve_2023_24816_ipython.py:9  title = cve_2023_24816_source()
CCEC edge 1: ccec-1
  from: IPython.utils.terminal.set_term_title#line_120
  at: IPython/utils/terminal.py:124 _set_term_title(title)
  to: IPython.utils.terminal._set_term_title#line_104
  calleeKind: rebound_function
  evidence: IPython/utils/terminal.py:124  _set_term_title(title)  [ast_callsite]
  evidence: IPython/utils/terminal.py:104  def _set_term_title(title): ...  [function_signature]
  evidence: IPython/utils/terminal.py:56  def _set_term_title(): ...  [function_signature]
  evidence: IPython/utils/terminal.py:120  connectivity_candidates kind: module_rebinding_or_guarded_dispatch with multiple _set_term_title definitions (lines 56, 100, 104)  [baseline_diagnostic]
  effect: add_call_edge IPython.utils.terminal.set_term_title#line_120 -> IPython.utils.terminal._set_term_title#line_104 at IPython/utils/terminal.py:124
sink: source/IPython/utils/terminal.py:112  os.system("title " + title)
```
