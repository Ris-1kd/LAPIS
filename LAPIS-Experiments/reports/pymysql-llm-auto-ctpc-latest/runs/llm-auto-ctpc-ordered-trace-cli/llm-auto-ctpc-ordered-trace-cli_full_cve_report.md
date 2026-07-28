# LAPIS Full-CVE YASA Report

- Label: `llm-auto-ctpc-ordered-trace-cli`
- Case: `cve-2024-36039-pymysql`
- Status: `reported`
- Result: `finding`
- Return code: `0`
- Tool: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool`
- Source path: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/dataset`
- Rule: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/rules/final-sink-only.json`
- CTPC: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc-latest/ctpc/ctpc/ctpc.json`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc-latest/runs/llm-auto-ctpc-ordered-trace-cli/llm-auto-ctpc-ordered-trace-cli`

## Summary

- Findings: `1`
- Sources marked: `1`
- Sinks matched: `2`
- Entry points: `1`
- Files analyzed: `20`
- Lines analyzed: `4367`

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
  sinkRule: self._query
  sinkAttribute: CVE-2024-36039-pymysql-query-send
  primary: /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/dataset/pymysql/cursors.py:153:18
  Step 0: file:///poc/poc_cve_2024_36039_pymysql.py:30:1
    node: source rule cve_2024_36039_source: key = cve_2024_36039_source()
    snippet:
      /home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/dataset/poc/poc_cve_2024_36039_pymysql.py
        AffectedNodeName: source rule cve_2024_36039_source: key = cve_2024_36039_source()
        30:  SOURCE:      source rule cve_2024_36039_source: key = cve_2024_36039_source()
  Step 1: file:///dataset/poc/poc_cve_2024_36039_pymysql.py:31:1
    node: LAPIS CTPC e1_dict_literal_key_capture: Propagate taint from a user-controlled variable used as a dict key into the dictionary's keys access-path.
    snippet:
      dataset/poc/poc_cve_2024_36039_pymysql.py
        AffectedNodeName: LAPIS CTPC e1_dict_literal_key_capture: Propagate taint from a user-controlled variable used as a dict key into the dictionary's keys access-path.
        31:  Var Pass:      args = {key: "safe-value"}
  Step 2: file:///dataset/pymysql/cursors.py:104:1
    node: LAPIS CTPC fs1__escape_args_keys_preserved: Preserve dictionary key access-path facts across _escape_args: input mapping keys are preserved in the returned mapping.
    snippet:
      dataset/pymysql/cursors.py
        AffectedNodeName: LAPIS CTPC fs1__escape_args_keys_preserved: Preserve dictionary key access-path facts across _escape_args: input mapping keys are preserved in the returned mapping.
        104:  Return Value:      return {key: conn.literal(val) for (key, val) in args.items()}
  Step 3: file:///dataset/pymysql/cursors.py:129:1
    node: LAPIS CTPC e2_percent_mapping_key_to_query: Propagate taint from mapping keys used in percent-format substitution into the formatted SQL query string.
    snippet:
      dataset/pymysql/cursors.py
        AffectedNodeName: LAPIS CTPC e2_percent_mapping_key_to_query: Propagate taint from mapping keys used in percent-format substitution into the formatted SQL query string.
        129:  Var Pass:      query = query % self._escape_args(args, conn)
  Step 4: file:///pymysql/cursors.py:153:18
    node: self._query
    snippet:
       /pymysql/cursors.py
        AffectedNodeName: self._query
        153: SINK:          result = self._query(query)
```

## Ordered Source-To-Sink Chain

```text
Step 0: SOURCE poc/poc_cve_2024_36039_pymysql.py:30  key = cve_2024_36039_source() [case.source]
Step 1: VAR PASS poc/poc_cve_2024_36039_pymysql.py:31  args = {key: "safe-value"} [source-scan]
Step 2: CALL poc/poc_cve_2024_36039_pymysql.py:33  return FakeCursor().execute(query, args) [source-scan]
Step 3: ARG PASS pymysql/cursors.py:133  def execute(self, query, args=None): [source-scan]
Step 4: CALL pymysql/cursors.py:151  query = self.mogrify(query, args) [source-scan]
Step 5: ARG PASS pymysql/cursors.py:110  def mogrify(self, query, guan=None): [source-scan]
Step 6: ARG PASS pymysql/cursors.py:100  def _escape_args(self, args, conn): [source-scan]
Step 7: CTPC return_fact_from_argument pymysql/cursors.py:104  return {key: conn.literal(val) for (key, val) in args.items()} [fs1__escape_args_keys_preserved]
Step 8: CTPC percent_mapping_key pymysql/cursors.py:129  query = query % self._escape_args(args, conn) [e2_percent_mapping_key_to_query]
Step 9: RETURN pymysql/cursors.py:131  return query [source-scan]
Step 10: SINK pymysql/cursors.py:153  result = self._query(query) [case.sink]
```
