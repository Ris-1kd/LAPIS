You are synthesizing a Conditional Taint Propagation Contract (CTPC).

Use only the Evidence Pack below. Do not invent source functions, sink functions,
variables, files, or edges that are not supported by the evidence.

Goal:
- Explain the missing access-path propagation.
- Synthesize a CTPC that propagates only under the structural guards supported
  by the evidence.
- Do not generate validation programs in this step. Validation sample generation
  is handled by a separate module.
- Use only CTPC pattern kinds implemented by the analyzer:
  - propagation_edges[].pattern.kind: dict_literal_key, dict_comprehension_key_preserved, percent_mapping_key,
    direct_assignment, constructor_keyword_capture, path_join_keep_filename,
    filesystem_path_assignment, filesystem_sink_argument, sink_argument
  - function_summaries[].pattern.kind: return_fact_from_argument
  - kill_conditions[].pattern.kind: membership_rejection_guard, missing_mapping_key_fact
- Do not invent generic pattern kinds such as dict_literal, percent_mapping,
  return_variable, call_assignment, db_execute, arbitrary_callback, or object_graph_magic.
- Model ordinary variable assignment/return/sink reachability with the existing
  analyzer, not with CTPC propagation edges. CTPC should only repair missing
  access-path/dataflow semantics supported by the evidence.
- For mixed callback cases where post-CCEC still cannot materialize the callback
  body, a sink propagation edge may set pattern.callee to the observed callback
  boundary and pattern.virtual_final_sink to the local final sink supported by
  static evidence, but only when the Evidence Pack exposes that boundary and
  local final sink.

Return one JSON object with this exact top-level shape. Conditions must be
machine-readable: use event + pattern + effect fields. Keep natural-language
explanations only in description/evidence fields.

{
  "schema_version": "ctpc.v2",
  "contract_name": "string",
  "gap_type": ["string"],
  "applies_to": {
    "language": "python",
    "risk_kind": "string"
  },
  "fact_types": [
    {
      "name": "string",
      "shape": {"access_path": "string"}
    }
  ],
  "propagation_edges": [
    {
      "edge_id": "string",
      "event": "assignment | binary_operation | function_call | return | member_access | if_condition | sink",
      "pattern": {"kind": "string", "callee": "string | optional", "argument_index": 0, "virtual_final_sink": "string | optional"},
      "from": {"fact": "string", "expr": "string"},
      "to": {"fact": "string", "expr": "string", "access_path": "string", "risk_kind": "string"},
      "evidence": {"file": "string", "line": 0, "code": "string"},
      "description": "string"
    }
  ],
  "function_summaries": [
    {
      "summary_id": "string",
      "event": "function_call | return",
      "pattern": {
        "kind": "return_fact_from_argument",
        "callee": "string",
        "argument_index": 0,
        "receiver_policy": "any | exact"
      },
      "from": {"fact": "string", "expr": "$arg0.access_path"},
      "to": {"fact": "string", "expr": "$return", "access_path": "$return.access_path", "risk_kind": "string"},
      "evidence": {"file": "string", "line": 0, "code": "string"}
    }
  ],
  "risk_upgrades": [
    {
      "upgrade_id": "string",
      "event": "assignment | binary_operation | function_call | return | member_access | sink",
      "pattern": {"kind": "string"},
      "from": {"fact": "string", "expr": "string"},
      "to": {"fact": "string", "expr": "string"},
      "risk_kind": "string"
    }
  ],
  "kill_conditions": [
    {
      "kill_id": "string",
      "event": "if_condition | assignment | function_call | sink",
      "pattern": {"kind": "string"},
      "effect": {"action": "suppress", "risk_kind": "string", "for_fact": "string"},
      "evidence": {"file": "string", "line": 0, "code": "string"}
    }
  ],
  "validation_expectations": {
    "must_flow": "finding",
    "must_not_flow": "no_finding",
    "must_kill": "no_finding"
  },
  "description": "string",
  "notes": ["string"]
}

Evidence Pack:

```json
{
  "case_id": "cve-2024-36039-pymysql",
  "project": "PyMySQL",
  "vulnerability": "SQL injection",
  "baseline_status": {
    "source_hit": true,
    "sink_hit": true,
    "call_context_reachable": true,
    "complete_taint_path_found": false,
    "sources_marked": 1,
    "sinks_matched": 2,
    "findings": 0,
    "entrypoints": 1
  },
  "source": {
    "file": "poc/poc_cve_2024_36039_pymysql.py",
    "line": 30,
    "function": "cve_2024_36039_driver",
    "symbol": "key",
    "expr": "key = cve_2024_36039_source()",
    "path": "dataset/poc/poc_cve_2024_36039_pymysql.py",
    "observed": "key = cve_2024_36039_source()",
    "matches_anchor": true
  },
  "sink": {
    "file": "pymysql/cursors.py",
    "line": 153,
    "function": "execute",
    "callee": "self._query",
    "argument": "query",
    "expr": "result = self._query(query)",
    "path": "dataset/pymysql/cursors.py",
    "observed": "result = self._query(query)",
    "matches_anchor": true
  },
  "source_forward_slice": {
    "source": "key",
    "reached": [
      "key"
    ],
    "frontier": "key",
    "observations": [
      {
        "kind": "dict_literal",
        "file": "dataset/poc/poc_cve_2024_36039_pymysql.py",
        "line": 31,
        "lhs": "args",
        "keys": [
          "key"
        ],
        "expr": "args = {key: \"safe-value\"}"
      },
      {
        "kind": "call",
        "file": "dataset/poc/poc_cve_2024_36039_pymysql.py",
        "line": 33,
        "callee": "FakeCursor(...).execute",
        "args": [
          "query",
          "args"
        ],
        "expr": "return FakeCursor().execute(query, args)"
      }
    ]
  },
  "sink_backward_slice": {
    "sink": "result = self._query(query)",
    "argument": "query",
    "dependency_chain": [
      "result = self._query(query)",
      "query"
    ],
    "observations": [
      {
        "kind": "assignment",
        "function": "execute",
        "file": "dataset/pymysql/cursors.py",
        "line": 151,
        "targets": [
          "query"
        ],
        "expr": "query = self.mogrify(query, args)"
      },
      {
        "kind": "assignment",
        "function": "execute",
        "file": "dataset/pymysql/cursors.py",
        "line": 153,
        "targets": [
          "result"
        ],
        "expr": "result = self._query(query)"
      },
      {
        "kind": "assignment",
        "function": "execute",
        "file": "dataset/pymysql/cursors.py",
        "line": 154,
        "targets": [
          "self._executed"
        ],
        "expr": "self._executed = query"
      }
    ]
  },
  "local_structure_evidence": {
    "dict_literals": [
      {
        "kind": "dict_literal",
        "file": "dataset/poc/poc_cve_2024_36039_pymysql.py",
        "line": 31,
        "lhs": "args",
        "keys": [
          "key"
        ],
        "expr": "args = {key: \"safe-value\"}"
      }
    ],
    "calls": [
      {
        "kind": "call",
        "file": "dataset/poc/poc_cve_2024_36039_pymysql.py",
        "line": 33,
        "callee": "FakeCursor(...).execute",
        "args": [
          "query",
          "args"
        ],
        "expr": "return FakeCursor().execute(query, args)"
      }
    ],
    "assignments": [
      {
        "kind": "assignment",
        "function": "execute",
        "file": "dataset/pymysql/cursors.py",
        "line": 151,
        "targets": [
          "query"
        ],
        "expr": "query = self.mogrify(query, args)"
      },
      {
        "kind": "assignment",
        "function": "execute",
        "file": "dataset/pymysql/cursors.py",
        "line": 153,
        "targets": [
          "result"
        ],
        "expr": "result = self._query(query)"
      },
      {
        "kind": "assignment",
        "function": "execute",
        "file": "dataset/pymysql/cursors.py",
        "line": 154,
        "targets": [
          "self._executed"
        ],
        "expr": "self._executed = query"
      }
    ],
    "dict_comprehensions": [],
    "format_operations": [],
    "scoped_function_evidence": {
      "functions": [
        {
          "name": "cve_2024_36039_driver",
          "file": "poc/poc_cve_2024_36039_pymysql.py",
          "line": 29,
          "args": []
        },
        {
          "name": "escape_dict",
          "file": "pymysql/converters.py",
          "line": 29,
          "args": [
            "val",
            "charset",
            "mapping"
          ]
        },
        {
          "name": "_escape_args",
          "file": "pymysql/cursors.py",
          "line": 100,
          "args": [
            "self",
            "args",
            "conn"
          ]
        },
        {
          "name": "mogrify",
          "file": "pymysql/cursors.py",
          "line": 110,
          "args": [
            "self",
            "query",
            "guan"
          ]
        },
        {
          "name": "execute",
          "file": "pymysql/cursors.py",
          "line": 133,
          "args": [
            "self",
            "query",
            "args"
          ]
        }
      ],
      "assignments": [
        {
          "function": "cve_2024_36039_driver",
          "file": "poc/poc_cve_2024_36039_pymysql.py",
          "line": 30,
          "targets": [
            "key"
          ],
          "expr": "key = cve_2024_36039_source()"
        },
        {
          "function": "cve_2024_36039_driver",
          "file": "poc/poc_cve_2024_36039_pymysql.py",
          "line": 31,
          "targets": [
            "args"
          ],
          "expr": "args = {key: \"safe-value\"}"
        },
        {
          "function": "cve_2024_36039_driver",
          "file": "poc/poc_cve_2024_36039_pymysql.py",
          "line": 32,
          "targets": [
            "query"
          ],
          "expr": "query = \"SELECT * FROM users WHERE name=%(name)s\""
        },
        {
          "function": "escape_dict",
          "file": "pymysql/converters.py",
          "line": 30,
          "targets": [
            "n"
          ],
          "expr": "n = {}"
        },
        {
          "function": "escape_dict",
          "file": "pymysql/converters.py",
          "line": 32,
          "targets": [
            "quoted"
          ],
          "expr": "quoted = escape_item(v, charset, mapping)"
        },
        {
          "function": "escape_dict",
          "file": "pymysql/converters.py",
          "line": 33,
          "targets": [
            "n[k]"
          ],
          "expr": "n[k] = quoted"
        },
        {
          "function": "mogrify",
          "file": "pymysql/cursors.py",
          "line": 126,
          "targets": [
            "conn"
          ],
          "expr": "conn = self._get_db()"
        },
        {
          "function": "mogrify",
          "file": "pymysql/cursors.py",
          "line": 129,
          "targets": [
            "query"
          ],
          "expr": "query = query % self._escape_args(args, conn)"
        },
        {
          "function": "execute",
          "file": "pymysql/cursors.py",
          "line": 151,
          "targets": [
            "query"
          ],
          "expr": "query = self.mogrify(query, args)"
        },
        {
          "function": "execute",
          "file": "pymysql/cursors.py",
          "line": 153,
          "targets": [
            "result"
          ],
          "expr": "result = self._query(query)"
        },
        {
          "function": "execute",
          "file": "pymysql/cursors.py",
          "line": 154,
          "targets": [
            "self._executed"
          ],
          "expr": "self._executed = query"
        }
      ],
      "returns": [
        {
          "function": "cve_2024_36039_driver",
          "file": "poc/poc_cve_2024_36039_pymysql.py",
          "line": 33,
          "expr": "return FakeCursor().execute(query, args)"
        },
        {
          "function": "escape_dict",
          "file": "pymysql/converters.py",
          "line": 34,
          "expr": "return n"
        },
        {
          "function": "_escape_args",
          "file": "pymysql/cursors.py",
          "line": 102,
          "expr": "return tuple(conn.literal(arg) for arg in args)"
        },
        {
          "function": "_escape_args",
          "file": "pymysql/cursors.py",
          "line": 104,
          "expr": "return {key: conn.literal(val) for (key, val) in args.items()}"
        },
        {
          "function": "_escape_args",
          "file": "pymysql/cursors.py",
          "line": 108,
          "expr": "return conn.escape(args)"
        },
        {
          "function": "mogrify",
          "file": "pymysql/cursors.py",
          "line": 131,
          "expr": "return query"
        },
        {
          "function": "execute",
          "file": "pymysql/cursors.py",
          "line": 155,
          "expr": "return result"
        }
      ],
      "calls": [
        {
          "function": "cve_2024_36039_driver",
          "function_line": 29,
          "file": "poc/poc_cve_2024_36039_pymysql.py",
          "line": 30,
          "callee": "cve_2024_36039_source",
          "args": [],
          "expr": "cve_2024_36039_source()"
        },
        {
          "function": "cve_2024_36039_driver",
          "function_line": 29,
          "file": "poc/poc_cve_2024_36039_pymysql.py",
          "line": 33,
          "callee": "FakeCursor",
          "args": [],
          "expr": "FakeCursor()"
        },
        {
          "function": "cve_2024_36039_driver",
          "function_line": 29,
          "file": "poc/poc_cve_2024_36039_pymysql.py",
          "line": 33,
          "callee": "FakeCursor(...).execute",
          "args": [
            "query",
            "args"
          ],
          "expr": "FakeCursor().execute(query, args)"
        },
        {
          "function": "escape_dict",
          "function_line": 29,
          "file": "pymysql/converters.py",
          "line": 31,
          "callee": "val.items",
          "args": [],
          "expr": "val.items()"
        },
        {
          "function": "escape_dict",
          "function_line": 29,
          "file": "pymysql/converters.py",
          "line": 32,
          "callee": "escape_item",
          "args": [
            "v",
            "charset",
            "mapping"
          ],
          "expr": "escape_item(v, charset, mapping)"
        },
        {
          "function": "_escape_args",
          "function_line": 100,
          "file": "pymysql/cursors.py",
          "line": 101,
          "callee": "isinstance",
          "args": [
            "args",
            "(tuple, list)"
          ],
          "expr": "isinstance(args, (tuple, list))"
        },
        {
          "function": "_escape_args",
          "function_line": 100,
          "file": "pymysql/cursors.py",
          "line": 102,
          "callee": "conn.literal",
          "args": [
            "arg"
          ],
          "expr": "conn.literal(arg)"
        },
        {
          "function": "_escape_args",
          "function_line": 100,
          "file": "pymysql/cursors.py",
          "line": 102,
          "callee": "tuple",
          "args": [
            "(conn.literal(arg) for arg in args)"
          ],
          "expr": "tuple(conn.literal(arg) for arg in args)"
        },
        {
          "function": "_escape_args",
          "function_line": 100,
          "file": "pymysql/cursors.py",
          "line": 103,
          "callee": "isinstance",
          "args": [
            "args",
            "dict"
          ],
          "expr": "isinstance(args, dict)"
        },
        {
          "function": "_escape_args",
          "function_line": 100,
          "file": "pymysql/cursors.py",
          "line": 104,
          "callee": "args.items",
          "args": [],
          "expr": "args.items()"
        },
        {
          "function": "_escape_args",
          "function_line": 100,
          "file": "pymysql/cursors.py",
          "line": 104,
          "callee": "conn.literal",
          "args": [
            "val"
          ],
          "expr": "conn.literal(val)"
        },
        {
          "function": "_escape_args",
          "function_line": 100,
          "file": "pymysql/cursors.py",
          "line": 108,
          "callee": "conn.escape",
          "args": [
            "args"
          ],
          "expr": "conn.escape(args)"
        },
        {
          "function": "mogrify",
          "function_line": 110,
          "file": "pymysql/cursors.py",
          "line": 126,
          "callee": "self._get_db",
          "args": [],
          "expr": "self._get_db()"
        },
        {
          "function": "mogrify",
          "function_line": 110,
          "file": "pymysql/cursors.py",
          "line": 129,
          "callee": "self._escape_args",
          "args": [
            "args",
            "conn"
          ],
          "expr": "self._escape_args(args, conn)"
        },
        {
          "function": "execute",
          "function_line": 133,
          "file": "pymysql/cursors.py",
          "line": 148,
          "callee": "self.nextset",
          "args": [],
          "expr": "self.nextset()"
        },
        {
          "function": "execute",
          "function_line": 133,
          "file": "pymysql/cursors.py",
          "line": 151,
          "callee": "self.mogrify",
          "args": [
            "query",
            "args"
          ],
          "expr": "self.mogrify(query, args)"
        },
        {
          "function": "execute",
          "function_line": 133,
          "file": "pymysql/cursors.py",
          "line": 153,
          "callee": "self._query",
          "args": [
            "query"
          ],
          "expr": "self._query(query)"
        }
      ],
      "dict_comprehensions": [
        {
          "function": "_escape_args",
          "file": "pymysql/cursors.py",
          "line": 104,
          "expr": "return {key: conn.literal(val) for (key, val) in args.items()}",
          "targets": [
            "$return"
          ],
          "generators": [
            "args.items()"
          ]
        }
      ],
      "percent_operations": [
        {
          "function": "mogrify",
          "file": "pymysql/cursors.py",
          "line": 129,
          "targets": [
            "query"
          ],
          "expr": "query = query % self._escape_args(args, conn)"
        }
      ]
    },
    "connectivity_candidates": []
  },
  "local_convergence": {
    "object": null,
    "access_path": "$return.keys()[*]",
    "source_frontier": "key",
    "sink_dependency_node": null,
    "is_converged": true
  },
  "top_k_edges": [
    {
      "from": "key",
      "to": "args.keys()[*]",
      "kind": "dict_literal_key",
      "score": 0.92,
      "evidence": "args = {key: \"safe-value\"}",
      "location": "dataset/poc/poc_cve_2024_36039_pymysql.py:31"
    },
    {
      "from": "format_mapping.keys()[*]",
      "to": "query",
      "kind": "percent_mapping_key",
      "score": 0.88,
      "evidence": "query = query % self._escape_args(args, conn)",
      "location": "pymysql/cursors.py:129",
      "function": "mogrify"
    },
    {
      "from": "input_mapping.keys()[*]",
      "to": "returned_mapping.keys()[*]",
      "kind": "dict_comprehension_key_preserved",
      "score": 0.86,
      "evidence": "return {key: conn.literal(val) for (key, val) in args.items()}",
      "location": "pymysql/cursors.py:104",
      "function": "_escape_args"
    },
    {
      "from": "arg0.keys()[*]",
      "to": "$return.keys()[*]",
      "kind": "return_fact_from_argument",
      "score": 0.84,
      "evidence": "return {key: conn.literal(val) for (key, val) in args.items()}",
      "location": "pymysql/cursors.py:104",
      "function": "_escape_args"
    }
  ]
}
```
