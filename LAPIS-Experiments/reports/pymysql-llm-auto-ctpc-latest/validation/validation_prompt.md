You are generating validation samples for a CTPC.

Use only the Evidence Pack and CTPC below. Generate small standalone Python
programs. Do not change the CTPC. Do not invent additional source or sink names
unless they are local stubs inside the validation program.

Goal:
- Generate one must-flow sample where the CTPC should recover a finding.
- Generate one must-not-flow sample where a nearby unsupported access path should
  not produce a finding.
- Generate one must-kill sample where a guard/sanitizer should prevent the risky
  flow.

Return one JSON object with this exact top-level shape:

{
  "must_flow": {
    "name": "string",
    "expected": "finding",
    "code": "string"
  },
  "must_not_flow": {
    "name": "string",
    "expected": "no_finding",
    "code": "string"
  },
  "must_kill": {
    "name": "string",
    "expected": "no_finding",
    "code": "string"
  },
  "notes": ["string"]
}

Evidence Pack and CTPC:

```json
{
  "evidence_pack": {
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
  },
  "ctpc": {
    "schema_version": "ctpc.v2",
    "contract_name": "pymysql_percent_mapping_key_ctpc",
    "gap_type": [
      "missing_access_path_propagation"
    ],
    "applies_to": {
      "language": "python",
      "risk_kind": "sql_injection"
    },
    "fact_types": [
      {
        "name": "mapping_key",
        "shape": {
          "access_path": "$obj.keys()[*]"
        }
      }
    ],
    "propagation_edges": [
      {
        "edge_id": "e1_dict_literal_key_capture",
        "event": "assignment",
        "pattern": {
          "kind": "dict_literal_key",
          "argument_index": 0
        },
        "from": {
          "fact": "mapping_key",
          "expr": "key"
        },
        "to": {
          "fact": "mapping_key",
          "expr": "args",
          "access_path": "args.keys()[*]",
          "risk_kind": "sql_injection"
        },
        "evidence": {
          "file": "dataset/poc/poc_cve_2024_36039_pymysql.py",
          "line": 31,
          "code": "args = {key: \"safe-value\"}"
        },
        "description": "Propagate taint from a user-controlled variable used as a dict key into the dictionary's keys access-path."
      },
      {
        "edge_id": "e2_percent_mapping_key_to_query",
        "event": "binary_operation",
        "pattern": {
          "kind": "percent_mapping_key",
          "argument_index": 1
        },
        "from": {
          "fact": "mapping_key",
          "expr": "format_mapping.keys()[*]"
        },
        "to": {
          "fact": "mapping_key",
          "expr": "query",
          "access_path": "query",
          "risk_kind": "sql_injection"
        },
        "evidence": {
          "file": "dataset/pymysql/cursors.py",
          "line": 129,
          "code": "query = query % self._escape_args(args, conn)"
        },
        "description": "Propagate taint from mapping keys used in percent-format substitution into the formatted SQL query string."
      }
    ],
    "function_summaries": [
      {
        "summary_id": "fs1__escape_args_keys_preserved",
        "event": "return",
        "pattern": {
          "kind": "return_fact_from_argument",
          "callee": "_escape_args",
          "argument_index": 0,
          "receiver_policy": "any"
        },
        "from": {
          "fact": "mapping_key",
          "expr": "$arg0.access_path"
        },
        "to": {
          "fact": "mapping_key",
          "expr": "$return",
          "access_path": "$return.access_path",
          "risk_kind": "sql_injection"
        },
        "evidence": {
          "file": "dataset/pymysql/cursors.py",
          "line": 104,
          "code": "return {key: conn.literal(val) for (key, val) in args.items()}"
        },
        "description": "Preserve dictionary key access-path facts across _escape_args: input mapping keys are preserved in the returned mapping."
      }
    ],
    "risk_upgrades": [],
    "kill_conditions": [],
    "validation_expectations": {
      "must_flow": "finding",
      "must_not_flow": "no_finding",
      "must_kill": "no_finding"
    },
    "description": "The analyzer is missing access-path propagation for mapping keys flowing into percent-format substitution of SQL queries. Evidence shows: (1) a user-controlled variable key is used as a dictionary key (args = {key: \"safe-value\"}); (2) PyMySQL _escape_args returns a mapping via a dict comprehension that preserves the original keys; and (3) mogrify performs query = query % mapping, where mapping keys drive variable interpolation. This CTPC adds: (a) a dict-literal key capture edge to taint args.keys()[*] from key; (b) a function summary to preserve mapping key facts across _escape_args; and (c) a percent-mapping-key edge to taint the formatted SQL query from the mapping keys. With ordinary assignment/call modeling already present, these repairs connect the source to the sink self._query(query) under the exact structural guards observed.",
    "notes": [
      "Top-k structural hints aligned: dict_literal_key (driver:31), return_fact_from_argument/dict comprehension key preservation (_escape_args:104), and percent_mapping_key (mogrify:129).",
      "No generic or unsupported patterns were used; only mapping-key access-path semantics required for this CVE were added."
    ]
  }
}
```
