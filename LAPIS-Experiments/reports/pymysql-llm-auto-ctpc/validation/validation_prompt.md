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
            "file": "dataset/poc/poc_cve_2024_36039_pymysql.py",
            "line": 29,
            "args": []
          },
          {
            "name": "escape_dict",
            "file": "dataset/pymysql/converters.py",
            "line": 29,
            "args": [
              "val",
              "charset",
              "mapping"
            ]
          },
          {
            "name": "_escape_args",
            "file": "dataset/pymysql/cursors.py",
            "line": 100,
            "args": [
              "self",
              "args",
              "conn"
            ]
          },
          {
            "name": "mogrify",
            "file": "dataset/pymysql/cursors.py",
            "line": 110,
            "args": [
              "self",
              "query",
              "guan"
            ]
          },
          {
            "name": "execute",
            "file": "dataset/pymysql/cursors.py",
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
            "file": "dataset/poc/poc_cve_2024_36039_pymysql.py",
            "line": 30,
            "targets": [
              "key"
            ],
            "expr": "key = cve_2024_36039_source()"
          },
          {
            "function": "cve_2024_36039_driver",
            "file": "dataset/poc/poc_cve_2024_36039_pymysql.py",
            "line": 31,
            "targets": [
              "args"
            ],
            "expr": "args = {key: \"safe-value\"}"
          },
          {
            "function": "cve_2024_36039_driver",
            "file": "dataset/poc/poc_cve_2024_36039_pymysql.py",
            "line": 32,
            "targets": [
              "query"
            ],
            "expr": "query = \"SELECT * FROM users WHERE name=%(name)s\""
          },
          {
            "function": "escape_dict",
            "file": "dataset/pymysql/converters.py",
            "line": 30,
            "targets": [
              "n"
            ],
            "expr": "n = {}"
          },
          {
            "function": "escape_dict",
            "file": "dataset/pymysql/converters.py",
            "line": 32,
            "targets": [
              "quoted"
            ],
            "expr": "quoted = escape_item(v, charset, mapping)"
          },
          {
            "function": "escape_dict",
            "file": "dataset/pymysql/converters.py",
            "line": 33,
            "targets": [
              "n[k]"
            ],
            "expr": "n[k] = quoted"
          },
          {
            "function": "mogrify",
            "file": "dataset/pymysql/cursors.py",
            "line": 126,
            "targets": [
              "conn"
            ],
            "expr": "conn = self._get_db()"
          },
          {
            "function": "mogrify",
            "file": "dataset/pymysql/cursors.py",
            "line": 129,
            "targets": [
              "query"
            ],
            "expr": "query = query % self._escape_args(args, conn)"
          },
          {
            "function": "execute",
            "file": "dataset/pymysql/cursors.py",
            "line": 151,
            "targets": [
              "query"
            ],
            "expr": "query = self.mogrify(query, args)"
          },
          {
            "function": "execute",
            "file": "dataset/pymysql/cursors.py",
            "line": 153,
            "targets": [
              "result"
            ],
            "expr": "result = self._query(query)"
          },
          {
            "function": "execute",
            "file": "dataset/pymysql/cursors.py",
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
            "file": "dataset/poc/poc_cve_2024_36039_pymysql.py",
            "line": 33,
            "expr": "return FakeCursor().execute(query, args)"
          },
          {
            "function": "escape_dict",
            "file": "dataset/pymysql/converters.py",
            "line": 34,
            "expr": "return n"
          },
          {
            "function": "_escape_args",
            "file": "dataset/pymysql/cursors.py",
            "line": 102,
            "expr": "return tuple(conn.literal(arg) for arg in args)"
          },
          {
            "function": "_escape_args",
            "file": "dataset/pymysql/cursors.py",
            "line": 104,
            "expr": "return {key: conn.literal(val) for (key, val) in args.items()}"
          },
          {
            "function": "_escape_args",
            "file": "dataset/pymysql/cursors.py",
            "line": 108,
            "expr": "return conn.escape(args)"
          },
          {
            "function": "mogrify",
            "file": "dataset/pymysql/cursors.py",
            "line": 131,
            "expr": "return query"
          },
          {
            "function": "execute",
            "file": "dataset/pymysql/cursors.py",
            "line": 155,
            "expr": "return result"
          }
        ],
        "calls": [
          {
            "function": "cve_2024_36039_driver",
            "file": "dataset/poc/poc_cve_2024_36039_pymysql.py",
            "line": 30,
            "callee": "cve_2024_36039_source",
            "args": [],
            "expr": "cve_2024_36039_source()"
          },
          {
            "function": "cve_2024_36039_driver",
            "file": "dataset/poc/poc_cve_2024_36039_pymysql.py",
            "line": 33,
            "callee": "FakeCursor",
            "args": [],
            "expr": "FakeCursor()"
          },
          {
            "function": "cve_2024_36039_driver",
            "file": "dataset/poc/poc_cve_2024_36039_pymysql.py",
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
            "file": "dataset/pymysql/converters.py",
            "line": 31,
            "callee": "val.items",
            "args": [],
            "expr": "val.items()"
          },
          {
            "function": "escape_dict",
            "file": "dataset/pymysql/converters.py",
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
            "file": "dataset/pymysql/cursors.py",
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
            "file": "dataset/pymysql/cursors.py",
            "line": 102,
            "callee": "conn.literal",
            "args": [
              "arg"
            ],
            "expr": "conn.literal(arg)"
          },
          {
            "function": "_escape_args",
            "file": "dataset/pymysql/cursors.py",
            "line": 102,
            "callee": "tuple",
            "args": [
              "(conn.literal(arg) for arg in args)"
            ],
            "expr": "tuple(conn.literal(arg) for arg in args)"
          },
          {
            "function": "_escape_args",
            "file": "dataset/pymysql/cursors.py",
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
            "file": "dataset/pymysql/cursors.py",
            "line": 104,
            "callee": "args.items",
            "args": [],
            "expr": "args.items()"
          },
          {
            "function": "_escape_args",
            "file": "dataset/pymysql/cursors.py",
            "line": 104,
            "callee": "conn.literal",
            "args": [
              "val"
            ],
            "expr": "conn.literal(val)"
          },
          {
            "function": "_escape_args",
            "file": "dataset/pymysql/cursors.py",
            "line": 108,
            "callee": "conn.escape",
            "args": [
              "args"
            ],
            "expr": "conn.escape(args)"
          },
          {
            "function": "mogrify",
            "file": "dataset/pymysql/cursors.py",
            "line": 126,
            "callee": "self._get_db",
            "args": [],
            "expr": "self._get_db()"
          },
          {
            "function": "mogrify",
            "file": "dataset/pymysql/cursors.py",
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
            "file": "dataset/pymysql/cursors.py",
            "line": 148,
            "callee": "self.nextset",
            "args": [],
            "expr": "self.nextset()"
          },
          {
            "function": "execute",
            "file": "dataset/pymysql/cursors.py",
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
            "file": "dataset/pymysql/cursors.py",
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
            "file": "dataset/pymysql/cursors.py",
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
            "file": "dataset/pymysql/cursors.py",
            "line": 129,
            "targets": [
              "query"
            ],
            "expr": "query = query % self._escape_args(args, conn)"
          }
        ]
      }
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
        "location": "dataset/pymysql/cursors.py:129",
        "function": "mogrify"
      },
      {
        "from": "input_mapping.keys()[*]",
        "to": "returned_mapping.keys()[*]",
        "kind": "dict_comprehension_key_preserved",
        "score": 0.86,
        "evidence": "return {key: conn.literal(val) for (key, val) in args.items()}",
        "location": "dataset/pymysql/cursors.py:104",
        "function": "_escape_args"
      },
      {
        "from": "arg0.keys()[*]",
        "to": "$return.keys()[*]",
        "kind": "return_fact_from_argument",
        "score": 0.84,
        "evidence": "return {key: conn.literal(val) for (key, val) in args.items()}",
        "location": "dataset/pymysql/cursors.py:104",
        "function": "_escape_args"
      }
    ]
  },
  "ctpc": {
    "schema_version": "ctpc.v2",
    "contract_name": "pymysql_percent_mapping_key_to_query",
    "gap_type": [
      "access_path"
    ],
    "applies_to": {
      "language": "python",
      "risk_kind": "sql_injection"
    },
    "fact_types": [
      {
        "name": "TaintedString",
        "shape": {
          "access_path": "string"
        }
      },
      {
        "name": "MappingKeys",
        "shape": {
          "access_path": "string"
        }
      }
    ],
    "propagation_edges": [
      {
        "edge_id": "e1_dict_key_to_args_keys",
        "event": "assignment",
        "pattern": {
          "kind": "dict_literal"
        },
        "from": {
          "fact": "TaintedString",
          "expr": "key"
        },
        "to": {
          "fact": "MappingKeys",
          "expr": "args",
          "access_path": "keys()[*]",
          "risk_kind": "sql_injection"
        },
        "evidence": {
          "file": "dataset/poc/poc_cve_2024_36039_pymysql.py",
          "line": 31,
          "code": "args = {key: \"safe-value\"}"
        },
        "description": "Taint on the variable used as a dict key flows to the mapping's keys access-path (args.keys()[*])."
      },
      {
        "edge_id": "e3_percent_mapping_keys_to_query",
        "event": "binary_operation",
        "pattern": {
          "kind": "percent_mapping"
        },
        "from": {
          "fact": "MappingKeys",
          "expr": "self._escape_args(args, conn).keys()[*]"
        },
        "to": {
          "fact": "TaintedString",
          "expr": "query",
          "access_path": "$",
          "risk_kind": "sql_injection"
        },
        "evidence": {
          "file": "dataset/pymysql/cursors.py",
          "line": 129,
          "code": "query = query % self._escape_args(args, conn)"
        },
        "description": "During '%'-mapping formatting, the keys of the mapping influence the resulting query string; propagate taint from mapping keys to the formatted query."
      },
      {
        "edge_id": "e4_mogrify_return_query",
        "event": "return",
        "pattern": {
          "kind": "return_variable"
        },
        "from": {
          "fact": "TaintedString",
          "expr": "query"
        },
        "to": {
          "fact": "TaintedString",
          "expr": "$return",
          "access_path": "$",
          "risk_kind": "sql_injection"
        },
        "evidence": {
          "file": "dataset/pymysql/cursors.py",
          "line": 131,
          "code": "return query"
        },
        "description": "Propagate taint from the local 'query' variable in mogrify to its return value."
      },
      {
        "edge_id": "e5_assign_mogrify_return_to_query",
        "event": "assignment",
        "pattern": {
          "kind": "call_assignment"
        },
        "from": {
          "fact": "TaintedString",
          "expr": "self.mogrify(query, args)"
        },
        "to": {
          "fact": "TaintedString",
          "expr": "query",
          "access_path": "$",
          "risk_kind": "sql_injection"
        },
        "evidence": {
          "file": "dataset/pymysql/cursors.py",
          "line": 151,
          "code": "query = self.mogrify(query, args)"
        },
        "description": "Propagate the tainted string returned by mogrify into the caller's 'query' variable."
      },
      {
        "edge_id": "e6_sink_query_to__query",
        "event": "sink",
        "pattern": {
          "kind": "db_execute"
        },
        "from": {
          "fact": "TaintedString",
          "expr": "query"
        },
        "to": {
          "fact": "TaintedString",
          "expr": "self._query(query)",
          "access_path": "$",
          "risk_kind": "sql_injection"
        },
        "evidence": {
          "file": "dataset/pymysql/cursors.py",
          "line": 153,
          "code": "result = self._query(query)"
        },
        "description": "The tainted query string reaches the database execution sink."
      }
    ],
    "function_summaries": [
      {
        "summary_id": "s1_escape_args_key_preservation",
        "event": "return",
        "pattern": {
          "kind": "return_fact_from_argument",
          "callee": "_escape_args",
          "argument_index": 0,
          "receiver_policy": "any"
        },
        "from": {
          "fact": "MappingKeys",
          "expr": "$arg0.keys()[*]"
        },
        "to": {
          "fact": "MappingKeys",
          "expr": "$return",
          "access_path": "$return.keys()[*]",
          "risk_kind": "sql_injection"
        },
        "evidence": {
          "file": "dataset/pymysql/cursors.py",
          "line": 104,
          "code": "return {key: conn.literal(val) for (key, val) in args.items()}"
        }
      }
    ],
    "risk_upgrades": [],
    "kill_conditions": [],
    "validation_expectations": {
      "must_flow": "finding",
      "must_not_flow": "no_finding",
      "must_kill": "no_finding"
    },
    "description": "Missing access-path propagation for mapping keys allows user-controlled dict keys to influence the formatted SQL string. Evidence shows: (1) a user-controlled variable 'key' is used as a dict key (args = {key: \"safe-value\"}), (2) _escape_args preserves mapping keys when returning a new dict comprehension, and (3) mogrify performs percent-style mapping substitution where the mapping's keys affect the resulting 'query' string. Without propagating taint along keys()[*] access paths through the dict literal, the _escape_args return, and the percent-mapping operation, the analysis fails to connect the source ('key') to the sink (self._query(query)). This CTPC adds structurally guarded edges to model: dict-literal key to mapping keys, key preservation through _escape_args, mapping keys to formatted query via '%', propagation through mogrify's return, and finally to the SQL execution sink.",
    "notes": [
      "Top supporting edges: dict_literal_key (args = {key: ...}), dict_comprehension_key_preserved in _escape_args, and percent_mapping_key in mogrify.",
      "Interprocedural flow is captured by returning taint from mogrify('query') and assigning it to the caller's 'query'.",
      "This contract is restricted to the observed structures; it does not assume other sources/sinks beyond the evidence."
    ]
  }
}
```
