"""CTPC schema helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _edge(edge_id: str, event: str, pattern: dict[str, Any], from_fact: dict[str, Any], to_fact: dict[str, Any], evidence: str) -> dict[str, Any]:
    return {
        "edge_id": edge_id,
        "event": event,
        "pattern": pattern,
        "from": from_fact,
        "to": to_fact,
        "evidence": {"code": evidence},
    }


def upgrade_ctpc_v1_to_v2(ctpc: dict[str, Any]) -> dict[str, Any]:
    """Convert the current seed CTPC shape into structured CTPC v2."""

    if ctpc.get("schema_version") == "ctpc.v2":
        return ctpc

    return {
        "schema_version": "ctpc.v2",
        "contract_name": ctpc["contract_name"],
        "gap_type": ctpc.get("gap_type", []),
        "applies_to": {
            "language": "python",
            "risk_kind": "SQL_STRUCTURE",
        },
        "fact_types": [
            {
                "name": "tainted_symbol",
                "shape": {"access_path": "$symbol"},
            },
            {
                "name": "mapping_key",
                "shape": {"access_path": "$map.keys()[*]", "value_kind": "key"},
            },
            {
                "name": "sql_structure_value",
                "shape": {"access_path": "$expr", "risk_kind": "SQL_STRUCTURE"},
            },
        ],
        "propagation_edges": [
            _edge(
                "dict_literal_key_to_mapping_key",
                "assignment",
                {
                    "kind": "dict_literal_key",
                    "lhs": "$lhs",
                    "rhs_kind": "dict_literal",
                    "source_position": "key",
                    "source_expr": "$key",
                },
                {"fact": "tainted_symbol", "expr": "$key"},
                {
                    "fact": "mapping_key",
                    "expr": "$lhs",
                    "access_path": "$lhs.keys()[*]",
                    "value_kind": "key",
                    "risk_kind": "SQL_STRUCTURE",
                },
                'args = {key: "safe-value"}',
            ),
            _edge(
                "dict_comprehension_key_preserved",
                "assignment",
                {
                    "kind": "dict_comprehension_key_preserved",
                    "lhs": "$lhs",
                    "iterable": "$map.items()",
                    "emits_original_key": True,
                },
                {"fact": "mapping_key", "expr": "$map.keys()[*]"},
                {
                    "fact": "mapping_key",
                    "expr": "$lhs",
                    "access_path": "$lhs.keys()[*]",
                    "value_kind": "key",
                    "risk_kind": "SQL_STRUCTURE",
                },
                "return {key: conn.literal(val) for (key, val) in args.items()}",
            ),
            _edge(
                "percent_mapping_key_to_sql_structure",
                "assignment",
                {
                    "kind": "percent_mapping_key",
                    "operator": "%",
                    "lhs": "$result",
                    "rhs_fact": "mapping_key",
                },
                {"fact": "mapping_key", "expr": "$rhs.keys()[*]"},
                {
                    "fact": "sql_structure_value",
                    "expr": "$result",
                    "access_path": "$result",
                    "risk_kind": "SQL_STRUCTURE",
                },
                "query = query % self._escape_args(args, conn)",
            ),
        ],
        "function_summaries": [
            {
                "summary_id": "escape_args_return_preserves_mapping_keys",
                "event": "function_call",
                "pattern": {
                    "kind": "return_fact_from_argument",
                    "callee": "_escape_args",
                    "argument_index": 0,
                    "receiver_policy": "any",
                },
                "from": {
                    "fact": "mapping_key",
                    "expr": "$arg0.keys()[*]",
                },
                "to": {
                    "fact": "mapping_key",
                    "expr": "$return",
                    "access_path": "$return.keys()[*]",
                    "value_kind": "key",
                    "risk_kind": "SQL_STRUCTURE",
                },
                "evidence": {
                    "code": "return {key: conn.literal(val) for (key, val) in args.items()}"
                },
            }
        ],
        "risk_upgrades": [
            {
                "upgrade_id": "mapping_key_to_sql_structure",
                "event": "assignment",
                "pattern": {
                    "kind": "percent_mapping_key",
                    "operator": "%",
                },
                "from": {"fact": "mapping_key", "expr": "$rhs.keys()[*]"},
                "to": {"fact": "sql_structure_value", "expr": "$lhs"},
                "risk_kind": "SQL_STRUCTURE",
            }
        ],
        "kill_conditions": [
            {
                "kill_id": "key_whitelist_guard",
                "event": "if_condition",
                "pattern": {
                    "kind": "membership_rejection_guard",
                    "operator": "not in",
                    "left_fact": "tainted_symbol",
                    "right_kind": "literal_collection",
                },
                "effect": {
                    "action": "suppress",
                    "risk_kind": "SQL_STRUCTURE",
                    "for_fact": "tainted_symbol",
                },
                "evidence": {"code": 'if key not in {"name"}: return'},
            },
            {
                "kill_id": "value_only_parameterization",
                "event": "sink",
                "pattern": {
                    "kind": "missing_mapping_key_fact",
                    "value_taint_only": True,
                },
                "effect": {
                    "action": "suppress",
                    "risk_kind": "SQL_STRUCTURE",
                },
                "evidence": {"code": 'args = {"name": val}'},
            },
        ],
        "validation_expectations": {
            "must_flow": "finding",
            "must_not_flow": "no_finding",
            "must_kill": "no_finding",
        },
        "description": "Structured CTPC generated from the seed PyMySQL dict-key percent-format contract.",
        "notes": ctpc.get("notes", []),
    }


def validate_ctpc_v2(ctpc: dict[str, Any]) -> None:
    if ctpc.get("schema_version") != "ctpc.v2":
        raise ValueError("CTPC must have schema_version='ctpc.v2'")
    required = ["contract_name", "applies_to", "fact_types", "propagation_edges", "kill_conditions"]
    for key in required:
        if key not in ctpc:
            raise ValueError(f"CTPC v2 missing {key!r}")
    for edge in ctpc["propagation_edges"]:
        for key in ["edge_id", "event", "pattern", "from", "to"]:
            if key not in edge:
                raise ValueError(f"propagation edge missing {key!r}: {edge}")
        if "kind" not in edge["pattern"]:
            raise ValueError(f"propagation edge pattern missing kind: {edge}")
    for summary in ctpc.get("function_summaries", []):
        for key in ["summary_id", "event", "pattern", "from", "to"]:
            if key not in summary:
                raise ValueError(f"function summary missing {key!r}: {summary}")
        if "kind" not in summary["pattern"]:
            raise ValueError(f"function summary pattern missing kind: {summary}")
    for kill in ctpc["kill_conditions"]:
        for key in ["kill_id", "event", "pattern", "effect"]:
            if key not in kill:
                raise ValueError(f"kill condition missing {key!r}: {kill}")


def upgrade_ctpc_file(in_path: Path, out_path: Path) -> dict[str, Any]:
    ctpc = upgrade_ctpc_v1_to_v2(_load_json(in_path))
    validate_ctpc_v2(ctpc)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(ctpc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return ctpc
