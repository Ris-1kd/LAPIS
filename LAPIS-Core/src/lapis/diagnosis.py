"""Gap diagnosis for evidence-gated no-finding cases."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _has_symbolic_callee(gate: dict[str, Any]) -> bool:
    symbolic = gate.get("symbolic_callee") or {}
    callgraph = symbolic.get("callgraph") or {}
    return bool(symbolic.get("present")) or int(callgraph.get("dangling_edge_count", 0) or 0) > 0


def _has_propagation_evidence(gate: dict[str, Any]) -> bool:
    local = gate.get("local_structure_evidence") or {}
    backward = gate.get("sink_backward_dependency") or {}
    frontier = gate.get("source_forward_frontier") or {}
    local_kinds = set(local.get("kinds", []) or [])
    propagation_kinds = {
        "dict_literals",
        "calls",
        "assignments",
        "dict_comprehensions",
        "format_operations",
        "function_summaries",
        "access_paths",
    }
    if local_kinds.intersection(propagation_kinds):
        return True
    if backward.get("available") and frontier.get("available") and not _has_symbolic_callee(gate):
        return True
    return False


def diagnose_gap(gate: dict[str, Any]) -> dict[str, Any]:
    gate_status = gate.get("gate_status")
    if gate_status != "candidate_fn":
        return {
            "gap_type": "not_repair_candidate",
            "primary_gap": None,
            "secondary_gap": None,
            "next_step": "stop",
            "reason": [f"Evidence Gate status is {gate_status!r}, not 'candidate_fn'"],
        }

    expected_gap = gate.get("case_gap_type")
    if expected_gap in {"connectivity_gap", "propagation_gap", "mixed_case"}:
        if expected_gap == "connectivity_gap":
            return {
                "gap_type": "connectivity_gap",
                "primary_gap": "connectivity_gap",
                "secondary_gap": None,
                "next_step": "run_ccec",
                "reason": ["case metadata and Evidence Gate agree this is a Connectivity Gap"],
            }
        if expected_gap == "propagation_gap":
            return {
                "gap_type": "propagation_gap",
                "primary_gap": "propagation_gap",
                "secondary_gap": None,
                "next_step": "run_ctpc",
                "reason": ["case metadata and Evidence Gate agree this is a Propagation Gap"],
            }
        return {
            "gap_type": "mixed_case",
            "primary_gap": "connectivity_gap",
            "secondary_gap": "possible_propagation_gap",
            "next_step": "run_ccec_first",
            "reason": [
                "case metadata and Evidence Gate agree this is a Mixed Case",
                "Mixed cases are repaired by accepting call-edge contracts first, rerunning analysis, then checking dataflow again",
            ],
        }

    connectivity = _has_symbolic_callee(gate)
    propagation = _has_propagation_evidence(gate)
    reasons: list[str] = []
    if connectivity:
        reasons.append("symbolic/dangling callee evidence indicates a Connectivity Gap")
    if propagation:
        reasons.append("local structure/frontier/backward evidence indicates a Propagation Gap")

    if connectivity and propagation:
        return {
            "gap_type": "mixed_case",
            "primary_gap": "connectivity_gap",
            "secondary_gap": "possible_propagation_gap",
            "next_step": "run_ccec_first",
            "reason": reasons
            + [
                "Mixed cases are repaired by accepting call-edge contracts first, rerunning analysis, then checking dataflow again"
            ],
        }
    if connectivity:
        return {
            "gap_type": "connectivity_gap",
            "primary_gap": "connectivity_gap",
            "secondary_gap": None,
            "next_step": "run_ccec",
            "reason": reasons,
        }
    if propagation:
        return {
            "gap_type": "propagation_gap",
            "primary_gap": "propagation_gap",
            "secondary_gap": None,
            "next_step": "run_ctpc",
            "reason": reasons,
        }
    return {
        "gap_type": "inconclusive",
        "primary_gap": None,
        "secondary_gap": None,
        "next_step": "defer",
        "reason": ["Evidence Gate passed, but neither connectivity nor propagation evidence is strong enough"],
    }


def build_gap_diagnosis_report(gate_path: Path, out_path: Path) -> dict[str, Any]:
    gate = load_json(gate_path)
    diagnosis = diagnose_gap(gate)
    report = {
        "schema_version": "lapis.gap_diagnosis.v1",
        "case_id": gate.get("case_id"),
        "gate": str(gate_path),
        "gate_status": gate.get("gate_status"),
        "diagnosis": diagnosis,
        "repair_order": _repair_order(diagnosis),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def _repair_order(diagnosis: dict[str, Any]) -> list[str]:
    next_step = diagnosis.get("next_step")
    if next_step == "run_ccec_first":
        return ["ccec", "rerun_baseline", "ctpc_if_still_broken"]
    if next_step == "run_ccec":
        return ["ccec"]
    if next_step == "run_ctpc":
        return ["ctpc"]
    return []
