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


def _has_connectivity_structure(gate: dict[str, Any]) -> bool:
    local = gate.get("local_structure_evidence") or {}
    kinds = set(local.get("kinds", []) or [])
    items = local.get("items") or {}
    if "connectivity_candidates" in kinds:
        return True
    baseline = gate.get("baseline_status") or {}
    branch = gate.get("declared_repair_branch")
    if (
        branch in {"ccec", "ccec_then_ctpc"}
        and bool(baseline.get("source_hit"))
        and not bool(baseline.get("sink_hit"))
    ):
        return True
    return bool(items.get("connectivity_candidates"))


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
            "confirmed_gap_type": "not_repair_candidate",
            "primary_gap": None,
            "secondary_gap": None,
            "next_step": "stop",
            "needs_post_ccec_rediagnosis": False,
            "reason": [f"Evidence Gate status is {gate_status!r}, not 'candidate_fn'"],
        }

    connectivity = _has_symbolic_callee(gate) or _has_connectivity_structure(gate)
    propagation = _has_propagation_evidence(gate)
    reasons: list[str] = []
    if connectivity:
        reasons.append("symbolic/dangling or guarded/rebound call evidence indicates a Connectivity Gap")
    if propagation:
        reasons.append("local structure/frontier/backward evidence indicates a Propagation Gap")

    if connectivity and propagation:
        return {
            "gap_type": "connectivity_gap",
            "confirmed_gap_type": None,
            "primary_gap": "connectivity_gap",
            "secondary_gap": "possible_propagation_gap",
            "next_step": "run_ccec_first",
            "needs_post_ccec_rediagnosis": True,
            "rediagnosis_after": "post_ccec_rerun",
            "reason": reasons
            + [
                "Baseline evidence cannot confirm a mixed case before CCEC repair",
                "Accept call-edge contracts first, rerun analysis, then diagnose whether a propagation gap remains",
            ],
        }
    if connectivity:
        return {
            "gap_type": "connectivity_gap",
            "confirmed_gap_type": "connectivity_gap",
            "primary_gap": "connectivity_gap",
            "secondary_gap": None,
            "next_step": "run_ccec",
            "needs_post_ccec_rediagnosis": False,
            "reason": reasons,
        }
    if propagation:
        return {
            "gap_type": "propagation_gap",
            "confirmed_gap_type": "propagation_gap",
            "primary_gap": "propagation_gap",
            "secondary_gap": None,
            "next_step": "run_ctpc",
            "needs_post_ccec_rediagnosis": False,
            "reason": reasons,
        }
    return {
        "gap_type": "inconclusive",
        "confirmed_gap_type": None,
        "primary_gap": None,
        "secondary_gap": None,
        "next_step": "defer",
        "needs_post_ccec_rediagnosis": False,
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
        return ["ccec", "rerun_with_ccec", "rediagnose_gap", "ctpc_if_propagation_gap_remains"]
    if next_step == "run_ccec":
        return ["ccec"]
    if next_step == "run_ctpc":
        return ["ctpc"]
    return []
