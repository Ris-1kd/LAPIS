"""Evidence gate for deciding whether a no-finding case should be repaired."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _resolve_case_file(case_dir: Path, value: str | None) -> Path | None:
    if not value:
        return None
    path = Path(value)
    return path if path.is_absolute() else case_dir / path


def _baseline_status(baseline: dict[str, Any]) -> dict[str, Any]:
    source_count = int(baseline.get("markedSourceCount", 0) or 0)
    sink_count = int(baseline.get("matchedSinkCount", 0) or 0)
    finding_count = int(baseline.get("findingCount", 0) or 0)
    entrypoint_count = int(baseline.get("entryPointCount", 0) or 0)
    return {
        "source_hit": source_count > 0,
        "sink_hit": sink_count > 0,
        "complete_taint_path_found": finding_count > 0,
        "call_context_related": source_count > 0 and sink_count > 0 and entrypoint_count > 0,
        "sources_marked": source_count,
        "sinks_matched": sink_count,
        "findings": finding_count,
        "entrypoints": entrypoint_count,
    }


def _is_symbolic_node(node: dict[str, Any]) -> bool:
    func_def = node.get("funcDef")
    if not func_def:
        return True
    if isinstance(func_def, str) and not func_def.strip():
        return True
    return False


def summarize_callgraph(callgraph_path: Path | None, max_samples: int = 25) -> dict[str, Any]:
    if not callgraph_path or not callgraph_path.exists():
        return {
            "available": False,
            "node_count": 0,
            "edge_count": 0,
            "symbolic_node_count": 0,
            "dangling_edge_count": 0,
            "symbolic_samples": [],
            "dangling_edge_samples": [],
        }

    callgraph = load_json(callgraph_path)
    nodes = callgraph.get("nodes", {}) or {}
    edges = callgraph.get("edges", {}) or {}
    symbolic_ids = {node_id for node_id, node in nodes.items() if isinstance(node, dict) and _is_symbolic_node(node)}
    dangling_edges = [
        edge
        for edge in edges.values()
        if isinstance(edge, dict) and edge.get("targetNodeId") in symbolic_ids
    ]
    symbolic_samples = []
    for node_id in list(symbolic_ids)[:max_samples]:
        node = nodes.get(node_id, {})
        symbolic_samples.append(
            {
                "id": node_id,
                "fullName": node.get("fullName") if isinstance(node, dict) else None,
            }
        )
    dangling_samples = []
    for edge in dangling_edges[:max_samples]:
        dangling_samples.append(
            {
                "id": edge.get("id"),
                "sourceNodeId": edge.get("sourceNodeId"),
                "targetNodeId": edge.get("targetNodeId"),
                "callSite": edge.get("callSite"),
            }
        )
    return {
        "available": True,
        "path": str(callgraph_path),
        "node_count": len(nodes),
        "edge_count": len(edges),
        "symbolic_node_count": len(symbolic_ids),
        "dangling_edge_count": len(dangling_edges),
        "symbolic_samples": symbolic_samples,
        "dangling_edge_samples": dangling_samples,
    }


def _source_frontier(evidence: dict[str, Any] | None, callgraph_summary: dict[str, Any]) -> dict[str, Any]:
    if evidence:
        forward = evidence.get("source_forward_slice") or {}
        if forward:
            return {
                "available": True,
                "frontier": forward.get("frontier"),
                "reached": forward.get("reached", []),
                "observations": forward.get("observations", []),
            }
    if callgraph_summary.get("dangling_edge_count", 0) > 0:
        return {
            "available": True,
            "frontier": "symbolic/dangling callgraph edge",
            "reached": [],
            "observations": callgraph_summary.get("dangling_edge_samples", []),
        }
    return {"available": False, "frontier": None, "reached": [], "observations": []}


def _sink_backward(evidence: dict[str, Any] | None) -> dict[str, Any]:
    if not evidence:
        return {"available": False, "dependency_chain": [], "observations": []}
    backward = evidence.get("sink_backward_slice") or {}
    return {
        "available": bool(backward),
        "dependency_chain": backward.get("dependency_chain", []),
        "observations": backward.get("observations", []),
    }


def _local_structure(evidence: dict[str, Any] | None) -> dict[str, Any]:
    if not evidence:
        return {"available": False, "kinds": [], "items": {}}
    structure = evidence.get("local_structure_evidence") or {}
    kinds = [key for key, value in structure.items() if value]
    return {"available": bool(kinds), "kinds": kinds, "items": structure}


def _negative_evidence(evidence: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not evidence:
        return []
    negatives: list[dict[str, Any]] = []
    for item in evidence.get("safe_evidence", []) or []:
        if isinstance(item, dict):
            negatives.append(item)
    for item in evidence.get("negative_evidence", []) or []:
        if isinstance(item, dict):
            negatives.append(item)
    return negatives


def _explosion_risk(callgraph_summary: dict[str, Any]) -> dict[str, Any]:
    dangling = int(callgraph_summary.get("dangling_edge_count", 0) or 0)
    symbolic = int(callgraph_summary.get("symbolic_node_count", 0) or 0)
    if dangling > 1000 or symbolic > 2000:
        level = "high"
    elif dangling > 100 or symbolic > 300:
        level = "medium"
    else:
        level = "low"
    return {"level": level, "dangling_edge_count": dangling, "symbolic_node_count": symbolic}


def _decide_gate(
    baseline: dict[str, Any],
    frontier: dict[str, Any],
    backward: dict[str, Any],
    symbolic_present: bool,
    local_structure: dict[str, Any],
    negative_evidence: list[dict[str, Any]],
    explosion_risk: dict[str, Any],
    declared_repair_branch: str | None = None,
    evidence: dict[str, Any] | None = None,
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if baseline["complete_taint_path_found"]:
        return "already_reported", ["baseline already produced a finding"]
    if not baseline["source_hit"]:
        return "true_negative", ["source was not marked by baseline"]
    if not baseline["sink_hit"]:
        branch = declared_repair_branch or ""
        sink_anchor = (evidence or {}).get("sink") or {}
        source_anchor = (evidence or {}).get("source") or {}
        if (
            branch in {"ccec", "ccec_then_ctpc"}
            and bool(source_anchor.get("matches_anchor"))
            and bool(sink_anchor.get("matches_anchor"))
        ):
            return "candidate_fn", [
                "final sink anchor exists in source but was not matched by baseline",
                f"declared repair branch is {branch}, so treat this as a callgraph/connectivity candidate",
            ]
        return "true_negative", ["sink was not matched by baseline"]
    if not baseline["call_context_related"]:
        return "infeasible", ["source and sink do not share an observed entrypoint/call context"]
    if negative_evidence and not symbolic_present and not local_structure.get("available"):
        return "safe_killed", ["negative safety evidence exists and no repairable structure was observed"]
    if explosion_risk["level"] == "high" and not local_structure.get("available"):
        return "deferred", ["symbolic callgraph space is too large without local structure evidence"]
    if symbolic_present or local_structure.get("available") or frontier.get("available") or backward.get("available"):
        if symbolic_present:
            reasons.append("symbolic/dangling callee evidence exists")
        if local_structure.get("available"):
            reasons.append("local structure evidence exists")
        if frontier.get("available"):
            reasons.append("source forward frontier evidence exists")
        if backward.get("available"):
            reasons.append("sink backward dependency evidence exists")
        return "candidate_fn", reasons
    return "deferred", ["source and sink are observed but repair evidence is insufficient"]


def build_evidence_gate_report(
    case_path: Path,
    out_path: Path,
    evidence_path: Path | None = None,
    callgraph_path: Path | None = None,
    baseline_summary_path: Path | None = None,
) -> dict[str, Any]:
    case_path = case_path.resolve()
    case_dir = case_path.parent
    case = load_json(case_path)
    baseline_path = baseline_summary_path or _resolve_case_file(case_dir, case["baseline_summary"])
    if baseline_path is None:
        raise ValueError("case.json must contain baseline_summary")
    baseline_path = baseline_path.resolve()
    baseline = _baseline_status(load_json(baseline_path))
    baseline["partial_findings"] = False
    evidence_file = evidence_path or _resolve_case_file(case_dir, "evidence/evidence_pack.json")
    evidence = load_json(evidence_file) if evidence_file and evidence_file.exists() else None
    cg_file = callgraph_path or _resolve_case_file(case_dir, case.get("callgraph"))
    callgraph_summary = summarize_callgraph(cg_file)
    frontier = _source_frontier(evidence, callgraph_summary)
    backward = _sink_backward(evidence)
    local = _local_structure(evidence)
    negatives = _negative_evidence(evidence)
    symbolic_present = callgraph_summary.get("dangling_edge_count", 0) > 0
    risk = _explosion_risk(callgraph_summary)
    status, reasons = _decide_gate(
        baseline,
        frontier,
        backward,
        symbolic_present,
        local,
        negatives,
        risk,
        case.get("repair_branch"),
        evidence,
    )
    report = {
        "schema_version": "lapis.evidence_gate.v1",
        "case_id": case.get("case_id"),
        "case": str(case_path),
        "baseline_summary": str(baseline_path),
        "declared_case_group": case.get("gap_type"),
        "declared_repair_branch": case.get("repair_branch"),
        "gate_status": status,
        "baseline_status": baseline,
        "source_forward_frontier": frontier,
        "sink_backward_dependency": backward,
        "symbolic_callee": {
            "present": symbolic_present,
            "callgraph": callgraph_summary,
        },
        "local_structure_evidence": local,
        "negative_evidence": negatives,
        "explosion_risk": risk,
        "decision_reason": reasons,
        "oracle_note": (
            "This gate identifies evidence-supported candidate FNs. Benchmark oracle fields "
            "are hidden by default and must only be used after repair for evaluation."
        ),
        "oracle_fallback_used": False,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report
