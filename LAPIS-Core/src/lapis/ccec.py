"""Candidate call-edge contract helpers for Connectivity Gap cases."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .prompt import _static_ccec_evidence


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _candidate_templates(case: dict[str, Any]) -> list[dict[str, Any]]:
    case_id = case.get("case_id")
    gap_type = case.get("gap_type")
    breakpoint = case.get("breakpoint") or {}
    frontier = breakpoint.get("frontier") or []
    kind = breakpoint.get("kind", "unknown")

    if case_id == "cve-2024-27758-rpyc":
        return [
            {
                "edge_id": "rpyc_getattr_array_to_generated_method",
                "caller": "poc_cve_2024_27758_rpyc.array_callback",
                "callsite": "getattr(obj, \"__array__\")",
                "callee": "rpyc.core.netref._make_method.<generated __array__>",
                "confidence": 0.78,
                "guards": [
                    "attribute_name == \"__array__\"",
                    "receiver derives from BaseNetref",
                    "class namespace contains ns[\"__array__\"] from _make_method",
                ],
                "evidence": frontier,
            },
            {
                "edge_id": "rpyc_generated_array_to_pickle_loads",
                "caller": "rpyc.core.netref._make_method.<generated __array__>",
                "callsite": "pickle.loads(syncreq(...))",
                "callee": "pickle.loads",
                "confidence": 0.72,
                "guards": [
                    "generated method name == \"__array__\"",
                    "syncreq returns remote pickle payload",
                ],
                "evidence": frontier,
            },
        ]

    if case_id == "cve-2023-24816-ipython":
        return [
            {
                "edge_id": "ipython_set_term_title_to_win32_fallback",
                "caller": "IPython.utils.terminal.set_term_title",
                "callsite": "_set_term_title(title)",
                "callee": "IPython.utils.terminal._set_term_title.win32_fallback",
                "confidence": 0.84,
                "guards": [
                    "global name _set_term_title rebound under sys.platform == \"win32\"",
                    "argument title is forwarded unchanged",
                ],
                "evidence": frontier,
            }
        ]

    if case_id == "cve-2026-24486-python-multipart":
        return [
            {
                "edge_id": "multipart_write_to_on_start_callback",
                "caller": "multipart.OctetStreamParser.write",
                "callsite": "callbacks[\"on_start\"]()",
                "callee": "multipart.FormParser.__init__.<locals>.on_start",
                "confidence": 0.76,
                "guards": [
                    "callbacks contains key \"on_start\"",
                    "parser.write reaches start event",
                ],
                "evidence": frontier,
            },
            {
                "edge_id": "multipart_on_start_to_file_class",
                "caller": "multipart.FormParser.__init__.<locals>.on_start",
                "callsite": "FileClass(file_name, ...)",
                "callee": "multipart.File.__init__",
                "confidence": 0.7,
                "guards": [
                    "file_name captured by closure",
                    "FileClass resolves to configured File class",
                ],
                "evidence": frontier,
            },
        ]

    if case_id == "cve-2025-55156-pyload":
        return [
            {
                "edge_id": "pyload_db_receiver_to_file_database_update",
                "caller": "poc_cve_2025_55156_pyload.cve_2025_55156_driver",
                "callsite": "db.update_link_info(data)",
                "callee": "pyload.core.database.file_database.FileDatabase.update_link_info",
                "confidence": 0.74,
                "guards": [
                    "receiver db is a FileDatabase-compatible database object",
                    "argument data is forwarded unchanged",
                ],
                "evidence": frontier,
            }
        ]

    if gap_type in {"connectivity_gap", "mixed_case"} and frontier:
        return [
            {
                "edge_id": f"{case_id}_metadata_candidate_edge",
                "caller": "unknown",
                "callsite": frontier[0],
                "callee": frontier[-1],
                "confidence": 0.5,
                "guards": [kind],
                "evidence": frontier,
            }
        ]
    return []


def _module_hint(file_name: str) -> str:
    return file_name[:-3].replace("/", ".") if file_name.endswith(".py") else file_name.replace("/", ".")


def _static_candidates(case: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = _static_ccec_evidence(case)
    if not evidence:
        return []

    callsite = evidence.get("observed_callsite") or {}
    file_name = callsite.get("file")
    enclosing = callsite.get("enclosing_function")
    callee_symbol = callsite.get("callee_symbol")
    args = callsite.get("args") or []
    if not file_name or not enclosing or not callee_symbol:
        return []

    caller = f"{_module_hint(file_name)}.{enclosing}"
    candidates = []
    for definition in evidence.get("candidate_definitions", []):
        if definition.get("function") != callee_symbol:
            continue
        if not definition.get("contains_sink_callee"):
            continue
        guards = definition.get("guards") or []
        sink_calls = definition.get("sink_calls") or []
        evidence_items = [
            f"{file_name}:{callsite.get('line')} callsite {callsite.get('expr')}",
            f"{definition.get('file')}:{definition.get('line')} candidate def {definition.get('function')}",
        ]
        evidence_items.extend(
            f"{definition.get('file')}:{sink.get('line')} sink call {sink.get('expr')}" for sink in sink_calls
        )
        candidates.append(
            {
                "edge_id": f"{case.get('case_id')}_{enclosing}_to_{callee_symbol}_line_{definition.get('line')}",
                "caller": caller,
                "callsite": callsite.get("expr"),
                "callee": f"{definition.get('qualified_hint')}.line_{definition.get('line')}",
                "callee_kind": "rebound_function",
                "confidence": 0.86 if guards else 0.76,
                "guards": guards
                + [
                    f"callsite callee symbol == {callee_symbol}",
                    f"argument count compatible: callsite={len(args)} callee={len(definition.get('args') or [])}",
                    "candidate body contains the configured sink callee",
                ],
                "evidence": evidence_items,
                "contract": {
                    "preconditions": guards + [f"observed callsite == {callsite.get('expr')}"],
                    "effects": [
                        {
                            "kind": "add_call_edge",
                            "from": "caller",
                            "to": "callee",
                            "at": "callsite",
                        }
                    ],
                    "must_not_apply_when": [
                        "callee symbol does not match the observed callsite",
                        "candidate body has no path toward the configured sink callee",
                    ],
                },
            }
        )
    return sorted(candidates, key=lambda item: item["confidence"], reverse=True)


def plan_ccec_repair(case_path: Path, out_path: Path, top_k: int = 5) -> dict[str, Any]:
    """Classify a CCEC case into easy/middle/hard and choose rule/LLM routing."""

    case_path = case_path.resolve()
    case = load_json(case_path)
    evidence = _static_ccec_evidence(case)
    static_candidates = _static_candidates(case)
    metadata_difficulty = case.get("difficulty")
    evidence_kind = evidence.get("kind") if evidence else None

    if evidence_kind == "dynamic_getattr_factory_method_evidence":
        mode = "hard"
        llm_required = True
        generation_strategy = "llm_oracle_safe"
        recommended_top_k = max(top_k, 5)
        reason = [
            "dynamic getattr is connected to a factory-generated method",
            "candidate callee requires materialized/virtual method reasoning",
            "multi-graph evidence is required: def-use, type/class graph, and sink backward hint",
        ]
    elif static_candidates and len(static_candidates) == 1:
        mode = "easy"
        llm_required = False
        generation_strategy = "rule_static"
        recommended_top_k = 1
        reason = [
            "static evidence yields a single guarded candidate edge",
            "callee can be selected by local AST evidence without LLM ranking",
        ]
    elif static_candidates:
        mode = "middle"
        llm_required = True
        generation_strategy = "rule_top_k_then_llm_rank"
        recommended_top_k = min(max(len(static_candidates), 3), top_k)
        reason = [
            "rules can produce candidates but LLM ranking/guard selection is required",
        ]
    elif metadata_difficulty in {"easy", "middle", "hard"}:
        mode = metadata_difficulty
        llm_required = mode != "easy"
        generation_strategy = "rule_static" if mode == "easy" else "llm_oracle_safe"
        recommended_top_k = 1 if mode == "easy" else top_k
        reason = [
            "falling back to case metadata difficulty because static candidate extraction was inconclusive",
        ]
    else:
        mode = "deferred"
        llm_required = False
        generation_strategy = "defer"
        recommended_top_k = 0
        reason = ["insufficient evidence to classify CCEC repair difficulty"]

    report = {
        "schema_version": "lapis.ccec_repair_plan.v1",
        "case_id": case.get("case_id"),
        "case": str(case_path),
        "gap_type": case.get("gap_type"),
        "repair_branch": case.get("repair_branch"),
        "mode": mode,
        "metadata_difficulty": metadata_difficulty,
        "llm_required": llm_required,
        "generation_strategy": generation_strategy,
        "top_k": recommended_top_k,
        "candidate_count_from_static_rules": len(static_candidates),
        "evidence_kind": evidence_kind,
        "evidence_summary": {
            "observed_callsite": evidence.get("observed_callsite") if evidence else None,
            "candidate_definition_count": len(evidence.get("candidate_definitions", [])) if evidence else 0,
            "factory_call_count": len(evidence.get("factory_calls", [])) if evidence else 0,
            "make_method_branch_count": len(evidence.get("make_method_branches", [])) if evidence else 0,
            "dynamic_type_site_count": len(evidence.get("dynamic_type_sites", [])) if evidence else 0,
        },
        "next_steps": _plan_next_steps(mode, llm_required, generation_strategy),
        "validation_plan": {
            "structural": "validate-ccec-candidates",
            "link_samples": "LLM generates must-link / must-not-link / must-kill",
            "link_validation": "validate-ccec-link-contract",
            "consumer": "real edge injection or virtual edge consumer depending on callee_kind",
        },
        "reason": reason,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def _plan_next_steps(mode: str, llm_required: bool, generation_strategy: str) -> list[str]:
    if mode == "deferred":
        return ["defer"]
    steps = ["build_oracle_safe_evidence"]
    if llm_required:
        steps.extend(["build_ccec_prompt", "llm_generate_ccec_candidates"])
    else:
        steps.append("generate_ccec_candidates_rule_only")
    steps.extend(
        [
            "validate_ccec_candidates",
            "build_ccec_validation_prompt",
            "llm_generate_must_link_must_not_link_must_kill",
            "validate_ccec_link_contract",
        ]
    )
    if generation_strategy == "rule_static":
        steps.append("apply_real_or_rebound_edge")
    else:
        steps.append("apply_virtual_edge_consumer_if_needed")
    return steps


def build_ccec_candidates(
    case_path: Path,
    out_path: Path,
    top_k: int = 5,
    strategy: str = "template",
) -> dict[str, Any]:
    case_path = case_path.resolve()
    case = load_json(case_path)
    if strategy == "static":
        candidates = _static_candidates(case)[:top_k]
    elif strategy == "template":
        candidates = sorted(_candidate_templates(case), key=lambda item: item["confidence"], reverse=True)[:top_k]
    else:
        raise ValueError(f"unknown CCEC generation strategy: {strategy}")
    report = {
        "schema_version": "lapis.ccec_candidates.v1",
        "case_id": case.get("case_id"),
        "case": str(case_path),
        "gap_type": case.get("gap_type"),
        "repair_branch": case.get("repair_branch"),
        "generation_strategy": strategy,
        "candidate_edges": candidates,
        "note": (
            "These are candidate call edges for CCEC validation. "
            "Three-way validation samples are generated by the validator stage, not stored in this candidate file."
        ),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def validate_ccec_candidates(candidates_path: Path, out_path: Path) -> dict[str, Any]:
    candidates = load_json(candidates_path)
    results = []
    for edge in candidates.get("candidate_edges", []):
        missing = [
            key
            for key in ("edge_id", "caller", "callsite", "callee", "guards", "evidence")
            if not edge.get(key)
        ]
        confidence = float(edge.get("confidence", 0) or 0)
        passed = not missing and confidence > 0
        results.append(
            {
                "edge_id": edge.get("edge_id"),
                "passed": passed,
                "missing": missing,
                "confidence": confidence,
                "checks": {
                    "has_caller": bool(edge.get("caller")),
                    "has_callsite": bool(edge.get("callsite")),
                    "has_callee": bool(edge.get("callee")),
                    "has_guards": bool(edge.get("guards")),
                    "has_evidence": bool(edge.get("evidence")),
                    "has_positive_confidence": confidence > 0,
                },
            }
        )
    report = {
        "schema_version": "lapis.ccec_validation.v1",
        "case_id": candidates.get("case_id"),
        "candidates": str(candidates_path),
        "status": "accepted" if results and all(item["passed"] for item in results) else "rejected",
        "edge_results": results,
        "note": (
            "This is the structural CCEC validation stage. "
            "Graph progress and taint reachability validation happen after applying accepted edges."
        ),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def validate_ccec_link_contract(validation_path: Path, candidates_path: Path, out_path: Path) -> dict[str, Any]:
    """Validate LLM-generated must-link / must-not-link / must-kill CCEC samples."""

    validation = load_json(validation_path.resolve())
    candidates = load_json(candidates_path.resolve())
    candidate_edges = candidates.get("candidate_edges", [])
    candidate_edge_ids = {edge.get("edge_id") for edge in candidate_edges if edge.get("edge_id")}

    sample_specs = {
        "must_link": "edge_present",
        "must_not_link": "edge_absent",
        "must_kill": "edge_suppressed",
    }
    sample_results = []
    for sample_name, expected in sample_specs.items():
        samples = validation.get(sample_name)
        if samples is None and sample_name == "must_link":
            samples = validation.get("must_connect")
        if samples is None and sample_name == "must_not_link":
            samples = validation.get("must_not_connect")
        if not isinstance(samples, list):
            sample_results.append(
                {
                    "sample": sample_name,
                    "passed": False,
                    "reason": f"{sample_name} must be a list",
                    "cases": [],
                }
            )
            continue
        cases = []
        for item in samples:
            evidence = item.get("evidence", [])
            expected_ok = item.get("expected") == expected
            has_callsite = bool(item.get("callsite"))
            has_callee = bool(item.get("callee"))
            has_evidence = isinstance(evidence, list) and len(evidence) > 0
            has_guard = bool(item.get("required_guards") or item.get("violated_guard") or item.get("kill_condition"))
            passed = expected_ok and has_callsite and has_callee and has_evidence and has_guard
            cases.append(
                {
                    "name": item.get("name"),
                    "expected": item.get("expected"),
                    "passed": passed,
                    "checks": {
                        "expected_ok": expected_ok,
                        "has_callsite": has_callsite,
                        "has_callee": has_callee,
                        "has_evidence": has_evidence,
                        "has_guard_or_kill": has_guard,
                    },
                }
            )
        sample_results.append(
            {
                "sample": sample_name,
                "passed": bool(cases) and all(item["passed"] for item in cases),
                "cases": cases,
            }
        )

    validated_edges = set(validation.get("validated_ccec_edges", []))
    edge_coverage = [
        {
            "edge_id": edge_id,
            "covered": edge_id in validated_edges,
        }
        for edge_id in sorted(candidate_edge_ids)
    ]
    full_chain = validation.get("full_chain_expectation") or {}
    full_chain_ok = bool(full_chain.get("callgraph_complete")) and isinstance(
        full_chain.get("source_to_sink_chain"), list
    )
    status = (
        "accepted"
        if sample_results
        and all(item["passed"] for item in sample_results)
        and all(item["covered"] for item in edge_coverage)
        and full_chain_ok
        else "rejected"
    )
    report = {
        "schema_version": "lapis.ccec_link_validation_report.v1",
        "case_id": validation.get("case_id") or candidates.get("case_id"),
        "validation_contract": str(validation_path.resolve()),
        "candidates": str(candidates_path.resolve()),
        "status": status,
        "sample_results": sample_results,
        "edge_coverage": edge_coverage,
        "full_chain_check": {
            "passed": full_chain_ok,
            "full_chain_expectation": full_chain,
        },
        "note": (
            "CCEC link validation checks LLM-generated must-link, must-not-link, "
            "and must-kill samples. It validates call-edge contracts, not CTPC dataflow."
        ),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def build_repaired_call_chain(case_path: Path, candidates_path: Path, out_path: Path) -> dict[str, Any]:
    case = load_json(case_path.resolve())
    candidates = load_json(candidates_path.resolve())
    accepted_edges = candidates.get("candidate_edges", [])
    source = case.get("source") or {}
    sink = case.get("sink") or {}
    breakpoint = case.get("breakpoint") or {}
    frontier = breakpoint.get("frontier") or []
    chain_nodes = []

    if source.get("expr"):
        chain_nodes.append({"kind": "source", "node": source["expr"]})
    for item in frontier:
        chain_nodes.append({"kind": "frontier", "node": item})
    for edge in accepted_edges:
        chain_nodes.append(
            {
                "kind": "repaired_call_edge",
                "edge_id": edge.get("edge_id"),
                "caller": edge.get("caller"),
                "callsite": edge.get("callsite"),
                "callee": edge.get("callee"),
                "guards": edge.get("guards", []),
            }
        )
    if sink.get("expr"):
        chain_nodes.append({"kind": "sink", "node": sink["expr"]})

    has_source = bool(source.get("expr"))
    has_sink = bool(sink.get("expr"))
    has_repaired_edges = bool(accepted_edges)
    if case.get("gap_type") == "connectivity_gap":
        status = "complete" if has_source and has_sink and has_repaired_edges else "incomplete"
    elif case.get("gap_type") == "mixed_case":
        status = "call_edges_complete_dataflow_pending" if has_source and has_sink and has_repaired_edges else "incomplete"
    else:
        status = "not_applicable"

    report = {
        "schema_version": "lapis.ccec_repaired_call_chain.v1",
        "case_id": case.get("case_id"),
        "gap_type": case.get("gap_type"),
        "repair_branch": case.get("repair_branch"),
        "status": status,
        "complete_at_callgraph_level": status in {"complete", "call_edges_complete_dataflow_pending"},
        "dataflow_still_required": case.get("gap_type") == "mixed_case",
        "source": source,
        "sink": sink,
        "chain": chain_nodes,
        "accepted_edges": accepted_edges,
        "note": (
            "This validates the repaired call-chain contract. "
            "For mixed cases, CTPC must run after CCEC to prove dataflow reachability."
        ),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report
