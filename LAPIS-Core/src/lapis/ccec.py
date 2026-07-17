"""Candidate call-edge contract helpers for Connectivity Gap cases."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

from .prompt import _static_ccec_evidence


CCEC_REQUIRED_SAMPLES = {
    "must-link": "edge_present",
    "must-not-link": "edge_absent",
    "must-kill": "edge_suppressed",
}


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _module_hint(file_name: str) -> str:
    return file_name[:-3].replace("/", ".") if file_name.endswith(".py") else file_name.replace("/", ".")


def _guard_text(guard: dict[str, Any]) -> str:
    return str(guard.get("condition") or guard.get("guard") or "")


def _guard_evidence_text(guard: dict[str, Any]) -> str:
    evidence = guard.get("evidence") or {}
    if not evidence:
        return _guard_text(guard)
    file_name = evidence.get("file")
    line = evidence.get("line")
    code = evidence.get("code")
    if file_name and line and code:
        return f"{file_name}:{line} guard {_guard_text(guard)} from {code}"
    return _guard_text(guard)


def _mode_profile(mode: str) -> dict[str, Any]:
    profiles = {
        "easy": {
            "mechanism": "direct_static_edge",
            "llm_role": "not_required",
            "candidate_source": "single baseline-observed callsite and unique static callee evidence",
            "repair_consumer": "real_or_rebound_call_edge",
            "validation_strength": "structural plus minimal must-link/must-not-link",
            "description": (
                "Use deterministic static evidence to add one guarded call edge. "
                "LLM may format explanations but must not invent candidates."
            ),
        },
        "middle": {
            "mechanism": "top_k_static_edges_then_llm_ranking",
            "llm_role": "rank_candidates_and_refine_guards",
            "candidate_source": "multiple static candidates from dynamic dispatch, rebinding, callbacks, or receiver uncertainty",
            "repair_consumer": "guarded_real_or_rebound_call_edge",
            "validation_strength": "structural plus must-link/must-not-link/must-kill",
            "description": (
                "Generate top-k candidates from static evidence, then ask LLM to rank, "
                "select, and refine guards using only the supplied evidence."
            ),
        },
        "hard": {
            "mechanism": "llm_synthesized_virtual_or_materialized_edge",
            "llm_role": "synthesize_dynamic_edge_contract_from_static_evidence",
            "candidate_source": "factory/reflection/callback-table evidence without a directly materialized callee",
            "repair_consumer": "virtual_or_materialized_edge_consumer",
            "validation_strength": "strict must-link/must-not-link/must-kill plus rerun",
            "description": (
                "Use multi-source static evidence to synthesize a guarded dynamic, virtual, "
                "or materialized call-edge contract. No benchmark chain oracle is allowed."
            ),
        },
        "deferred": {
            "mechanism": "insufficient_evidence",
            "llm_role": "not_allowed_to_guess",
            "candidate_source": "none",
            "repair_consumer": "none",
            "validation_strength": "none",
            "description": "Do not generate CCEC candidates until baseline evidence is sufficient.",
        },
    }
    return profiles.get(mode, profiles["deferred"])


def _classify_ccec(evidence: dict[str, Any] | None, static_candidates: list[dict[str, Any]], top_k: int) -> dict[str, Any]:
    evidence_kind = evidence.get("kind") if evidence else None
    if evidence_kind == "dynamic_getattr_factory_method_evidence":
        mode = "hard"
        llm_required = True
        generation_strategy = "baseline_static_evidence_then_llm_synthesis"
        recommended_top_k = max(top_k, 5)
        reason = [
            "baseline evidence indicates dynamic getattr/factory materialization",
            "callee may need virtual or materialized edge synthesis",
            "candidate must be guarded by observed static factory/branch evidence",
        ]
    elif static_candidates and len(static_candidates) == 1:
        mode = "easy"
        llm_required = False
        generation_strategy = "rule_static_single_edge"
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
            "static evidence yields multiple plausible candidate edges",
            "LLM ranking and guard refinement are required",
        ]
    else:
        mode = "deferred"
        llm_required = False
        generation_strategy = "defer"
        recommended_top_k = 0
        reason = ["insufficient evidence to classify CCEC repair difficulty"]

    return {
        "mode": mode,
        "profile": _mode_profile(mode),
        "llm_required": llm_required,
        "generation_strategy": generation_strategy,
        "recommended_top_k": recommended_top_k,
        "reason": reason,
    }


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
        branch_guards = definition.get("guards") or []
        derived_guards = [
            {
                "condition": f"callsite callee symbol == {callee_symbol}",
                "derived_from": "baseline_observed_callsite_ast",
                "evidence": {
                    "file": file_name,
                    "line": callsite.get("line"),
                    "code": callsite.get("expr"),
                },
            },
            {
                "condition": (
                    "argument count compatible: "
                    f"callsite={len(args)} callee={len(definition.get('args') or [])}"
                ),
                "derived_from": "callsite_and_candidate_signature",
                "evidence": {
                    "callsite_args": len(args),
                    "callee_params": len(definition.get("args") or []),
                    "callee_file": definition.get("file"),
                    "callee_line": definition.get("line"),
                },
            },
        ]
        guard_objects = [*branch_guards, *derived_guards]
        evidence_items = [
            f"{file_name}:{callsite.get('line')} callsite {callsite.get('expr')}",
            f"{definition.get('file')}:{definition.get('line')} candidate def {definition.get('function')}",
        ]
        evidence_items.extend(_guard_evidence_text(guard) for guard in guard_objects)
        candidates.append(
            {
                "edge_id": f"{case.get('case_id')}_{enclosing}_to_{callee_symbol}_line_{definition.get('line')}",
                "caller": caller,
                "callsite": callsite.get("expr"),
                "callee": f"{definition.get('qualified_hint')}.line_{definition.get('line')}",
                "callee_kind": "rebound_function",
                "repair_mechanism": "direct_static_edge",
                "confidence": 0.86 if branch_guards else 0.76,
                "guards": [_guard_text(guard) for guard in guard_objects],
                "guard_evidence": guard_objects,
                "evidence": evidence_items,
                "contract": {
                    "preconditions": [_guard_text(guard) for guard in guard_objects],
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
                        "argument count is incompatible",
                        "static branch guard evidence is not satisfied",
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
    evidence_kind = evidence.get("kind") if evidence else None
    classification = _classify_ccec(evidence, static_candidates, top_k)
    mode = classification["mode"]
    profile = classification["profile"]
    llm_required = classification["llm_required"]
    generation_strategy = classification["generation_strategy"]
    recommended_top_k = classification["recommended_top_k"]
    reason = classification["reason"]

    report = {
        "schema_version": "lapis.ccec_repair_plan.v1",
        "case_id": case.get("case_id"),
        "case": str(case_path),
        "candidate_gap_type": "connectivity_gap",
        "declared_case_group": case.get("gap_type"),
        "declared_repair_branch": case.get("repair_branch"),
        "mode": mode,
        "mode_profile": profile,
        "metadata_difficulty": None,
        "llm_required": llm_required,
        "generation_strategy": generation_strategy,
        "top_k": recommended_top_k,
        "candidate_count_from_static_rules": len(static_candidates),
        "evidence_kind": evidence_kind,
        "evidence_summary": {
            "observed_callsite": evidence.get("observed_callsite") if evidence else None,
            "candidate_definition_count": len(evidence.get("candidate_definitions", [])) if evidence else 0,
            "factory_call_count": len(evidence.get("factory_calls", [])) if evidence else 0,
            "factory_method_branch_count": len(evidence.get("factory_method_branches", [])) if evidence else 0,
            "dynamic_type_site_count": len(evidence.get("dynamic_type_sites", [])) if evidence else 0,
        },
        "next_steps": _plan_next_steps(mode, llm_required, generation_strategy),
        "validation_plan": {
            "structural": "validate-ccec-candidates",
            "link_samples": "LLM generates must-link / must-not-link / must-kill",
            "link_validation": "validate-ccec-link-contract",
            "consumer": profile["repair_consumer"],
            "strength": profile["validation_strength"],
        },
        "reason": reason,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def _plan_next_steps(mode: str, llm_required: bool, generation_strategy: str) -> list[str]:
    if mode == "deferred":
        return ["defer"]
    steps = ["build_baseline_facts", "build_static_evidence_from_baseline"]
    if mode == "easy":
        steps.append("generate_ccec_candidates_rule_only")
    elif mode == "middle":
        steps.extend(["generate_top_k_static_candidates", "build_ccec_prompt", "llm_rank_and_refine_guards"])
    else:
        steps.extend(["build_ccec_prompt", "llm_synthesize_dynamic_or_virtual_edge_contract"])
    steps.extend(
        [
            "validate_ccec_candidates",
            "build_ccec_validation_prompt",
            "llm_generate_must_link_must_not_link_must_kill",
            "validate_ccec_link_contract",
        ]
    )
    if mode == "easy":
        steps.append("apply_real_or_rebound_edge")
    elif mode == "middle":
        steps.append("apply_guarded_ranked_edge")
    else:
        steps.append("apply_virtual_edge_consumer_if_needed")
    return steps


def build_ccec_candidates(
    case_path: Path,
    out_path: Path,
    top_k: int = 5,
    strategy: str = "static",
) -> dict[str, Any]:
    case_path = case_path.resolve()
    case = load_json(case_path)
    if strategy != "static":
        raise ValueError(f"unknown CCEC generation strategy: {strategy}")
    evidence = _static_ccec_evidence(case)
    static_candidates = _static_candidates(case)
    classification = _classify_ccec(evidence, static_candidates, top_k)
    candidates = static_candidates[: classification["recommended_top_k"] or top_k]
    for edge in candidates:
        edge["ccec_mode"] = classification["mode"]
        edge["repair_mechanism"] = edge.get("repair_mechanism") or classification["profile"]["mechanism"]
    report = {
        "schema_version": "lapis.ccec_candidates.v1",
        "case_id": case.get("case_id"),
        "case": str(case_path),
        "candidate_gap_type": "connectivity_gap",
        "declared_case_group": case.get("gap_type"),
        "declared_repair_branch": case.get("repair_branch"),
        "ccec_mode": classification["mode"],
        "mode_profile": classification["profile"],
        "llm_required": classification["llm_required"],
        "generation_strategy": strategy,
        "routing_strategy": classification["generation_strategy"],
        "static_candidate_count": len(static_candidates),
        "candidate_edges": candidates,
        "generation_limits": {
            "oracle_blind": True,
            "candidate_source": classification["profile"]["candidate_source"],
            "llm_role": classification["profile"]["llm_role"],
        },
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
            for key in ("edge_id", "caller", "callsite", "callee", "guards", "guard_evidence", "evidence")
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
                    "has_guard_evidence": bool(edge.get("guard_evidence")),
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
    status = (
        "accepted"
        if sample_results
        and all(item["passed"] for item in sample_results)
        and all(item["covered"] for item in edge_coverage)
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
        "note": (
            "CCEC link validation checks LLM-generated must-link, must-not-link, "
            "and must-kill samples. It validates call-edge contracts, not CTPC dataflow."
        ),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def _sample_key(name: str) -> str:
    return name.replace("_", "-")


def _sample_from_response(response: dict[str, Any], sample_key: str) -> dict[str, Any]:
    local_samples = response.get("local_samples") or {}
    if isinstance(local_samples, dict):
        sample = local_samples.get(sample_key) or local_samples.get(sample_key.replace("-", "_"))
        if isinstance(sample, dict):
            return sample

    legacy_key = sample_key.replace("-", "_")
    entries = response.get(legacy_key) or response.get(sample_key)
    if isinstance(entries, list) and entries and isinstance(entries[0], dict):
        return entries[0]
    if isinstance(entries, dict):
        return entries
    raise ValueError(f"{sample_key} local sample is required")


def materialize_ccec_validation(response_path: Path, out_dir: Path) -> dict[str, Path]:
    """Write LLM-generated CCEC local validation samples to ccec-validation/."""

    response = load_json(response_path.resolve())
    validation_dir = out_dir / "ccec-validation"
    validation_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    for sample_key, expected in CCEC_REQUIRED_SAMPLES.items():
        sample = _sample_from_response(response, sample_key)
        code = sample.get("code")
        if not isinstance(code, str) or not code.strip():
            raise ValueError(f"{sample_key}.code must be non-empty")
        if sample.get("expected") != expected:
            raise ValueError(f"{sample_key}.expected must be {expected!r}")
        sample_dir = validation_dir / sample_key
        sample_dir.mkdir(parents=True, exist_ok=True)
        code_path = sample_dir / "case.py"
        expected_path = sample_dir / "expected.json"
        code_path.write_text(code.rstrip() + "\n", encoding="utf-8")
        expected_path.write_text(
            json.dumps(
                {
                    "name": sample.get("name", sample_key),
                    "expected": expected,
                    "edge_id": sample.get("edge_id"),
                    "caller": sample.get("caller"),
                    "callsite": sample.get("callsite"),
                    "callee": sample.get("callee"),
                    "guards": sample.get("guards", []),
                    "violated_guard": sample.get("violated_guard"),
                    "kill_condition": sample.get("kill_condition"),
                    "evidence": sample.get("evidence", []),
                },
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
        written[f"{sample_key}_code"] = code_path
        written[f"{sample_key}_expected"] = expected_path

    return written


def _syntax_ok(path: Path) -> tuple[bool, str | None]:
    try:
        ast.parse(path.read_text(encoding="utf-8"))
        return True, None
    except SyntaxError as error:
        return False, str(error)


def _matches_candidate(expected: dict[str, Any], candidates: dict[str, Any]) -> bool:
    edges = candidates.get("candidate_edges", []) or []
    edge_id = expected.get("edge_id")
    caller = expected.get("caller")
    callsite = expected.get("callsite")
    callee = expected.get("callee")
    for edge in edges:
        if edge_id and edge.get("edge_id") == edge_id:
            return True
        if caller and callsite and callee:
            if edge.get("caller") == caller and edge.get("callsite") == callsite and edge.get("callee") == callee:
                return True
    return False


def validate_ccec_local_samples(validation_dir: Path, candidates_path: Path, out_path: Path) -> dict[str, Any]:
    """Validate CCEC local semantic sample structure before YASA callgraph rerun."""

    candidates = load_json(candidates_path.resolve())
    sample_results = []
    for sample_key, expected_value in CCEC_REQUIRED_SAMPLES.items():
        sample_dir = validation_dir / sample_key
        code_path = sample_dir / "case.py"
        expected_path = sample_dir / "expected.json"
        expected = load_json(expected_path) if expected_path.exists() else {"expected": expected_value}
        syntax_ok, syntax_error = _syntax_ok(code_path) if code_path.exists() else (False, f"missing {code_path}")
        target_covered = _matches_candidate(expected, candidates)
        has_required_negative = True
        if sample_key == "must-not-link":
            has_required_negative = bool(expected.get("violated_guard"))
        if sample_key == "must-kill":
            has_required_negative = bool(expected.get("kill_condition"))
        passed = (
            expected.get("expected") == expected_value
            and syntax_ok
            and target_covered
            and has_required_negative
        )
        sample_results.append(
            {
                "sample": sample_key,
                "expected": expected.get("expected"),
                "syntax_ok": syntax_ok,
                "syntax_error": syntax_error,
                "target_covered": target_covered,
                "has_required_negative_condition": has_required_negative,
                "passed": passed,
                "expected_file": str(expected_path),
                "code_file": str(code_path),
            }
        )

    status = "accepted" if all(item["passed"] for item in sample_results) else "rejected"
    report = {
        "schema_version": "lapis.ccec_local_validation.v1",
        "candidates": str(candidates_path.resolve()),
        "validation_dir": str(validation_dir.resolve()),
        "status": status,
        "sample_results": sample_results,
        "next_runner": {
            "kind": "yasa-callgraph-in-the-loop",
            "state": "ready_for_run_yasa_case_or_future_run_yasa_ccec_validation",
            "purpose": (
                "Run YASA with --lapisCcecFile and callgraph output, then check "
                "edge_present/edge_absent/edge_suppressed expectations."
            ),
        },
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report
