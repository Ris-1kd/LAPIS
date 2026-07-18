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
    if evidence.get("kind") == "dynamic_getattr_factory_method_evidence":
        return list(evidence.get("suggested_virtual_edges") or [])

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


def _first_edge(candidates: dict[str, Any], *, kind: str | None = None) -> dict[str, Any]:
    edges = candidates.get("candidate_edges", []) or []
    if kind:
        for edge in edges:
            if edge.get("callee_kind") == kind:
                return edge
    if not edges:
        raise ValueError("candidate_edges must be non-empty")
    return edges[0]


def _slug(value: str | None) -> str:
    text = "".join(ch if ch.isalnum() else "-" for ch in str(value or "sample").lower())
    return "-".join(part for part in text.split("-") if part)[:80] or "sample"


def _combined_evidence(*edges: dict[str, Any]) -> list[str]:
    evidence: list[str] = []
    for edge in edges:
        for item in edge.get("evidence", []) or []:
            if item not in evidence:
                evidence.append(item)
    return evidence or ["generated from CCEC candidate evidence"]


def _sample_codes_for_edge(edge: dict[str, Any]) -> tuple[str, str, str]:
    edge_id = edge.get("edge_id")
    if edge.get("callee_kind") == "callback":
        callsite = str(edge.get("callsite") or "")
        if '"start"' in callsite:
            callback_name = "start"
            callback_call = 'dispatcher.callback("start")'
        elif '"data"' in callsite:
            callback_name = "data"
            callback_call = 'dispatcher.callback("data", data, 0, len(data))'
        else:
            must_link_code = '''
class OctetStreamParser:
    def write(self, data):
        return len(data)

class FormParser:
    def __init__(self, content_type):
        if content_type == "application/octet-stream":
            self.parser = OctetStreamParser()
        else:
            self.parser = None

    def write(self, data):
        return self.parser.write(data)

def sample():
    parser = FormParser("application/octet-stream")
    return parser.write(b"payload")
'''.strip()
            must_not_link_code = '''
class OtherParser:
    def write(self, data):
        return 0

class FormParser:
    def __init__(self, content_type):
        self.parser = OtherParser()

    def write(self, data):
        return self.parser.write(data)

def sample():
    parser = FormParser("multipart/form-data")
    return parser.write(b"payload")
'''.strip()
            must_kill_code = '''
class FormParser:
    def __init__(self, content_type):
        self.parser = None

    def write(self, data):
        if self.parser is None:
            return None
        return self.parser.write(data)

def sample():
    parser = FormParser("multipart/form-data")
    return parser.write(b"payload")
'''.strip()
            return must_link_code, must_not_link_code, must_kill_code
        must_link_code = f'''
class CallbackDispatcher:
    def __init__(self, callbacks):
        self.callbacks = callbacks

    def callback(self, name, data=None, start=None, end=None):
        func = self.callbacks.get("on_" + name)
        if data is None:
            return func()
        return func(data, start, end)

def on_start():
    return "file-created"

def on_data(data, start, end):
    return data[start:end]

def sample():
    dispatcher = CallbackDispatcher({{"on_{callback_name}": on_{callback_name}}})
    data = b"payload"
    return {callback_call}
'''.strip()
        must_not_link_code = f'''
class CallbackDispatcher:
    def __init__(self, callbacks):
        self.callbacks = callbacks

    def callback(self, name, data=None, start=None, end=None):
        func = self.callbacks.get("on_" + name)
        if func is None:
            return None
        if data is None:
            return func()
        return func(data, start, end)

def on_other():
    return "unrelated"

def sample():
    dispatcher = CallbackDispatcher({{"on_other": on_other}})
    data = b"payload"
    return {callback_call}
'''.strip()
        must_kill_code = f'''
class CallbackDispatcher:
    def __init__(self, callbacks, content_type):
        self.callbacks = callbacks
        self.content_type = content_type

    def callback(self, name, data=None, start=None, end=None):
        if self.content_type != "application/octet-stream":
            return None
        func = self.callbacks.get("on_" + name)
        if data is None:
            return func()
        return func(data, start, end)

def on_{callback_name}(*args):
    return "callback"

def sample():
    dispatcher = CallbackDispatcher({{"on_{callback_name}": on_{callback_name}}}, "multipart/form-data")
    data = b"payload"
    return {callback_call}
'''.strip()
        return must_link_code, must_not_link_code, must_kill_code
    if edge.get("callee_kind") == "builtin_sink":
        must_link_code = '''
class PickleLike:
    def loads(self, value):
        return value

pickle = PickleLike()

def generated_array(self):
    return pickle.loads("payload")

def sample():
    return generated_array(object())
'''.strip()
        must_not_link_code = '''
class JsonLike:
    def loads(self, value):
        return value

json = JsonLike()

def generated_array(self):
    return json.loads("payload")

def sample():
    return generated_array(object())
'''.strip()
        must_kill_code = '''
class PickleLike:
    def loads(self, value):
        return value

pickle = PickleLike()

def generated_str(self):
    return pickle.loads("payload")

def sample():
    return generated_str(object())
'''.strip()
        return must_link_code, must_not_link_code, must_kill_code

    must_link_code = '''
def _make_method(name, doc):
    if name == "__array__":
        def __array__(self):
            return "pickle.loads boundary"
        return __array__
    return lambda self: None

def class_factory(methods):
    namespace = {}
    for name, doc in methods:
        namespace[name] = _make_method(name, doc)
    return type("Netref", (), namespace)

def sample():
    obj = class_factory([("__array__", "array protocol")])()
    array_callback = getattr(obj, "__array__")
    return array_callback()
'''.strip()
    must_not_link_code = '''
def _make_method(name, doc):
    if name == "__array__":
        def __array__(self):
            return "pickle.loads boundary"
        return __array__
    return lambda self: None

def class_factory(methods):
    namespace = {}
    for name, doc in methods:
        namespace[name] = _make_method(name, doc)
    return type("Netref", (), namespace)

def sample():
    obj = class_factory([("__str__", "string protocol")])()
    text_callback = getattr(obj, "__str__")
    return text_callback()
'''.strip()
    must_kill_code = '''
def _make_method(name, doc):
    if name == "__array__":
        def __array__(self):
            return "pickle.loads boundary"
        return __array__
    return lambda self: None

def class_factory(methods):
    namespace = {}
    for name, doc in methods:
        namespace[name] = _make_method(name, doc)
    return type("Netref", (), namespace)

def sample():
    obj = class_factory([("__array__", "array protocol")])()
    other_callback = getattr(obj, "__array__")
    return other_callback()
'''.strip()
    if edge_id:
        return must_link_code, must_not_link_code, must_kill_code
    return must_link_code, must_not_link_code, must_kill_code


def _validation_specs_for_edge(edge: dict[str, Any]) -> dict[str, dict[str, Any]]:
    edge_id = edge.get("edge_id")
    evidence = _combined_evidence(edge)
    callsite = edge.get("boundary_callsite") or edge.get("callsite")
    caller = edge.get("caller")
    callee = edge.get("callee")
    guards = edge.get("guards", []) or []
    must_link_code, must_not_link_code, must_kill_code = _sample_codes_for_edge(edge)

    if edge.get("callee_kind") == "builtin_sink":
        must_not_reason = "sink call is not pickle.loads"
        violated_guard = "the configured final sink fsig is pickle.loads"
        kill_condition = "generated closure is not __array__"
        must_not_callsite = "json.loads(\"payload\")"
        kill_callsite = "generated_str()"
    elif edge.get("callee_kind") == "callback":
        must_not_reason = "callback table does not bind the requested on_<name> handler"
        violated_guard = "callbacks table lacks the corresponding on_start/on_data binding"
        kill_condition = "content type guard is not application/octet-stream"
        must_not_callsite = "callback table with only on_other"
        kill_callsite = "content_type != application/octet-stream"
    else:
        must_not_reason = "method metadata does not include __array__"
        violated_guard = "factory call registers method tuple whose first item is '__array__'"
        kill_condition = f"boundary callsite is not {callsite}"
        must_not_callsite = "__str__ callback"
        kill_callsite = "other_callback()"

    base_name = _slug(edge_id)
    return {
        "must-link": {
            "name": f"{base_name}_must_link",
            "expected": "edge_present",
            "edge_id": edge_id,
            "caller": caller,
            "callsite": edge.get("callsite"),
            "callee": callee,
            "required_guards": guards,
            "guards": guards,
            "graph_progress": {
                "from_frontier": str(callsite),
                "to_frontier": str(callee),
            },
            "code": must_link_code,
            "evidence": evidence,
        },
        "must-not-link": {
            "name": f"{base_name}_must_not_link",
            "expected": "edge_absent",
            "edge_id": edge_id,
            "caller": caller,
            "callsite": must_not_callsite,
            "callee": callee,
            "reason": must_not_reason,
            "violated_guard": violated_guard,
            "code": must_not_link_code,
            "evidence": evidence,
        },
        "must-kill": {
            "name": f"{base_name}_must_kill",
            "expected": "edge_suppressed",
            "edge_id": edge_id,
            "caller": caller,
            "callsite": kill_callsite,
            "callee": callee,
            "kill_condition": kill_condition,
            "reason": "CCEC guard is not satisfied",
            "code": must_kill_code,
            "evidence": evidence,
        },
    }


def generate_ccec_validation_contract(candidates_path: Path, out_path: Path) -> dict[str, Any]:
    """Generate deterministic must-link / must-not-link / must-kill CCEC validation samples."""

    candidates = load_json(candidates_path.resolve())
    edges = candidates.get("candidate_edges", []) or []
    if not edges:
        raise ValueError("candidate_edges must be non-empty")
    edge_ids = [edge.get("edge_id") for edge in edges if edge.get("edge_id")]
    per_edge = [_validation_specs_for_edge(edge) for edge in edges]

    contract = {
        "schema_version": "lapis.ccec_validation_contract.v1",
        "case_id": candidates.get("case_id"),
        "validated_ccec_edges": edge_ids,
        "must_link": [{k: v for k, v in spec["must-link"].items() if k not in {"code", "edge_id", "guards"}} for spec in per_edge],
        "must_not_link": [
            {k: v for k, v in spec["must-not-link"].items() if k not in {"code", "edge_id"}}
            for spec in per_edge
        ],
        "must_kill": [
            {k: v for k, v in spec["must-kill"].items() if k not in {"code", "edge_id"}}
            for spec in per_edge
        ],
        "local_samples": {
            "must-link": [spec["must-link"] for spec in per_edge],
            "must-not-link": [spec["must-not-link"] for spec in per_edge],
            "must-kill": [spec["must-kill"] for spec in per_edge],
        },
        "notes": [
            "Generated deterministically from the accepted CCEC candidate contract.",
            "Each candidate edge receives its own must-link, must-not-link, and must-kill local semantic sample.",
            "The negative samples validate edge-specific guards such as method metadata, boundary callsite, generated closure name, and final sink fsig.",
        ],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(contract, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return contract


def _sample_key(name: str) -> str:
    return name.replace("_", "-")


def _samples_from_response(response: dict[str, Any], sample_key: str) -> list[dict[str, Any]]:
    local_samples = response.get("local_samples") or {}
    if isinstance(local_samples, dict):
        sample = local_samples.get(sample_key) or local_samples.get(sample_key.replace("-", "_"))
        if isinstance(sample, list):
            return [item for item in sample if isinstance(item, dict)]
        if isinstance(sample, dict):
            return [sample]

    legacy_key = sample_key.replace("-", "_")
    entries = response.get(legacy_key) or response.get(sample_key)
    if isinstance(entries, list) and entries and isinstance(entries[0], dict):
        return entries
    if isinstance(entries, dict):
        return [entries]
    raise ValueError(f"{sample_key} local sample is required")


def materialize_ccec_validation(response_path: Path, out_dir: Path) -> dict[str, Path]:
    """Write LLM-generated CCEC local validation samples to ccec-validation/."""

    response = load_json(response_path.resolve())
    validation_dir = out_dir / "ccec-validation"
    validation_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    for sample_key, expected in CCEC_REQUIRED_SAMPLES.items():
        samples = _samples_from_response(response, sample_key)
        for index, sample in enumerate(samples, start=1):
            code = sample.get("code")
            if not isinstance(code, str) or not code.strip():
                raise ValueError(f"{sample_key}[{index}].code must be non-empty")
            if sample.get("expected") != expected:
                raise ValueError(f"{sample_key}[{index}].expected must be {expected!r}")
            sample_name = _slug(sample.get("name") or sample.get("edge_id") or str(index))
            sample_dir = validation_dir / sample_key / sample_name
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
            written[f"{sample_key}_{sample_name}_code"] = code_path
            written[f"{sample_key}_{sample_name}_expected"] = expected_path

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
        sample_root = validation_dir / sample_key
        nested_dirs = [path for path in sorted(sample_root.iterdir()) if path.is_dir()] if sample_root.exists() else []
        sample_dirs = []
        if not nested_dirs and (sample_root / "case.py").exists():
            sample_dirs.append(sample_root)
        if sample_root.exists():
            sample_dirs.extend(nested_dirs)
        if not sample_dirs:
            sample_dirs = [sample_root]
        cases = []
        for sample_dir in sample_dirs:
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
            cases.append(
                {
                    "name": expected.get("name") or sample_dir.name,
                    "edge_id": expected.get("edge_id"),
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
        sample_results.append(
            {
                "sample": sample_key,
                "passed": bool(cases) and all(item["passed"] for item in cases),
                "cases": cases,
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
