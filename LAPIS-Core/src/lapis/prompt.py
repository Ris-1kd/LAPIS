"""Prompt construction for LAPIS synthesis steps."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any


def _compact_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "case_id": evidence["case_id"],
        "project": evidence["project"],
        "vulnerability": evidence["vulnerability"],
        "baseline_status": evidence["baseline_status"],
        "source": evidence["source"],
        "sink": evidence["sink"],
        "source_forward_slice": evidence["source_forward_slice"],
        "sink_backward_slice": evidence["sink_backward_slice"],
        "local_structure_evidence": evidence["local_structure_evidence"],
        "local_convergence": evidence["local_convergence"],
        "top_k_edges": evidence["top_k_edges"],
    }


def build_ctpc_prompt(evidence: dict[str, Any]) -> str:
    """Build a deterministic prompt for CTPC synthesis only."""

    evidence_json = json.dumps(_compact_evidence(evidence), indent=2, ensure_ascii=False)

    return f"""You are synthesizing a Conditional Taint Propagation Contract (CTPC).

Use only the Evidence Pack below. Do not invent source functions, sink functions,
variables, files, or edges that are not supported by the evidence.

Goal:
- Explain the missing access-path propagation.
- Synthesize a CTPC that propagates only under the structural guards supported
  by the evidence.
- Do not generate validation programs in this step. Validation sample generation
  is handled by a separate module.

Return one JSON object with this exact top-level shape. Conditions must be
machine-readable: use event + pattern + effect fields. Keep natural-language
explanations only in description/evidence fields.

{{
  "schema_version": "ctpc.v2",
  "contract_name": "string",
  "gap_type": ["string"],
  "applies_to": {{
    "language": "python",
    "risk_kind": "string"
  }},
  "fact_types": [
    {{
      "name": "string",
      "shape": {{"access_path": "string"}}
    }}
  ],
  "propagation_edges": [
    {{
      "edge_id": "string",
      "event": "assignment | binary_operation | function_call | return | member_access | if_condition | sink",
      "pattern": {{"kind": "string"}},
      "from": {{"fact": "string", "expr": "string"}},
      "to": {{"fact": "string", "expr": "string", "access_path": "string", "risk_kind": "string"}},
      "evidence": {{"file": "string", "line": 0, "code": "string"}},
      "description": "string"
    }}
  ],
  "function_summaries": [
    {{
      "summary_id": "string",
      "event": "function_call | return",
      "pattern": {{
        "kind": "return_fact_from_argument",
        "callee": "string",
        "argument_index": 0,
        "receiver_policy": "any | exact"
      }},
      "from": {{"fact": "string", "expr": "$arg0.access_path"}},
      "to": {{"fact": "string", "expr": "$return", "access_path": "$return.access_path", "risk_kind": "string"}},
      "evidence": {{"file": "string", "line": 0, "code": "string"}}
    }}
  ],
  "risk_upgrades": [
    {{
      "upgrade_id": "string",
      "event": "assignment | binary_operation | function_call | return | member_access | sink",
      "pattern": {{"kind": "string"}},
      "from": {{"fact": "string", "expr": "string"}},
      "to": {{"fact": "string", "expr": "string"}},
      "risk_kind": "string"
    }}
  ],
  "kill_conditions": [
    {{
      "kill_id": "string",
      "event": "if_condition | assignment | function_call | sink",
      "pattern": {{"kind": "string"}},
      "effect": {{"action": "suppress", "risk_kind": "string", "for_fact": "string"}},
      "evidence": {{"file": "string", "line": 0, "code": "string"}}
    }}
  ],
  "validation_expectations": {{
    "must_flow": "finding",
    "must_not_flow": "no_finding",
    "must_kill": "no_finding"
  }},
  "description": "string",
  "notes": ["string"]
}}

Evidence Pack:

```json
{evidence_json}
```
"""


def _compact_ccec_payload(
    case: dict[str, Any],
    gate: dict[str, Any] | None = None,
    diagnosis: dict[str, Any] | None = None,
    oracle_safe: bool = False,
) -> dict[str, Any]:
    return _compact_oracle_safe_ccec_payload(case, gate, diagnosis)


def _first_frontier_item(items: list[Any]) -> Any:
    return items[0] if items else None


def _oracle_safe_frontier(frontier: dict[str, Any] | None) -> dict[str, Any] | None:
    if not frontier:
        return None
    reached = frontier.get("reached") or []
    observations = frontier.get("observations") or []
    return {
        "available": frontier.get("available"),
        "observed_boundary": _first_frontier_item(reached) or frontier.get("frontier"),
        "observations": observations[:1],
        "note": "Only the first observed frontier/boundary is exposed; downstream benchmark chain is hidden.",
    }


def _oracle_safe_sink_dependency(dependency: dict[str, Any] | None) -> dict[str, Any] | None:
    if not dependency:
        return None
    chain = dependency.get("dependency_chain") or []
    observations = dependency.get("observations") or []
    return {
        "available": dependency.get("available"),
        "sink": dependency.get("sink") or _first_frontier_item(chain),
        "argument_or_local_dependency": chain[1] if len(chain) > 1 else None,
        "observations": observations[:2],
        "note": "Only sink-local dependencies are exposed; source-to-sink benchmark path is hidden.",
    }


def _oracle_safe_structure(structure: dict[str, Any] | None) -> dict[str, Any] | None:
    if not structure:
        return None
    return {
        "available": structure.get("available"),
        "kinds": structure.get("kinds", []),
        "note": "Case metadata summaries/frontier arrays are omitted in oracle-safe mode.",
    }


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return f"{_call_name(node.func)}(...)"
    return ""


def _source_segment(text: str, node: ast.AST) -> str:
    return ast.get_source_segment(text, node) or node.__class__.__name__


def _parse_boundary(boundary: str | None) -> tuple[str, int, str] | None:
    if not boundary:
        return None
    match = re.match(r"^(?P<file>.+?):(?P<line>\d+)\s+(?P<expr>.+)$", boundary)
    if not match:
        return None
    return match.group("file"), int(match.group("line")), match.group("expr")


def _resolve_dataset_file(dataset_dir: Path, relative_file: str) -> Path | None:
    path = dataset_dir / relative_file
    if path.exists():
        return path
    matches = sorted(dataset_dir.rglob(Path(relative_file).name))
    return matches[0] if matches else None


def _function_at_line(module: ast.Module, line: int) -> ast.FunctionDef | None:
    matches = [
        node
        for node in ast.walk(module)
        if isinstance(node, ast.FunctionDef)
        and getattr(node, "lineno", 0) <= line <= getattr(node, "end_lineno", node.lineno)
    ]
    if not matches:
        return None
    return max(matches, key=lambda node: node.lineno)


def _calls_at_line(module: ast.Module, line: int) -> list[ast.Call]:
    return [node for node in ast.walk(module) if isinstance(node, ast.Call) and getattr(node, "lineno", 0) == line]


def _if_guard_for_function(module: ast.Module, function: ast.FunctionDef, text: str, file_name: str) -> list[dict[str, Any]]:
    def if_guard(statement: ast.If, branch: str, condition: str) -> dict[str, Any]:
        return {
            "condition": condition,
            "derived_from": "ast_control_flow_guard",
            "evidence": {
                "file": file_name,
                "line": statement.lineno,
                "code": _source_segment(text, statement.test),
                "branch": branch,
            },
        }

    def try_guard(handler: ast.ExceptHandler) -> dict[str, Any]:
        handler_type = _source_segment(text, handler.type) if handler.type else "Exception"
        return {
            "condition": f"except {handler_type}",
            "derived_from": "ast_exception_handler_guard",
            "evidence": {
                "file": file_name,
                "line": handler.lineno,
                "code": handler_type,
            },
        }

    def visit_statements(statements: list[ast.stmt], guards: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
        for statement in statements:
            if statement is function:
                return guards
            if isinstance(statement, ast.If):
                test = _source_segment(text, statement.test)
                found = visit_statements(statement.body, guards + [if_guard(statement, "body", test)])
                if found is not None:
                    return found
                found = visit_statements(statement.orelse, guards + [if_guard(statement, "orelse", f"else of ({test})")])
                if found is not None:
                    return found
            elif isinstance(statement, ast.Try):
                found = visit_statements(statement.body, guards)
                if found is not None:
                    return found
                for handler in statement.handlers:
                    found = visit_statements(handler.body, guards + [try_guard(handler)])
                    if found is not None:
                        return found
                found = visit_statements(statement.orelse, guards)
                if found is not None:
                    return found
                found = visit_statements(statement.finalbody, guards)
                if found is not None:
                    return found
            else:
                child_bodies = [
                    getattr(statement, name)
                    for name in ("body", "orelse", "finalbody")
                    if isinstance(getattr(statement, name, None), list)
                ]
                for body in child_bodies:
                    found = visit_statements(body, guards)
                    if found is not None:
                        return found
        return None

    return visit_statements(module.body, []) or []


def _literal_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Str):
        return node.s
    return None


def _literal_string_tuples(node: ast.AST) -> list[tuple[str, ...]]:
    tuples: list[tuple[str, ...]] = []
    if not isinstance(node, (ast.List, ast.Tuple)):
        return tuples
    for element in node.elts:
        if not isinstance(element, ast.Tuple):
            continue
        values = tuple(value for value in (_literal_string(item) for item in element.elts) if value is not None)
        if values:
            tuples.append(values)
    return tuples


def _extract_dynamic_factory_evidence(
    dataset_dir: Path,
    relative_file: str,
    line: int,
    expr: str,
    module: ast.Module,
    text: str,
) -> dict[str, Any] | None:
    calls = _calls_at_line(module, line)
    getattr_call = next((call for call in calls if _call_name(call.func) == "getattr"), None)
    if not getattr_call or len(getattr_call.args) < 2:
        return None
    attribute_name = _literal_string(getattr_call.args[1])
    if not attribute_name:
        return None

    enclosing = _function_at_line(module, line)
    factory_calls = []
    for file_path in sorted(dataset_dir.rglob("*.py")):
        try:
            file_text = file_path.read_text(encoding="utf-8")
            file_module = ast.parse(file_text)
        except (SyntaxError, UnicodeDecodeError):
            continue
        rel = str(file_path.relative_to(dataset_dir))
        for call in ast.walk(file_module):
            if not isinstance(call, ast.Call):
                continue
            call_expr = _source_segment(file_text, call)
            if attribute_name not in call_expr:
                continue
            method_literals = []
            for arg in call.args:
                method_literals.extend(_literal_string_tuples(arg))
            factory_calls.append(
                {
                    "file": rel,
                    "line": call.lineno,
                    "callee": _call_name(call.func),
                    "expr": call_expr,
                    "method_literals": method_literals,
                    "mentions_observed_attribute": attribute_name in call_expr,
                }
            )

    factory_method_branches = []
    dynamic_type_sites = []
    for file_path in sorted(dataset_dir.rglob("*.py")):
        try:
            file_text = file_path.read_text(encoding="utf-8")
            file_module = ast.parse(file_text)
        except (SyntaxError, UnicodeDecodeError):
            continue
        rel = str(file_path.relative_to(dataset_dir))
        for call in ast.walk(file_module):
            if isinstance(call, ast.Call) and _call_name(call.func) == "type" and len(call.args) == 3:
                dynamic_type_sites.append(
                    {"file": rel, "line": call.lineno, "expr": _source_segment(file_text, call)}
                )
        for func in ast.walk(file_module):
            if not isinstance(func, ast.FunctionDef):
                continue
            for branch in ast.walk(func):
                if not isinstance(branch, ast.If):
                    continue
                test = _source_segment(file_text, branch.test)
                if attribute_name not in test:
                    continue
                inner_functions = []
                body_nodes = [descendant for statement in branch.body for descendant in ast.walk(statement)]
                for child in body_nodes:
                    if isinstance(child, ast.FunctionDef) and child is not func:
                        inner_functions.append(
                            {
                                "name": child.name,
                                "line": child.lineno,
                                "args": [arg.arg for arg in child.args.args],
                            }
                        )
                factory_method_branches.append(
                    {
                        "file": rel,
                        "line": branch.lineno,
                        "factory_function": func.name,
                        "guard": {
                            "condition": test,
                            "derived_from": "ast_control_flow_guard",
                            "evidence": {
                                "file": rel,
                                "line": branch.lineno,
                                "code": test,
                            },
                        },
                        "inner_functions": inner_functions,
                    }
                )

    return {
        "kind": "dynamic_getattr_factory_method_evidence",
        "observed_callsite": {
            "file": relative_file,
            "line": line,
            "expr": expr,
            "enclosing_function": enclosing.name if enclosing else None,
            "attribute_name": attribute_name,
        },
        "factory_calls": factory_calls,
        "factory_method_branches": factory_method_branches,
        "dynamic_type_sites": dynamic_type_sites,
        "ranking_hints": [
            "Connect getattr(obj, observed_attribute) only to factory methods that materialize the same attribute.",
            "Prefer factory branches whose guard equals the observed attribute name.",
            "Require a dynamic type(..., namespace) site before materializing generated methods.",
        ],
    }


def _static_ccec_evidence(case: dict[str, Any]) -> dict[str, Any] | None:
    dataset_dir = case.get("dataset_dir")
    public_callsite = case.get("observed_callsite") or case.get("public_callsite")
    if isinstance(public_callsite, dict):
        boundary = (
            public_callsite.get("file"),
            int(public_callsite.get("line", 0) or 0),
            public_callsite.get("expr", ""),
        )
    else:
        # Do not read case["breakpoint"].frontier here. That field is benchmark
        # oracle material and must be hidden during repair synthesis.
        boundary = None
    if not dataset_dir or not boundary:
        return None

    relative_file, line, expr = boundary
    dataset_path = Path(dataset_dir)
    path = _resolve_dataset_file(dataset_path, relative_file)
    if path is None or not path.exists() or path.suffix != ".py":
        return None

    relative_file = str(path.relative_to(dataset_path))
    text = path.read_text(encoding="utf-8")
    module = ast.parse(text)
    enclosing = _function_at_line(module, line)
    calls = _calls_at_line(module, line)
    call = calls[0] if calls else None
    callee_symbol = _call_name(call.func) if call else None
    dynamic_evidence = _extract_dynamic_factory_evidence(
        dataset_path,
        relative_file,
        line,
        expr,
        module,
        text,
    )
    if dynamic_evidence:
        return dynamic_evidence

    candidate_definitions = []
    if callee_symbol and "." not in callee_symbol:
        for node in ast.walk(module):
            if not isinstance(node, ast.FunctionDef) or node.name != callee_symbol:
                continue
            candidate_definitions.append(
                {
                    "file": relative_file,
                    "line": node.lineno,
                    "function": node.name,
                    "qualified_hint": f"{relative_file[:-3].replace('/', '.')}.{node.name}",
                    "guards": _if_guard_for_function(module, node, text, relative_file),
                    "args": [arg.arg for arg in node.args.args],
                }
            )

    return {
        "kind": "static_python_callsite_and_candidate_definitions",
        "observed_callsite": {
            "file": relative_file,
            "line": line,
            "expr": expr,
            "enclosing_function": enclosing.name if enclosing else None,
            "callee_symbol": callee_symbol,
            "args": [_source_segment(text, arg) for arg in call.args] if call else [],
        },
        "candidate_definitions": candidate_definitions,
        "ranking_hints": [
            "Prefer definitions whose name matches the observed callee symbol.",
            "Prefer candidates whose guard explains dynamic rebinding or platform dispatch.",
        ],
    }


def _compact_oracle_safe_ccec_payload(
    case: dict[str, Any],
    gate: dict[str, Any] | None = None,
    diagnosis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    gate_payload = None
    if gate:
        gate_payload = {
            "gate_status": gate.get("gate_status"),
            "baseline_status": gate.get("baseline_status"),
            "source_forward_frontier": _oracle_safe_frontier(gate.get("source_forward_frontier")),
            "sink_backward_dependency": _oracle_safe_sink_dependency(gate.get("sink_backward_dependency")),
            "symbolic_callee": gate.get("symbolic_callee"),
            "local_structure_evidence": _oracle_safe_structure(gate.get("local_structure_evidence")),
            "negative_evidence": gate.get("negative_evidence"),
            "explosion_risk": gate.get("explosion_risk"),
            "decision_reason": gate.get("decision_reason"),
        }

    return {
        "oracle_safe_mode": True,
        "case_id": case.get("case_id"),
        "project": case.get("project"),
        "declared_case_group": case.get("gap_type"),
        "declared_repair_branch": case.get("repair_branch"),
        "candidate_gap_type": "connectivity_gap",
        "ccec_generation_modes": {
            "easy": {
                "mechanism": "direct_static_edge",
                "llm_role": "format/explain only; do not invent candidates",
                "condition": "single observed callsite and unique static callee evidence",
            },
            "middle": {
                "mechanism": "top_k_static_edges_then_llm_ranking",
                "llm_role": "rank candidates and refine guards from evidence",
                "condition": "multiple plausible static callees or guard-sensitive dispatch",
            },
            "hard": {
                "mechanism": "llm_synthesized_virtual_or_materialized_edge",
                "llm_role": "synthesize a guarded dynamic edge contract from multi-source static evidence",
                "condition": "factory/reflection/callback-table evidence without a directly materialized callee",
            },
        },
        "static_call_evidence": _static_ccec_evidence(case),
        "evidence_gate": gate_payload,
        "gap_diagnosis": diagnosis.get("diagnosis") if diagnosis else None,
        "omitted_oracle_fields": [
            "manual source/sink annotations",
            "manual breakpoint annotations",
            "manual repair-order annotations",
            "manual source-to-sink chain summaries",
        ],
    }


def build_ccec_prompt(
    case: dict[str, Any],
    gate: dict[str, Any] | None = None,
    diagnosis: dict[str, Any] | None = None,
    oracle_safe: bool = False,
) -> str:
    """Build a deterministic prompt for CCEC candidate call-edge synthesis."""

    oracle_safe = True
    payload_json = json.dumps(
        _compact_ccec_payload(case, gate, diagnosis, oracle_safe=oracle_safe),
        indent=2,
        ensure_ascii=False,
    )
    oracle_safe_note = (
        "\nOracle-safe mode is enabled: benchmark oracle fields and the full "
        "source-to-sink repair chain are intentionally omitted. Infer candidate "
        "edges only from the exposed static evidence.\n"
        if oracle_safe
        else ""
    )

    return f"""You are synthesizing Candidate Call-Edge Contracts (CCEC).

Use only the case metadata, Evidence Gate report, and Gap Diagnosis below.
Do not invent source functions, sink functions, files, or callees that are not
supported by the evidence. If evidence is insufficient, return an empty
candidate_edges array and explain why in notes.

Goal:
- Repair a missing call-graph connection, not dataflow propagation.
- Produce candidate call edges and their guard conditions.
- First classify the CCEC mechanism as easy, middle, or hard:
  easy = direct static edge; middle = top-k static edges plus LLM ranking;
  hard = dynamic/virtual/materialized edge synthesis from static evidence.
- Every guard must be derived from baseline/static evidence and must include
  derived_from + evidence. Do not use benchmark oracle, known final chain, or
  case metadata breakpoint fields to create guards.
- Keep candidates inside the observed callee universe or explicitly mark
  materialized factory-generated callees.
- Do not generate validation programs in this step. Validation sample
  generation is handled by a separate validator stage.
- If Gap Diagnosis reports possible_propagation_gap, repair only call edges
  first. Mark dataflow as pending until the post-CCEC rerun confirms it.
{oracle_safe_note}

Return one JSON object with this exact top-level shape:

{{
  "schema_version": "lapis.ccec_candidates.v1",
  "case_id": "string",
  "gap_type": "connectivity_gap",
  "repair_branch": "ccec | ccec_then_ctpc",
  "ccec_mode": "easy | middle | hard | deferred",
  "generation_mechanism": "direct_static_edge | top_k_static_edges_then_llm_ranking | llm_synthesized_virtual_or_materialized_edge | insufficient_evidence",
  "llm_role": "string",
  "candidate_edges": [
    {{
      "edge_id": "string",
      "caller": "string",
      "callsite": "string",
      "callee": "string",
      "callee_kind": "real_function | materialized_factory_method | callback | rebound_function | builtin_sink",
      "confidence": 0.0,
      "guards": ["string"],
      "guard_evidence": [
        {{
          "condition": "string",
          "derived_from": "baseline_callgraph | baseline_diagnostic | sarif | ast_callsite | ast_control_flow_guard | function_signature | import_alias | callback_registration | receiver_type",
          "evidence": {{"file": "string", "line": 0, "code": "string"}}
        }}
      ],
      "evidence": ["string"],
      "contract": {{
        "preconditions": ["string"],
        "effects": [
          {{
            "kind": "add_call_edge",
            "from": "caller",
            "to": "callee",
            "at": "callsite"
          }}
        ],
        "must_not_apply_when": ["string"]
      }}
    }}
  ],
  "ranking": {{
    "top_k": 0,
    "ranking_reason": ["string"]
  }},
  "validation_expectations": {{
    "structural": "callee exists or can be materialized from evidence",
    "graph_progress": "source frontier advances beyond the symbolic/dangling callsite",
    "taint_progress": "source becomes closer to sink; possible propagation gaps require post-CCEC rediagnosis"
  }},
  "dataflow_still_required": false,
  "notes": ["string"]
}}

Important distinction:
- CCEC contracts may contain guards and add_call_edge effects.
- They must not contain CTPC dataflow propagation edges.
- must / must-not / must-kill validation samples are produced later by the
  validator, not by this candidate synthesis prompt.

Evidence:

```json
{payload_json}
```
"""


def build_ccec_validation_prompt(
    case: dict[str, Any],
    ccec: dict[str, Any],
    gate: dict[str, Any] | None = None,
    diagnosis: dict[str, Any] | None = None,
) -> str:
    """Build a deterministic prompt for CCEC validation contract/sample generation."""

    payload = {
        "case": _compact_ccec_payload(case, gate, diagnosis),
        "ccec": ccec,
    }
    payload_json = json.dumps(payload, indent=2, ensure_ascii=False)

    return f"""You are generating validation contracts for Candidate Call-Edge Contracts (CCEC).

Use only the case metadata, Evidence Gate report, Gap Diagnosis, and CCEC below.
Do not change the CCEC. Do not invent unrelated callees, sources, sinks, files,
or framework behavior.

Goal:
- Generate validation expectations for repaired call edges.
- Generate three small standalone Python local semantic samples for callgraph
  validation. These samples must exercise only the candidate CCEC edge and its
  guards, not the full CVE chain.
- Check that the accepted CCEC advances the source frontier past the missing
  symbolic/dangling callsite.
- Check that nearby unsupported call edges are not accepted.
- Check that guards can kill or suppress an invalid edge.
- If a possible propagation gap is pending, validate only callgraph progress
  and leave dataflow confirmation to the post-CCEC rerun.

Return one JSON object with this exact top-level shape:

{{
  "schema_version": "lapis.ccec_validation_contract.v1",
  "case_id": "string",
  "validated_ccec_edges": ["string"],
  "must_link": [
    {{
      "name": "string",
      "expected": "edge_present",
      "caller": "string",
      "callsite": "string",
      "callee": "string",
      "required_guards": ["string"],
      "graph_progress": {{
        "from_frontier": "string",
        "to_frontier": "string"
      }},
      "evidence": ["string"]
    }}
  ],
  "must_not_link": [
    {{
      "name": "string",
      "expected": "edge_absent",
      "caller": "string",
      "callsite": "string",
      "callee": "string",
      "reason": "string",
      "violated_guard": "string",
      "evidence": ["string"]
    }}
  ],
  "must_kill": [
    {{
      "name": "string",
      "expected": "edge_suppressed",
      "caller": "string",
      "callsite": "string",
      "callee": "string",
      "kill_condition": "string",
      "reason": "string",
      "evidence": ["string"]
    }}
  ],
  "local_samples": {{
    "must-link": {{
      "name": "string",
      "expected": "edge_present",
      "edge_id": "string",
      "caller": "string",
      "callsite": "string",
      "callee": "string",
      "guards": ["string"],
      "code": "def test():\\n    ...\\n",
      "evidence": ["string"]
    }},
    "must-not-link": {{
      "name": "string",
      "expected": "edge_absent",
      "edge_id": "string",
      "caller": "string",
      "callsite": "string",
      "callee": "string",
      "violated_guard": "string",
      "code": "def test():\\n    ...\\n",
      "evidence": ["string"]
    }},
    "must-kill": {{
      "name": "string",
      "expected": "edge_suppressed",
      "edge_id": "string",
      "caller": "string",
      "callsite": "string",
      "callee": "string",
      "kill_condition": "string",
      "code": "def test():\\n    ...\\n",
      "evidence": ["string"]
    }}
  }},
  "notes": ["string"]
}}

Important distinction:
- This prompt generates CCEC validation contracts, not CCEC candidate edges.
- It must not generate CTPC dataflow propagation rules.
- CCEC validation uses must-link / must-not-link / must-kill.
  CTPC validation uses must-flow / must-not-flow / must-kill.
- local_samples are minimal executable Python programs for local callgraph
  validation. They must not include the full benchmark source-to-sink path.
- If possible_propagation_gap is pending, use notes to say whether the
  validation contract covers only callgraph progress and leaves taint/value
  propagation for post-CCEC rediagnosis.

Input:

```json
{payload_json}
```
"""


def build_validation_prompt(evidence: dict[str, Any], ctpc: dict[str, Any]) -> str:
    """Build a deterministic prompt for validation sample generation."""

    payload = {
        "evidence_pack": _compact_evidence(evidence),
        "ctpc": ctpc,
    }
    payload_json = json.dumps(payload, indent=2, ensure_ascii=False)

    return f"""You are generating validation samples for a CTPC.

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

{{
  "must_flow": {{
    "name": "string",
    "expected": "finding",
    "code": "string"
  }},
  "must_not_flow": {{
    "name": "string",
    "expected": "no_finding",
    "code": "string"
  }},
  "must_kill": {{
    "name": "string",
    "expected": "no_finding",
    "code": "string"
  }},
  "notes": ["string"]
}}

Evidence Pack and CTPC:

```json
{payload_json}
```
"""
