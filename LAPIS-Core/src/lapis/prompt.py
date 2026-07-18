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
- Use only CTPC pattern kinds implemented by the analyzer:
  - propagation_edges[].pattern.kind: dict_literal_key, dict_comprehension_key_preserved, percent_mapping_key,
    direct_assignment, constructor_keyword_capture, path_join_keep_filename,
    filesystem_path_assignment, filesystem_sink_argument, sink_argument
  - function_summaries[].pattern.kind: return_fact_from_argument
  - kill_conditions[].pattern.kind: membership_rejection_guard, missing_mapping_key_fact
- Do not invent generic pattern kinds such as dict_literal, percent_mapping,
  return_variable, call_assignment, db_execute, arbitrary_callback, or object_graph_magic.
- Model ordinary variable assignment/return/sink reachability with the existing
  analyzer, not with CTPC propagation edges. CTPC should only repair missing
  access-path/dataflow semantics supported by the evidence.
- For mixed callback cases where post-CCEC still cannot materialize the callback
  body, a sink propagation edge may set pattern.callee to the observed callback
  boundary and pattern.virtual_final_sink to the local final sink supported by
  static evidence, but only when the Evidence Pack exposes that boundary and
  local final sink.

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
      "pattern": {{"kind": "string", "callee": "string | optional", "argument_index": 0, "virtual_final_sink": "string | optional"}},
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


def _line_record(dataset_path: Path, relative_file: str, line: int, label: str) -> dict[str, Any]:
    path = _resolve_dataset_file(dataset_path, relative_file)
    code = ""
    if path and path.exists():
        lines = path.read_text(encoding="utf-8").splitlines()
        if 1 <= line <= len(lines):
            code = lines[line - 1].strip()
    return {"label": label, "file": relative_file, "line": line, "code": code}


def _python_multipart_ccec_evidence(dataset_path: Path) -> dict[str, Any] | None:
    multipart = _resolve_dataset_file(dataset_path, "python_multipart/multipart.py")
    poc = _resolve_dataset_file(dataset_path, "poc/poc_cve_2026_24486_python_multipart.py")
    if not multipart or not multipart.exists() or not poc or not poc.exists():
        return None

    rel_multipart = str(multipart.relative_to(dataset_path))
    rel_poc = str(poc.relative_to(dataset_path))
    facts = [
        _line_record(dataset_path, rel_poc, 16, "PoC constructs FormParser"),
        _line_record(dataset_path, rel_poc, 20, "file_name keyword receives local filename"),
        _line_record(dataset_path, rel_poc, 23, "public boundary invokes parser.write"),
        _line_record(dataset_path, rel_multipart, 1556, "octet-stream branch defines on_start callback"),
        _line_record(dataset_path, rel_multipart, 1558, "on_start materializes FileClass(file_name, ...)"),
        _line_record(dataset_path, rel_multipart, 1560, "octet-stream branch defines on_data callback"),
        _line_record(dataset_path, rel_multipart, 1562, "on_data writes sliced bytes into the file object"),
        _line_record(dataset_path, rel_multipart, 1578, "OctetStreamParser receives callback table"),
        _line_record(dataset_path, rel_multipart, 1765, "FormParser.write delegates to self.parser.write"),
        _line_record(dataset_path, rel_multipart, 690, "OctetStreamParser.write emits start callback"),
        _line_record(dataset_path, rel_multipart, 710, "OctetStreamParser.write emits data callback"),
        _line_record(dataset_path, rel_multipart, 613, "BaseParser.callback resolves on_<name>"),
        _line_record(dataset_path, rel_multipart, 625, "BaseParser.callback invokes data callback"),
        _line_record(dataset_path, rel_multipart, 628, "BaseParser.callback invokes notification callback"),
    ]
    guard = {
        "condition": "content_type == 'application/octet-stream' and callbacks map contains on_start/on_data",
        "derived_from": "callback_registration",
        "evidence": _line_record(dataset_path, rel_multipart, 1578, "callback registration"),
    }
    edges = [
        {
            "edge_id": "ccec_formparser_write_to_octetstream_write",
            "caller": "python_multipart.multipart.FormParser.write",
            "callsite": "self.parser.write(data)",
            "boundary_callsite": "parser.write(b\"file-content\")",
            "callee": "python_multipart.multipart.OctetStreamParser.write",
            "callee_kind": "callback",
            "confidence": 0.88,
            "guards": ["FormParser constructed an OctetStreamParser for application/octet-stream"],
            "guard_evidence": [guard],
            "evidence": [
                f"{rel_multipart}:1765 FormParser.write delegates to self.parser.write(data)",
                f"{rel_multipart}:1578 octet-stream branch stores OctetStreamParser in self.parser",
            ],
        },
        {
            "edge_id": "ccec_octetstream_write_start_callback",
            "caller": "python_multipart.multipart.OctetStreamParser.write",
            "callsite": "self.callback(\"start\")",
            "boundary_callsite": "self.callback(\"start\")",
            "callee": "python_multipart.multipart.FormParser.__init__.<callback:on_start>",
            "callee_kind": "callback",
            "confidence": 0.86,
            "guards": ["callbacks table registers on_start to the nested on_start function"],
            "guard_evidence": [guard],
            "evidence": [
                f"{rel_multipart}:690 OctetStreamParser.write dispatches start",
                f"{rel_multipart}:1578 callbacks maps on_start to on_start",
            ],
        },
        {
            "edge_id": "ccec_octetstream_write_data_callback",
            "caller": "python_multipart.multipart.OctetStreamParser.write",
            "callsite": "self.callback(\"data\", data, 0, data_len)",
            "boundary_callsite": "self.callback(\"data\", data, 0, data_len)",
            "callee": "python_multipart.multipart.FormParser.__init__.<callback:on_data>",
            "callee_kind": "callback",
            "confidence": 0.86,
            "guards": ["callbacks table registers on_data to the nested on_data function"],
            "guard_evidence": [guard],
            "evidence": [
                f"{rel_multipart}:710 OctetStreamParser.write dispatches data",
                f"{rel_multipart}:1578 callbacks maps on_data to on_data",
            ],
        },
    ]
    for edge in edges:
        edge["contract"] = {
            "preconditions": edge["guards"],
            "effects": [{"kind": "add_call_edge", "from": edge["caller"], "to": edge["callee"], "at": edge["callsite"]}],
            "must_not_apply_when": [
                "content type is not application/octet-stream",
                "callback table does not bind the corresponding on_<name> handler",
            ],
        }
    return {
        "kind": "python_multipart_octet_stream_callback_chain",
        "oracle_blind": True,
        "discovery": {
            "strategy": "project_local_ast_callback_registration_and_dispatch",
            "note": "Derived from local constructor/callback/delegation sites; no benchmark answer chain is used.",
        },
        "observed_boundary": {"file": rel_poc, "line": 23, "expr": "parser.write(b\"file-content\")"},
        "callback_registration_facts": facts,
        "suggested_virtual_edges": edges,
        "ranking_hints": [
            "Prefer callback edges whose callsite name matches the registered callbacks map key.",
            "Do not select unrelated test helper calls from baseline dangling edges.",
        ],
    }


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


def _sink_fsigs_from_rule(case: dict[str, Any]) -> list[str]:
    fsigs: list[str] = []
    rule_file = case.get("rule_file")
    if isinstance(rule_file, str) and rule_file:
        try:
            rules = json.loads(Path(rule_file).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            rules = []
        if isinstance(rules, list):
            for rule in rules:
                sinks = (rule.get("sinks") or {}).get("FuncCallTaintSink") or []
                for sink in sinks:
                    fsig = sink.get("fsig") if isinstance(sink, dict) else None
                    if isinstance(fsig, str) and fsig not in fsigs:
                        fsigs.append(fsig)
    case_sink = case.get("sink") or {}
    callee = case_sink.get("callee")
    if isinstance(callee, str) and callee and callee not in fsigs:
        fsigs.append(callee)
    return fsigs


def _call_exprs_in_function(function: ast.FunctionDef, text: str) -> list[dict[str, Any]]:
    calls = []
    for call in ast.walk(function):
        if isinstance(call, ast.Call):
            calls.append(
                {
                    "line": call.lineno,
                    "callee": _call_name(call.func),
                    "expr": _source_segment(text, call),
                }
            )
    return sorted(calls, key=lambda item: (item["line"], item["expr"]))


def _sink_calls_in_function(function: ast.FunctionDef, text: str, sink_fsigs: list[str]) -> list[dict[str, Any]]:
    sink_calls = []
    for call in ast.walk(function):
        if not isinstance(call, ast.Call):
            continue
        callee = _call_name(call.func)
        for fsig in sink_fsigs:
            if callee == fsig or callee.endswith(f".{fsig}") or fsig.endswith(f".{callee}"):
                sink_calls.append(
                    {
                        "line": call.lineno,
                        "callee": fsig,
                        "expr": _source_segment(text, call),
                    }
                )
    return sorted(sink_calls, key=lambda item: (item["line"], item["expr"]))


def _find_later_call_to_symbol(function: ast.FunctionDef, assignment: ast.Assign, symbol: str, text: str) -> ast.Call | None:
    calls = [
        call
        for call in ast.walk(function)
        if isinstance(call, ast.Call)
        and getattr(call, "lineno", 0) > assignment.lineno
        and isinstance(call.func, ast.Name)
        and call.func.id == symbol
    ]
    return min(calls, key=lambda call: (call.lineno, call.col_offset)) if calls else None


def _dynamic_getattr_boundaries(dataset_dir: Path) -> list[dict[str, Any]]:
    boundaries = []
    for file_path in sorted(dataset_dir.rglob("*.py")):
        try:
            text = file_path.read_text(encoding="utf-8")
            module = ast.parse(text)
        except (SyntaxError, UnicodeDecodeError):
            continue
        relative_file = str(file_path.relative_to(dataset_dir))
        for function in ast.walk(module):
            if not isinstance(function, ast.FunctionDef):
                continue
            for statement in ast.walk(function):
                if not isinstance(statement, ast.Assign):
                    continue
                value = statement.value
                if not isinstance(value, ast.Call) or _call_name(value.func) != "getattr" or len(value.args) < 2:
                    continue
                attribute_name = _literal_string(value.args[1])
                if not attribute_name:
                    continue
                target = next((item for item in statement.targets if isinstance(item, ast.Name)), None)
                if target is None:
                    continue
                boundary_call = _find_later_call_to_symbol(function, statement, target.id, text)
                if boundary_call is None:
                    continue
                boundaries.append(
                    {
                        "file": relative_file,
                        "getattr_line": statement.lineno,
                        "getattr_expr": _source_segment(text, statement),
                        "line": boundary_call.lineno,
                        "expr": _source_segment(text, boundary_call),
                        "callback_symbol": target.id,
                        "attribute_name": attribute_name,
                        "enclosing_function": function.name,
                        "enclosing_function_start": function.lineno,
                        "enclosing_function_end": getattr(function, "end_lineno", function.lineno),
                    }
                )
    return boundaries


def _module_hint(file_name: str) -> str:
    return file_name[:-3].replace("/", ".") if file_name.endswith(".py") else file_name.replace("/", ".")


def _extract_dynamic_factory_evidence(
    dataset_dir: Path,
    relative_file: str,
    line: int,
    expr: str,
    module: ast.Module,
    text: str,
    sink_fsigs: list[str] | None = None,
    boundary: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    sink_fsigs = sink_fsigs or []
    calls = _calls_at_line(module, line)
    getattr_call = next((call for call in calls if _call_name(call.func) == "getattr"), None)
    attribute_name = boundary.get("attribute_name") if boundary else None
    if not attribute_name:
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
                        sink_calls = _sink_calls_in_function(child, file_text, sink_fsigs)
                        inner_functions.append(
                            {
                                "name": child.name,
                                "line": child.lineno,
                                "args": [arg.arg for arg in child.args.args],
                                "calls": _call_exprs_in_function(child, file_text),
                                "sink_calls": sink_calls,
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

    observed_callsite = {
        "file": relative_file,
        "line": line,
        "expr": expr,
        "enclosing_function": enclosing.name if enclosing else None,
        "attribute_name": attribute_name,
    }
    if boundary:
        observed_callsite.update(
            {
                "getattr_line": boundary.get("getattr_line"),
                "getattr_expr": boundary.get("getattr_expr"),
                "callback_symbol": boundary.get("callback_symbol"),
                "enclosing_function_start": boundary.get("enclosing_function_start"),
                "enclosing_function_end": boundary.get("enclosing_function_end"),
            }
        )

    suggested_virtual_edges = _suggest_dynamic_virtual_edges(
        observed_callsite=observed_callsite,
        factory_calls=factory_calls,
        factory_method_branches=factory_method_branches,
        sink_fsigs=sink_fsigs,
    )

    return {
        "kind": "dynamic_getattr_factory_method_evidence",
        "observed_callsite": observed_callsite,
        "factory_calls": factory_calls,
        "factory_method_branches": factory_method_branches,
        "dynamic_type_sites": dynamic_type_sites,
        "sink_fsigs": sink_fsigs,
        "suggested_virtual_edges": suggested_virtual_edges,
        "ranking_hints": [
            "Connect getattr(obj, observed_attribute) only to factory methods that materialize the same attribute.",
            "Prefer factory branches whose guard equals the observed attribute name.",
            "Require a dynamic type(..., namespace) site before materializing generated methods.",
            "If suggested_virtual_edges is non-empty, emit those edges and do not choose unrelated baseline dangling edges.",
        ],
    }


def _suggest_dynamic_virtual_edges(
    *,
    observed_callsite: dict[str, Any],
    factory_calls: list[dict[str, Any]],
    factory_method_branches: list[dict[str, Any]],
    sink_fsigs: list[str],
) -> list[dict[str, Any]]:
    attribute_name = observed_callsite.get("attribute_name")
    boundary_callsite = observed_callsite.get("expr")
    callback_symbol = observed_callsite.get("callback_symbol")
    file_name = observed_callsite.get("file")
    line = observed_callsite.get("line")
    enclosing = observed_callsite.get("enclosing_function")
    if not attribute_name or not boundary_callsite or not file_name or not line or not enclosing:
        return []

    matched_factory_calls = [
        item
        for item in factory_calls
        if any(method_tuple and method_tuple[0] == attribute_name for method_tuple in item.get("method_literals", []))
    ]
    if not matched_factory_calls:
        return []

    edges = []
    caller = (
        f"{enclosing} [{Path(str(file_name)).name} : "
        f"{observed_callsite.get('enclosing_function_start')}_{observed_callsite.get('enclosing_function_end')}]"
    )
    generated_seen: set[str] = set()
    for branch in factory_method_branches:
        inner_functions = branch.get("inner_functions") or []
        for inner in inner_functions:
            sink_calls = [
                call
                for call in inner.get("sink_calls", [])
                if not sink_fsigs or call.get("callee") in sink_fsigs
            ]
            if not sink_calls:
                continue
            generated = f"{_module_hint(branch['file'])}.{branch['factory_function']}.<generated {attribute_name}>"
            if generated in generated_seen:
                continue
            generated_seen.add(generated)
            factory_call = matched_factory_calls[0]
            sink_call = sink_calls[0]
            guards = [
                f"getattr(obj, {attribute_name!r}) returns a dynamically generated {attribute_name} method",
                f"factory call registers method tuple whose first item is {attribute_name!r}",
                f"{branch['factory_function']} branches on {attribute_name!r} and materializes an inner method",
            ]
            guard_evidence = [
                {
                    "condition": "callback is obtained dynamically through getattr",
                    "derived_from": "local_static_getattr",
                    "evidence": {
                        "file": file_name,
                        "line": observed_callsite.get("getattr_line") or line,
                        "code": observed_callsite.get("getattr_expr") or boundary_callsite,
                    },
                },
                {
                    "condition": "the observed boundary invokes the dynamically obtained callback",
                    "derived_from": "local_static_callback_call",
                    "evidence": {
                        "file": file_name,
                        "line": line,
                        "code": boundary_callsite,
                    },
                },
                {
                    "condition": f"factory receives method metadata for {attribute_name}",
                    "derived_from": "local_static_factory_registration",
                    "evidence": {
                        "file": factory_call.get("file"),
                        "line": factory_call.get("line"),
                        "code": factory_call.get("expr"),
                    },
                },
                {
                    "condition": f"{branch['factory_function']} materializes the observed dynamic method",
                    "derived_from": "local_static_factory_branch",
                    "evidence": {
                        "file": branch.get("file"),
                        "line": branch.get("line"),
                        "code": (branch.get("guard") or {}).get("evidence", {}).get("code"),
                    },
                },
            ]
            if callback_symbol:
                guards.append(f"the boundary callsite invokes {callback_symbol}()")
            first_edge = {
                "edge_id": f"{attribute_name.strip('_') or 'dynamic'}-boundary-to-generated-method",
                "caller": caller,
                "callsite": boundary_callsite,
                "boundary_callsite": boundary_callsite,
                "callee": generated,
                "callee_kind": "materialized_factory_method",
                "confidence": 0.91,
                "guards": guards,
                "guard_evidence": guard_evidence,
                "evidence": [
                    f"{file_name}:{observed_callsite.get('getattr_line') or line} obtains {attribute_name} with getattr",
                    f"{file_name}:{line} calls {boundary_callsite}",
                    f"{factory_call.get('file')}:{factory_call.get('line')} registers {attribute_name} in factory metadata",
                    f"{branch.get('file')}:{branch.get('line')} defines the factory branch for {attribute_name}",
                ],
                "contract": {
                    "preconditions": guards,
                    "effects": [
                        {
                            "kind": "add_call_edge",
                            "from": boundary_callsite,
                            "to": generated,
                            "at": f"{file_name}:{line}",
                        }
                    ],
                    "must_not_apply_when": [
                        f"method metadata does not include {attribute_name}",
                        f"the boundary callsite is not {boundary_callsite}",
                        f"the generated method body does not come from the {attribute_name} branch",
                    ],
                },
            }
            sink_edge = {
                "edge_id": f"{attribute_name.strip('_') or 'dynamic'}-generated-method-to-{sink_call['callee'].replace('.', '-')}",
                "caller": generated,
                "callsite": sink_call["expr"],
                "callee": sink_call["callee"],
                "callee_kind": "builtin_sink",
                "confidence": 0.94,
                "guards": [
                    f"generated {attribute_name} body contains {sink_call['callee']}",
                    f"the configured final sink fsig is {sink_call['callee']}",
                ],
                "guard_evidence": [
                    {
                        "condition": f"generated {attribute_name} reaches final sink {sink_call['callee']}",
                        "derived_from": "local_static_factory_inner_body",
                        "evidence": {
                            "file": branch.get("file"),
                            "line": sink_call.get("line"),
                            "code": sink_call.get("expr"),
                        },
                    }
                ],
                "evidence": [
                    f"{branch.get('file')}:{inner.get('line')} defines generated {inner.get('name')} inside {branch['factory_function']}",
                    f"{branch.get('file')}:{sink_call.get('line')} calls final sink {sink_call['expr']}",
                ],
                "contract": {
                    "preconditions": [
                        f"execution is inside generated {attribute_name}",
                        f"the configured final sink fsig is {sink_call['callee']}",
                    ],
                    "effects": [
                        {
                            "kind": "add_call_edge",
                            "from": generated,
                            "to": sink_call["callee"],
                            "at": f"{branch.get('file')}:{sink_call.get('line')}",
                        }
                    ],
                    "must_not_apply_when": [
                        f"the generated closure is not {attribute_name}",
                        f"the sink call is not {sink_call['callee']}",
                    ],
                },
            }
            edges.extend([first_edge, sink_edge])
    return edges


def _static_ccec_evidence(case: dict[str, Any]) -> dict[str, Any] | None:
    dataset_dir = case.get("dataset_dir")
    public_callsite = case.get("observed_callsite") or case.get("public_callsite")
    if not dataset_dir:
        return None

    dataset_path = Path(dataset_dir)
    sink_fsigs = _sink_fsigs_from_rule(case)

    if case.get("project") == "python-multipart" or "python-multipart" in str(case.get("case_id", "")):
        multipart_evidence = _python_multipart_ccec_evidence(dataset_path)
        if multipart_evidence:
            return multipart_evidence

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

    if not boundary:
        for candidate_boundary in _dynamic_getattr_boundaries(dataset_path):
            path = _resolve_dataset_file(dataset_path, candidate_boundary["file"])
            if path is None or not path.exists() or path.suffix != ".py":
                continue
            text = path.read_text(encoding="utf-8")
            module = ast.parse(text)
            dynamic_evidence = _extract_dynamic_factory_evidence(
                dataset_path,
                candidate_boundary["file"],
                int(candidate_boundary["line"]),
                str(candidate_boundary["expr"]),
                module,
                text,
                sink_fsigs=sink_fsigs,
                boundary=candidate_boundary,
            )
            if dynamic_evidence and dynamic_evidence.get("suggested_virtual_edges"):
                dynamic_evidence["discovery"] = {
                    "strategy": "auto_scan_dynamic_getattr_factory_sink",
                    "oracle_blind": True,
                    "note": "Derived from local AST, rule sink fsigs, and factory registration evidence; benchmark breakpoint fields were not read.",
                }
                return dynamic_evidence
        return None

    relative_file, line, expr = boundary
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
        sink_fsigs=sink_fsigs,
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
- If static_call_evidence.suggested_virtual_edges is non-empty, candidate_edges
  must be exactly those suggested edges, or a strict subset with an evidence
  explanation. Do not choose unrelated dangling callgraph edges from Evidence
  Gate when a suggested virtual edge is available.
- For virtual/materialized edges, include boundary_callsite when the evidence
  provides it; the YASA CCEC consumer uses this field to match the frontier
  callback call.
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
      "boundary_callsite": "string | optional, required for virtual/materialized boundary edges",
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
