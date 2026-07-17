"""Command line entry points for the LAPIS prototype."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Any

from .cases import build_case_index, run_repair_workflow
from .ccec import (
    build_ccec_candidates,
    materialize_ccec_validation,
    plan_ccec_repair,
    validate_ccec_candidates,
    validate_ccec_link_contract,
    validate_ccec_local_samples,
)
from .ctpc_schema import upgrade_ctpc_file
from .diagnosis import build_gap_diagnosis_report
from .e2e import run_end_to_end_case, run_end_to_end_cases
from .gate import build_evidence_gate_report, summarize_callgraph
from .llm import chat_json, chat_text, config_from_env, extract_json_object, read_api_key_from_stdin, write_llm_artifacts
from .prompt import build_ccec_prompt, build_ccec_validation_prompt, build_ctpc_prompt, build_validation_prompt
from .validator import build_yasa_validation_rules, validate_ctpc
from .yasa_runner import build_feasibility_report, run_yasa_case, run_yasa_validation


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _llm_config_from_args(args: argparse.Namespace):
    api_key = read_api_key_from_stdin() if getattr(args, "api_key_stdin", False) else None
    return config_from_env(
        api_key=api_key,
        base_url=getattr(args, "base_url", None),
        model=getattr(args, "model", None),
        timeout_seconds=getattr(args, "llm_timeout_seconds", 120),
        temperature=getattr(args, "temperature", 0.0),
        max_tokens=getattr(args, "max_tokens", 4096),
    )


def _add_llm_args(parser: argparse.ArgumentParser, *, max_tokens: int = 4096) -> None:
    parser.add_argument("--base-url", help="OpenAI-compatible base URL, e.g. https://dasuapi.com/v1")
    parser.add_argument("--model", help="LLM model name")
    parser.add_argument("--api-key-stdin", action="store_true", help="Read API key from stdin instead of env")
    parser.add_argument("--llm-timeout-seconds", default=120, type=int, help="LLM API timeout")
    parser.add_argument("--temperature", default=0.0, type=float, help="LLM sampling temperature")
    parser.add_argument("--max-tokens", default=max_tokens, type=int, help="LLM response token budget")


def _resolve_case_value(case_dir: Path, value: str | None) -> Path | None:
    if not value:
        return None
    path = Path(value)
    return path if path.is_absolute() else case_dir / path


def _read_line(path: Path, line: int) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    if line < 1 or line > len(lines):
        raise ValueError(f"line {line} out of range for {path}")
    return lines[line - 1].strip()


def _safe_relative(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


def _line_at(path: Path, line: int) -> str | None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    if line < 1 or line > len(lines):
        return None
    return lines[line - 1].strip()


def _resolve_dataset_file(dataset_dir: Path, item: dict[str, Any]) -> Path:
    file_name = item["file"]
    line = int(item["line"])
    expected_expr = item.get("expr")
    direct = dataset_dir / file_name
    if direct.exists():
        return direct
    matches = sorted(dataset_dir.rglob(file_name))
    matches.extend(path for path in sorted(dataset_dir.rglob(Path(file_name).name)) if path.is_file())
    line_matches = [path for path in matches if _line_at(path, line) is not None]
    if expected_expr:
        for path in line_matches:
            if _line_at(path, line) == expected_expr:
                return path
        expr_tail = str(expected_expr).strip()
        for path in line_matches:
            observed = _line_at(path, line) or ""
            if expr_tail in observed or observed in expr_tail:
                return path
    if line_matches:
        return line_matches[0]
    if matches:
        return matches[0]
    return direct


def _with_observed_line(case_dir: Path, dataset_dir: Path, item: dict[str, Any]) -> dict[str, Any]:
    source_file = _resolve_dataset_file(dataset_dir, item)
    observed = _read_line(source_file, int(item["line"]))
    return {
        **item,
        "path": _safe_relative(source_file, case_dir),
        "observed": observed,
        "matches_anchor": observed == item.get("expr"),
    }


def _parse_python(path: Path) -> tuple[ast.Module, str]:
    text = path.read_text(encoding="utf-8")
    return ast.parse(text), text


def _segment(text: str, node: ast.AST) -> str:
    return ast.get_source_segment(text, node) or node.__class__.__name__


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return f"{_call_name(node.func)}(...)"
    return ""


def _find_function(module: ast.Module, name: str) -> ast.FunctionDef | None:
    for node in ast.walk(module):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def _names_in(node: ast.AST) -> set[str]:
    return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}


def _extract_source_forward(case_dir: Path, dataset_dir: Path, source_anchor: dict[str, Any]) -> dict[str, Any]:
    path = dataset_dir / source_anchor["file"]
    module, text = _parse_python(path)
    func = _find_function(module, source_anchor["function"]) if source_anchor.get("function") else None
    source_symbol = source_anchor["symbol"]
    observations: list[dict[str, Any]] = []
    reached = [source_symbol]
    frontier = source_symbol

    if not func:
        return {"source": source_symbol, "reached": reached, "frontier": frontier, "observations": observations}

    for stmt in func.body:
        if getattr(stmt, "lineno", 0) <= int(source_anchor["line"]):
            continue
        if source_symbol not in _names_in(stmt) and "args" not in _names_in(stmt):
            continue

        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Dict):
            lhs = _segment(text, stmt.targets[0])
            keys = [_segment(text, key) for key in stmt.value.keys if key is not None]
            observations.append(
                {
                    "kind": "dict_literal",
                    "file": str(path.relative_to(case_dir)),
                    "line": stmt.lineno,
                    "lhs": lhs,
                    "keys": keys,
                    "expr": _segment(text, stmt),
                }
            )
        elif isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Call):
            observations.append(
                {
                    "kind": "call",
                    "file": str(path.relative_to(case_dir)),
                    "line": stmt.lineno,
                    "callee": _call_name(stmt.value.func),
                    "args": [_segment(text, arg) for arg in stmt.value.args],
                    "expr": _segment(text, stmt),
                }
            )

    return {
        "source": source_symbol,
        "reached": reached,
        "frontier": frontier,
        "observations": observations,
    }


def _extract_sink_backward(case_dir: Path, dataset_dir: Path, sink_anchor: dict[str, Any]) -> dict[str, Any]:
    path = dataset_dir / sink_anchor["file"]
    module, text = _parse_python(path)
    function_names = [sink_anchor["function"]] if sink_anchor.get("function") else []
    if not function_names:
        function_names = [node.name for node in ast.walk(module) if isinstance(node, ast.FunctionDef)]
    observations: list[dict[str, Any]] = []
    dependency_chain = [sink_anchor["expr"], sink_anchor["argument"]]
    sink_terms = {str(sink_anchor.get("argument") or ""), str(sink_anchor.get("callee") or "")}
    sink_terms = {term for term in sink_terms if term}

    for function_name in function_names:
        func = _find_function(module, function_name)
        if not func:
            continue
        for node in ast.walk(func):
            if isinstance(node, ast.Assign):
                expr = _segment(text, node)
                names = _names_in(node)
                if not sink_terms or names.intersection(sink_terms) or any(term in expr for term in sink_terms):
                    observations.append(
                        {
                            "kind": "assignment",
                            "function": function_name,
                            "file": str(path.relative_to(case_dir)),
                            "line": node.lineno,
                            "targets": [_segment(text, target) for target in node.targets],
                            "expr": expr,
                        }
                    )
                    if "%" in expr:
                        dependency_chain.append(expr)
            elif isinstance(node, ast.Return):
                expr = _segment(text, node)
                if isinstance(node.value, ast.DictComp) and ".items()" in expr:
                    observations.append(
                        {
                            "kind": "dict_comprehension_return",
                            "function": function_name,
                            "file": str(path.relative_to(case_dir)),
                            "line": node.lineno,
                            "expr": expr,
                        }
                    )
                    dependency_chain.append(expr)
                    dependency_chain.append("mapping.items()")
                    dependency_chain.append("mapping.keys()[*]")

    return {
        "sink": sink_anchor["expr"],
        "argument": sink_anchor["argument"],
        "dependency_chain": dependency_chain,
        "observations": sorted(observations, key=lambda item: (item["file"], item["line"], item["kind"])),
    }


def _extract_structure(forward: dict[str, Any], backward: dict[str, Any]) -> dict[str, Any]:
    dict_literals = [item for item in forward["observations"] if item["kind"] == "dict_literal"]
    calls = [item for item in forward["observations"] if item["kind"] == "call"]
    assignments = [item for item in backward["observations"] if item["kind"] == "assignment"]
    dict_comprehensions = [
        item for item in backward["observations"] if item["kind"] == "dict_comprehension_return"
    ]
    return {
        "dict_literals": dict_literals,
        "calls": calls,
        "assignments": assignments,
        "dict_comprehensions": dict_comprehensions,
        "format_operations": [
            item for item in assignments if "%" in item["expr"]
        ],
    }


def _generate_candidate_edges(structure: dict[str, Any]) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []

    for item in structure["dict_literals"]:
        lhs = item.get("lhs")
        for key in item.get("keys", []):
            if not lhs or not key or key.startswith(("'", '"')):
                continue
            edges.append(
                {
                    "from": key,
                    "to": f"{lhs}.keys()[*]",
                    "kind": "dict_literal_key",
                    "score": 0.92,
                    "evidence": item["expr"],
                    "location": f"{item['file']}:{item['line']}",
                }
            )

    for item in structure["dict_comprehensions"]:
        edges.append(
            {
                "from": "input_mapping.keys()[*]",
                "to": "returned_mapping.keys()[*]",
                "kind": "dict_comprehension_key_preserved",
                "score": 0.72,
                "evidence": item["expr"],
                "location": f"{item['file']}:{item['line']}",
            }
        )

    for item in structure["format_operations"]:
        targets = item.get("targets") or []
        target = targets[0] if targets else "formatted_value"
        edges.append(
            {
                "from": "format_mapping.keys()[*]",
                "to": target,
                "kind": "named_percent_format_mapping_key",
                "score": 0.70,
                "evidence": item["expr"],
                "location": f"{item['file']}:{item['line']}",
            }
        )

    return sorted(edges, key=lambda item: item["score"], reverse=True)


def _flatten_rule_config(rule_config: list[dict[str, Any]]) -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    sinks: list[dict[str, Any]] = []
    entrypoints: list[dict[str, Any]] = []
    checker_ids: list[str] = []

    for rule in rule_config or []:
        checker_ids.extend(str(item) for item in rule.get("checkerIds", []) or [])
        for source_kind, items in (rule.get("sources") or {}).items():
            for item in items or []:
                sources.append(
                    {
                        "kind": source_kind,
                        "fsig": item.get("fsig"),
                        "values": item.get("values", []),
                        "scopeFile": item.get("scopeFile"),
                        "scopeFunc": item.get("scopeFunc"),
                    }
                )
        for sink_kind, items in (rule.get("sinks") or {}).items():
            for item in items or []:
                sinks.append(
                    {
                        "kind": sink_kind,
                        "fsig": item.get("fsig"),
                        "args": item.get("args", []),
                        "attribute": item.get("attribute"),
                    }
                )
        for item in rule.get("entrypoints", []) or []:
            entrypoints.append(
                {
                    "filePath": item.get("filePath"),
                    "functionName": item.get("functionName"),
                    "attribute": item.get("attribute"),
                }
            )

    return {
        "checker_ids": sorted(set(checker_ids)),
        "sources": sources,
        "sinks": sinks,
        "entrypoints": entrypoints,
    }


def _diagnostics_facts(path: Path | None, max_samples: int = 20) -> dict[str, Any]:
    if not path or not path.exists():
        return {"available": False, "path": str(path) if path else None, "log_key_counts": {}, "samples": []}
    counts: dict[str, int] = {}
    samples: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        key = str(item.get("log_key"))
        counts[key] = counts.get(key, 0) + 1
        if len(samples) < max_samples:
            samples.append(
                {
                    "log_key": item.get("log_key"),
                    "log_time": item.get("log_time"),
                    "string1": item.get("string1"),
                    "string2": item.get("string2"),
                    "number1": item.get("number1"),
                    "number2": item.get("number2"),
                    "number3": item.get("number3"),
                }
            )
    return {"available": True, "path": str(path), "log_key_counts": counts, "samples": samples}


def _sarif_facts(path: Path | None, max_results: int = 10) -> dict[str, Any]:
    if not path or not path.exists():
        return {"available": False, "path": str(path) if path else None, "result_count": 0, "results": []}
    sarif = _load_json(path)
    results: list[dict[str, Any]] = []
    for run in sarif.get("runs", []) or []:
        for result in run.get("results", []) or []:
            locations = []
            for location in result.get("locations", []) or []:
                physical = location.get("physicalLocation", {}) if isinstance(location, dict) else {}
                artifact = physical.get("artifactLocation", {}) if isinstance(physical, dict) else {}
                region = physical.get("region", {}) if isinstance(physical, dict) else {}
                locations.append(
                    {
                        "uri": artifact.get("uri"),
                        "startLine": region.get("startLine"),
                        "snippet": (region.get("snippet") or {}).get("text") if isinstance(region, dict) else None,
                    }
                )
            if len(results) < max_results:
                results.append(
                    {
                        "level": result.get("level"),
                        "message": (result.get("message") or {}).get("text"),
                        "locations": locations,
                    }
                )
    return {"available": True, "path": str(path), "result_count": len(results), "results": results}


def build_baseline_facts(
    out_path: Path,
    case_path: Path | None = None,
    baseline_summary_path: Path | None = None,
    diagnostics_path: Path | None = None,
    sarif_path: Path | None = None,
    callgraph_path: Path | None = None,
    include_rule_config: bool = False,
) -> dict[str, Any]:
    case: dict[str, Any] = {}
    case_dir: Path | None = None
    if case_path is not None:
        case_path = case_path.resolve()
        case_dir = case_path.parent
        case = _load_json(case_path)
        baseline_summary_path = baseline_summary_path or _resolve_case_value(case_dir, case.get("baseline_summary"))

    if baseline_summary_path is None:
        raise ValueError("baseline summary is required")
    baseline_summary_path = baseline_summary_path.resolve()
    baseline = _load_json(baseline_summary_path)
    baseline_dir = baseline_summary_path.parent
    diagnostics_path = diagnostics_path or baseline_dir / "yasa-diagnostics-log.txt"
    sarif_path = sarif_path or baseline_dir / "report.sarif"
    callgraph_path = callgraph_path or baseline_dir / "callgraph.json"
    full_rule_facts = _flatten_rule_config(baseline.get("ruleConfig", []) or [])
    rule_facts = (
        full_rule_facts
        if include_rule_config
        else {
            "included": False,
            "source_rule_count": len(full_rule_facts["sources"]),
            "sink_rule_count": len(full_rule_facts["sinks"]),
            "entrypoint_rule_count": len(full_rule_facts["entrypoints"]),
            "note": (
                "Rule signatures are analyzer configuration, not baseline-observed facts. "
                "They are hidden by default to avoid leaking manual boundary hints."
            ),
        }
    )

    facts = {
        "schema_version": "lapis.baseline_facts.v1",
        "oracle_blind": True,
        "case": {
            "case_id": case.get("case_id"),
            "project": case.get("project"),
            "case_path": str(case_path) if case_path else None,
            "note": (
                "case.json is used only to locate baseline artifacts and non-oracle identifiers; "
                "source/sink/breakpoint/frontier fields are not read."
            ),
        },
        "artifacts": {
            "baseline_summary": str(baseline_summary_path),
            "diagnostics": str(diagnostics_path) if diagnostics_path else None,
            "sarif": str(sarif_path) if sarif_path else None,
            "callgraph": str(callgraph_path) if callgraph_path else None,
        },
        "scan": {
            "projectName": baseline.get("projectName"),
            "projectPath": baseline.get("projectPath"),
            "yasaVersion": baseline.get("yasaVersion"),
            "language": baseline.get("language"),
            "findingCount": baseline.get("findingCount", 0),
            "markedSourceCount": baseline.get("markedSourceCount", 0),
            "matchedSinkCount": baseline.get("matchedSinkCount", 0),
            "entryPointCount": baseline.get("entryPointCount", 0),
            "fileCount": baseline.get("fileCount", 0),
            "lineCount": baseline.get("lineCount", 0),
            "totalTimeMs": baseline.get("totalTimeMs", 0),
            "dumpAllCG": baseline.get("dumpAllCG"),
            "cgAlgorithm": baseline.get("cgAlgorithm"),
        },
        "rule_config_facts": rule_facts,
        "diagnostics_facts": _diagnostics_facts(diagnostics_path),
        "sarif_facts": _sarif_facts(sarif_path),
        "callgraph_facts": summarize_callgraph(callgraph_path),
        "known_public_conclusion": {
            "source_observed": int(baseline.get("markedSourceCount", 0) or 0) > 0,
            "sink_observed": int(baseline.get("matchedSinkCount", 0) or 0) > 0,
            "finding_observed": int(baseline.get("findingCount", 0) or 0) > 0,
            "repair_candidate_if_no_finding": (
                int(baseline.get("markedSourceCount", 0) or 0) > 0
                and int(baseline.get("matchedSinkCount", 0) or 0) > 0
                and int(baseline.get("findingCount", 0) or 0) == 0
            ),
        },
        "omitted_oracle_fields": [
            "case.source",
            "case.sink",
            "case.breakpoint",
            "case.breakpoint.frontier",
            "case.expected_repair_order",
            "case.references",
            "rule_config_facts.sources[].fsig",
            "rule_config_facts.sinks[].fsig",
            "candidate_edges seeded from case_id",
            "manual CTPC/CCEC answers",
        ],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(facts, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return facts


def _baseline_status(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_hit": summary.get("markedSourceCount", 0) > 0,
        "sink_hit": summary.get("matchedSinkCount", 0) > 0,
        "call_context_reachable": summary.get("matchedSinkCount", 0) > 0,
        "complete_taint_path_found": summary.get("findingCount", 0) > 0,
        "sources_marked": summary.get("markedSourceCount", 0),
        "sinks_matched": summary.get("matchedSinkCount", 0),
        "findings": summary.get("findingCount", 0),
        "entrypoints": summary.get("entryPointCount", 0),
    }


def _build_oracle_blind_mixed_evidence(
    case: dict[str, Any],
    baseline: dict[str, Any],
    source: dict[str, Any],
    sink: dict[str, Any],
) -> dict[str, Any]:
    baseline = _baseline_status(baseline)
    return {
        "case_id": case["case_id"],
        "project": case["project"],
        "affected_version": case["affected_version"],
        "vulnerability": case["vulnerability"],
        "declared_case_group": case.get("gap_type"),
        "declared_repair_branch": case.get("repair_branch"),
        "baseline_status": baseline,
        "source": source,
        "sink": sink,
        "source_forward_slice": {
            "source": source.get("symbol"),
            "reached": [source.get("symbol")],
            "frontier": source.get("symbol"),
            "observations": [],
        },
        "sink_backward_slice": {
            "sink": sink.get("expr"),
            "argument": sink.get("argument"),
            "dependency_chain": [sink.get("argument")] if sink.get("argument") else [],
            "observations": [],
        },
        "local_structure_evidence": {},
        "local_convergence": {
            "object": None,
            "access_path": None,
            "source_frontier": source.get("symbol"),
            "sink_dependency_node": sink.get("argument"),
            "is_converged": False,
        },
        "candidate_edges": [],
        "top_k_edges": [],
        "verdict": {
            "is_access_path_gap_candidate": False,
            "gap_type": ["mixed case requires oracle-blind CCEC evidence before CTPC synthesis"],
            "summary": (
                "Oracle-blind mode hides benchmark breakpoint/frontier chains. "
                "Run callgraph/source-slice evidence extraction first, then synthesize CCEC/CTPC "
                "from observed analyzer evidence only."
            ),
        },
        "oracle_blind": True,
    }


def build_evidence(
    case_path: Path,
    out_path: Path,
    top_k: int = 3,
) -> dict[str, Any]:
    case_path = case_path.resolve()
    case_dir = case_path.parent
    case = _load_json(case_path)
    dataset_dir = case_dir / case["dataset_dir"]
    baseline = _load_json(case_dir / case["baseline_summary"])

    source = _with_observed_line(case_dir, dataset_dir, case["source"])
    sink = _with_observed_line(case_dir, dataset_dir, case["sink"])
    if case.get("gap_type") == "mixed_case":
        evidence = _build_oracle_blind_mixed_evidence(case, baseline, source, sink)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return evidence

    source_forward_slice = _extract_source_forward(case_dir, dataset_dir, case["source"])
    sink_backward_slice = _extract_sink_backward(case_dir, dataset_dir, case["sink"])
    structure = _extract_structure(source_forward_slice, sink_backward_slice)
    candidate_edges = _generate_candidate_edges(structure)
    top_k_edges = candidate_edges[:top_k]
    candidate_access_paths = sorted(
        {
            value
            for edge in candidate_edges
            for value in (edge.get("from"), edge.get("to"))
            if isinstance(value, str) and value
        }
    )
    local_convergence = {
        "object": None,
        "access_path": candidate_access_paths[0] if candidate_access_paths else None,
        "source_frontier": source_forward_slice["frontier"],
        "sink_dependency_node": None,
        "is_converged": bool(candidate_edges),
    }

    baseline_status = _baseline_status(baseline)

    verdict = {
        "is_access_path_gap_candidate": (
            baseline_status["source_hit"]
            and baseline_status["sink_hit"]
            and baseline_status["call_context_reachable"]
            and not baseline_status["complete_taint_path_found"]
        ),
        "gap_type": sorted({edge["kind"] for edge in candidate_edges}) or ["access-path propagation"],
        "summary": (
            "Source and final sink are both observed by baseline YASA, but no taint "
            "finding is produced. Candidate CTPC obligations are derived from local static structure."
        ),
    }

    evidence = {
        "case_id": case["case_id"],
        "project": case["project"],
        "affected_version": case["affected_version"],
        "vulnerability": case["vulnerability"],
        "baseline_status": baseline_status,
        "source": source,
        "sink": sink,
        "source_forward_slice": source_forward_slice,
        "sink_backward_slice": sink_backward_slice,
        "local_structure_evidence": structure,
        "local_convergence": local_convergence,
        "candidate_edges": candidate_edges,
        "top_k_edges": top_k_edges,
        "verdict": verdict,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return evidence


def plan_ctpc_repair(evidence_path: Path, out_path: Path, top_k: int = 5) -> dict[str, Any]:
    evidence = _load_json(evidence_path.resolve())
    candidates = sorted(
        evidence.get("candidate_edges", []),
        key=lambda item: float(item.get("score", 0) or 0),
        reverse=True,
    )
    top_k_candidates = candidates[:top_k]
    gap_type = evidence.get("gap_type") or "propagation_gap"
    mode = "easy" if len(top_k_candidates) == 1 else "middle"
    if len(top_k_candidates) >= 3:
        mode = "middle"
    if gap_type == "mixed_case" and top_k_candidates:
        mode = "hard"
    if not top_k_candidates:
        mode = "deferred"

    report = {
        "schema_version": "lapis.ctpc_repair_plan.v1",
        "case_id": evidence.get("case_id"),
        "gap_type": gap_type,
        "repair_branch": evidence.get("repair_branch"),
        "mode": mode,
        "llm_required": bool(top_k_candidates),
        "top_k": len(top_k_candidates),
        "candidate_count": len(candidates),
        "top_k_propagation_candidates": top_k_candidates,
        "generation_strategy": "ranked_candidates_to_llm_ctpc" if top_k_candidates else "defer",
        "next_steps": [
            "build_ctpc_prompt_with_top_k_candidates",
            "llm_generate_ctpc_contract",
            "llm_generate_must_flow_must_not_flow_must_kill",
            "validate_ctpc",
            "run_yasa_with_ctpc",
        ]
        if top_k_candidates
        else ["defer"],
        "contract_mapping": {
            "dict_literal_key": "propagation_edges",
            "dict_comprehension_key_preserved": "propagation_edges or function_summaries",
            "named_percent_format_mapping_key": "propagation_edges and risk_upgrades",
            "safe_patterns": "kill_conditions",
        },
        "note": (
            "CTPC top-k is a ranked candidate propagation-obligation set used while generating "
            "the contract. It is not the final CTPC; the LLM maps selected candidates into "
            "propagation_edges, function_summaries, risk_upgrades, and kill_conditions."
        ),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def materialize_ctpc(response_path: Path, out_dir: Path) -> dict[str, Path]:
    ctpc = _load_json(response_path)
    from .ctpc_schema import validate_ctpc_v2

    validate_ctpc_v2(ctpc)
    ctpc_dir = out_dir / "ctpc"
    ctpc_dir.mkdir(parents=True, exist_ok=True)
    ctpc_path = ctpc_dir / "ctpc.json"
    ctpc_path.write_text(json.dumps(ctpc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return {"ctpc": ctpc_path}


def materialize_validation(response_path: Path, out_dir: Path) -> dict[str, Path]:
    samples = _load_json(response_path)
    required_samples = {
        "must_flow": "finding",
        "must_not_flow": "no_finding",
        "must_kill": "no_finding",
    }
    for sample_name, expected in required_samples.items():
        sample = samples.get(sample_name)
        if not isinstance(sample, dict):
            raise ValueError(f"{sample_name} is required")
        if sample.get("expected") != expected:
            raise ValueError(f"{sample_name}.expected must be {expected!r}")
        if not isinstance(sample.get("code"), str) or not sample["code"].strip():
            raise ValueError(f"{sample_name}.code must be non-empty")

    validation_dir = out_dir / "validation"
    validation_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    for sample_name in required_samples:
        sample = samples[sample_name]
        sample_dir = validation_dir / sample_name.replace("_", "-")
        sample_dir.mkdir(parents=True, exist_ok=True)
        code_path = sample_dir / "case.py"
        meta_path = sample_dir / "expected.json"
        code_path.write_text(sample["code"].rstrip() + "\n", encoding="utf-8")
        meta_path.write_text(
            json.dumps(
                {
                    "name": sample.get("name", sample_name),
                    "expected": sample["expected"],
                },
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
        written[f"{sample_name}_code"] = code_path
        written[f"{sample_name}_expected"] = meta_path

    return written


def main() -> None:
    parser = argparse.ArgumentParser(description="LAPIS access-path gap prototype")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build-evidence", help="Build an Evidence Pack for one case")
    build.add_argument("--case", required=True, type=Path, help="Path to case.json")
    build.add_argument("--out", required=True, type=Path, help="Output evidence_pack.json")
    build.add_argument("--top-k", default=3, type=int, help="Top-K propagation candidates to include")

    baseline_facts_cmd = subparsers.add_parser(
        "build-baseline-facts",
        help="Build an oracle-blind fact pack from YASA baseline artifacts",
    )
    baseline_facts_cmd.add_argument("--out", required=True, type=Path, help="Output baseline_facts.json")
    baseline_facts_cmd.add_argument("--case", type=Path, help="Optional case.json used only to locate artifacts")
    baseline_facts_cmd.add_argument("--baseline-summary", type=Path, help="Path to baseline scan_summary.json")
    baseline_facts_cmd.add_argument("--diagnostics", type=Path, help="Optional yasa-diagnostics-log.txt")
    baseline_facts_cmd.add_argument("--sarif", type=Path, help="Optional baseline report.sarif")
    baseline_facts_cmd.add_argument("--callgraph", type=Path, help="Optional baseline callgraph.json")
    baseline_facts_cmd.add_argument(
        "--include-rule-config",
        action="store_true",
        help="Include analyzer rule signatures; hidden by default because they may encode manual hints",
    )

    gate_cmd = subparsers.add_parser(
        "evidence-gate",
        help="Run Step 1 Evidence Gate for a no-finding candidate case",
    )
    gate_cmd.add_argument("--case", required=True, type=Path, help="Path to case.json")
    gate_cmd.add_argument("--out", required=True, type=Path, help="Output evidence_gate_report.json")
    gate_cmd.add_argument("--evidence", type=Path, help="Optional existing evidence_pack.json")
    gate_cmd.add_argument("--callgraph", type=Path, help="Optional callgraph.json")
    gate_cmd.add_argument("--baseline-summary", type=Path, help="Optional scan_summary.json for rerun rediagnosis")

    diagnosis_cmd = subparsers.add_parser(
        "diagnose-gap",
        help="Run Step 2 gap diagnosis from an Evidence Gate report",
    )
    diagnosis_cmd.add_argument("--gate", required=True, type=Path, help="Path to evidence_gate_report.json")
    diagnosis_cmd.add_argument("--out", required=True, type=Path, help="Output gap_diagnosis.json")

    list_cases_cmd = subparsers.add_parser(
        "list-cases",
        help="List CVE cases grouped by repair gap type",
    )
    list_cases_cmd.add_argument("--cases-root", required=True, type=Path, help="Path to LAPIS-Experiments/cases")
    list_cases_cmd.add_argument("--out", type=Path, help="Optional output case_index.json")

    workflow_cmd = subparsers.add_parser(
        "run-repair-workflow",
        help="Run Evidence Gate, Gap Diagnosis, and first-stage candidate generation for all cases",
    )
    workflow_cmd.add_argument("--cases-root", required=True, type=Path, help="Path to LAPIS-Experiments/cases")
    workflow_cmd.add_argument("--out", required=True, type=Path, help="Output workflow_report.json")

    e2e_case_cmd = subparsers.add_parser(
        "run-end-to-end-case",
        help="Run baseline, CCEC rerun, rediagnosis, optional CTPC rerun, and final evaluation for one case",
    )
    e2e_case_cmd.add_argument("--tool-dir", required=True, type=Path, help="YASA/LAPIS-Tool directory")
    e2e_case_cmd.add_argument("--case", required=True, type=Path, help="Path to case.json")
    e2e_case_cmd.add_argument("--out-dir", required=True, type=Path, help="Output directory for the E2E report")
    e2e_case_cmd.add_argument("--uast-sdk-path", required=True, type=Path, help="Path to uast4py binary")
    e2e_case_cmd.add_argument("--timeout-seconds", default=180, type=int, help="Timeout per full-case run")
    e2e_case_cmd.add_argument("--checker-ids", default="taint_flow_python_input_inner", help="Checker IDs for YASA")
    e2e_case_cmd.add_argument("--oracle", type=Path, help="Optional hidden oracle JSON, read only during final evaluation")
    e2e_case_cmd.add_argument("--llm-auto", action="store_true", help="Call the configured LLM for CCEC/CTPC synthesis")
    _add_llm_args(e2e_case_cmd, max_tokens=8192)

    e2e_cases_cmd = subparsers.add_parser(
        "run-end-to-end-cases",
        help="Run the full E2E repair loop for every case under a cases root",
    )
    e2e_cases_cmd.add_argument("--tool-dir", required=True, type=Path, help="YASA/LAPIS-Tool directory")
    e2e_cases_cmd.add_argument("--cases-root", required=True, type=Path, help="Path to LAPIS-Experiments/cases")
    e2e_cases_cmd.add_argument("--out-dir", required=True, type=Path, help="Output directory for suite reports")
    e2e_cases_cmd.add_argument("--uast-sdk-path", required=True, type=Path, help="Path to uast4py binary")
    e2e_cases_cmd.add_argument("--timeout-seconds", default=180, type=int, help="Timeout per full-case run")
    e2e_cases_cmd.add_argument("--checker-ids", default="taint_flow_python_input_inner", help="Checker IDs for YASA")
    e2e_cases_cmd.add_argument("--oracle-root", type=Path, help="Optional directory of hidden oracle JSON files by case_id")
    e2e_cases_cmd.add_argument("--llm-auto", action="store_true", help="Call the configured LLM for CCEC/CTPC synthesis")
    _add_llm_args(e2e_cases_cmd, max_tokens=8192)

    llm_smoke_cmd = subparsers.add_parser(
        "llm-smoke-test",
        help="Call an OpenAI-compatible LLM API and parse a tiny JSON response",
    )
    _add_llm_args(llm_smoke_cmd, max_tokens=256)

    llm_ccec_cmd = subparsers.add_parser(
        "llm-generate-ccec",
        help="Build a CCEC prompt, call the LLM, and write candidate_edges JSON",
    )
    llm_ccec_cmd.add_argument("--case", required=True, type=Path, help="Path to case.json")
    llm_ccec_cmd.add_argument("--out", required=True, type=Path, help="Output candidate_edges JSON")
    llm_ccec_cmd.add_argument("--gate", type=Path, help="Optional evidence_gate.json")
    llm_ccec_cmd.add_argument("--diagnosis", type=Path, help="Optional gap_diagnosis.json")
    llm_ccec_cmd.add_argument("--raw-out", type=Path, help="Optional raw LLM text output")
    _add_llm_args(llm_ccec_cmd, max_tokens=8192)

    llm_ctpc_cmd = subparsers.add_parser(
        "llm-generate-ctpc",
        help="Build a CTPC prompt from an Evidence Pack, call the LLM, and write CTPC JSON",
    )
    llm_ctpc_cmd.add_argument("--evidence", required=True, type=Path, help="Path to evidence_pack.json")
    llm_ctpc_cmd.add_argument("--out", required=True, type=Path, help="Output CTPC response JSON")
    llm_ctpc_cmd.add_argument("--raw-out", type=Path, help="Optional raw LLM text output")
    _add_llm_args(llm_ctpc_cmd, max_tokens=8192)

    ccec_cmd = subparsers.add_parser(
        "generate-ccec-candidates",
        help="Generate candidate call edges for one Connectivity Gap or Mixed Case",
    )
    ccec_cmd.add_argument("--case", required=True, type=Path, help="Path to case.json")
    ccec_cmd.add_argument("--out", required=True, type=Path, help="Output candidate_edges.json")
    ccec_cmd.add_argument("--top-k", default=5, type=int, help="Maximum number of candidates")
    ccec_cmd.add_argument(
        "--strategy",
        choices=("static",),
        default="static",
        help="Candidate generation strategy",
    )

    ccec_plan_cmd = subparsers.add_parser(
        "plan-ccec-repair",
        help="Classify CCEC difficulty and choose top-k / rule / LLM routing",
    )
    ccec_plan_cmd.add_argument("--case", required=True, type=Path, help="Path to case.json")
    ccec_plan_cmd.add_argument("--out", required=True, type=Path, help="Output ccec_repair_plan.json")
    ccec_plan_cmd.add_argument("--top-k", default=5, type=int, help="Maximum candidate budget for LLM ranking")

    ccec_prompt = subparsers.add_parser("build-ccec-prompt", help="Build a CCEC prompt from case/gate/diagnosis")
    ccec_prompt.add_argument("--case", required=True, type=Path, help="Path to case.json")
    ccec_prompt.add_argument("--out", required=True, type=Path, help="Output prompt text file")
    ccec_prompt.add_argument("--gate", type=Path, help="Optional evidence_gate.json")
    ccec_prompt.add_argument("--diagnosis", type=Path, help="Optional gap_diagnosis.json")
    ccec_prompt.add_argument(
        "--oracle-safe",
        action="store_true",
        default=True,
        help="Omit benchmark-oracle chain fields from the CCEC prompt",
    )

    validate_ccec_cmd = subparsers.add_parser(
        "validate-ccec-candidates",
        help="Run structural validation for candidate CCEC call edges",
    )
    validate_ccec_cmd.add_argument("--candidates", required=True, type=Path, help="Path to candidate_edges.json")
    validate_ccec_cmd.add_argument("--out", required=True, type=Path, help="Output validation_report.json")

    ccec_validation_prompt = subparsers.add_parser(
        "build-ccec-validation-prompt",
        help="Build a CCEC validation-contract prompt from case/gate/diagnosis/CCEC",
    )
    ccec_validation_prompt.add_argument("--case", required=True, type=Path, help="Path to case.json")
    ccec_validation_prompt.add_argument("--ccec", required=True, type=Path, help="Path to candidate_edges.json")
    ccec_validation_prompt.add_argument("--out", required=True, type=Path, help="Output prompt text file")
    ccec_validation_prompt.add_argument("--gate", type=Path, help="Optional evidence_gate.json")
    ccec_validation_prompt.add_argument("--diagnosis", type=Path, help="Optional gap_diagnosis.json")

    ccec_link_validation_cmd = subparsers.add_parser(
        "validate-ccec-link-contract",
        help="Validate LLM-generated CCEC must-link/must-not-link/must-kill samples",
    )
    ccec_link_validation_cmd.add_argument(
        "--validation", required=True, type=Path, help="Path to CCEC validation contract JSON"
    )
    ccec_link_validation_cmd.add_argument("--candidates", required=True, type=Path, help="Path to CCEC candidates")
    ccec_link_validation_cmd.add_argument("--out", required=True, type=Path, help="Output validation report")

    materialize_ccec_validation_cmd = subparsers.add_parser(
        "materialize-ccec-validation",
        help="Write CCEC must-link/must-not-link/must-kill local code samples from response JSON",
    )
    materialize_ccec_validation_cmd.add_argument(
        "--response", required=True, type=Path, help="Path to CCEC validation response JSON"
    )
    materialize_ccec_validation_cmd.add_argument("--out-dir", required=True, type=Path, help="Case output directory")

    validate_ccec_local_cmd = subparsers.add_parser(
        "validate-ccec-local",
        help="Validate materialized CCEC local semantic samples before callgraph rerun",
    )
    validate_ccec_local_cmd.add_argument(
        "--validation-dir", required=True, type=Path, help="Directory with CCEC local samples"
    )
    validate_ccec_local_cmd.add_argument("--candidates", required=True, type=Path, help="Path to CCEC candidates")
    validate_ccec_local_cmd.add_argument("--out", required=True, type=Path, help="Output CCEC local validation report")

    ctpc_prompt = subparsers.add_parser("build-ctpc-prompt", help="Build a CTPC prompt from an Evidence Pack")
    ctpc_prompt.add_argument("--evidence", required=True, type=Path, help="Path to evidence_pack.json")
    ctpc_prompt.add_argument("--out", required=True, type=Path, help="Output prompt text file")

    ctpc_plan = subparsers.add_parser(
        "plan-ctpc-repair",
        help="Rank propagation candidates and choose top-k for CTPC synthesis",
    )
    ctpc_plan.add_argument("--evidence", required=True, type=Path, help="Path to evidence_pack.json")
    ctpc_plan.add_argument("--out", required=True, type=Path, help="Output ctpc_repair_plan.json")
    ctpc_plan.add_argument("--top-k", default=5, type=int, help="Candidate budget for CTPC synthesis")

    validation_prompt = subparsers.add_parser(
        "build-validation-prompt",
        help="Build a validation-sample prompt from an Evidence Pack and CTPC",
    )
    validation_prompt.add_argument("--evidence", required=True, type=Path, help="Path to evidence_pack.json")
    validation_prompt.add_argument("--ctpc", required=True, type=Path, help="Path to ctpc.json")
    validation_prompt.add_argument("--out", required=True, type=Path, help="Output prompt text file")

    materialize_ctpc_cmd = subparsers.add_parser("materialize-ctpc", help="Validate and write CTPC JSON")
    materialize_ctpc_cmd.add_argument("--response", required=True, type=Path, help="Path to CTPC response JSON")
    materialize_ctpc_cmd.add_argument("--out-dir", required=True, type=Path, help="Case output directory")

    upgrade_ctpc_cmd = subparsers.add_parser(
        "upgrade-ctpc-v2",
        help="Validate and write a structured CTPC v2 JSON file",
    )
    upgrade_ctpc_cmd.add_argument("--ctpc", required=True, type=Path, help="Input CTPC v2 JSON")
    upgrade_ctpc_cmd.add_argument("--out", required=True, type=Path, help="Output CTPC v2 JSON")

    materialize_validation_cmd = subparsers.add_parser(
        "materialize-validation",
        help="Validate and write validation samples from response JSON",
    )
    materialize_validation_cmd.add_argument(
        "--response", required=True, type=Path, help="Path to validation response JSON"
    )
    materialize_validation_cmd.add_argument("--out-dir", required=True, type=Path, help="Case output directory")

    validate_cmd = subparsers.add_parser(
        "validate-ctpc",
        help="Run three-way structural validation for a CTPC",
    )
    validate_cmd.add_argument("--ctpc", required=True, type=Path, help="Path to ctpc.json")
    validate_cmd.add_argument("--validation-dir", required=True, type=Path, help="Directory with validation samples")
    validate_cmd.add_argument("--out-dir", required=True, type=Path, help="Directory for validation reports")

    validation_rules_cmd = subparsers.add_parser(
        "build-validation-rules",
        help="Build YASA rule files for CTPC validation samples",
    )
    validation_rules_cmd.add_argument(
        "--validation-dir", required=True, type=Path, help="Directory with validation samples"
    )
    validation_rules_cmd.add_argument("--out-dir", required=True, type=Path, help="Output directory for rule files")

    run_yasa_cmd = subparsers.add_parser(
        "run-yasa-validation",
        help="Run YASA on all CTPC validation samples and summarize results",
    )
    run_yasa_cmd.add_argument("--tool-dir", required=True, type=Path, help="YASA tool directory")
    run_yasa_cmd.add_argument("--validation-dir", required=True, type=Path, help="Directory with validation samples")
    run_yasa_cmd.add_argument("--rules-dir", required=True, type=Path, help="Directory with validation YASA rules")
    run_yasa_cmd.add_argument("--out-dir", required=True, type=Path, help="Output directory for YASA run reports")
    run_yasa_cmd.add_argument("--uast-sdk-path", required=True, type=Path, help="Path to uast4py binary")
    run_yasa_cmd.add_argument("--label", default="baseline", help="Label for this YASA run")
    run_yasa_cmd.add_argument("--timeout-seconds", default=180, type=int, help="Timeout per sample")
    run_yasa_cmd.add_argument("--ctpc-file", type=Path, help="Optional CTPC JSON file for LAPIS-Tool")
    run_yasa_cmd.add_argument("--ccec-file", type=Path, help="Optional CCEC JSON file for LAPIS-Tool")

    run_case_cmd = subparsers.add_parser(
        "run-yasa-case",
        help="Run YASA on the original CVE case dataset and summarize the full-CVE result",
    )
    run_case_cmd.add_argument("--tool-dir", required=True, type=Path, help="YASA tool directory")
    run_case_cmd.add_argument("--case", required=True, type=Path, help="Path to case.json")
    run_case_cmd.add_argument("--out-dir", required=True, type=Path, help="Output directory for YASA run reports")
    run_case_cmd.add_argument("--uast-sdk-path", required=True, type=Path, help="Path to uast4py binary")
    run_case_cmd.add_argument("--label", default="full-cve", help="Label for this YASA run")
    run_case_cmd.add_argument("--timeout-seconds", default=180, type=int, help="Timeout for the case run")
    run_case_cmd.add_argument("--ctpc-file", type=Path, help="Optional CTPC JSON file for LAPIS-Tool")
    run_case_cmd.add_argument("--ccec-file", type=Path, help="Optional CCEC JSON file for LAPIS-Tool")
    run_case_cmd.add_argument("--checker-ids", default="taint_flow_python_input_inner", help="Checker IDs for YASA")
    run_case_cmd.add_argument("--dump-cg", action="store_true", help="Ask YASA to dump callgraph.json")

    feasibility_cmd = subparsers.add_parser(
        "build-feasibility-report",
        help="Combine CTPC validation and upstream YASA validation into a feasibility report",
    )
    feasibility_cmd.add_argument(
        "--ctpc-validation", required=True, type=Path, help="Path to validation_report.json"
    )
    feasibility_cmd.add_argument(
        "--baseline-yasa", required=True, type=Path, help="Path to upstream YASA validation report JSON"
    )
    feasibility_cmd.add_argument(
        "--enhanced-yasa", type=Path, help="Optional path to LAPIS-Tool enhanced YASA validation report JSON"
    )
    feasibility_cmd.add_argument("--out", required=True, type=Path, help="Output feasibility report JSON")

    args = parser.parse_args()

    if args.command == "build-evidence":
        evidence = build_evidence(
            args.case,
            args.out,
            args.top_k,
        )
        status = evidence["baseline_status"]
        verdict = evidence["verdict"]
        print(f"case_id={evidence['case_id']}")
        print(
            "baseline="
            f"source_hit={status['source_hit']} "
            f"sink_hit={status['sink_hit']} "
            f"findings={status['findings']}"
        )
        print(f"access_path_gap_candidate={verdict['is_access_path_gap_candidate']}")
        print(f"top_k_edges={len(evidence['top_k_edges'])}")
        print(f"wrote={args.out}")
    elif args.command == "build-baseline-facts":
        facts = build_baseline_facts(
            out_path=args.out,
            case_path=args.case,
            baseline_summary_path=args.baseline_summary,
            diagnostics_path=args.diagnostics,
            sarif_path=args.sarif,
            callgraph_path=args.callgraph,
            include_rule_config=args.include_rule_config,
        )
        scan = facts["scan"]
        conclusion = facts["known_public_conclusion"]
        print(f"case_id={facts['case'].get('case_id')}")
        print(
            "baseline="
            f"sources={scan['markedSourceCount']} "
            f"sinks={scan['matchedSinkCount']} "
            f"findings={scan['findingCount']}"
        )
        print(f"repair_candidate_if_no_finding={conclusion['repair_candidate_if_no_finding']}")
        print(f"wrote={args.out}")
    elif args.command == "evidence-gate":
        report = build_evidence_gate_report(
            args.case,
            args.out,
            args.evidence,
            args.callgraph,
            args.baseline_summary,
        )
        print(f"case_id={report.get('case_id')}")
        print(f"gate_status={report['gate_status']}")
        print(f"reasons={'; '.join(report.get('decision_reason', []))}")
        print(f"wrote={args.out}")
    elif args.command == "diagnose-gap":
        report = build_gap_diagnosis_report(args.gate, args.out)
        diagnosis = report["diagnosis"]
        print(f"case_id={report.get('case_id')}")
        print(f"gap_type={diagnosis['gap_type']}")
        print(f"next_step={diagnosis['next_step']}")
        print(f"wrote={args.out}")
    elif args.command == "list-cases":
        report = build_case_index(args.cases_root, args.out)
        print(f"cases_root={report['cases_root']}")
        print(f"case_count={report['case_count']}")
        for item in report["cases"]:
            print(
                f"{item['gap_type']} {item['case_id']} "
                f"project={item['project']} branch={item['repair_branch']}"
            )
        if args.out:
            print(f"wrote={args.out}")
    elif args.command == "run-repair-workflow":
        report = run_repair_workflow(args.cases_root, args.out)
        print(f"cases_root={report['cases_root']}")
        print(f"case_count={report['case_count']}")
        for item in report["cases"]:
            print(
                f"{item['case_id']} gate={item['gate_status']} "
                f"diagnosis={item['diagnosed_gap_type']} next={item['next_step']}"
            )
        print(f"wrote={args.out}")
        print(f"wrote={args.out.with_suffix('.md')}")
    elif args.command == "run-end-to-end-case":
        llm_config = _llm_config_from_args(args) if args.llm_auto else None
        report = run_end_to_end_case(
            tool_dir=args.tool_dir,
            case_path=args.case,
            out_dir=args.out_dir,
            uast_sdk_path=args.uast_sdk_path,
            timeout_seconds=args.timeout_seconds,
            checker_ids=args.checker_ids,
            oracle_path=args.oracle,
            llm_config=llm_config,
        )
        print(f"case_id={report['case_id']}")
        print(f"final_result={report['evaluation']['final_result']}")
        print(f"evaluation={report['evaluation']['status']}")
        print(f"wrote={Path(report['out_dir']) / 'end_to_end_report.json'}")
    elif args.command == "run-end-to-end-cases":
        llm_config = _llm_config_from_args(args) if args.llm_auto else None
        report = run_end_to_end_cases(
            tool_dir=args.tool_dir,
            cases_root=args.cases_root,
            out_dir=args.out_dir,
            uast_sdk_path=args.uast_sdk_path,
            timeout_seconds=args.timeout_seconds,
            checker_ids=args.checker_ids,
            oracle_root=args.oracle_root,
            llm_config=llm_config,
        )
        print(f"cases_root={report['cases_root']}")
        print(f"case_count={report['case_count']}")
        for item in report["cases"]:
            print(f"{item['case_id']} final={item['final_result']} evaluation={item['evaluation_status']}")
        print(f"wrote={Path(report['out_dir']) / 'end_to_end_suite_report.json'}")
    elif args.command == "llm-smoke-test":
        config = _llm_config_from_args(args)
        prompt_text = (
            "Return exactly one JSON object with this shape: "
            "{\"ok\": true, \"message\": \"lapis llm smoke test\"}"
        )
        response = chat_json(prompt_text, config)
        print(f"base_url={config.base_url}")
        print(f"model={config.model}")
        print(f"ok={response.get('ok')}")
        print(f"message={response.get('message')}")
    elif args.command == "llm-generate-ccec":
        config = _llm_config_from_args(args)
        case = _load_json(args.case)
        gate = _load_json(args.gate) if args.gate else None
        diagnosis = _load_json(args.diagnosis) if args.diagnosis else None
        prompt_text = build_ccec_prompt(case, gate, diagnosis, oracle_safe=True)
        raw_text = chat_text(prompt_text, config)
        response = extract_json_object(raw_text)
        write_llm_artifacts(args.out, response, raw_text)
        if args.raw_out:
            args.raw_out.parent.mkdir(parents=True, exist_ok=True)
            args.raw_out.write_text(raw_text, encoding="utf-8")
        print(f"case_id={response.get('case_id') or case.get('case_id')}")
        print(f"candidate_edges={len(response.get('candidate_edges', []) or [])}")
        print(f"wrote={args.out}")
    elif args.command == "llm-generate-ctpc":
        config = _llm_config_from_args(args)
        evidence = _load_json(args.evidence)
        prompt_text = build_ctpc_prompt(evidence)
        raw_text = chat_text(prompt_text, config)
        response = extract_json_object(raw_text)
        write_llm_artifacts(args.out, response, raw_text)
        if args.raw_out:
            args.raw_out.parent.mkdir(parents=True, exist_ok=True)
            args.raw_out.write_text(raw_text, encoding="utf-8")
        print(f"case_id={evidence.get('case_id')}")
        print(f"schema_version={response.get('schema_version')}")
        print(f"propagation_edges={len(response.get('propagation_edges', []) or [])}")
        print(f"wrote={args.out}")
    elif args.command == "generate-ccec-candidates":
        report = build_ccec_candidates(
            args.case,
            args.out,
            args.top_k,
            strategy=args.strategy,
        )
        print(f"case_id={report['case_id']}")
        print(f"candidate_gap_type={report['candidate_gap_type']}")
        print(f"ccec_mode={report['ccec_mode']}")
        print(f"strategy={report['generation_strategy']}")
        print(f"routing={report['routing_strategy']}")
        print(f"candidate_edges={len(report['candidate_edges'])}")
        print(f"wrote={args.out}")
    elif args.command == "plan-ccec-repair":
        report = plan_ccec_repair(args.case, args.out, args.top_k)
        print(f"case_id={report['case_id']}")
        print(f"mode={report['mode']}")
        print(f"llm_required={report['llm_required']}")
        print(f"top_k={report['top_k']}")
        print(f"strategy={report['generation_strategy']}")
        print(f"wrote={args.out}")
    elif args.command == "build-ccec-prompt":
        case = _load_json(args.case)
        gate = _load_json(args.gate) if args.gate else None
        diagnosis = _load_json(args.diagnosis) if args.diagnosis else None
        oracle_safe = True
        prompt_text = build_ccec_prompt(case, gate, diagnosis, oracle_safe=oracle_safe)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(prompt_text, encoding="utf-8")
        print(f"case_id={case['case_id']}")
        print(f"oracle_safe={oracle_safe}")
        print(f"wrote={args.out}")
    elif args.command == "validate-ccec-candidates":
        report = validate_ccec_candidates(args.candidates, args.out)
        print(f"case_id={report['case_id']}")
        print(f"status={report['status']}")
        print(f"edges={len(report['edge_results'])}")
        print(f"wrote={args.out}")
    elif args.command == "build-ccec-validation-prompt":
        case = _load_json(args.case)
        ccec = _load_json(args.ccec)
        gate = _load_json(args.gate) if args.gate else None
        diagnosis = _load_json(args.diagnosis) if args.diagnosis else None
        prompt_text = build_ccec_validation_prompt(case, ccec, gate, diagnosis)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(prompt_text, encoding="utf-8")
        print(f"case_id={case['case_id']}")
        print(f"wrote={args.out}")
    elif args.command == "validate-ccec-link-contract":
        report = validate_ccec_link_contract(args.validation, args.candidates, args.out)
        print(f"case_id={report['case_id']}")
        print(f"status={report['status']}")
        for item in report["sample_results"]:
            print(f"{item['sample']}={item['passed']}")
        print(f"wrote={args.out}")
    elif args.command == "materialize-ccec-validation":
        written = materialize_ccec_validation(args.response, args.out_dir)
        for key, path in written.items():
            print(f"{key}={path}")
    elif args.command == "validate-ccec-local":
        report = validate_ccec_local_samples(args.validation_dir, args.candidates, args.out)
        print(f"status={report['status']}")
        for item in report["sample_results"]:
            print(f"{item['sample']}={item['passed']}")
        print(f"wrote={args.out}")
    elif args.command == "build-ctpc-prompt":
        evidence = _load_json(args.evidence)
        prompt_text = build_ctpc_prompt(evidence)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(prompt_text, encoding="utf-8")
        print(f"case_id={evidence['case_id']}")
        print(f"wrote={args.out}")
    elif args.command == "plan-ctpc-repair":
        report = plan_ctpc_repair(args.evidence, args.out, args.top_k)
        print(f"case_id={report['case_id']}")
        print(f"mode={report['mode']}")
        print(f"top_k={report['top_k']}")
        print(f"candidate_count={report['candidate_count']}")
        print(f"strategy={report['generation_strategy']}")
        print(f"wrote={args.out}")
    elif args.command == "build-validation-prompt":
        evidence = _load_json(args.evidence)
        ctpc = _load_json(args.ctpc)
        prompt_text = build_validation_prompt(evidence, ctpc)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(prompt_text, encoding="utf-8")
        print(f"case_id={evidence['case_id']}")
        print(f"wrote={args.out}")
    elif args.command == "materialize-ctpc":
        written = materialize_ctpc(args.response, args.out_dir)
        for key, path in written.items():
            print(f"{key}={path}")
    elif args.command == "upgrade-ctpc-v2":
        ctpc = upgrade_ctpc_file(args.ctpc, args.out)
        print(f"schema_version={ctpc['schema_version']}")
        print(f"edges={len(ctpc['propagation_edges'])}")
        print(f"kill_conditions={len(ctpc['kill_conditions'])}")
        print(f"wrote={args.out}")
    elif args.command == "materialize-validation":
        written = materialize_validation(args.response, args.out_dir)
        for key, path in written.items():
            print(f"{key}={path}")
    elif args.command == "validate-ctpc":
        report = validate_ctpc(args.ctpc, args.validation_dir, args.out_dir)
        print(f"status={report['status']}")
        print(f"samples={len(report['sample_results'])}")
        print(f"edges={len(report['edge_coverage'])}")
        print(f"wrote={args.out_dir / 'validation_report.json'}")
    elif args.command == "build-validation-rules":
        written = build_yasa_validation_rules(args.validation_dir, args.out_dir)
        for sample, path in written.items():
            print(f"{sample}={path}")
    elif args.command == "run-yasa-validation":
        report = run_yasa_validation(
            tool_dir=args.tool_dir,
            validation_dir=args.validation_dir,
            rules_dir=args.rules_dir,
            out_dir=args.out_dir,
            uast_sdk_path=args.uast_sdk_path,
            label=args.label,
            timeout_seconds=args.timeout_seconds,
            ctpc_file=args.ctpc_file,
            ccec_file=args.ccec_file,
        )
        print(f"label={report['label']}")
        print(f"status={report['status']}")
        for item in report["sample_results"]:
            print(f"{item['sample']} expected={item['expected']} predicted={item['predicted']} passed={item['passed']}")
        print(f"wrote={args.out_dir / (args.label + '_yasa_validation_report.json')}")
    elif args.command == "run-yasa-case":
        report = run_yasa_case(
            tool_dir=args.tool_dir,
            case_path=args.case,
            out_dir=args.out_dir,
            uast_sdk_path=args.uast_sdk_path,
            label=args.label,
            timeout_seconds=args.timeout_seconds,
            ctpc_file=args.ctpc_file,
            ccec_file=args.ccec_file,
            checker_ids=args.checker_ids,
            dump_cg=args.dump_cg,
        )
        summary = report.get("summary") or {}
        print(f"label={report['label']}")
        print(f"scope={report['scope']}")
        print(f"status={report['status']}")
        print(f"result={report['result']}")
        print(f"findings={summary.get('findingCount', 'n/a')}")
        print(f"sources={summary.get('markedSourceCount', 'n/a')}")
        print(f"sinks={summary.get('matchedSinkCount', 'n/a')}")
        print(f"wrote={args.out_dir / (args.label + '_full_cve_report.json')}")
    elif args.command == "build-feasibility-report":
        report = build_feasibility_report(args.ctpc_validation, args.baseline_yasa, args.out, args.enhanced_yasa)
        print(f"status={report['status']}")
        for item in report["observations"]:
            print(f"{item['kind']} supported={item['supported']}")
        print(f"wrote={args.out}")


if __name__ == "__main__":
    main()
