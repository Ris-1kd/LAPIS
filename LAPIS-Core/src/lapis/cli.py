"""Command line entry points for the LAPIS prototype."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Any

from .ctpc_schema import upgrade_ctpc_file
from .prompt import build_ctpc_prompt, build_validation_prompt
from .validator import build_yasa_validation_rules, validate_ctpc
from .yasa_runner import build_feasibility_report, run_yasa_case, run_yasa_validation


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _read_line(path: Path, line: int) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    if line < 1 or line > len(lines):
        raise ValueError(f"line {line} out of range for {path}")
    return lines[line - 1].strip()


def _with_observed_line(case_dir: Path, dataset_dir: Path, item: dict[str, Any]) -> dict[str, Any]:
    source_file = dataset_dir / item["file"]
    observed = _read_line(source_file, int(item["line"]))
    return {
        **item,
        "path": str(source_file.relative_to(case_dir)),
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
    func = _find_function(module, source_anchor["function"])
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
    function_names = ["execute", "mogrify", "_escape_args"]
    observations: list[dict[str, Any]] = []
    dependency_chain = [sink_anchor["expr"], sink_anchor["argument"]]

    for function_name in function_names:
        func = _find_function(module, function_name)
        if not func:
            continue
        for node in ast.walk(func):
            if isinstance(node, ast.Assign):
                expr = _segment(text, node)
                if "query" in _names_in(node) or "args" in _names_in(node):
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
                    if "query %" in expr or "% self._escape_args" in expr:
                        dependency_chain.append(expr)
            elif isinstance(node, ast.Return):
                expr = _segment(text, node)
                if isinstance(node.value, ast.DictComp) and "args.items()" in expr:
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
                    dependency_chain.append("args.items()")
                    dependency_chain.append("args.keys()[*]")

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
            item for item in assignments if "% self._escape_args" in item["expr"] or "query %" in item["expr"]
        ],
    }


def _generate_candidate_edges(structure: dict[str, Any]) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []

    for item in structure["dict_literals"]:
        if "key" in item.get("keys", []):
            edges.append(
                {
                    "from": "key",
                    "to": f"{item['lhs']}.keys()[*]",
                    "kind": "dict_literal_key",
                    "score": 0.92,
                    "evidence": item["expr"],
                    "location": f"{item['file']}:{item['line']}",
                }
            )

    for item in structure["dict_comprehensions"]:
        if "for (key, val) in args.items()" in item["expr"]:
            edges.append(
                {
                    "from": "args.keys()[*]",
                    "to": "escaped_args.keys()[*]",
                    "kind": "dict_comprehension_key_preserved",
                    "score": 0.88,
                    "evidence": item["expr"],
                    "location": f"{item['file']}:{item['line']}",
                }
            )

    for item in structure["format_operations"]:
        edges.append(
            {
                "from": "escaped_args.keys()[*]",
                "to": "query",
                "kind": "named_percent_format_mapping_key",
                "score": 0.83,
                "evidence": item["expr"],
                "location": f"{item['file']}:{item['line']}",
            }
        )

    return sorted(edges, key=lambda item: item["score"], reverse=True)


def build_evidence(case_path: Path, out_path: Path) -> dict[str, Any]:
    case_path = case_path.resolve()
    case_dir = case_path.parent
    case = _load_json(case_path)
    dataset_dir = case_dir / case["dataset_dir"]
    baseline = _load_json(case_dir / case["baseline_summary"])

    source = _with_observed_line(case_dir, dataset_dir, case["source"])
    sink = _with_observed_line(case_dir, dataset_dir, case["sink"])
    source_forward_slice = _extract_source_forward(case_dir, dataset_dir, case["source"])
    sink_backward_slice = _extract_sink_backward(case_dir, dataset_dir, case["sink"])
    structure = _extract_structure(source_forward_slice, sink_backward_slice)
    candidate_edges = _generate_candidate_edges(structure)
    top_k_edges = candidate_edges[:3]
    local_convergence = {
        "object": "args",
        "access_path": "args.keys()[*]",
        "source_frontier": source_forward_slice["frontier"],
        "sink_dependency_node": "args.keys()[*]"
        if "args.keys()[*]" in sink_backward_slice["dependency_chain"]
        else None,
        "is_converged": source_forward_slice["frontier"] == "key"
        and "args.keys()[*]" in sink_backward_slice["dependency_chain"],
    }

    baseline_status = {
        "source_hit": baseline.get("markedSourceCount", 0) > 0,
        "sink_hit": baseline.get("matchedSinkCount", 0) > 0,
        "call_context_reachable": baseline.get("matchedSinkCount", 0) > 0,
        "complete_taint_path_found": baseline.get("findingCount", 0) > 0,
        "sources_marked": baseline.get("markedSourceCount", 0),
        "sinks_matched": baseline.get("matchedSinkCount", 0),
        "findings": baseline.get("findingCount", 0),
        "entrypoints": baseline.get("entryPointCount", 0),
    }

    verdict = {
        "is_access_path_gap_candidate": (
            baseline_status["source_hit"]
            and baseline_status["sink_hit"]
            and baseline_status["call_context_reachable"]
            and not baseline_status["complete_taint_path_found"]
        ),
        "gap_type": [
            "dict-key taint propagation",
            "dict-comprehension key preservation",
            "named-placeholder percent-format propagation",
        ],
        "summary": (
            "Source and final sink are both observed by baseline YASA, but no taint "
            "finding is produced. The local convergence is at args.keys()[*]."
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


def materialize_ctpc(response_path: Path, out_dir: Path) -> dict[str, Path]:
    ctpc = _load_json(response_path)
    if ctpc.get("schema_version") == "ctpc.v2":
        required = ["contract_name", "applies_to", "fact_types", "propagation_edges", "kill_conditions"]
    else:
        required = ["contract_name", "propagation_edges", "structural_guards"]
    for key in required:
        if key not in ctpc:
            raise ValueError(f"CTPC response must contain {key!r}")
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

    ctpc_prompt = subparsers.add_parser("build-ctpc-prompt", help="Build a CTPC prompt from an Evidence Pack")
    ctpc_prompt.add_argument("--evidence", required=True, type=Path, help="Path to evidence_pack.json")
    ctpc_prompt.add_argument("--out", required=True, type=Path, help="Output prompt text file")

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
        help="Upgrade a legacy CTPC JSON file to structured CTPC v2",
    )
    upgrade_ctpc_cmd.add_argument("--ctpc", required=True, type=Path, help="Input CTPC JSON")
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
        evidence = build_evidence(args.case, args.out)
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
        print(f"wrote={args.out}")
    elif args.command == "build-ctpc-prompt":
        evidence = _load_json(args.evidence)
        prompt_text = build_ctpc_prompt(evidence)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(prompt_text, encoding="utf-8")
        print(f"case_id={evidence['case_id']}")
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
