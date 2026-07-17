"""Validation helpers for CTPC candidates."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any


REQUIRED_SAMPLES = {
    "must-flow": "finding",
    "must-not-flow": "no_finding",
    "must-kill": "no_finding",
}


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _segment(text: str, node: ast.AST) -> str:
    return ast.get_source_segment(text, node) or node.__class__.__name__


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return f"{_name(node.func)}(...)"
    if isinstance(node, ast.Subscript):
        return _name(node.value)
    return ""


def _names_in(node: ast.AST) -> set[str]:
    return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}


def _iter_assignments(module: ast.Module) -> list[ast.Assign]:
    return [node for node in ast.walk(module) if isinstance(node, ast.Assign)]


def _assigned_name(stmt: ast.Assign) -> str | None:
    if len(stmt.targets) != 1:
        return None
    target = stmt.targets[0]
    if isinstance(target, ast.Name):
        return target.id
    return None


def _is_source_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and _name(node.func) == "source"


def _has_sink_call(module: ast.Module) -> bool:
    for node in ast.walk(module):
        if isinstance(node, ast.Call) and _name(node.func) == "sink":
            return True
    return False


def _has_key_whitelist_return(module: ast.Module, tainted_names: set[str]) -> bool:
    for node in ast.walk(module):
        if not isinstance(node, ast.If):
            continue
        if not tainted_names.intersection(_names_in(node.test)):
            continue
        has_return = any(isinstance(stmt, ast.Return) for stmt in node.body)
        has_literal_set = any(isinstance(child, (ast.Set, ast.Tuple, ast.List)) for child in ast.walk(node.test))
        if has_return and has_literal_set:
            return True
    return False


def analyze_validation_code(path: Path) -> dict[str, Any]:
    """Extract the small structural facts used by the prototype validator."""

    text = path.read_text(encoding="utf-8")
    try:
        module = ast.parse(text)
    except SyntaxError as exc:
        return {
            "path": str(path),
            "syntax_ok": False,
            "syntax_error": f"{exc.msg} at line {exc.lineno}",
            "features": {},
            "predicted": "invalid",
            "evidence": [],
        }

    tainted_names: set[str] = set()
    dict_vars_with_tainted_key: set[str] = set()
    dict_vars_with_tainted_value: set[str] = set()
    escaped_vars_preserving_keys: set[str] = set()
    formatted_query_vars: set[str] = set()
    evidence: list[dict[str, Any]] = []

    for stmt in _iter_assignments(module):
        target = _assigned_name(stmt)
        if not target:
            continue

        if _is_source_call(stmt.value):
            tainted_names.add(target)
            evidence.append({"kind": "source_assignment", "line": stmt.lineno, "expr": _segment(text, stmt)})
            continue

        if isinstance(stmt.value, ast.Dict):
            key_names = set()
            value_names = set()
            for key in stmt.value.keys:
                if key is not None:
                    key_names.update(_names_in(key))
            for value in stmt.value.values:
                value_names.update(_names_in(value))
            if tainted_names.intersection(key_names):
                dict_vars_with_tainted_key.add(target)
                evidence.append({"kind": "tainted_dict_key", "line": stmt.lineno, "expr": _segment(text, stmt)})
            if tainted_names.intersection(value_names):
                dict_vars_with_tainted_value.add(target)
                evidence.append({"kind": "tainted_dict_value", "line": stmt.lineno, "expr": _segment(text, stmt)})
            continue

        if isinstance(stmt.value, ast.DictComp):
            generators = stmt.value.generators
            iter_exprs = [_segment(text, generator.iter) for generator in generators]
            source_dicts = {_name(generator.iter.func.value) for generator in generators if isinstance(generator.iter, ast.Call)}
            key_names = _names_in(stmt.value.key)
            if source_dicts.intersection(dict_vars_with_tainted_key) and key_names:
                escaped_vars_preserving_keys.add(target)
                evidence.append({"kind": "dict_comprehension_key_preserved", "line": stmt.lineno, "expr": _segment(text, stmt)})
            if iter_exprs:
                evidence.append({"kind": "dict_comprehension", "line": stmt.lineno, "expr": _segment(text, stmt)})
            continue

        if isinstance(stmt.value, ast.BinOp) and isinstance(stmt.value.op, ast.Mod):
            rhs_names = _names_in(stmt.value.right)
            if rhs_names.intersection(escaped_vars_preserving_keys) or rhs_names.intersection(dict_vars_with_tainted_key):
                formatted_query_vars.add(target)
                evidence.append({"kind": "percent_format_mapping_key", "line": stmt.lineno, "expr": _segment(text, stmt)})

    kill_guard = _has_key_whitelist_return(module, tainted_names)
    sink_hit = _has_sink_call(module)
    finding = bool(formatted_query_vars and sink_hit and not kill_guard)

    features = {
        "source_hit": bool(tainted_names),
        "sink_hit": sink_hit,
        "tainted_names": sorted(tainted_names),
        "dict_vars_with_tainted_key": sorted(dict_vars_with_tainted_key),
        "dict_vars_with_tainted_value": sorted(dict_vars_with_tainted_value),
        "escaped_vars_preserving_keys": sorted(escaped_vars_preserving_keys),
        "formatted_query_vars": sorted(formatted_query_vars),
        "kill_guard": kill_guard,
    }

    return {
        "path": str(path),
        "syntax_ok": True,
        "features": features,
        "predicted": "finding" if finding else "no_finding",
        "evidence": evidence,
    }


def _edge_coverage(ctpc: dict[str, Any], sample_analyses: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    must_flow = sample_analyses.get("must-flow", {})
    features = must_flow.get("features", {})
    coverage: list[dict[str, Any]] = []
    for edge in ctpc.get("propagation_edges", []):
        if ctpc.get("schema_version") == "ctpc.v2":
            edge_from = edge.get("from", {}).get("expr")
            edge_to = edge.get("to", {}).get("access_path") or edge.get("to", {}).get("expr")
            edge_kind = edge.get("pattern", {}).get("kind")
            condition = edge.get("pattern", {})
        else:
            edge_from = edge.get("from")
            edge_to = edge.get("to")
            edge_kind = edge.get("kind")
            condition = edge.get("condition")
        covered = False
        reason = "not observed in must-flow sample"
        if edge_kind == "dict_literal_key":
            covered = bool(features.get("dict_vars_with_tainted_key"))
            reason = "tainted source variable appears in dict key position"
        elif edge_kind == "dict_comprehension_key_preserved":
            covered = bool(features.get("escaped_vars_preserving_keys"))
            reason = "dict comprehension preserves keys from tainted-key mapping"
        elif edge_kind == "percent_mapping_key":
            covered = bool(features.get("formatted_query_vars"))
            reason = "percent formatting consumes mapping with preserved tainted keys"
        coverage.append(
            {
                "edge_id": edge.get("edge_id"),
                "from": edge_from,
                "to": edge_to,
                "pattern_kind": edge_kind,
                "covered": covered,
                "reason": reason,
                "condition": condition,
            }
        )
    return coverage


def _status(sample_results: list[dict[str, Any]], edge_coverage: list[dict[str, Any]]) -> str:
    if any(not item["syntax_ok"] for item in sample_results):
        return "rejected"
    if any(not item["passed"] for item in sample_results):
        return "rejected"
    if any(not item["covered"] for item in edge_coverage):
        return "needs_revision"
    return "accepted"


def _feedback(status: str, sample_results: list[dict[str, Any]], edge_coverage: list[dict[str, Any]]) -> list[str]:
    messages: list[str] = []
    for item in sample_results:
        if not item["syntax_ok"]:
            messages.append(f"{item['sample']} has invalid Python syntax: {item.get('syntax_error')}")
        elif not item["passed"]:
            messages.append(
                f"{item['sample']} expected {item['expected']} but CTPC simulation predicted {item['predicted']}"
            )
    for item in edge_coverage:
        if not item["covered"]:
            messages.append(f"Propagation edge {item['from']} -> {item['to']} is not covered by must-flow sample")
    if status == "accepted":
        messages.append("CTPC passes the current three-way structural validation set.")
    return messages


def validate_ctpc(ctpc_path: Path, validation_dir: Path, out_dir: Path) -> dict[str, Any]:
    ctpc = _load_json(ctpc_path)
    sample_analyses: dict[str, dict[str, Any]] = {}
    sample_results: list[dict[str, Any]] = []

    for sample, expected in REQUIRED_SAMPLES.items():
        sample_dir = validation_dir / sample
        expected_path = sample_dir / "expected.json"
        code_path = sample_dir / "case.py"
        if expected_path.exists():
            expected = _load_json(expected_path).get("expected", expected)
        analysis = analyze_validation_code(code_path)
        sample_analyses[sample] = analysis
        passed = analysis["predicted"] == expected and analysis["syntax_ok"]
        sample_results.append(
            {
                "sample": sample,
                "expected": expected,
                "predicted": analysis["predicted"],
                "passed": passed,
                "syntax_ok": analysis["syntax_ok"],
                "syntax_error": analysis.get("syntax_error"),
                "features": analysis.get("features", {}),
                "evidence": analysis.get("evidence", []),
            }
        )

    coverage = _edge_coverage(ctpc, sample_analyses)
    status = _status(sample_results, coverage)
    report = {
        "ctpc": str(ctpc_path),
        "validation_dir": str(validation_dir),
        "status": status,
        "sample_results": sample_results,
        "edge_coverage": coverage,
        "feedback": _feedback(status, sample_results, coverage),
        "next_runner": {
            "kind": "yasa-in-the-loop",
            "state": "available_via_build_validation_rules_and_run_yasa_validation",
            "purpose": "confirm structural simulation with baseline/enhanced YASA findings for each validation sample",
        },
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "validation_report.json"
    md_path = out_dir / "validation_report.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md_path.write_text(render_validation_markdown(report), encoding="utf-8")
    return report


def build_yasa_validation_rules(validation_dir: Path, out_dir: Path) -> dict[str, Path]:
    """Write one YASA rule file per validation sample."""

    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    for sample in REQUIRED_SAMPLES:
        sample_dir = validation_dir / sample
        case_path = sample_dir / "case.py"
        if not case_path.exists():
            raise FileNotFoundError(case_path)
        rule = [
            {
                "checkerIds": ["taint_flow_python_input_inner"],
                "sources": {
                    "FuncCallReturnValueTaintSource": [
                        {
                            "fsig": "source",
                            "values": ["0"],
                            "scopeFile": "all",
                            "scopeFunc": "all",
                        }
                    ]
                },
                "sinks": {
                    "FuncCallTaintSink": [
                        {
                            "args": ["0"],
                            "attribute": f"lapis-{sample}-sink",
                            "fsig": "sink",
                        }
                    ]
                },
                "entrypoints": [
                    {
                        "filePath": "/case.py",
                        "functionName": "test",
                        "attribute": f"lapis-{sample}",
                    }
                ],
                "outputAtTaint": {
                    "traceStrategy": "full",
                },
            }
        ]
        out_path = out_dir / f"{sample}.json"
        out_path.write_text(json.dumps(rule, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        written[sample] = out_path
    return written


def render_validation_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# LAPIS CTPC Validation Report",
        "",
        f"- Status: `{report['status']}`",
        f"- CTPC: `{report['ctpc']}`",
        f"- Validation dir: `{report['validation_dir']}`",
        "",
        "## Three-Way Samples",
        "",
    ]
    for item in report["sample_results"]:
        passed = "PASS" if item["passed"] else "FAIL"
        lines.extend(
            [
                f"### {item['sample']} - {passed}",
                "",
                f"- Expected: `{item['expected']}`",
                f"- Predicted: `{item['predicted']}`",
                f"- Syntax OK: `{item['syntax_ok']}`",
                f"- Features: `{json.dumps(item['features'], ensure_ascii=False)}`",
                "",
            ]
        )
    lines.extend(["## Propagation Edge Coverage", ""])
    for item in report["edge_coverage"]:
        covered = "covered" if item["covered"] else "missing"
        lines.append(f"- `{item['from']} -> {item['to']}`: {covered}. {item['reason']}")
    lines.extend(["", "## Feedback", ""])
    for message in report["feedback"]:
        lines.append(f"- {message}")
    lines.extend(
        [
            "",
            "## Next Runner",
            "",
            (
                "当前报告使用结构模拟器完成 CTPC 的第一轮闭环验证；下一步将把同一个 "
                "validation_report 接口替换为 YASA baseline/enhanced 双运行结果，用真实 "
                "finding/no-finding 判决驱动 CTPC 接受、拒绝和反馈迭代。"
            ),
            "",
        ]
    )
    return "\n".join(lines)
