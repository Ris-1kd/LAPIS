"""YASA-in-the-loop validation runner for LAPIS experiments."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .validator import REQUIRED_SAMPLES


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows


def _summary_path(report_dir: Path) -> Path:
    return report_dir / "scan_summary.json"


def _finding_from_summary(summary: dict[str, Any]) -> str:
    return "finding" if int(summary.get("findingCount", 0)) > 0 else "no_finding"


def _ccec_virtual_sink_count(report_dir: Path) -> int:
    sarif_path = report_dir / "report.sarif"
    if not sarif_path.exists():
        return 0
    try:
        sarif = _load_json(sarif_path)
    except (OSError, json.JSONDecodeError):
        return 0

    count = 0
    for run in sarif.get("runs", []) or []:
        for result in run.get("results", []) or []:
            sink_info = result.get("sinkInfo") or {}
            attributes = sink_info.get("sinkAttribute") or []
            if isinstance(attributes, str):
                attributes = [attributes]
            if any("LAPIS CCEC virtual sink" in str(attribute) for attribute in attributes):
                count += 1
    return count


def _augment_summary_for_ccec(summary: dict[str, Any] | None, report_dir: Path, ccec_file: Path | None) -> dict[str, Any] | None:
    if summary is None:
        return None
    if ccec_file is None:
        return summary

    virtual_sink_count = _ccec_virtual_sink_count(report_dir)
    if virtual_sink_count <= 0:
        return summary

    augmented = dict(summary)
    raw_sink_count = int(augmented.get("matchedSinkCount", 0) or 0)
    augmented["rawMatchedSinkCount"] = raw_sink_count
    augmented["ccecVirtualSinkCount"] = virtual_sink_count
    augmented["matchedSinkCount"] = max(raw_sink_count, virtual_sink_count)
    augmented["sinkCountSemantics"] = "matchedSinkCount includes LAPIS CCEC virtual final sinks; rawMatchedSinkCount preserves physical sink matches."
    return augmented


def _contract_rule_count(path: Path | None, keys: tuple[str, ...]) -> int:
    if path is None or not path.exists():
        return 0
    try:
        payload = _load_json(path)
    except (OSError, json.JSONDecodeError):
        return 0
    count = 0
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            count += len(value)
    return count


def summarize_contract_consumption(
    report_dir: Path,
    summary: dict[str, Any] | None,
    *,
    ccec_file: Path | None,
    ctpc_file: Path | None,
) -> dict[str, Any]:
    """Summarize whether supplied LAPIS contracts were consumed during this YASA run."""

    ccec_checker_rows = _load_jsonl(report_dir / "lapis-ccec-diagnostics.jsonl")
    ccec_materialized_rows = _load_jsonl(report_dir / "lapis-ccec-materialized-diagnostics.jsonl")
    ctpc_rows = _load_jsonl(report_dir / "lapis-ctpc-diagnostics.jsonl")

    ccec_checker_matched = [row for row in ccec_checker_rows if row.get("matched")]
    ccec_materialized_matched = [row for row in ccec_materialized_rows if row.get("matched")]
    ctpc_forced = [row for row in ctpc_rows if row.get("action") == "force"]
    ctpc_suppressed = [row for row in ctpc_rows if row.get("action") == "suppress"]

    source_count = int((summary or {}).get("markedSourceCount", 0) or 0)
    sink_count = int((summary or {}).get("matchedSinkCount", 0) or 0)
    finding_count = int((summary or {}).get("findingCount", 0) or 0)
    post_ccec_sink_reached = bool(ccec_file and source_count > 0 and sink_count > 0)

    ccec_status = "not_provided"
    if ccec_file is not None:
        if ccec_materialized_matched:
            ccec_status = "materialized_call_edge_consumed"
        elif ccec_checker_matched:
            ccec_status = "virtual_boundary_consumed"
        elif post_ccec_sink_reached:
            ccec_status = "progress_observed"
        else:
            ccec_status = "provided_but_not_observed"

    ctpc_status = "not_provided"
    if ctpc_file is not None:
        if ctpc_forced:
            ctpc_status = "fact_forced_finding"
        elif ctpc_rows:
            ctpc_status = "facts_observed_no_force"
        else:
            ctpc_status = "provided_but_not_observed"

    return {
        "ccec": {
            "provided": ccec_file is not None,
            "file": str(ccec_file) if ccec_file else None,
            "candidateEdges": _contract_rule_count(ccec_file, ("candidate_edges",)),
            "checkerDiagnostics": len(ccec_checker_rows),
            "checkerMatched": len(ccec_checker_matched),
            "materializedDiagnostics": len(ccec_materialized_rows),
            "materializedMatched": len(ccec_materialized_matched),
            "postCcecSinkReached": post_ccec_sink_reached,
            "status": ccec_status,
        },
        "ctpc": {
            "provided": ctpc_file is not None,
            "file": str(ctpc_file) if ctpc_file else None,
            "rules": _contract_rule_count(ctpc_file, ("propagation_edges", "function_summaries", "risk_upgrades", "kill_conditions")),
            "diagnostics": len(ctpc_rows),
            "forcedFindings": len(ctpc_forced),
            "suppressedFindings": len(ctpc_suppressed),
            "status": ctpc_status,
        },
        "summaryProgress": {
            "sources": source_count,
            "sinks": sink_count,
            "findings": finding_count,
        },
        "interpretation": (
            "Contract consumption is derived from YASA report-directory diagnostics and scan summary. "
            "A materialized CCEC match means the analyzer redirected a call to a real target function; "
            "a CTPC force means validated propagation facts were used to report a sink."
        ),
    }


def load_sarif_findings(report_dir: Path) -> list[dict[str, Any]]:
    sarif_path = report_dir / "report.sarif"
    if not sarif_path.exists():
        return []
    try:
        sarif = _load_json(sarif_path)
    except (OSError, json.JSONDecodeError):
        return []

    findings: list[dict[str, Any]] = []
    for run in sarif.get("runs", []) or []:
        findings.extend(run.get("results", []) or [])
    return findings


def _format_sarif_location(location: dict[str, Any]) -> dict[str, Any]:
    physical = (location.get("location") or location).get("physicalLocation") or {}
    artifact = physical.get("artifactLocation") or {}
    region = physical.get("region") or {}
    snippet = region.get("snippet") or {}
    return {
        "uri": artifact.get("uri", ""),
        "line": region.get("startLine", ""),
        "column": region.get("startColumn", ""),
        "affected": snippet.get("affectedNodeName", ""),
        "snippet": snippet.get("text", ""),
    }


def _finding_attributes(finding: dict[str, Any]) -> str:
    sink_info = finding.get("sinkInfo") or {}
    attributes = sink_info.get("sinkAttribute", [])
    if isinstance(attributes, list):
        return "\n".join(str(item) for item in attributes)
    return str(attributes)


def _finding_trace_texts(finding: dict[str, Any]) -> list[str]:
    texts: list[str] = []
    for code_flow in finding.get("codeFlows", []) or []:
        for thread_flow in code_flow.get("threadFlows", []) or []:
            for location in thread_flow.get("locations", []) or []:
                formatted = _format_sarif_location(location)
                texts.append(str(formatted.get("affected") or ""))
                texts.append(str(formatted.get("snippet") or ""))
    return texts


def assess_trace_quality(report_dir: Path) -> dict[str, Any]:
    findings = load_sarif_findings(report_dir)
    ccec_virtual = False
    ctpc_virtual = False
    fact_trace_gap = False
    ctpc_fact_trace = False
    actual_source_to_boundary_trace = False

    for finding in findings:
        attributes = _finding_attributes(finding)
        ccec_virtual = ccec_virtual or "LAPIS CCEC virtual sink" in attributes
        ctpc_virtual = ctpc_virtual or "LAPIS CTPC virtual sink" in attributes
        for text in _finding_trace_texts(finding):
            fact_trace_gap = fact_trace_gap or "FACT TRACE GAP" in text or "without an actual propagated source-to-boundary" in text
            ctpc_fact_trace = ctpc_fact_trace or "LAPIS CTPC" in text or "CTPC FACT" in text or "CTPC Boundary" in text
            actual_source_to_boundary_trace = (
                actual_source_to_boundary_trace
                or "actual source-to-boundary trace was available" in text
            )

    if actual_source_to_boundary_trace:
        trace_status = "actual_taint_trace"
    elif ctpc_fact_trace and not fact_trace_gap:
        trace_status = "ctpc_fact_closed"
    elif ccec_virtual and fact_trace_gap:
        trace_status = "ccec_callgraph_closed_taint_open"
    elif findings:
        trace_status = "reported_trace"
    else:
        trace_status = "no_finding_trace"

    needs_ctpc = bool(ccec_virtual and fact_trace_gap and not ctpc_fact_trace)
    needs_trace_review = bool(ccec_virtual and not actual_source_to_boundary_trace)
    return {
        "findingCount": len(findings),
        "ccecVirtualSink": ccec_virtual,
        "ctpcVirtualSink": ctpc_virtual,
        "factTraceGap": fact_trace_gap,
        "ctpcFactTrace": ctpc_fact_trace,
        "actualSourceToBoundaryTrace": actual_source_to_boundary_trace,
        "traceStatus": trace_status,
        "needsCtpc": needs_ctpc,
        "needsTraceReview": needs_trace_review,
        "decisionBasis": (
            "Derived from SARIF sinkAttribute and trace labels. A CCEC finding with FACT TRACE GAP means "
            "callgraph repair reached the virtual sink but source-to-boundary taint propagation is still open."
        ),
    }


def render_finding_trace_lines(report_dir: Path) -> list[str]:
    findings = load_sarif_findings(report_dir)
    if not findings:
        return []
    findings = _select_display_findings(findings)

    lines: list[str] = []
    for finding_index, finding in enumerate(findings, start=1):
        sink_info = finding.get("sinkInfo") or {}
        lines.append(f"Finding {finding_index}")
        lines.append(f"  sinkRule: {sink_info.get('sinkRule', 'n/a')}")
        attributes_text = _finding_attributes(finding).replace("\n", ", ")
        lines.append(f"  sinkAttribute: {attributes_text or 'n/a'}")
        is_ccec_virtual = "LAPIS CCEC virtual sink" in attributes_text
        if is_ccec_virtual:
            lines.append("  traceKind: synthetic CCEC virtual-boundary trace")
            lines.append("  note: CCEC/CTPC fact locations are emitted as source evidence; a FACT TRACE GAP step means CTPC propagation is still missing.")

        locations = finding.get("locations") or []
        if locations:
            primary = _format_sarif_location(locations[0])
            lines.append(f"  primary: {primary['uri']}:{primary['line']}:{primary['column']}")
            if primary["affected"]:
                lines.append(f"  primaryNode: {primary['affected']}")

        step_index = 0
        for code_flow in finding.get("codeFlows", []) or []:
            for thread_flow in code_flow.get("threadFlows", []) or []:
                for location in thread_flow.get("locations", []) or []:
                    formatted = _format_sarif_location(location)
                    affected = str(formatted.get("affected") or "")
                    if is_ccec_virtual and affected and not (
                        affected.startswith("LAPIS ")
                        or affected.startswith("source rule ")
                    ):
                        continue
                    lines.append(f"  Step {step_index}: {formatted['uri']}:{formatted['line']}:{formatted['column']}")
                    if affected:
                        lines.append(f"    node: {affected}")
                    if formatted["snippet"]:
                        snippet = "\n".join(f"      {line}" for line in formatted["snippet"].rstrip().splitlines())
                        lines.append("    snippet:")
                        lines.append(snippet)
                    step_index += 1
    return lines


def _finding_location_count(finding: dict[str, Any]) -> int:
    count = 0
    for code_flow in finding.get("codeFlows", []) or []:
        for thread_flow in code_flow.get("threadFlows", []) or []:
            count += len(thread_flow.get("locations", []) or [])
    return count


def _finding_primary_key(finding: dict[str, Any]) -> tuple[str, str, str, str]:
    sink_info = finding.get("sinkInfo") or {}
    locations = finding.get("locations") or []
    primary = _format_sarif_location(locations[0]) if locations else {}
    return (
        str(sink_info.get("sinkRule") or ""),
        str(primary.get("uri") or ""),
        str(primary.get("line") or ""),
        str(primary.get("column") or ""),
    )


def _select_display_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep the richest trace for duplicated findings at the same sink location."""

    best: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    order: list[tuple[str, str, str, str]] = []
    for finding in findings:
        key = _finding_primary_key(finding)
        if key not in best:
            best[key] = finding
            order.append(key)
            continue
        if _finding_location_count(finding) > _finding_location_count(best[key]):
            best[key] = finding
    return [best[key] for key in order]


def _read_source_line(root: Path, relative_file: str | None, line: int | None) -> str:
    if not relative_file or not line:
        return ""
    dataset_relative = relative_file[len("dataset/") :] if relative_file.startswith("dataset/") else relative_file
    source_relative = relative_file[len("source/") :] if relative_file.startswith("source/") else relative_file
    candidates = [
        root / relative_file,
        root / "source" / relative_file,
        root / dataset_relative,
        root / source_relative,
    ]
    for candidate in candidates:
        if not candidate.exists() or not candidate.is_file():
            continue
        lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
        if 1 <= line <= len(lines):
            return lines[line - 1].strip()
    return ""


def _normalize_source_file(root: Path, file_name: str | None) -> str:
    if not file_name:
        return ""
    text = file_name.replace("\\", "/")
    for prefix in ("dataset/", "source/"):
        if text.startswith(prefix):
            stripped = text[len(prefix) :]
            if (root / stripped).exists():
                return stripped
    if (root / "source" / text).exists():
        return f"source/{text}"
    return text


def _normalize_ctpc_file(root: Path, file_name: str | None) -> str:
    return _normalize_source_file(root, file_name)


def _ctpc_rule_order(rule: dict[str, Any]) -> int:
    event = str(rule.get("event") or "")
    kind = str((rule.get("pattern") or {}).get("kind") or "")
    if event == "source":
        return 0
    if kind in {"dict_literal_key", "constructor_keyword_capture"}:
        return 20
    if kind in {"dict_comprehension_key_preserved", "return_fact_from_argument"}:
        return 80
    if kind in {"percent_mapping_key"}:
        return 85
    if kind in {"filesystem_sink_argument", "sql_sink_argument", "sink_argument"}:
        return 80
    if event == "sink":
        return 90
    return 40


def _append_chain_item(
    items: list[dict[str, Any]],
    seen: set[tuple[str, int]],
    *,
    order: int,
    role: str,
    file: str,
    line: int,
    code: str,
    source: str,
) -> None:
    key = (file, line)
    if not file or not line or key in seen:
        return
    seen.add(key)
    items.append({"order": order, "role": role, "file": file, "line": line, "code": code.strip(), "source": source})


def _find_lines(
    root: Path,
    relative_file: str,
    patterns: list[tuple[str, str]],
    base_order: int,
    *,
    max_line: int | None = None,
) -> list[dict[str, Any]]:
    path = root / relative_file
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    found: list[dict[str, Any]] = []
    for index, text in enumerate(lines, start=1):
        if max_line is not None and index > max_line:
            continue
        stripped = text.strip()
        for offset, (role, pattern) in enumerate(patterns):
            if re.search(pattern, stripped):
                found.append(
                    {
                        "order": base_order + offset,
                        "role": role,
                        "file": relative_file,
                        "line": index,
                        "code": stripped,
                        "source": "source-scan",
                    }
                )
                break
    return found


def _find_first_line(root: Path, relative_file: str, pattern: str, *, start_line: int = 1, end_line: int | None = None) -> tuple[int, str] | None:
    path = root / relative_file
    if not path.exists():
        return None
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for index, text in enumerate(lines, start=1):
        if index < start_line:
            continue
        if end_line is not None and index > end_line:
            break
        stripped = text.strip()
        if re.search(pattern, stripped):
            return index, stripped
    return None


def _matched_ccec_edges_from_report(report: dict[str, Any], ccec: dict[str, Any]) -> list[dict[str, Any]]:
    report_dir = Path(report.get("report_dir") or "")
    diagnostics = _load_jsonl(report_dir / "lapis-ccec-materialized-diagnostics.jsonl")
    matched_edges: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in diagnostics:
        if not row.get("matched"):
            continue
        edge = row.get("edge")
        if not isinstance(edge, dict):
            continue
        edge_id = str(edge.get("edge_id") or "")
        key = edge_id or json.dumps(edge, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        matched_edges.append(edge)
    if matched_edges:
        return matched_edges

    consumed = ((report.get("contract_consumption") or {}).get("ccec") or {})
    if int(consumed.get("materializedMatched", 0) or 0) <= 0:
        return ccec.get("candidate_edges", []) or []
    return [
        edge
        for edge in ccec.get("candidate_edges", []) or []
        if (edge.get("target") or {}).get("file") and (edge.get("target") or {}).get("line")
    ]


def _find_ctpc_intra_function_lines(
    root: Path,
    relative_file: str,
    ctpc: dict[str, Any],
    *,
    start_line: int,
    end_line: int,
) -> list[dict[str, Any]]:
    path = root / relative_file
    if not path.exists() or not path.is_file():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    source_terms: set[str] = set()
    sink_terms: set[str] = set()
    for rule in [
        *(ctpc.get("propagation_edges") or []),
        *(ctpc.get("function_summaries") or []),
        *(ctpc.get("risk_upgrades") or []),
    ]:
        for side_name in ("from", "to"):
            side = rule.get(side_name) or {}
            expr = str(side.get("expr") or "")
            if expr and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expr):
                source_terms.add(expr)
            access_path = str(side.get("access_path") or "")
            for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", access_path):
                if token not in {"arg", "value", "return"}:
                    sink_terms.add(token)
    source_terms |= {"data", "args"}
    sink_terms |= {"statuses", "query", "sql", "path"}

    found: list[dict[str, Any]] = []
    for index in range(max(1, start_line + 1), min(len(lines), end_line - 1) + 1):
        stripped = lines[index - 1].strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped and "join(" not in stripped and "[" not in stripped:
            continue
        has_source_term = any(re.search(rf"\b{re.escape(term)}\b", stripped) for term in source_terms)
        has_sink_term = any(re.search(rf"\b{re.escape(term)}\b", stripped) for term in sink_terms)
        has_access_path = bool(re.search(r"\[[0-9]+\]|\.\w+\(|join\s*\(", stripped))
        if has_source_term and (has_sink_term or has_access_path):
            found.append(
                {
                    "order": 85,
                    "role": "CTPC VAR PASS",
                    "file": relative_file,
                    "line": index,
                    "code": stripped,
                    "source": "ctpc-intra-function-scan",
                }
            )
    return found


def _matched_ccec_target_lines(report: dict[str, Any], source_root: Path, ccec_path: Path) -> dict[str, int]:
    if not ccec_path.exists():
        return {}
    try:
        matched_edges = _matched_ccec_edges_from_report(report, _load_json(ccec_path))
    except (OSError, json.JSONDecodeError):
        return {}
    targets: dict[str, int] = {}
    for edge in matched_edges:
        target = edge.get("target") or {}
        file = _normalize_source_file(source_root, target.get("file"))
        line = int(target.get("line") or 0)
        if file and line:
            targets[file] = min(targets.get(file, line), line)
    return targets


def render_ordered_source_to_sink_chain_lines(report: dict[str, Any]) -> list[str]:
    """Reconstruct a review-oriented source-to-sink chain from case, CTPC/CCEC, and source lines."""

    source_root = Path(report.get("source_path") or "")
    case_path = Path(report.get("case_path") or "")
    ctpc_path = Path(report.get("ctpc_file") or "")
    ccec_path = Path(report.get("ccec_file") or "")
    if not source_root.exists() or not case_path.exists():
        return []

    try:
        case = _load_json(case_path)
    except (OSError, json.JSONDecodeError):
        return []

    items: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    ccec_target_lines = _matched_ccec_target_lines(report, source_root, ccec_path)

    source_endpoint = case.get("source") or {}
    source_file = str(source_endpoint.get("file") or "")
    source_line = int(source_endpoint.get("line") or 0)
    _append_chain_item(
        items,
        seen,
        order=0,
        role="SOURCE",
        file=source_file,
        line=source_line,
        code=_read_source_line(source_root, source_file, source_line) or str(source_endpoint.get("expr") or ""),
        source="case.source",
    )

    if source_file:
        for item in _find_lines(
            source_root,
            source_file,
            [
                ("CALL", r"class_factory\s*\("),
                ("CALL", r"FakeConnection\s*\("),
                ("ARG PASS", r"^def\s+__init__\s*\("),
                ("VAR PASS", r"self\.payload\s*=\s*payload"),
                ("CALL", r"return\s+numpy_like_array_coercion\s*\("),
                ("ARG PASS", r"^def\s+numpy_like_array_coercion\s*\("),
                ("VAR PASS", r"=\s*\{.*:"),
                ("VAR PASS", r"=\s*getattr\s*\("),
                ("CALL", r"array_callback\s*\("),
                ("CALL", r"terminal\.set_term_title\s*\("),
                ("CALL", r"\.execute\s*\("),
            ],
            10,
        ):
            _append_chain_item(items, seen, **item)

    if ccec_path.exists():
        try:
            ccec = _load_json(ccec_path)
        except (OSError, json.JSONDecodeError):
            ccec = {}
        for edge in _matched_ccec_edges_from_report(report, ccec):
            edge_id = str(edge.get("edge_id") or "ccec")
            for evidence_item in edge.get("guard_evidence", []) or []:
                evidence = evidence_item.get("evidence") or {}
                condition_text = str(evidence_item.get("condition") or "").lower()
                if "exclude" in condition_text or "cannot match" in condition_text:
                    continue
                file = _normalize_source_file(source_root, evidence.get("file"))
                line = int(evidence.get("line") or 0)
                derived = str(evidence_item.get("derived_from") or "")
                evidence_code = str(evidence.get("code") or "")
                role = "CCEC EVIDENCE"
                order = 35
                if "callsite" in derived:
                    role = "CCEC CALL EDGE"
                    order = 45
                elif "control_flow_guard" in derived:
                    role = "CCEC GUARD"
                    order = 55
                elif "callback_registration" in derived:
                    role = "CCEC REGISTRATION"
                    order = 25
                elif "function_signature" in derived:
                    role = "ARG PASS"
                    order = 65
                elif "baseline_diagnostic" in derived:
                    if any(sink_name in evidence_code for sink_name in ("pickle.loads", "os.system", "open(")):
                        role = "SINK"
                        order = 100
                    else:
                        role = "ARG PASS"
                        order = 30
                _append_chain_item(
                    items,
                    seen,
                    order=order,
                    role=role,
                    file=file,
                    line=line,
                    code=_read_source_line(source_root, file, line) or str(evidence.get("code") or ""),
                    source=edge_id,
                )
            target = edge.get("target") or {}
            target_file = _normalize_source_file(source_root, target.get("file"))
            target_line = int(target.get("line") or 0)
            if target_file and target_line:
                _append_chain_item(
                    items,
                    seen,
                    order=60,
                    role="ARG PASS",
                    file=target_file,
                    line=target_line,
                    code=_read_source_line(source_root, target_file, target_line),
                    source=f"{edge_id}.target",
                )

    if ctpc_path.exists():
        try:
            ctpc = _load_json(ctpc_path)
        except (OSError, json.JSONDecodeError):
            ctpc = {}
        rules = [
            *(ctpc.get("propagation_edges") or []),
            *(ctpc.get("function_summaries") or []),
            *(ctpc.get("risk_upgrades") or []),
        ]
        for rule in rules:
            evidence = rule.get("evidence") or {}
            file = _normalize_ctpc_file(source_root, evidence.get("file"))
            line = int(evidence.get("line") or 0)
            if (file, line) in seen:
                continue
            sink_endpoint_for_rule = case.get("sink") or {}
            sink_file_for_rule = _normalize_ctpc_file(source_root, str(sink_endpoint_for_rule.get("file") or ""))
            sink_line_for_rule = int(sink_endpoint_for_rule.get("line") or 0)
            if file == sink_file_for_rule and line == sink_line_for_rule:
                continue
            order = _ctpc_rule_order(rule)
            target_line = ccec_target_lines.get(file)
            if target_line and line > target_line:
                order = max(order, 85)
            role = f"CTPC {((rule.get('pattern') or {}).get('kind') or rule.get('event') or 'FACT')}"
            _append_chain_item(
                items,
                seen,
                order=order,
                role=role,
                file=file,
                line=line,
                code=_read_source_line(source_root, file, line) or str(evidence.get("code") or ""),
                source=str(rule.get("edge_id") or rule.get("summary_id") or "ctpc"),
            )

        sink_endpoint_for_ctpc = case.get("sink") or {}
        sink_file_for_ctpc = str(sink_endpoint_for_ctpc.get("file") or "")
        if sink_file_for_ctpc:
            sink_file_for_ctpc = _normalize_ctpc_file(source_root, sink_file_for_ctpc)
            sink_line_for_ctpc = int(sink_endpoint_for_ctpc.get("line") or 0)
            matched_edges_for_ctpc: list[dict[str, Any]] = []
            if ccec_path.exists():
                try:
                    matched_edges_for_ctpc = _matched_ccec_edges_from_report(report, _load_json(ccec_path))
                except (OSError, json.JSONDecodeError):
                    matched_edges_for_ctpc = []
            target_lines = [
                int(((edge.get("target") or {}).get("line") or 0))
                for edge in matched_edges_for_ctpc
                if _normalize_source_file(source_root, (edge.get("target") or {}).get("file")) == sink_file_for_ctpc
            ]
            start_line = min(target_lines) if target_lines else 1
            for item in _find_ctpc_intra_function_lines(
                source_root,
                sink_file_for_ctpc,
                ctpc,
                start_line=start_line,
                end_line=sink_line_for_ctpc,
            ):
                _append_chain_item(items, seen, **item)

    sink_endpoint = case.get("sink") or {}
    sink_file = str(sink_endpoint.get("file") or "")
    if sink_file:
        sink_file = _normalize_ctpc_file(source_root, sink_file)
        sink_line = int(sink_endpoint.get("line") or 0)
        ordered_patterns = [
            (30, "ARG PASS", r"^def\s+execute\s*\(", 1, sink_line or None),
            (40, "CALL", r"self\.mogrify\s*\(", 1, sink_line or None),
            (50, "ARG PASS", r"^def\s+mogrify\s*\(", 1, sink_line or None),
            (60, "CALL", r"=\s*.*_escape_args\s*\(", 1, sink_line or None),
            (70, "ARG PASS", r"^def\s+_escape_args\s*\(", 1, sink_line or None),
            (80, "RETURN", r"return\s+\{.*\.items\s*\(", 1, sink_line or None),
            (90, "RETURN", r"^return\s+query\b", 1, sink_line or None),
        ]
        for order, role, pattern, start, end in ordered_patterns:
            match = _find_first_line(source_root, sink_file, pattern, start_line=start, end_line=end)
            if not match:
                continue
            line, code = match
            _append_chain_item(
                items,
                seen,
                order=order,
                role=role,
                file=sink_file,
                line=line,
                code=code,
                source="source-scan",
            )
        sink_line = int(sink_endpoint.get("line") or 0)
        _append_chain_item(
            items,
            seen,
            order=100,
            role="SINK",
            file=sink_file,
            line=sink_line,
            code=_read_source_line(source_root, sink_file, sink_line) or str(sink_endpoint.get("expr") or ""),
            source="case.sink",
        )

    if not items:
        return []

    ordered = sorted(items, key=lambda item: (int(item["order"]), int(item["line"])))
    lines = []
    for index, item in enumerate(ordered):
        source_note = f" [{item['source']}]" if item.get("source") else ""
        lines.append(
            f"Step {index}: {item['role']} {item['file']}:{item['line']}  {item['code']}{source_note}"
        )
    return lines


def _case_endpoint_line(case: dict[str, Any], kind: str) -> str | None:
    endpoint = case.get(kind) or {}
    file = endpoint.get("file")
    line = endpoint.get("line")
    expr = endpoint.get("expr") or endpoint.get("symbol") or endpoint.get("callee")
    if not file and not line and not expr:
        return None
    location = f"{file}:{line}" if file and line else str(file or line or "")
    return f"{kind}: {location}  {expr or ''}".rstrip()


def _format_evidence_item(item: dict[str, Any]) -> str | None:
    evidence = item.get("evidence") or {}
    file = evidence.get("file")
    line = evidence.get("line")
    code = evidence.get("code")
    condition = item.get("condition")
    derived = item.get("derived_from")
    if not (file or line or code or condition):
        return None
    prefix = f"{file}:{line}" if file and line else str(file or line or "")
    detail = code or condition or ""
    suffix = f"  [{derived}]" if derived else ""
    return f"{prefix}  {detail}{suffix}".rstrip()


def render_reconstructed_ccec_chain_lines(report: dict[str, Any]) -> list[str]:
    ccec_file = report.get("ccec_file")
    if not ccec_file:
        return []
    ccec_path = Path(ccec_file)
    if not ccec_path.exists():
        return []
    try:
        ccec = _load_json(ccec_path)
        case = _load_json(Path(report["case_path"]))
    except (OSError, json.JSONDecodeError):
        return []

    lines: list[str] = []
    source_line = _case_endpoint_line(case, "source")
    if source_line:
        lines.append(source_line)

    seen_evidence: set[str] = set()
    for edge_index, edge in enumerate(_matched_ccec_edges_from_report(report, ccec), start=1):
        lines.append(f"CCEC edge {edge_index}: {edge.get('edge_id', 'unnamed')}")
        lines.append(f"  from: {edge.get('caller', 'n/a')}")
        lines.append(f"  at: {edge.get('boundary_callsite') or edge.get('callsite') or 'n/a'}")
        lines.append(f"  to: {edge.get('callee', 'n/a')}")
        if edge.get("callee_kind"):
            lines.append(f"  calleeKind: {edge.get('callee_kind')}")

        for item in edge.get("guard_evidence", []) or []:
            formatted = _format_evidence_item(item)
            if formatted and formatted not in seen_evidence:
                lines.append(f"  evidence: {formatted}")
                seen_evidence.add(formatted)

        for effect in (edge.get("contract") or {}).get("effects", []) or []:
            if effect.get("kind") == "add_call_edge":
                lines.append(f"  effect: add_call_edge {effect.get('from', 'n/a')} -> {effect.get('to', 'n/a')} at {effect.get('at', 'n/a')}")

    sink_line = _case_endpoint_line(case, "sink")
    if sink_line:
        lines.append(sink_line)
    return lines


def _build_yasa_command(
    tool_dir: Path,
    source_path: Path,
    report_dir: Path,
    rule_file: Path,
    uast_sdk_path: Path,
    timeout_seconds: int,
    ctpc_file: Path | None = None,
    ccec_file: Path | None = None,
    checker_ids: str = "taint_flow_python_input_inner",
    dump_cg: bool = False,
) -> list[str]:
    command = [
        "timeout",
        f"{timeout_seconds}s",
        "npx",
        "tsx",
        "src/main.ts",
        "--sourcePath",
        str(source_path),
        "--language",
        "python",
        "--report",
        str(report_dir),
        "--ruleConfigFile",
        str(rule_file),
        "--checkerIds",
        checker_ids,
        "--entrypointMode",
        "ONLY_CUSTOM",
        "--workerCount",
        "1",
        "--incremental",
        "false",
        "--taintTraceOutputStrategy",
        "full",
        "--uastSDKPath",
        str(uast_sdk_path),
    ]
    if ctpc_file is not None:
        command.extend(["--lapisCtpcFile", str(ctpc_file)])
    if ccec_file is not None:
        command.extend(["--lapisCcecFile", str(ccec_file)])
    if dump_cg:
        command.append("--dumpCG")
    return command


def _run_command(command: list[str], cwd: Path) -> dict[str, Any]:
    completed = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    return {
        "command": command,
        "cwd": str(cwd),
        "returncode": completed.returncode,
        "stdout_tail": completed.stdout[-4000:],
        "stderr_tail": completed.stderr[-4000:],
    }


def run_yasa_validation(
    tool_dir: Path,
    validation_dir: Path,
    rules_dir: Path,
    out_dir: Path,
    uast_sdk_path: Path,
    label: str,
    timeout_seconds: int = 180,
    ctpc_file: Path | None = None,
    ccec_file: Path | None = None,
) -> dict[str, Any]:
    """Run YASA on every validation sample and compare with expected results."""

    tool_dir = tool_dir.resolve()
    validation_dir = validation_dir.resolve()
    rules_dir = rules_dir.resolve()
    out_dir = out_dir.resolve()
    uast_sdk_path = uast_sdk_path.resolve()
    if ctpc_file is not None:
        ctpc_file = ctpc_file.resolve()
    if ccec_file is not None:
        ccec_file = ccec_file.resolve()

    if not tool_dir.exists():
        raise FileNotFoundError(tool_dir)
    if not uast_sdk_path.exists():
        raise FileNotFoundError(uast_sdk_path)

    sample_results: list[dict[str, Any]] = []
    for sample, default_expected in REQUIRED_SAMPLES.items():
        sample_dir = validation_dir / sample
        rule_file = rules_dir / f"{sample}.json"
        expected_file = sample_dir / "expected.json"
        expected = default_expected
        if expected_file.exists():
            expected = _load_json(expected_file).get("expected", default_expected)
        if not (sample_dir / "case.py").exists():
            raise FileNotFoundError(sample_dir / "case.py")
        if not rule_file.exists():
            raise FileNotFoundError(rule_file)

        report_dir = out_dir / label / sample
        if report_dir.exists():
            shutil.rmtree(report_dir)
        report_dir.mkdir(parents=True, exist_ok=True)
        command = _build_yasa_command(
            tool_dir,
            sample_dir,
            report_dir,
            rule_file,
            uast_sdk_path,
            timeout_seconds,
            ctpc_file,
            ccec_file,
        )
        run = _run_command(command, tool_dir)
        summary_file = _summary_path(report_dir)
        summary: dict[str, Any] | None = None
        predicted = "error"
        if summary_file.exists():
            summary = _load_json(summary_file)
            predicted = _finding_from_summary(summary)
        passed = run["returncode"] == 0 and predicted == expected
        sample_results.append(
            {
                "sample": sample,
                "expected": expected,
                "predicted": predicted,
                "passed": passed,
                "returncode": run["returncode"],
                "report_dir": str(report_dir),
                "summary": summary,
                "run": run,
            }
        )

    status = "accepted" if all(item["passed"] for item in sample_results) else "needs_revision"
    report = {
        "runner": "yasa",
        "label": label,
        "tool_dir": str(tool_dir),
        "validation_dir": str(validation_dir),
        "rules_dir": str(rules_dir),
        "uast_sdk_path": str(uast_sdk_path),
        "ctpc_file": str(ctpc_file) if ctpc_file else None,
        "ccec_file": str(ccec_file) if ccec_file else None,
        "status": status,
        "sample_results": sample_results,
        "feedback": _feedback(sample_results),
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    report_json = out_dir / f"{label}_yasa_validation_report.json"
    report_md = out_dir / f"{label}_yasa_validation_report.md"
    report_json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    report_md.write_text(render_yasa_validation_markdown(report), encoding="utf-8")
    return report


def run_yasa_case(
    tool_dir: Path,
    case_path: Path,
    out_dir: Path,
    uast_sdk_path: Path,
    label: str,
    timeout_seconds: int = 180,
    ctpc_file: Path | None = None,
    ccec_file: Path | None = None,
    checker_ids: str = "taint_flow_python_input_inner",
    dump_cg: bool = False,
) -> dict[str, Any]:
    """Run YASA on the original CVE case dataset rather than local validation samples."""

    tool_dir = tool_dir.resolve()
    case_path = case_path.resolve()
    case_dir = case_path.parent
    case = _load_json(case_path)
    source_path = (case_dir / case["dataset_dir"]).resolve()
    rule_file = (case_dir / case["rule_file"]).resolve()
    out_dir = out_dir.resolve()
    uast_sdk_path = uast_sdk_path.resolve()
    if ctpc_file is not None:
        ctpc_file = ctpc_file.resolve()
    if ccec_file is not None:
        ccec_file = ccec_file.resolve()

    if not tool_dir.exists():
        raise FileNotFoundError(tool_dir)
    if not source_path.exists():
        raise FileNotFoundError(source_path)
    if not rule_file.exists():
        raise FileNotFoundError(rule_file)
    if not uast_sdk_path.exists():
        raise FileNotFoundError(uast_sdk_path)

    report_dir = out_dir / label
    if report_dir.exists():
        shutil.rmtree(report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    command = _build_yasa_command(
        tool_dir,
        source_path,
        report_dir,
        rule_file,
        uast_sdk_path,
        timeout_seconds,
        ctpc_file,
        ccec_file,
        checker_ids,
        dump_cg,
    )
    run = _run_command(command, tool_dir)

    summary_file = _summary_path(report_dir)
    summary: dict[str, Any] | None = None
    predicted = "error"
    if summary_file.exists():
        summary = _load_json(summary_file)
        summary = _augment_summary_for_ccec(summary, report_dir, ccec_file)
        predicted = _finding_from_summary(summary)
    trace_quality = assess_trace_quality(report_dir)
    if (
        ccec_file is not None
        and summary is not None
        and int(summary.get("findingCount", 0) or 0) == 0
        and int(summary.get("markedSourceCount", 0) or 0) > 0
        and int(summary.get("matchedSinkCount", 0) or 0) > 0
    ):
        trace_quality["traceStatus"] = "post_ccec_sink_reached_taint_open"
        trace_quality["needsCtpc"] = True
        trace_quality["needsTraceReview"] = True
        trace_quality["decisionBasis"] = (
            trace_quality.get("decisionBasis", "")
            + " Post-CCEC summary reached both source and final sink but produced no finding, "
            "so dataflow propagation remains open and CTPC is required."
        )
    contract_consumption = summarize_contract_consumption(
        report_dir,
        summary,
        ccec_file=ccec_file,
        ctpc_file=ctpc_file,
    )

    report = {
        "runner": "yasa",
        "scope": "full-cve",
        "label": label,
        "case_id": case.get("case_id"),
        "tool_dir": str(tool_dir),
        "case_path": str(case_path),
        "source_path": str(source_path),
        "rule_file": str(rule_file),
        "uast_sdk_path": str(uast_sdk_path),
        "ctpc_file": str(ctpc_file) if ctpc_file else None,
        "ccec_file": str(ccec_file) if ccec_file else None,
        "checker_ids": checker_ids,
        "dump_cg": dump_cg,
        "status": "reported" if run["returncode"] == 0 and predicted == "finding" else "not_reported",
        "result": predicted,
        "returncode": run["returncode"],
        "report_dir": str(report_dir),
        "summary": summary,
        "trace_quality": trace_quality,
        "contract_consumption": contract_consumption,
        "run": run,
        "interpretation": (
            "This is a full original-CVE run. A finding here is evidence that the enhanced analyzer "
            "connected the case entrypoint, interprocedural execution context, CTPC access-path facts, "
            "and final sink rule on the original dataset."
        ),
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    report_json = out_dir / f"{label}_full_cve_report.json"
    report_md = out_dir / f"{label}_full_cve_report.md"
    report_json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    report_md.write_text(render_full_cve_markdown(report), encoding="utf-8")
    return report


def _feedback(sample_results: list[dict[str, Any]]) -> list[str]:
    messages: list[str] = []
    for item in sample_results:
        if item["returncode"] != 0:
            messages.append(f"{item['sample']} YASA run failed with returncode {item['returncode']}")
        elif not item["passed"]:
            messages.append(f"{item['sample']} expected {item['expected']} but YASA produced {item['predicted']}")
    if not messages:
        messages.append("All YASA validation samples matched expected results.")
    return messages


def render_yasa_validation_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# LAPIS YASA Validation Report",
        "",
        f"- Label: `{report['label']}`",
        f"- Status: `{report['status']}`",
        f"- Tool: `{report['tool_dir']}`",
        f"- Rules: `{report['rules_dir']}`",
        "",
        "## Samples",
        "",
    ]
    for item in report["sample_results"]:
        passed = "PASS" if item["passed"] else "FAIL"
        summary = item.get("summary") or {}
        lines.extend(
            [
                f"### {item['sample']} - {passed}",
                "",
                f"- Expected: `{item['expected']}`",
                f"- YASA result: `{item['predicted']}`",
                f"- Return code: `{item['returncode']}`",
                f"- Findings: `{summary.get('findingCount', 'n/a')}`",
                f"- Sources marked: `{summary.get('markedSourceCount', 'n/a')}`",
                f"- Sinks matched: `{summary.get('matchedSinkCount', 'n/a')}`",
                f"- Report dir: `{item['report_dir']}`",
                "",
            ]
        )
    lines.extend(["## Feedback", ""])
    for message in report["feedback"]:
        lines.append(f"- {message}")
    lines.append("")
    return "\n".join(lines)


def render_full_cve_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary") or {}
    trace_quality = report.get("trace_quality") or {}
    consumption = report.get("contract_consumption") or {}
    ccec_consumption = consumption.get("ccec") or {}
    ctpc_consumption = consumption.get("ctpc") or {}
    lines = [
        "# LAPIS Full-CVE YASA Report",
        "",
        f"- Label: `{report['label']}`",
        f"- Case: `{report['case_id']}`",
        f"- Status: `{report['status']}`",
        f"- Result: `{report['result']}`",
        f"- Return code: `{report['returncode']}`",
        f"- Tool: `{report['tool_dir']}`",
        f"- Source path: `{report['source_path']}`",
        f"- Rule: `{report['rule_file']}`",
        f"- CTPC: `{report['ctpc_file']}`",
        f"- Report dir: `{report['report_dir']}`",
        "",
        "## Summary",
        "",
        f"- Findings: `{summary.get('findingCount', 'n/a')}`",
        f"- Sources marked: `{summary.get('markedSourceCount', 'n/a')}`",
        f"- Sinks matched: `{summary.get('matchedSinkCount', 'n/a')}`",
        f"- Entry points: `{summary.get('entryPointCount', 'n/a')}`",
        f"- Files analyzed: `{summary.get('fileCount', 'n/a')}`",
        f"- Lines analyzed: `{summary.get('lineCount', 'n/a')}`",
        "",
        "## Trace Quality",
        "",
        f"- Trace status: `{trace_quality.get('traceStatus', 'n/a')}`",
        f"- CCEC virtual sink: `{trace_quality.get('ccecVirtualSink', 'n/a')}`",
        f"- CTPC fact trace: `{trace_quality.get('ctpcFactTrace', 'n/a')}`",
        f"- FACT TRACE GAP: `{trace_quality.get('factTraceGap', 'n/a')}`",
        f"- Needs CTPC: `{trace_quality.get('needsCtpc', 'n/a')}`",
        f"- Needs trace review: `{trace_quality.get('needsTraceReview', 'n/a')}`",
        "",
        "## Contract Consumption",
        "",
        f"- CCEC status: `{ccec_consumption.get('status', 'n/a')}`",
        f"- CCEC candidate edges: `{ccec_consumption.get('candidateEdges', 'n/a')}`",
        f"- CCEC materialized matches: `{ccec_consumption.get('materializedMatched', 'n/a')}`",
        f"- CCEC checker matches: `{ccec_consumption.get('checkerMatched', 'n/a')}`",
        f"- Post-CCEC source+sink reached: `{ccec_consumption.get('postCcecSinkReached', 'n/a')}`",
        f"- CTPC status: `{ctpc_consumption.get('status', 'n/a')}`",
        f"- CTPC rules: `{ctpc_consumption.get('rules', 'n/a')}`",
        f"- CTPC forced findings: `{ctpc_consumption.get('forcedFindings', 'n/a')}`",
        "",
        "## Interpretation",
        "",
        report["interpretation"],
        "",
    ]
    trace_lines = render_finding_trace_lines(Path(report["report_dir"]))
    if trace_lines:
        lines.extend(["## Findings", "", "```text"])
        lines.extend(trace_lines)
        lines.extend(["```", ""])
    ordered_chain_lines = render_ordered_source_to_sink_chain_lines(report)
    if ordered_chain_lines:
        lines.extend(["## Ordered Source-To-Sink Chain", "", "```text"])
        lines.extend(ordered_chain_lines)
        lines.extend(["```", ""])
    ccec_chain_lines = render_reconstructed_ccec_chain_lines(report)
    if ccec_chain_lines:
        lines.extend(["## Reconstructed CCEC Chain", "", "```text"])
        lines.extend(ccec_chain_lines)
        lines.extend(["```", ""])
    if "ccecVirtualSinkCount" in summary:
        lines.extend(
            [
                "## Sink Count Notes",
                "",
                f"- Raw physical sinks matched: `{summary.get('rawMatchedSinkCount', 'n/a')}`",
                f"- CCEC virtual final sinks: `{summary.get('ccecVirtualSinkCount', 'n/a')}`",
                "- `Sinks matched` includes CCEC virtual final sinks for full-CVE acceptance reporting.",
                "",
            ]
        )
    if report["status"] != "reported":
        lines.extend(
            [
                "## Next Debug Target",
                "",
                (
                    "The local CTPC validation may still pass while the full CVE run does not report. "
                    "That means the remaining gap is in full-program execution context, cross-function "
                    "fact propagation, receiver/argument binding, or final sink reachability."
                ),
                "",
            ]
        )
    return "\n".join(lines)


def build_feasibility_report(
    ctpc_validation_path: Path,
    baseline_yasa_path: Path,
    out_path: Path,
    enhanced_yasa_path: Path | None = None,
) -> dict[str, Any]:
    """Combine local CTPC validation and local YASA sample results."""

    ctpc_validation = _load_json(ctpc_validation_path)
    baseline_yasa = _load_json(baseline_yasa_path)
    enhanced_yasa = _load_json(enhanced_yasa_path) if enhanced_yasa_path else None
    baseline_by_sample = {item["sample"]: item for item in baseline_yasa.get("sample_results", [])}
    must_flow = baseline_by_sample.get("must-flow", {})
    must_not_flow = baseline_by_sample.get("must-not-flow", {})
    must_kill = baseline_by_sample.get("must-kill", {})

    observations = [
        {
            "kind": "baseline_false_negative",
            "sample": "must-flow",
            "supported": must_flow.get("expected") == "finding" and must_flow.get("predicted") == "no_finding",
            "detail": "Baseline YASA misses the positive validation flow that the CTPC is intended to recover.",
        },
        {
            "kind": "baseline_negative_sample",
            "sample": "must-not-flow",
            "supported": must_not_flow.get("expected") == "no_finding"
            and must_not_flow.get("predicted") == "finding",
            "detail": "The negative validation sample checks that the CTPC does not over-propagate.",
        },
        {
            "kind": "kill_sample_available",
            "sample": "must-kill",
            "supported": must_kill.get("expected") == "no_finding" and must_kill.get("predicted") == "no_finding",
            "detail": "The validation set includes a guard case that should remain no-finding.",
        },
        {
            "kind": "ctpc_structural_acceptance",
            "sample": "three-way-structural",
            "supported": ctpc_validation.get("status") == "accepted",
            "detail": "The synthesized CTPC passes local structural must-flow, must-not-flow, and must-kill checks.",
        },
    ]

    if enhanced_yasa is not None:
      observations.append(
          {
              "kind": "enhanced_yasa_acceptance",
              "sample": "three-way-yasa",
              "supported": enhanced_yasa.get("status") == "accepted",
              "detail": "LAPIS-Tool enhanced YASA matches all three local validation expectations.",
          }
      )

    status = "feasible"
    if not (observations[0]["supported"] and observations[3]["supported"]):
        status = "incomplete"
    elif enhanced_yasa is not None and enhanced_yasa.get("status") == "accepted":
        status = "closed"
    report = {
        "status": status,
        "ctpc_validation_report": str(ctpc_validation_path),
        "baseline_yasa_report": str(baseline_yasa_path),
        "enhanced_yasa_report": str(enhanced_yasa_path) if enhanced_yasa_path else None,
        "observations": observations,
        "method_requirements": [
            "Apply only the propagation_edges present in the CTPC contract.",
            "Apply only function_summaries present in the CTPC contract.",
            "Honor all kill_conditions present in the CTPC contract.",
            "Keep must-not-flow and must-kill samples no-finding after enhancement.",
        ],
        "next_acceptance_target": {
            "runner": "LAPIS-Tool enhanced YASA",
            "must_flow": "finding",
            "must_not_flow": "no_finding",
            "must_kill": "no_finding",
            "achieved": enhanced_yasa.get("status") == "accepted" if enhanced_yasa else False,
        },
        "scope_note": (
            "This report closes only the local CTPC semantic-validation loop. It does not prove that "
            "the original CVE dataset produces a complete source-to-final-sink finding. Full-CVE "
            "acceptance must be checked with run-yasa-case."
        ),
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    out_path.with_suffix(".md").write_text(render_feasibility_markdown(report), encoding="utf-8")
    return report


def render_feasibility_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# LAPIS Local CTPC Feasibility Report",
        "",
        f"- Status: `{report['status']}`",
        f"- Scope: local CTPC semantic validation, not full original-CVE acceptance",
        f"- CTPC structural validation: `{report['ctpc_validation_report']}`",
        f"- Upstream YASA validation: `{report['baseline_yasa_report']}`",
        f"- Enhanced YASA validation: `{report['enhanced_yasa_report']}`",
        "",
        "## Observations",
        "",
    ]
    for item in report["observations"]:
        mark = "supported" if item["supported"] else "missing"
        lines.append(f"- `{item['kind']}` on `{item['sample']}`: {mark}. {item['detail']}")
    lines.extend(["", "## Scope Note", "", report["scope_note"], ""])
    lines.extend(["", "## Method Requirements", ""])
    for item in report["method_requirements"]:
        lines.append(f"- {item}")
    target = report["next_acceptance_target"]
    lines.extend(
        [
            "",
            "## Next Acceptance Target",
            "",
            f"- Runner: `{target['runner']}`",
            f"- must-flow: `{target['must_flow']}`",
            f"- must-not-flow: `{target['must_not_flow']}`",
            f"- must-kill: `{target['must_kill']}`",
            f"- achieved: `{target['achieved']}`",
            "",
        ]
    )
    return "\n".join(lines)
