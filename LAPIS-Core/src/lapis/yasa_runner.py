"""YASA-in-the-loop validation runner for LAPIS experiments."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .validator import REQUIRED_SAMPLES


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _summary_path(report_dir: Path) -> Path:
    return report_dir / "scan_summary.json"


def _finding_from_summary(summary: dict[str, Any]) -> str:
    return "finding" if int(summary.get("findingCount", 0)) > 0 else "no_finding"


def _build_yasa_command(
    tool_dir: Path,
    source_path: Path,
    report_dir: Path,
    rule_file: Path,
    uast_sdk_path: Path,
    timeout_seconds: int,
    ctpc_file: Path | None = None,
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
        "taint_flow_python_input_inner",
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
) -> dict[str, Any]:
    """Run YASA on every validation sample and compare with expected results."""

    tool_dir = tool_dir.resolve()
    validation_dir = validation_dir.resolve()
    rules_dir = rules_dir.resolve()
    out_dir = out_dir.resolve()
    uast_sdk_path = uast_sdk_path.resolve()
    if ctpc_file is not None:
        ctpc_file = ctpc_file.resolve()

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
        command = _build_yasa_command(tool_dir, sample_dir, report_dir, rule_file, uast_sdk_path, timeout_seconds, ctpc_file)
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
    command = _build_yasa_command(tool_dir, source_path, report_dir, rule_file, uast_sdk_path, timeout_seconds, ctpc_file)
    run = _run_command(command, tool_dir)

    summary_file = _summary_path(report_dir)
    summary: dict[str, Any] | None = None
    predicted = "error"
    if summary_file.exists():
        summary = _load_json(summary_file)
        predicted = _finding_from_summary(summary)

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
        "status": "reported" if run["returncode"] == 0 and predicted == "finding" else "not_reported",
        "result": predicted,
        "returncode": run["returncode"],
        "report_dir": str(report_dir),
        "summary": summary,
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
        "## Interpretation",
        "",
        report["interpretation"],
        "",
    ]
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
            "detail": "Upstream YASA marks source and sink but misses the dict-key/access-path propagation chain.",
        },
        {
            "kind": "baseline_risk_kind_confusion",
            "sample": "must-not-flow",
            "supported": must_not_flow.get("expected") == "no_finding"
            and must_not_flow.get("predicted") == "finding",
            "detail": "Upstream YASA reports ordinary value taint even though the CTPC target is SQL structure risk from mapping keys.",
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
            "Add guarded access-path propagation for dict key to mapping keys.",
            "Preserve key taint through dict comprehensions that return the original key.",
            "Propagate mapping-key SQL-structure risk through named percent-format operations.",
            "Keep value taint separate from SQL-structure risk so must-not-flow remains no-finding.",
            "Honor kill conditions such as key whitelist/rejection guards.",
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
