"""End-to-end orchestration for oracle-blind LAPIS repair experiments."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .cases import discover_cases
from .ccec import build_ccec_candidates, validate_ccec_candidates
from .diagnosis import build_gap_diagnosis_report
from .gate import build_evidence_gate_report
from .prompt import build_ctpc_prompt
from .yasa_runner import run_yasa_case


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _summary_from_run(run_report: dict[str, Any]) -> Path | None:
    report_dir = run_report.get("report_dir")
    if not report_dir:
        return None
    path = Path(report_dir) / "scan_summary.json"
    return path if path.exists() else None


def _callgraph_from_run(run_report: dict[str, Any]) -> Path | None:
    report_dir = run_report.get("report_dir")
    if not report_dir:
        return None
    path = Path(report_dir) / "callgraph.json"
    return path if path.exists() else None


def _existing_ctpc(case_dir: Path) -> Path | None:
    for relative in ("ctpc/ctpc.v2.json", "ctpc/ctpc.json"):
        path = case_dir / relative
        if path.exists():
            return path
    return None


def _default_oracle(case_dir: Path) -> Path | None:
    for relative in ("oracle/final_oracle.json", "oracle/expected.json", "hidden_oracle.json"):
        path = case_dir / relative
        if path.exists():
            return path
    return None


def _prepare_ctpc_synthesis(case_dir: Path, out_dir: Path) -> dict[str, Any]:
    evidence_path = case_dir / "evidence" / "evidence_pack.json"
    ctpc_dir = out_dir / "ctpc"
    ctpc_dir.mkdir(parents=True, exist_ok=True)
    todo_path = ctpc_dir / "ctpc_synthesis_todo.json"
    prompt_path = ctpc_dir / "ctpc_prompt.md"
    todo = {
        "schema_version": "lapis.ctpc_synthesis_todo.v1",
        "status": "awaiting_ctpc_contract",
        "evidence_pack": str(evidence_path) if evidence_path.exists() else None,
        "expected_outputs": ["ctpc/ctpc.v2.json", "ctpc/ctpc.json"],
        "next_steps": [
            "build or review oracle-blind CTPC prompt",
            "LLM synthesizes CTPC contract from evidence only",
            "materialize-ctpc",
            "materialize-validation",
            "validate-ctpc",
            "rerun end-to-end case",
        ],
    }
    if evidence_path.exists():
        evidence = load_json(evidence_path)
        prompt_path.write_text(build_ctpc_prompt(evidence), encoding="utf-8")
        todo["ctpc_prompt"] = str(prompt_path)
    else:
        todo["note"] = "No evidence/evidence_pack.json exists yet; build CTPC evidence before synthesis."
    todo_path.write_text(json.dumps(todo, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return {"todo": str(todo_path), "prompt": str(prompt_path) if prompt_path.exists() else None}


def _evaluate_final(
    case: dict[str, Any],
    final_run: dict[str, Any] | None,
    oracle_path: Path | None,
) -> dict[str, Any]:
    result = final_run.get("result") if final_run else "not_run"
    reported = result == "finding"
    oracle = load_json(oracle_path) if oracle_path and oracle_path.exists() else None
    if oracle:
        expected = (
            oracle.get("expected_result")
            or oracle.get("expected")
            or ("finding" if oracle.get("should_report") is True else None)
            or ("no_finding" if oracle.get("should_report") is False else None)
        )
        matched = expected == result if expected in {"finding", "no_finding"} else None
        status = "matched_oracle" if matched else "mismatched_oracle" if matched is False else "oracle_uninterpretable"
    else:
        expected = None
        matched = None
        status = "reported_without_oracle" if reported else "not_reported_without_oracle"
    return {
        "case_id": case.get("case_id"),
        "declared_case_group": case.get("gap_type"),
        "final_result": result,
        "accepted_by_final_finding": reported,
        "oracle_path": str(oracle_path) if oracle_path else None,
        "oracle_expected_result": expected,
        "oracle_matched": matched,
        "status": status,
        "oracle_note": (
            "Hidden oracle is read only in this final evaluation block. It is not "
            "passed to gate, diagnosis, CCEC, CTPC, or rerun stages."
        ),
    }


def _write_report(report: dict[str, Any], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    out_path.with_suffix(".md").write_text(render_end_to_end_markdown(report), encoding="utf-8")


def run_end_to_end_case(
    *,
    tool_dir: Path,
    case_path: Path,
    out_dir: Path,
    uast_sdk_path: Path,
    timeout_seconds: int = 180,
    checker_ids: str = "taint_flow_python_input_inner",
    oracle_path: Path | None = None,
) -> dict[str, Any]:
    """Run baseline -> CCEC -> post-CCEC rediagnosis -> optional CTPC -> final evaluation."""

    case_path = case_path.resolve()
    case_dir = case_path.parent
    case = load_json(case_path)
    out_dir = out_dir.resolve()
    evidence_dir = out_dir / "evidence"
    ccec_dir = out_dir / "ccec"
    runs_dir = out_dir / "runs"

    stages: list[dict[str, Any]] = []
    artifacts: dict[str, Any] = {}

    baseline_run = run_yasa_case(
        tool_dir=tool_dir,
        case_path=case_path,
        out_dir=runs_dir,
        uast_sdk_path=uast_sdk_path,
        label="baseline",
        timeout_seconds=timeout_seconds,
        checker_ids=checker_ids,
        dump_cg=True,
    )
    stages.append({"name": "baseline_rerun", "status": baseline_run["status"], "result": baseline_run["result"]})
    artifacts["baseline_run"] = str(runs_dir / "baseline_full_cve_report.json")

    baseline_summary = _summary_from_run(baseline_run)
    baseline_callgraph = _callgraph_from_run(baseline_run)
    initial_gate_path = evidence_dir / "initial_evidence_gate.json"
    initial_gate = build_evidence_gate_report(
        case_path=case_path,
        out_path=initial_gate_path,
        evidence_path=case_dir / "evidence" / "evidence_pack.json",
        callgraph_path=baseline_callgraph,
        baseline_summary_path=baseline_summary,
    )
    initial_diagnosis_path = evidence_dir / "initial_gap_diagnosis.json"
    initial_diagnosis = build_gap_diagnosis_report(initial_gate_path, initial_diagnosis_path)
    stages.append(
        {
            "name": "initial_diagnosis",
            "gate_status": initial_gate["gate_status"],
            "gap_type": initial_diagnosis["diagnosis"]["gap_type"],
            "next_step": initial_diagnosis["diagnosis"]["next_step"],
        }
    )

    ccec_path: Path | None = None
    post_ccec_run: dict[str, Any] | None = None
    post_ccec_diagnosis: dict[str, Any] | None = None
    next_step = initial_diagnosis["diagnosis"].get("next_step")
    if next_step in {"run_ccec", "run_ccec_first"}:
        ccec_path = ccec_dir / "candidate_edges.json"
        ccec_report = build_ccec_candidates(case_path, ccec_path)
        ccec_validation_path = ccec_dir / "validation_report.json"
        ccec_validation = validate_ccec_candidates(ccec_path, ccec_validation_path)
        stages.append(
            {
                "name": "ccec_generation",
                "mode": ccec_report.get("ccec_mode"),
                "candidate_count": len(ccec_report.get("candidate_edges", [])),
                "validation_status": ccec_validation.get("status"),
            }
        )
        artifacts["ccec_candidates"] = str(ccec_path)
        artifacts["ccec_validation"] = str(ccec_validation_path)

        post_ccec_run = run_yasa_case(
            tool_dir=tool_dir,
            case_path=case_path,
            out_dir=runs_dir,
            uast_sdk_path=uast_sdk_path,
            label="post-ccec",
            timeout_seconds=timeout_seconds,
            ccec_file=ccec_path,
            checker_ids=checker_ids,
            dump_cg=True,
        )
        stages.append({"name": "post_ccec_rerun", "status": post_ccec_run["status"], "result": post_ccec_run["result"]})
        artifacts["post_ccec_run"] = str(runs_dir / "post-ccec_full_cve_report.json")

        post_ccec_summary = _summary_from_run(post_ccec_run)
        post_ccec_callgraph = _callgraph_from_run(post_ccec_run)
        post_ccec_gate_path = evidence_dir / "post_ccec_evidence_gate.json"
        build_evidence_gate_report(
            case_path=case_path,
            out_path=post_ccec_gate_path,
            evidence_path=case_dir / "evidence" / "evidence_pack.json",
            callgraph_path=post_ccec_callgraph,
            baseline_summary_path=post_ccec_summary,
        )
        post_ccec_diagnosis_path = evidence_dir / "post_ccec_gap_diagnosis.json"
        post_ccec_diagnosis = build_gap_diagnosis_report(post_ccec_gate_path, post_ccec_diagnosis_path)
        stages.append(
            {
                "name": "post_ccec_rediagnosis",
                "gap_type": post_ccec_diagnosis["diagnosis"]["gap_type"],
                "next_step": post_ccec_diagnosis["diagnosis"]["next_step"],
            }
        )
        artifacts["post_ccec_diagnosis"] = str(post_ccec_diagnosis_path)

    ctpc_path = _existing_ctpc(case_dir)
    final_run = post_ccec_run or baseline_run
    should_try_ctpc = False
    if post_ccec_diagnosis:
        diagnosis = post_ccec_diagnosis["diagnosis"]
        should_try_ctpc = diagnosis.get("next_step") == "run_ctpc" or (
            diagnosis.get("gap_type") == "propagation_gap"
        )
    elif initial_diagnosis["diagnosis"].get("next_step") == "run_ctpc":
        should_try_ctpc = True

    if should_try_ctpc:
        if ctpc_path:
            final_run = run_yasa_case(
                tool_dir=tool_dir,
                case_path=case_path,
                out_dir=runs_dir,
                uast_sdk_path=uast_sdk_path,
                label="post-ccec-ctpc" if ccec_path else "post-ctpc",
                timeout_seconds=timeout_seconds,
                ctpc_file=ctpc_path,
                ccec_file=ccec_path,
                checker_ids=checker_ids,
                dump_cg=True,
            )
            stages.append(
                {
                    "name": "ctpc_rerun",
                    "ctpc_file": str(ctpc_path),
                    "status": final_run["status"],
                    "result": final_run["result"],
                }
            )
            artifacts["ctpc_file"] = str(ctpc_path)
        else:
            ctpc_todo = _prepare_ctpc_synthesis(case_dir, out_dir)
            stages.append(
                {
                    "name": "ctpc_rerun",
                    "status": "blocked",
                    "reason": "post-CCEC diagnosis requires CTPC, but no ctpc/ctpc.v2.json or ctpc/ctpc.json exists",
                    "ctpc_todo": ctpc_todo["todo"],
                    "ctpc_prompt": ctpc_todo["prompt"],
                }
            )
            artifacts["ctpc_synthesis_todo"] = ctpc_todo["todo"]
            if ctpc_todo["prompt"]:
                artifacts["ctpc_prompt"] = ctpc_todo["prompt"]

    evaluation = _evaluate_final(case, final_run, oracle_path or _default_oracle(case_dir))
    report = {
        "schema_version": "lapis.end_to_end_repair.v1",
        "case_id": case.get("case_id"),
        "case": str(case_path),
        "out_dir": str(out_dir),
        "tool_dir": str(tool_dir.resolve()),
        "uast_sdk_path": str(uast_sdk_path.resolve()),
        "declared_case_group": case.get("gap_type"),
        "declared_repair_branch": case.get("repair_branch"),
        "stages": stages,
        "artifacts": artifacts,
        "evaluation": evaluation,
    }
    _write_report(report, out_dir / "end_to_end_report.json")
    return report


def run_end_to_end_cases(
    *,
    tool_dir: Path,
    cases_root: Path,
    out_dir: Path,
    uast_sdk_path: Path,
    timeout_seconds: int = 180,
    checker_ids: str = "taint_flow_python_input_inner",
    oracle_root: Path | None = None,
) -> dict[str, Any]:
    rows = []
    out_dir = out_dir.resolve()
    for case_path in discover_cases(cases_root):
        case = load_json(case_path)
        oracle_path = None
        if oracle_root:
            candidate = oracle_root / f"{case.get('case_id')}.json"
            oracle_path = candidate if candidate.exists() else None
        try:
            report = run_end_to_end_case(
                tool_dir=tool_dir,
                case_path=case_path,
                out_dir=out_dir / str(case.get("case_id")),
                uast_sdk_path=uast_sdk_path,
                timeout_seconds=timeout_seconds,
                checker_ids=checker_ids,
                oracle_path=oracle_path,
            )
            rows.append(
                {
                    "case_id": report["case_id"],
                    "declared_case_group": report["declared_case_group"],
                    "stage_count": len(report["stages"]),
                    "final_result": report["evaluation"]["final_result"],
                    "evaluation_status": report["evaluation"]["status"],
                    "report": str(Path(report["out_dir"]) / "end_to_end_report.json"),
                }
            )
        except Exception as exc:  # pragma: no cover - suite runner should summarize external tool failures.
            rows.append(
                {
                    "case_id": case.get("case_id"),
                    "declared_case_group": case.get("gap_type"),
                    "stage_count": 0,
                    "final_result": "error",
                    "evaluation_status": "runner_error",
                    "error": str(exc),
                    "report": None,
                }
            )
    report = {
        "schema_version": "lapis.end_to_end_suite.v1",
        "cases_root": str(cases_root.resolve()),
        "out_dir": str(out_dir),
        "case_count": len(rows),
        "cases": rows,
    }
    _write_report(report, out_dir / "end_to_end_suite_report.json")
    return report


def render_end_to_end_markdown(report: dict[str, Any]) -> str:
    if report.get("schema_version") == "lapis.end_to_end_suite.v1":
        lines = [
            "# LAPIS End-to-End Suite Report",
            "",
            f"- Cases root: `{report['cases_root']}`",
            f"- Case count: `{report['case_count']}`",
            "",
            "| Case | Group | Final | Evaluation | Report |",
            "|---|---|---|---|---|",
        ]
        for item in report["cases"]:
            lines.append(
                f"| {item['case_id']} | {item['declared_case_group']} | "
                f"{item['final_result']} | {item['evaluation_status']} | `{item['report']}` |"
            )
        lines.append("")
        return "\n".join(lines)

    evaluation = report["evaluation"]
    lines = [
        "# LAPIS End-to-End Repair Report",
        "",
        f"- Case: `{report['case_id']}`",
        f"- Declared group: `{report['declared_case_group']}`",
        f"- Final result: `{evaluation['final_result']}`",
        f"- Evaluation: `{evaluation['status']}`",
        f"- Oracle: `{evaluation['oracle_path']}`",
        "",
        "## Stages",
        "",
    ]
    for stage in report["stages"]:
        details = ", ".join(f"{key}={value}" for key, value in stage.items() if key != "name")
        lines.append(f"- `{stage['name']}`: {details}")
    lines.extend(["", "## Artifacts", ""])
    for key, value in report["artifacts"].items():
        lines.append(f"- `{key}`: `{value}`")
    lines.append("")
    return "\n".join(lines)
