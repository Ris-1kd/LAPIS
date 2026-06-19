"""Case discovery and end-to-end repair workflow orchestration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .ccec import build_ccec_candidates, build_repaired_call_chain, validate_ccec_candidates
from .diagnosis import build_gap_diagnosis_report
from .gate import build_evidence_gate_report


CASE_GROUPS = ("connectivity_gap", "propagation_gap", "mixed_case", "control")


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def discover_cases(cases_root: Path) -> list[Path]:
    cases_root = cases_root.resolve()
    paths = []
    for group in CASE_GROUPS:
        paths.extend(sorted((cases_root / group).glob("*/case.json")))
    return paths


def case_summary(case_path: Path) -> dict[str, Any]:
    case = load_json(case_path)
    return {
        "case_id": case.get("case_id"),
        "project": case.get("project"),
        "category": case.get("category"),
        "gap_type": case.get("gap_type"),
        "repair_branch": case.get("repair_branch"),
        "difficulty": case.get("difficulty"),
        "case_path": str(case_path),
    }


def build_case_index(cases_root: Path, out_path: Path | None = None) -> dict[str, Any]:
    cases = [case_summary(path) for path in discover_cases(cases_root)]
    report = {
        "schema_version": "lapis.case_index.v1",
        "cases_root": str(cases_root.resolve()),
        "case_count": len(cases),
        "groups": {
            group: [item for item in cases if item["gap_type"] == group or (group == "control" and item["gap_type"] == "no_gap_control")]
            for group in CASE_GROUPS
        },
        "cases": cases,
    }
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def _diagnosis_output(case_path: Path) -> tuple[Path, Path]:
    case_dir = case_path.parent
    return case_dir / "evidence" / "evidence_gate.json", case_dir / "evidence" / "gap_diagnosis.json"


def run_repair_workflow(cases_root: Path, out_path: Path | None = None) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for case_path in discover_cases(cases_root):
        case = load_json(case_path)
        gate_path, diagnosis_path = _diagnosis_output(case_path)
        evidence_path = case_path.parent / "evidence" / "evidence_pack.json"
        gate = build_evidence_gate_report(
            case_path=case_path,
            out_path=gate_path,
            evidence_path=evidence_path if evidence_path.exists() else None,
        )
        diagnosis = build_gap_diagnosis_report(gate_path, diagnosis_path)
        ccec_path = None
        if diagnosis["diagnosis"].get("next_step") in {"run_ccec", "run_ccec_first"}:
            ccec_path = case_path.parent / "ccec" / "candidate_edges.json"
            build_ccec_candidates(case_path, ccec_path)
            validate_ccec_candidates(ccec_path, case_path.parent / "ccec" / "validation_report.json")
            build_repaired_call_chain(case_path, ccec_path, case_path.parent / "ccec" / "repaired_call_chain.json")
        rows.append(
            {
                "case_id": case.get("case_id"),
                "project": case.get("project"),
                "category": case.get("category"),
                "expected_gap_type": case.get("gap_type"),
                "gate_status": gate.get("gate_status"),
                "diagnosed_gap_type": diagnosis["diagnosis"].get("gap_type"),
                "next_step": diagnosis["diagnosis"].get("next_step"),
                "repair_order": diagnosis.get("repair_order", []),
                "gate_report": str(gate_path),
                "diagnosis_report": str(diagnosis_path),
                "ccec_candidates": str(ccec_path) if ccec_path else None,
            }
        )

    report = {
        "schema_version": "lapis.repair_workflow.v1",
        "cases_root": str(cases_root.resolve()),
        "case_count": len(rows),
        "cases": rows,
    }
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        out_path.with_suffix(".md").write_text(_workflow_markdown(report), encoding="utf-8")
    return report


def _workflow_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# LAPIS Repair Workflow Report",
        "",
        f"- Cases root: `{report['cases_root']}`",
        f"- Case count: {report['case_count']}",
        "",
        "| Case | Project | Category | Gate | Diagnosis | Next step |",
        "|---|---|---|---|---|---|",
    ]
    for item in report["cases"]:
        lines.append(
            "| {case_id} | {project} | {category} | {gate_status} | {diagnosed_gap_type} | {next_step} |".format(
                **item
            )
        )
    lines.append("")
    return "\n".join(lines)
