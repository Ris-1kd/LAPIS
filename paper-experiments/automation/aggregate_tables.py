#!/usr/bin/env python3
"""Aggregate current LAPIS experiment reports into paper-table draft files."""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = Path(__file__).with_name("case-manifest.json")
DEFAULT_OUT_DIR = Path(__file__).with_name("generated")


def load_json(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def repo_path(value: str | None) -> Path | None:
    if not value:
        return None
    path = Path(value)
    if path.is_absolute():
        return path
    return ROOT / path


def rel(path: Path | None) -> str:
    if path is None:
        return ""
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def is_reported(report: dict[str, Any]) -> bool:
    return report.get("status") == "reported" or report.get("result") == "finding"


def finding_count(report: dict[str, Any]) -> int:
    summary = report.get("summary") or {}
    value = summary.get("findingCount", report.get("findings", 0))
    return int(value or 0)


def sink_count(report: dict[str, Any]) -> int:
    summary = report.get("summary") or {}
    value = summary.get("matchedSinkCount", report.get("sinks", 0))
    return int(value or 0)


def source_count(report: dict[str, Any]) -> int:
    summary = report.get("summary") or {}
    value = summary.get("markedSourceCount", report.get("sources", 0))
    return int(value or 0)


def trace_recovered(report: dict[str, Any]) -> bool:
    if not is_reported(report):
        return False
    quality = report.get("trace_quality") or {}
    if quality.get("needsTraceReview") is True:
        return False
    status = quality.get("traceStatus")
    if status in {"reported_trace", "ctpc_fact_closed", "actual_taint_trace"}:
        return True
    stdout = ((report.get("run") or {}).get("stdout_tail") or "")
    return "Trace:" in stdout or "ordered_source_to_sink_chain:" in stdout


def pct(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "NA"
    return f"{numerator / denominator:.2f}"


def contract_json_parseable(paths: Iterable[str]) -> int:
    count = 0
    for item in paths:
        if load_json(repo_path(item)):
            count += 1
    return count


def validation_passed(path_value: str | None) -> bool:
    data = load_json(repo_path(path_value))
    if not data:
        return False
    if data.get("status") == "accepted":
        return True
    must_keys = ["must_flow", "must_not_flow", "must_kill"]
    if all(key in data for key in must_keys):
        return all(bool(data.get(key)) for key in must_keys)
    camel_keys = ["mustFlow", "mustNotFlow", "mustKill"]
    if all(key in data for key in camel_keys):
        return all(bool(data.get(key)) for key in camel_keys)
    return False


def is_triple_validation(path_value: str | None) -> bool:
    data = load_json(repo_path(path_value))
    if not data:
        return False
    snake_keys = {"must_flow", "must_not_flow", "must_kill"}
    camel_keys = {"mustFlow", "mustNotFlow", "mustKill"}
    return snake_keys.issubset(data) or camel_keys.issubset(data)


def validation_pass_count(paths: Iterable[str]) -> int:
    return sum(1 for item in paths if validation_passed(item))


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def markdown_label(fieldname: str) -> str:
    labels = {
        "method": "Method",
        "detected_cves": "Detected CVEs",
        "recall": "Recall",
        "precision": "Precision",
        "f1": "F1",
        "path_recovery": "Path Recovery",
        "configuration": "Configuration",
        "fp": "FP",
        "model": "Model",
        "contract_accuracy": "Contract Accuracy",
        "triple_pass": "Triple Pass",
        "cost": "Cost",
        "notes": "Notes",
    }
    return labels.get(fieldname, fieldname.replace("_", " ").title())


def write_markdown(path: Path, title: str, rows: list[dict[str, Any]], fieldnames: list[str], note: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write(f"# {title}\n\n")
        handle.write(f"{note}\n\n")
        handle.write("| " + " | ".join(markdown_label(name) for name in fieldnames) + " |\n")
        handle.write("|" + "|".join(["---"] * len(fieldnames)) + "|\n")
        for row in rows:
            handle.write("| " + " | ".join(str(row.get(name, "")) for name in fieldnames) + " |\n")


def build_case_rows(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for case in cases:
        baseline = load_json(repo_path(case.get("baseline_report")))
        final = load_json(repo_path(case.get("final_report")))
        rows.append(
            {
                "case_id": case["case_id"],
                "project": case.get("project", ""),
                "gap_type": case.get("gap_type", ""),
                "is_no_gap_control": str(bool(case.get("is_no_gap_control"))).lower(),
                "requires_ccec": str(bool(case.get("requires_ccec"))).lower(),
                "requires_ctpc": str(bool(case.get("requires_ctpc"))).lower(),
                "baseline_status": baseline.get("status", "missing"),
                "baseline_findings": finding_count(baseline),
                "baseline_sources": source_count(baseline),
                "baseline_sinks": sink_count(baseline),
                "lapis_status": final.get("status", "missing"),
                "lapis_findings": finding_count(final),
                "lapis_sources": source_count(final),
                "lapis_sinks": sink_count(final),
                "trace_status": (final.get("trace_quality") or {}).get("traceStatus", ""),
                "ordered_trace_recovered": str(trace_recovered(final)).lower(),
                "baseline_report": case.get("baseline_report", ""),
                "final_report": case.get("final_report", ""),
            }
        )
    return rows


def build_table2(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    gap_cases = [case for case in cases if case.get("is_vulnerable") and not case.get("is_no_gap_control")]

    def row(method: str, report_key: str, notes: str) -> dict[str, Any]:
        reported = 0
        traces = 0
        for case in gap_cases:
            report = load_json(repo_path(case.get(report_key)))
            if is_reported(report):
                reported += 1
            if trace_recovered(report):
                traces += 1
        return {
            "method": method,
            "detected_cves": reported,
            "recall": pct(reported, len(gap_cases)),
            "precision": "TBD",
            "f1": "TBD",
            "path_recovery": pct(traces, len(gap_cases)),
            "notes": notes,
        }

    return [
        row("YASA", "baseline_report", "Baseline report without CCEC/CTPC contracts"),
        row("LAPIS", "final_report", "Validated CCEC/CTPC contracts consumed during re-scan"),
    ]


def build_table3(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    gap_cases = [case for case in cases if case.get("is_vulnerable") and not case.get("is_no_gap_control")]

    def count_cases(predicate) -> tuple[int, int]:
        selected = [case for case in gap_cases if predicate(case)]
        reported = sum(1 for case in selected if is_reported(load_json(repo_path(case.get("final_report")))))
        traced = sum(1 for case in selected if trace_recovered(load_json(repo_path(case.get("final_report")))))
        return reported, traced

    full_reported, full_traced = count_cases(lambda case: True)
    no_ccec_reported, no_ccec_traced = count_cases(lambda case: not case.get("requires_ccec"))
    no_ctpc_reported, no_ctpc_traced = count_cases(lambda case: not case.get("requires_ctpc"))

    return [
        {
            "configuration": "Full LAPIS",
            "recall": pct(full_reported, len(gap_cases)),
            "precision": "TBD",
            "f1": "TBD",
            "path_recovery": pct(full_traced, len(gap_cases)),
            "fp": "TBD",
            "notes": "Current small-sample upper-bound",
        },
        {
            "configuration": "w/o Evidence",
            "recall": "not_run",
            "precision": "not_run",
            "f1": "not_run",
            "path_recovery": "not_run",
            "fp": "not_run",
            "notes": "Requires explicit prompt ablation runs",
        },
        {
            "configuration": "w/o CCEC",
            "recall": pct(no_ccec_reported, len(gap_cases)),
            "precision": "TBD",
            "f1": "TBD",
            "path_recovery": pct(no_ccec_traced, len(gap_cases)),
            "fp": "TBD",
            "notes": "Derived lower bound: only cases not requiring CCEC remain recoverable",
        },
        {
            "configuration": "w/o CTPC",
            "recall": pct(no_ctpc_reported, len(gap_cases)),
            "precision": "TBD",
            "f1": "TBD",
            "path_recovery": pct(no_ctpc_traced, len(gap_cases)),
            "fp": "TBD",
            "notes": "Derived lower bound: only CCEC-only cases remain recoverable",
        },
        {
            "configuration": "w/o Validation",
            "recall": "not_run",
            "precision": "not_run",
            "f1": "not_run",
            "path_recovery": "not_run",
            "fp": "not_run",
            "notes": "Requires validation-bypass re-scan and manual/oracle audit",
        },
    ]


def build_table4(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_backend: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {
            "cases_attempted": 0,
            "parseable_contract_json": 0,
            "validated_contracts": 0,
            "triple_validation_attempts": 0,
            "triple_validation_passed": 0,
            "ordered_trace_recovered": 0,
        }
    )
    for case in cases:
        for run in case.get("llm_runs", []):
            key = (run.get("model", "unknown"), run.get("provider", "unknown"))
            item = by_backend[key]
            item["cases_attempted"] += 1
            item["parseable_contract_json"] += contract_json_parseable(run.get("contract_files", []))
            item["validated_contracts"] += validation_pass_count(run.get("validation_files", []))
            triple_files = [path for path in run.get("validation_files", []) if is_triple_validation(path)]
            item["triple_validation_attempts"] += len(triple_files)
            item["triple_validation_passed"] += validation_pass_count(triple_files)
            report = load_json(repo_path(run.get("final_report")))
            if trace_recovered(report):
                item["ordered_trace_recovered"] += 1

    rows = []
    for (model, provider), item in sorted(by_backend.items()):
        contract_accuracy = pct(item["validated_contracts"], item["parseable_contract_json"])
        triple_pass = pct(item["triple_validation_passed"], item["triple_validation_attempts"])
        rows.append(
            {
                "model": model,
                "contract_accuracy": contract_accuracy,
                "triple_pass": triple_pass,
                "path_recovery": pct(item["ordered_trace_recovered"], item["cases_attempted"]),
                "cost": "TBD",
                "notes": f"{provider}; current recorded backend",
            }
        )

    existing = {row["model"] for row in rows}
    for model in ["gemini", "deepseek"]:
        if model not in existing:
            rows.append(
                {
                    "model": model,
                    "contract_accuracy": "not_run",
                    "triple_pass": "not_run",
                    "path_recovery": "not_run",
                    "cost": "TBD",
                    "notes": "Backend slot reserved for future RQ3 runs",
                }
            )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    args = parser.parse_args()

    manifest = load_json(args.manifest)
    cases = manifest.get("cases", [])
    out_dir = args.out_dir

    case_rows = build_case_rows(cases)
    table2 = build_table2(cases)
    table3 = build_table3(cases)
    table4 = build_table4(cases)

    case_fields = [
        "case_id",
        "project",
        "gap_type",
        "is_no_gap_control",
        "requires_ccec",
        "requires_ctpc",
        "baseline_status",
        "baseline_findings",
        "baseline_sources",
        "baseline_sinks",
        "lapis_status",
        "lapis_findings",
        "lapis_sources",
        "lapis_sinks",
        "trace_status",
        "ordered_trace_recovered",
        "baseline_report",
        "final_report",
    ]
    table2_fields = [
        "method",
        "detected_cves",
        "recall",
        "precision",
        "f1",
        "path_recovery",
        "notes",
    ]
    table3_fields = [
        "configuration",
        "recall",
        "precision",
        "f1",
        "path_recovery",
        "fp",
        "notes",
    ]
    table4_fields = [
        "model",
        "contract_accuracy",
        "triple_pass",
        "path_recovery",
        "cost",
        "notes",
    ]

    write_csv(out_dir / "current_case_detail_results.csv", case_rows, case_fields)
    write_csv(out_dir / "table2_overall_detection_results.current.csv", table2, table2_fields)
    write_csv(out_dir / "table3_ablation_study.current.csv", table3, table3_fields)
    write_csv(out_dir / "table4_llm_backend_comparison.current.csv", table4, table4_fields)

    write_markdown(
        out_dir / "table2_overall_detection_results.current.md",
        "Table 2 Current Overall Detection Results",
        table2,
        table2_fields,
        "Draft values derived from the current small validation slice.",
    )
    write_markdown(
        out_dir / "table3_ablation_study.current.md",
        "Table 3 Current Ablation Study",
        table3,
        table3_fields,
        "Draft values combine measured full LAPIS runs with manifest-derived lower bounds where explicit ablation runs are not yet available.",
    )
    write_markdown(
        out_dir / "table4_llm_backend_comparison.current.md",
        "Table 4 Current LLM Backend Comparison",
        table4,
        table4_fields,
        "Draft values are grouped from `llm_runs` entries in the manifest.",
    )

    summary = {
        "cases": len(cases),
        "generated": [
            rel(out_dir / "current_case_detail_results.csv"),
            rel(out_dir / "table2_overall_detection_results.current.csv"),
            rel(out_dir / "table3_ablation_study.current.csv"),
            rel(out_dir / "table4_llm_backend_comparison.current.csv"),
        ],
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
