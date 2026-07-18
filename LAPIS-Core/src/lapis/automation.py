"""Automation entry points for LLM-backed LAPIS feasibility runs."""

from __future__ import annotations

import json
import multiprocessing
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .e2e import render_end_to_end_markdown, run_end_to_end_cases
from .llm import DEFAULT_LLM_BASE_URLS, LLMConfig, chat_json, resolve_host_for_llm


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _suite_counts(suite_report: dict[str, Any]) -> dict[str, int]:
    cases = suite_report.get("cases") or []
    return {
        "case_count": len(cases),
        "reported": sum(1 for item in cases if item.get("final_result") in {"finding", "reported"}),
        "not_reported": sum(1 for item in cases if item.get("final_result") in {"no_finding", "not_reported"}),
        "errors": sum(1 for item in cases if item.get("final_result") == "error"),
    }


def _replace_config_base_url(config: LLMConfig, base_url: str) -> LLMConfig:
    return LLMConfig(
        api_key=config.api_key,
        base_url=base_url.rstrip("/"),
        model=config.model,
        timeout_seconds=config.timeout_seconds,
        temperature=config.temperature,
        max_tokens=config.max_tokens,
    )


def _candidate_base_urls(config: LLMConfig) -> list[str]:
    candidates = [config.base_url]
    if config.base_url in DEFAULT_LLM_BASE_URLS:
        candidates.extend(DEFAULT_LLM_BASE_URLS)
    seen = set()
    ordered = []
    for url in candidates:
        normalized = url.rstrip("/")
        if normalized not in seen:
            seen.add(normalized)
            ordered.append(normalized)
    return ordered


def _resolve_host_worker(host: str, port: int, queue: multiprocessing.Queue) -> None:
    try:
        queue.put(resolve_host_for_llm(host, port))
    except Exception as exc:
        queue.put({"status": "failed", "host": host, "port": port, "error": str(exc)})


def _dns_preflight(base_url: str, timeout_seconds: int) -> dict[str, Any]:
    parsed = urlparse(base_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host:
        return {"status": "failed", "error": f"invalid LLM base URL: {base_url}"}

    queue: multiprocessing.Queue = multiprocessing.Queue()
    process = multiprocessing.Process(target=_resolve_host_worker, args=(host, port, queue))
    process.start()
    process.join(max(timeout_seconds, 1))
    if process.is_alive():
        process.terminate()
        process.join(1)
        return {"status": "failed", "host": host, "port": port, "error": "DNS preflight timed out"}
    if queue.empty():
        return {"status": "failed", "host": host, "port": port, "error": "DNS preflight returned no result"}
    return queue.get()


def render_llm_feasibility_markdown(report: dict[str, Any]) -> str:
    llm = report["llm"]
    lines = [
        "# LAPIS LLM Feasibility Report",
        "",
        f"- Status: `{report['status']}`",
        f"- Base URL: `{llm['base_url']}`",
        f"- Model: `{llm['model']}`",
        f"- Smoke test: `{llm['smoke_test']['status']}`",
    ]
    if llm.get("selected_base_url"):
        lines.append(f"- Selected base URL: `{llm['selected_base_url']}`")
    if llm["smoke_test"].get("error"):
        lines.append(f"- Smoke error: `{llm['smoke_test']['error']}`")
    attempts = llm["smoke_test"].get("attempts") or []
    if attempts:
        lines.extend(["", "## LLM Attempts", ""])
        for attempt in attempts:
            detail = attempt.get("error") or attempt.get("message") or ""
            preflight = attempt.get("preflight") or {}
            preflight_status = preflight.get("status")
            preflight_text = f", preflight={preflight_status}" if preflight_status else ""
            lines.append(f"- `{attempt['base_url']}`: `{attempt['status']}`{preflight_text} {detail}")
    if report.get("suite_report"):
        counts = report["summary"]
        lines.extend(
            [
                "",
                "## Dataset Summary",
                "",
                f"- Case count: `{counts['case_count']}`",
                f"- Reported: `{counts['reported']}`",
                f"- Not reported: `{counts['not_reported']}`",
                f"- Errors: `{counts['errors']}`",
                f"- Suite report: `{report['suite_report']}`",
            ]
        )
    lines.append("")
    return "\n".join(lines)


def run_llm_feasibility_suite(
    *,
    tool_dir: Path,
    cases_root: Path,
    out_dir: Path,
    uast_sdk_path: Path,
    llm_config: LLMConfig,
    timeout_seconds: int = 180,
    checker_ids: str = "taint_flow_python_input_inner",
    oracle_root: Path | None = None,
    connectivity_timeout_seconds: int = 5,
) -> dict[str, Any]:
    """Smoke-test the configured LLM, then run the dataset E2E suite with LLM automation."""

    out_dir = out_dir.resolve()
    report_path = out_dir / "llm_feasibility_report.json"
    smoke = {
        "status": "not_run",
        "ok": None,
        "message": None,
        "error": None,
    }
    report: dict[str, Any] = {
        "schema_version": "lapis.llm_feasibility.v1",
        "status": "running",
        "llm": {
            "base_url": llm_config.base_url,
            "candidate_base_urls": _candidate_base_urls(llm_config),
            "selected_base_url": None,
            "model": llm_config.model,
            "smoke_test": smoke,
        },
        "cases_root": str(cases_root.resolve()),
        "out_dir": str(out_dir),
        "suite_report": None,
        "summary": {
            "case_count": 0,
            "reported": 0,
            "not_reported": 0,
            "errors": 0,
        },
    }

    selected_config = None
    for base_url in report["llm"]["candidate_base_urls"]:
        candidate_config = _replace_config_base_url(llm_config, base_url)
        attempt = {
            "base_url": candidate_config.base_url,
            "status": "running",
            "ok": None,
            "message": None,
            "error": None,
            "connectivity_timeout_seconds": connectivity_timeout_seconds,
        }
        smoke.setdefault("attempts", []).append(attempt)
        preflight = _dns_preflight(candidate_config.base_url, connectivity_timeout_seconds)
        attempt["preflight"] = preflight
        if preflight["status"] != "passed":
            attempt["preflight_warning"] = f"DNS preflight failed: {preflight.get('error')}"
        try:
            response = chat_json(
                "Return exactly one JSON object with this shape: "
                '{"ok": true, "message": "lapis llm feasibility smoke test"}',
                candidate_config,
            )
        except Exception as exc:
            attempt.update({"status": "failed", "error": str(exc)})
            continue
        attempt.update(
            {
                "status": "passed" if response.get("ok") is True else "failed",
                "ok": response.get("ok"),
                "message": response.get("message"),
            }
        )
        if response.get("ok") is True:
            selected_config = candidate_config
            report["llm"]["selected_base_url"] = candidate_config.base_url
            report["llm"]["base_url"] = candidate_config.base_url
            smoke.update(
                {
                    "status": "passed",
                    "ok": response.get("ok"),
                    "message": response.get("message"),
                    "error": None,
                }
            )
            break

    if selected_config is None:
        smoke.update(
            {
                "status": "failed",
                "error": "all configured LLM base URLs failed smoke test",
            }
        )
        report["status"] = "blocked_llm_unreachable"
        _write_json(report_path, report)
        report_path.with_suffix(".md").write_text(render_llm_feasibility_markdown(report), encoding="utf-8")
        return report

    suite_report = run_end_to_end_cases(
        tool_dir=tool_dir,
        cases_root=cases_root,
        out_dir=out_dir / "e2e",
        uast_sdk_path=uast_sdk_path,
        timeout_seconds=timeout_seconds,
        checker_ids=checker_ids,
        oracle_root=oracle_root,
        llm_config=selected_config,
    )
    suite_path = out_dir / "e2e" / "end_to_end_suite_report.json"
    suite_path.parent.mkdir(parents=True, exist_ok=True)
    suite_path.with_suffix(".md").write_text(render_end_to_end_markdown(suite_report), encoding="utf-8")
    report["suite_report"] = str(suite_path)
    report["summary"] = _suite_counts(suite_report)
    report["status"] = "completed_with_errors" if report["summary"]["errors"] else "completed"
    _write_json(report_path, report)
    report_path.with_suffix(".md").write_text(render_llm_feasibility_markdown(report), encoding="utf-8")
    return report
