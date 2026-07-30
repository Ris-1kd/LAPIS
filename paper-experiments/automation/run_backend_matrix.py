#!/usr/bin/env python3
"""Build or run LLM backend matrix commands for LAPIS paper experiments."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = Path(__file__).with_name("case-manifest.json")
DEFAULT_BACKENDS = Path(__file__).with_name("llm-backends.example.json")
DEFAULT_OUT_ROOT = ROOT / "paper-experiments" / "automation" / "backend-runs"


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def repo_path(value: str | None) -> Path | None:
    if not value:
        return None
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def command_to_text(command: list[str]) -> str:
    return " ".join(shlex.quote(item) for item in command)


def run_command(command: list[str], *, env: dict[str, str]) -> None:
    print(command_to_text(command), flush=True)
    subprocess.run(command, cwd=ROOT, env=env, check=True)


def ensure_command_output_dirs(command: list[str]) -> None:
    for flag in ["--out", "--raw-out"]:
        if flag in command:
            Path(command[command.index(flag) + 1]).parent.mkdir(parents=True, exist_ok=True)
    if "--out-dir" in command:
        Path(command[command.index("--out-dir") + 1]).mkdir(parents=True, exist_ok=True)


def build_llm_args(backend: dict[str, Any]) -> list[str]:
    return [
        "--base-url",
        backend["base_url"],
        "--model",
        backend["model"],
        "--llm-timeout-seconds",
        str(backend.get("timeout_seconds", 120)),
        "--max-tokens",
        str(backend.get("max_tokens", 8192)),
    ]


def case_output_root(out_root: Path, backend: dict[str, Any], case: dict[str, Any]) -> Path:
    return out_root / backend["name"] / case["case_id"]


def build_case_commands(
    *,
    case: dict[str, Any],
    backend: dict[str, Any],
    out_root: Path,
    tool_dir: str,
    uast_sdk_path: str,
    timeout_seconds: int,
) -> list[list[str]]:
    base = case_output_root(out_root, backend, case)
    commands: list[list[str]] = []
    llm_args = build_llm_args(backend)
    case_json = case.get("case_json")

    ccec_out = base / "ccec" / "candidate_edges.llm.json"
    ccec_validation_out = base / "ccec" / "llm_validation_report.json"
    ctpc_out = base / "ctpc" / "ctpc.llm.json"
    ctpc_materialized_dir = base / "ctpc" / "materialized"
    ctpc_materialized = ctpc_materialized_dir / "ctpc" / "ctpc.json"
    ctpc_validation_out = base / "validation" / "validation_response.auto.json"

    if case.get("requires_ccec"):
        commands.append(
            [
                "python3",
                "-m",
                "lapis",
                "llm-generate-ccec",
                "--case",
                case_json,
                "--gate",
                case["evidence_gate"],
                "--diagnosis",
                case["gap_diagnosis"],
                "--out",
                str(ccec_out),
                "--raw-out",
                str(base / "ccec" / "candidate_edges.llm.raw.txt"),
                *llm_args,
            ]
        )
        commands.append(
            [
                "python3",
                "-m",
                "lapis",
                "validate-ccec-candidates",
                "--candidates",
                str(ccec_out),
                "--out",
                str(ccec_validation_out),
            ]
        )

    if case.get("requires_ctpc"):
        commands.append(
            [
                "python3",
                "-m",
                "lapis",
                "llm-generate-ctpc",
                "--evidence",
                case["evidence_pack"],
                "--out",
                str(ctpc_out),
                "--raw-out",
                str(base / "ctpc" / "ctpc.llm.raw.txt"),
                *llm_args,
            ]
        )
        commands.append(
            [
                "python3",
                "-m",
                "lapis",
                "materialize-ctpc",
                "--response",
                str(ctpc_out),
                "--out-dir",
                str(ctpc_materialized_dir),
            ]
        )
        commands.append(
            [
                "python3",
                "-m",
                "lapis",
                "llm-generate-validation",
                "--evidence",
                case["evidence_pack"],
                "--ctpc",
                str(ctpc_materialized),
                "--out",
                str(ctpc_validation_out),
                "--raw-out",
                str(base / "validation" / "validation_response.auto.raw.txt"),
                *llm_args,
            ]
        )

    re_scan = [
        "python3",
        "-m",
        "lapis",
        "run-yasa-case",
        "--tool-dir",
        tool_dir,
        "--case",
        case_json,
        "--out-dir",
        str(base / "runs" / "final"),
        "--uast-sdk-path",
        uast_sdk_path,
        "--label",
        f"{backend['name']}-final",
        "--timeout-seconds",
        str(timeout_seconds),
    ]
    if case.get("requires_ccec"):
        re_scan.extend(["--ccec-file", str(ccec_out)])
    if case.get("requires_ctpc"):
        re_scan.extend(["--ctpc-file", str(ctpc_materialized)])
    commands.append(re_scan)
    return commands


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--backends", type=Path, default=DEFAULT_BACKENDS)
    parser.add_argument("--out-root", type=Path, default=DEFAULT_OUT_ROOT)
    parser.add_argument("--backend", action="append", help="Run only selected backend name; can be repeated")
    parser.add_argument("--case", action="append", help="Run only selected case_id; can be repeated")
    parser.add_argument("--tool-dir", default="LAPIS-Tool")
    parser.add_argument("--uast-sdk-path", default="external-tools/YASA-Engine-upstream/uast4py-linux-amd64")
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--execute", action="store_true", help="Execute commands instead of printing them")
    args = parser.parse_args()

    manifest = load_json(args.manifest)
    backends = load_json(args.backends).get("backends", [])
    selected_backends = set(args.backend or [])
    selected_cases = set(args.case or [])

    env = os.environ.copy()
    env["PYTHONPATH"] = "LAPIS-Core/src"

    for backend in backends:
        if selected_backends and backend["name"] not in selected_backends:
            continue
        api_key_env = backend.get("api_key_env", "LAPIS_LLM_API_KEY")
        if args.execute and api_key_env != "LAPIS_LLM_API_KEY":
            if not env.get(api_key_env):
                raise SystemExit(f"missing API key environment variable: {api_key_env}")
            env["LAPIS_LLM_API_KEY"] = env[api_key_env]

        for case in manifest.get("cases", []):
            if case.get("is_no_gap_control"):
                continue
            if selected_cases and case["case_id"] not in selected_cases:
                continue
            missing = [key for key in ["case_json", "evidence_pack"] if not case.get(key)]
            if case.get("requires_ccec"):
                missing.extend(key for key in ["evidence_gate", "gap_diagnosis"] if not case.get(key))
            if missing:
                print(f"# skip {case['case_id']}: manifest missing {', '.join(sorted(set(missing)))}")
                continue

            commands = build_case_commands(
                case=case,
                backend=backend,
                out_root=args.out_root,
                tool_dir=args.tool_dir,
                uast_sdk_path=args.uast_sdk_path,
                timeout_seconds=args.timeout_seconds,
            )
            for command in commands:
                if args.execute:
                    ensure_command_output_dirs(command)
                    run_command(command, env=env)
                else:
                    print(command_to_text(command))


if __name__ == "__main__":
    main()
