"""CTPC schema helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def validate_ctpc_v2(ctpc: dict[str, Any]) -> None:
    if ctpc.get("schema_version") != "ctpc.v2":
        raise ValueError("CTPC must have schema_version='ctpc.v2'")
    required = ["contract_name", "applies_to", "fact_types", "propagation_edges", "kill_conditions"]
    for key in required:
        if key not in ctpc:
            raise ValueError(f"CTPC v2 missing {key!r}")
    for edge in ctpc["propagation_edges"]:
        for key in ["edge_id", "event", "pattern", "from", "to"]:
            if key not in edge:
                raise ValueError(f"propagation edge missing {key!r}: {edge}")
        if "kind" not in edge["pattern"]:
            raise ValueError(f"propagation edge pattern missing kind: {edge}")
    for summary in ctpc.get("function_summaries", []):
        for key in ["summary_id", "event", "pattern", "from", "to"]:
            if key not in summary:
                raise ValueError(f"function summary missing {key!r}: {summary}")
        if "kind" not in summary["pattern"]:
            raise ValueError(f"function summary pattern missing kind: {summary}")
    for kill in ctpc["kill_conditions"]:
        for key in ["kill_id", "event", "pattern", "effect"]:
            if key not in kill:
                raise ValueError(f"kill condition missing {key!r}: {kill}")


def upgrade_ctpc_file(in_path: Path, out_path: Path) -> dict[str, Any]:
    ctpc = _load_json(in_path)
    validate_ctpc_v2(ctpc)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(ctpc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return ctpc
