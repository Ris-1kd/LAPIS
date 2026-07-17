"""OpenAI-compatible LLM client helpers for LAPIS synthesis."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from getpass import getpass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class LLMConfig:
    api_key: str
    base_url: str
    model: str
    timeout_seconds: int = 120
    temperature: float = 0.0
    max_tokens: int = 4096


def config_from_env(
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    model: str | None = None,
    timeout_seconds: int = 120,
    temperature: float = 0.0,
    max_tokens: int = 4096,
) -> LLMConfig:
    key = api_key or os.environ.get("LAPIS_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")
    if not key:
        raise ValueError("set LAPIS_LLM_API_KEY or OPENAI_API_KEY")
    return LLMConfig(
        api_key=key,
        base_url=(base_url or os.environ.get("LAPIS_LLM_BASE_URL") or "https://api.openai.com/v1").rstrip("/"),
        model=model or os.environ.get("LAPIS_LLM_MODEL") or "gpt-4o-mini",
        timeout_seconds=timeout_seconds,
        temperature=temperature,
        max_tokens=max_tokens,
    )


def read_api_key_from_stdin() -> str:
    key = getpass("API key: ").strip() if sys.stdin.isatty() else sys.stdin.readline().strip()
    if not key:
        raise ValueError("empty API key from stdin")
    return key


def _post_json(url: str, payload: dict[str, Any], config: LLMConfig) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {config.api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=config.timeout_seconds) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"LLM API HTTP {exc.code}: {body[:1000]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"LLM API request failed: {exc}") from exc


def chat_text(
    prompt: str,
    config: LLMConfig,
    *,
    system: str = "You are a precise program-analysis assistant. Return only the requested output.",
) -> str:
    payload: dict[str, Any] = {
        "model": config.model,
        "temperature": config.temperature,
        "max_tokens": config.max_tokens,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
    }
    payload["response_format"] = {"type": "json_object"}
    url = f"{config.base_url}/chat/completions"
    try:
        response = _post_json(url, payload, config)
    except RuntimeError as exc:
        message = str(exc)
        if "LLM API HTTP 400" not in message and "LLM API HTTP 422" not in message:
            raise
        if "response_format" not in message.lower():
            raise
        payload.pop("response_format", None)
        response = _post_json(url, payload, config)
    choices = response.get("choices") or []
    if not choices:
        raise RuntimeError(f"LLM API returned no choices: {response}")
    message = choices[0].get("message") or {}
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise RuntimeError(f"LLM API returned empty content: {response}")
    return content


def extract_json_object(text: str) -> dict[str, Any]:
    stripped = text.strip()
    fence = re.match(r"^```(?:json)?\s*(?P<body>.*?)\s*```$", stripped, re.DOTALL)
    if fence:
        stripped = fence.group("body").strip()
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start < 0 or end <= start:
            raise
        data = json.loads(stripped[start : end + 1])
    if not isinstance(data, dict):
        raise ValueError("LLM output must be a JSON object")
    return data


def chat_json(prompt: str, config: LLMConfig) -> dict[str, Any]:
    return extract_json_object(chat_text(prompt, config))


def write_llm_artifacts(out_json: Path, response: dict[str, Any], raw_text: str | None = None) -> None:
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(response, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if raw_text is not None:
        out_json.with_suffix(".raw.txt").write_text(raw_text, encoding="utf-8")
