"""OpenAI-compatible LLM client helpers for LAPIS synthesis."""

from __future__ import annotations

import json
import os
import re
import socket
import ssl
import sys
import http.client
import urllib.error
import urllib.request
from dataclasses import dataclass
from getpass import getpass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DEFAULT_LLM_BASE_URL = "https://llm-api.net/v1"
FALLBACK_LLM_BASE_URLS = ("https://api.n1n.ai/v1",)
DEFAULT_LLM_BASE_URLS = (DEFAULT_LLM_BASE_URL, *FALLBACK_LLM_BASE_URLS)
DEFAULT_LLM_MODEL = "gpt-5"
SUPPORTED_LLM_MODELS = (DEFAULT_LLM_MODEL,)
DOH_RESOLVER_IPS = ("8.8.8.8", "1.1.1.1")
LOCAL_LLM_ENV_FILE = ".lapis-llm.env"


@dataclass(frozen=True)
class LLMConfig:
    api_key: str
    base_url: str
    model: str
    timeout_seconds: int = 120
    temperature: float = 0.0
    max_tokens: int = 4096


def _parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values


def _find_local_llm_env_file() -> Path | None:
    configured = os.environ.get("LAPIS_LLM_ENV_FILE")
    if configured:
        path = Path(configured).expanduser()
        return path if path.exists() else None
    for base in [Path.cwd(), *Path.cwd().parents]:
        path = base / LOCAL_LLM_ENV_FILE
        if path.exists():
            return path
    home_path = Path.home() / LOCAL_LLM_ENV_FILE
    return home_path if home_path.exists() else None


def _local_llm_env() -> dict[str, str]:
    path = _find_local_llm_env_file()
    return _parse_env_file(path) if path else {}


def config_from_env(
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    model: str | None = None,
    timeout_seconds: int = 120,
    temperature: float = 0.0,
    max_tokens: int = 4096,
) -> LLMConfig:
    local_env = _local_llm_env()
    key = (
        api_key
        or os.environ.get("LAPIS_LLM_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
        or local_env.get("LAPIS_LLM_API_KEY")
        or local_env.get("OPENAI_API_KEY")
    )
    if not key:
        raise ValueError("set LAPIS_LLM_API_KEY or OPENAI_API_KEY, or create .lapis-llm.env")
    selected_model = model or os.environ.get("LAPIS_LLM_MODEL") or local_env.get("LAPIS_LLM_MODEL") or DEFAULT_LLM_MODEL
    return LLMConfig(
        api_key=key,
        base_url=(base_url or os.environ.get("LAPIS_LLM_BASE_URL") or local_env.get("LAPIS_LLM_BASE_URL") or DEFAULT_LLM_BASE_URL).rstrip("/"),
        model=selected_model,
        timeout_seconds=timeout_seconds,
        temperature=temperature,
        max_tokens=max_tokens,
    )


def read_api_key_from_stdin() -> str:
    key = getpass("API key: ").strip() if sys.stdin.isatty() else sys.stdin.readline().strip()
    if not key:
        raise ValueError("empty API key from stdin")
    return key


class _SNIHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, connect_host: str, tls_host: str, *args: Any, **kwargs: Any) -> None:
        self._tls_host = tls_host
        super().__init__(connect_host, *args, **kwargs)

    def connect(self) -> None:
        sock = socket.create_connection((self.host, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._tls_host)


def _https_request_via_ip(
    *,
    connect_host: str,
    tls_host: str,
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes | None,
    timeout_seconds: int,
) -> tuple[int, str]:
    connection = _SNIHTTPSConnection(
        connect_host,
        tls_host,
        port=443,
        timeout=timeout_seconds,
        context=ssl.create_default_context(),
    )
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.read().decode("utf-8", errors="replace")
    finally:
        connection.close()


def resolve_host_with_doh(host: str, timeout_seconds: int = 10) -> list[str]:
    query_path = f"/resolve?name={host}&type=A"
    headers = {
        "Host": "dns.google",
        "Accept": "application/dns-json",
        "Connection": "close",
    }
    last_error = None
    for resolver_ip in DOH_RESOLVER_IPS:
        try:
            status, body = _https_request_via_ip(
                connect_host=resolver_ip,
                tls_host="dns.google",
                method="GET",
                path=query_path,
                headers=headers,
                body=None,
                timeout_seconds=timeout_seconds,
            )
            if status != 200:
                last_error = f"DoH HTTP {status}: {body[:200]}"
                continue
            data = json.loads(body)
            addresses = [
                answer.get("data")
                for answer in data.get("Answer", [])
                if answer.get("type") == 1 and isinstance(answer.get("data"), str)
            ]
            if addresses:
                return addresses
            last_error = f"DoH returned no A records for {host}: {body[:200]}"
        except Exception as exc:
            last_error = str(exc)
    raise RuntimeError(f"DoH resolution failed for {host}: {last_error}")


def resolve_host_for_llm(host: str, port: int = 443, timeout_seconds: int = 10) -> dict[str, Any]:
    try:
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        resolved = []
        for item in addresses:
            address = item[4][0]
            if address not in resolved:
                resolved.append(address)
        return {"status": "passed", "method": "system_dns", "host": host, "port": port, "addresses": resolved[:5]}
    except Exception as exc:
        system_error = str(exc)
    addresses = resolve_host_with_doh(host, timeout_seconds)
    return {
        "status": "passed",
        "method": "doh",
        "host": host,
        "port": port,
        "addresses": addresses[:5],
        "system_dns_error": system_error,
    }


def _post_json_via_resolved_ip(url: str, payload: dict[str, Any], config: LLMConfig) -> dict[str, Any]:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise RuntimeError(f"DoH retry only supports HTTPS URLs with a host: {url}")
    resolution = resolve_host_for_llm(parsed.hostname, parsed.port or 443, min(config.timeout_seconds, 20))
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    headers = {
        "Authorization": f"Bearer {config.api_key}",
        "Content-Type": "application/json",
        "Host": parsed.hostname,
        "Connection": "close",
    }
    body_bytes = json.dumps(payload).encode("utf-8")
    last_error = None
    for address in resolution["addresses"]:
        try:
            status, body = _https_request_via_ip(
                connect_host=address,
                tls_host=parsed.hostname,
                method="POST",
                path=path,
                headers=headers,
                body=body_bytes,
                timeout_seconds=config.timeout_seconds,
            )
            if status >= 400:
                raise RuntimeError(f"LLM API HTTP {status}: {body[:1000]}")
            return json.loads(body)
        except Exception as exc:
            last_error = exc
    raise RuntimeError(f"all resolved API addresses failed: {last_error}")


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
        reason = getattr(exc, "reason", None)
        if isinstance(reason, socket.gaierror):
            try:
                return _post_json_via_resolved_ip(url, payload, config)
            except Exception as retry_exc:
                raise RuntimeError(f"LLM API request failed after DoH retry: {retry_exc}") from retry_exc
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
