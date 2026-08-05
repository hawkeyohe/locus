from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from .config import Settings
from .security import CredentialVault, SecurityError, extract_path, redact, safe_headers, substitute_template, validate_endpoint


@dataclass
class AgentResponse:
    output: str | None
    raw_response: Any
    http_status: int | None
    latency_ms: int
    error_type: str | None = None
    error_message: str | None = None
    attempts: int = 1


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class AgentClient:
    def __init__(self, settings: Settings, vault: CredentialVault) -> None:
        self.settings = settings
        self.vault = vault
        self.opener = urllib.request.build_opener(NoRedirect)

    def _headers(self, agent: dict[str, Any]) -> dict[str, str]:
        custom_headers = self.vault.decrypt(agent.get("encrypted_request_headers")) if agent.get("encrypted_request_headers") else agent.get("request_headers", {})
        headers = {"Content-Type": "application/json", "Accept": "application/json", **custom_headers}
        auth_type = agent["authentication_type"]
        credentials = self.vault.decrypt(agent.get("encrypted_credentials"))
        if auth_type == "bearer": headers["Authorization"] = f"Bearer {credentials.get('token', '')}"
        elif auth_type == "api_key": headers[credentials.get("headerName", "X-API-Key")] = credentials.get("value", "")
        elif auth_type == "basic":
            encoded = base64.b64encode(f"{credentials.get('username','')}:{credentials.get('password','')}".encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"
        return safe_headers(headers)

    def send(self, agent: dict[str, Any], test_input: str, ids: dict[str, str]) -> AgentResponse:
        endpoint, before_ips = validate_endpoint(agent["endpoint_url"], self.settings.allow_local_endpoints)
        variables = {"test_input": test_input, **ids}
        payload = substitute_template(agent["request_template"], variables)
        body = json.dumps(payload).encode()
        if len(body) > self.settings.max_request_bytes:
            raise SecurityError("Rendered request exceeds the request-size limit")
        attempts, started = 0, time.monotonic()
        while attempts < 3:
            attempts += 1
            try:
                _, current_ips = validate_endpoint(endpoint, self.settings.allow_local_endpoints)
                if set(current_ips) != set(before_ips):
                    raise SecurityError("Endpoint DNS resolution changed during request")
                request = urllib.request.Request(endpoint, body, self._headers(agent), method="POST")
                with self.opener.open(request, timeout=agent["timeout_ms"] / 1000) as response:
                    raw_bytes = response.read(self.settings.max_response_bytes + 1)
                    if len(raw_bytes) > self.settings.max_response_bytes:
                        raise ValueError("Response exceeds configured size limit")
                    raw = json.loads(raw_bytes)
                    output = extract_path(raw, agent["response_path"])
                    if not isinstance(output, str):
                        raise TypeError("Configured response path must contain text")
                    return AgentResponse(output, redact(raw), response.status, round((time.monotonic()-started)*1000), attempts=attempts)
            except urllib.error.HTTPError as exc:
                if exc.code in {429, 502, 503, 504} and attempts < 3:
                    time.sleep(0.1 * (2 ** (attempts - 1))); continue
                return AgentResponse(None, None, exc.code, round((time.monotonic()-started)*1000), "http_error", f"Agent returned HTTP {exc.code}", attempts)
            except (TimeoutError, urllib.error.URLError) as exc:
                if attempts < 3:
                    time.sleep(0.1 * (2 ** (attempts - 1))); continue
                return AgentResponse(None, None, None, round((time.monotonic()-started)*1000), "network_error", str(exc.reason if hasattr(exc, 'reason') else exc), attempts)
            except (json.JSONDecodeError, KeyError, TypeError, ValueError, SecurityError) as exc:
                return AgentResponse(None, None, None, round((time.monotonic()-started)*1000), type(exc).__name__.lower(), str(exc), attempts)
        raise RuntimeError("Unreachable")
