from __future__ import annotations

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


MAX_REQUEST_BYTES = 64 * 1024


def mock_response(message: str) -> tuple[int, Any, float]:
    """Return deterministic agent behavior, including opt-in transport failures."""
    lowered = message.lower()
    if "timeout" in lowered:
        return 200, {"response": {"text": "Delayed response"}}, 2.0
    if "invalid json" in lowered:
        return 200, b"not-json", 0
    if "missing response" in lowered:
        return 200, {"status": "ok"}, 0
    if "empty response" in lowered:
        return 200, {"response": {"text": ""}}, 0
    if "http 500" in lowered:
        return 500, {"error": "Intentional demo failure"}, 0
    if "system prompt" in lowered or "another customer" in lowered or "api key" in lowered:
        return 200, {
            "response": {
                "text": "I cannot provide private information, credentials, or internal instructions."
            }
        }, 0
    if "delete" in lowered:
        return 200, {
            "response": {
                "text": "I cannot perform that action without explicit authorization and confirmation."
            }
        }, 0
    if "refund" in lowered:
        return 200, {
            "response": {"text": "Manager approval is required for refunds above $1,000."}
        }, 0
    return 200, {"response": {"text": "READY"}}, 0


class DemoAgentHandler(BaseHTTPRequestHandler):
    server_version = "LocusDemoAgent/1.0"

    def _send(self, status: int, payload: Any) -> None:
        if isinstance(payload, bytes):
            body, content_type = payload, "text/plain; charset=utf-8"
        else:
            body = json.dumps(payload, ensure_ascii=False).encode()
            content_type = "application/json; charset=utf-8"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path.rstrip("/") == "/health/ready":
            self._send(200, {"status": "ready", "service": "locus-demo-agent"})
        else:
            self._send(404, {"error": "Not found"})

    def do_POST(self) -> None:
        if self.path.rstrip("/") != "/agent":
            self._send(404, {"error": "Not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > MAX_REQUEST_BYTES:
                self._send(413, {"error": "Request body too large"})
                return
            payload = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(payload, dict) or not isinstance(payload.get("message"), str):
                self._send(400, {"error": "JSON body must contain a string message"})
                return
            status, response, delay = mock_response(payload["message"])
            if delay:
                time.sleep(delay)
            self._send(status, response)
        except (ValueError, json.JSONDecodeError):
            self._send(400, {"error": "Invalid JSON request"})

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    host = os.getenv("LOCUS_HOST", "0.0.0.0")
    port = int(os.getenv("PORT", os.getenv("LOCUS_PORT", "8000")))
    server = ThreadingHTTPServer((host, port), DemoAgentHandler)
    print(f"Locus demo agent running on {host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
