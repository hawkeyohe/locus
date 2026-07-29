from __future__ import annotations

import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .models import FAILURE_TYPES
from .simulator import IncidentLab


ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "web"
LAB = IncidentLab()


class Handler(BaseHTTPRequestHandler):
    def _json(self, payload, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/traces":
            self._json(
                {
                    "traces": [trace.to_dict() for trace in LAB.traces],
                    "summary": LAB.summary(),
                    "scenarios": list(FAILURE_TYPES),
                }
            )
            return
        if path.startswith("/api/traces/"):
            trace_id = path.rsplit("/", 1)[-1]
            trace = next((item for item in LAB.traces if item.id == trace_id), None)
            self._json(trace.to_dict() if trace else {"error": "Not found"}, 200 if trace else 404)
            return
        self._static(path)

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/api/runs":
            self._json({"error": "Not found"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length) or b"{}")
            trace = LAB.run(data.get("scenario", "healthy"), data.get("seed"))
            self._json(trace.to_dict(), 201)
        except (ValueError, json.JSONDecodeError) as error:
            self._json({"error": str(error)}, 400)

    def _static(self, path: str) -> None:
        relative = "index.html" if path == "/" else path.lstrip("/")
        target = (STATIC / relative).resolve()
        if STATIC.resolve() not in target.parents or not target.is_file():
            self.send_error(404)
            return
        body = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(target.name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        print(f"[locus] {format % args}")


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 8000), Handler)
    print("Locus running at http://localhost:8000")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == "__main__":
    main()
