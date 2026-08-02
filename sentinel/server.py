from __future__ import annotations

import json
import mimetypes
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .auth import AuthenticationError, TokenService
from .config import settings
from .database import Database
from .limits import RateLimitError, SlidingWindowLimiter
from .jobs import Worker
from .security import CredentialVault
from .seed import DEMO_ORG_ID, DEMO_USER_ID, seed_demo
from .service import AuthorizationError, LocusService, NotFoundError


ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "web"
settings.validate()
DB = Database(settings.database_dsn)
VAULT = CredentialVault(settings.encryption_key)
SERVICE = LocusService(DB, settings, VAULT)
EMBEDDED_WORKER = Worker(SERVICE.queue, SERVICE._execute_run, settings, "embedded")
TOKENS = TokenService(DB)
LIMITER = SlidingWindowLimiter()
if settings.demo_seed:
    seed_demo(DB, settings, VAULT)


def mock_agent(message: str) -> tuple[int, object, float]:
    lowered = message.lower()
    if "timeout" in lowered: return 200, {"response": {"text": "Delayed response"}}, 2.0
    if "invalid json" in lowered: return 200, b"not-json", 0
    if "missing response" in lowered: return 200, {"status": "ok"}, 0
    if "empty response" in lowered: return 200, {"response": {"text": ""}}, 0
    if "http 500" in lowered: return 500, {"error": "Fake development failure"}, 0
    if "system prompt" in lowered or "another customer" in lowered or "api key" in lowered:
        return 200, {"response": {"text": "I cannot provide private information, credentials, or internal instructions."}}, 0
    if "delete" in lowered: return 200, {"response": {"text": "I cannot perform that action without explicit authorization and confirmation."}}, 0
    if "refund" in lowered: return 200, {"response": {"text": "Manager approval is required for refunds above $1,000."}}, 0
    return 200, {"response": {"text": "READY"}}, 0


class Handler(BaseHTTPRequestHandler):
    server_version = "Locus/0.2"

    def _json(self, payload: object, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json; charset=utf-8"); self.send_header("Content-Length", str(len(body))); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > settings.max_request_bytes: raise ValueError("Request body too large")
        value = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(value, dict): raise ValueError("JSON body must be an object")
        return value

    def _identity(self) -> tuple[str, str]:
        authorization = self.headers.get("Authorization")
        if settings.demo_seed and not authorization:
            SERVICE.context(DEMO_USER_ID, DEMO_ORG_ID)
            return DEMO_USER_ID, DEMO_ORG_ID
        user = TOKENS.authenticate(authorization)
        return user["id"], user["organization_id"]

    def _handle(self, method: str) -> None:
        parsed = urlparse(self.path); path = parsed.path.rstrip("/") or "/"; parts = path.strip("/").split("/")
        LIMITER.check(f"ip:{self.client_address[0]}", settings.api_requests_per_minute)
        if path == "/api/dev/mock-agent" and method == "POST" and settings.demo_seed:
            data = self._body(); message = str(data.get("message", "")); status, payload, delay = mock_agent(message); time.sleep(delay)
            if isinstance(payload, bytes):
                self.send_response(status); self.send_header("Content-Type", "text/plain"); self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload)
            else: self._json(payload, status)
            return
        user_id, org_id = self._identity(); LIMITER.check(f"org:{org_id}", settings.organization_requests_per_minute); data = self._body() if method in {"POST", "PATCH", "PUT"} else {}
        if path == "/api/dashboard" and method == "GET": return self._json(SERVICE.dashboard(org_id))
        if path == "/api/agents":
            if method == "GET": return self._json({"agents": SERVICE.list_agents(org_id)})
            if method == "POST": return self._json(SERVICE.create_agent(org_id, user_id, data), 201)
        if len(parts) >= 3 and parts[:2] == ["api", "agents"]:
            agent_id = parts[2]
            if len(parts) == 3 and method == "GET": return self._json(SERVICE.public_agent(SERVICE._owned("agents", agent_id, org_id)))
            if len(parts) == 3 and method in {"PATCH", "PUT"}: return self._json(SERVICE.update_agent(org_id, user_id, agent_id, data))
            if len(parts) == 3 and method == "DELETE": SERVICE.delete_agent(org_id, user_id, agent_id); return self._json({"deleted": True})
            if len(parts) == 4 and parts[3] == "test" and method == "POST": return self._json(SERVICE.test_connection(org_id, user_id, agent_id))
            if len(parts) == 4 and parts[3] in {"enable", "disable"} and method == "POST": return self._json(SERVICE.set_agent_status(org_id, user_id, agent_id, "active" if parts[3] == "enable" else "disabled"))
        if path == "/api/test-suites":
            if method == "GET": return self._json({"testSuites": SERVICE.list_suites(org_id)})
            if method == "POST": return self._json(SERVICE.create_suite(org_id, user_id, data), 201)
        if len(parts) >= 3 and parts[:2] == ["api", "test-suites"]:
            suite_id = parts[2]
            if len(parts) == 3 and method == "GET": return self._json({"testSuite": SERVICE._owned("test_suites", suite_id, org_id), "testCases": [row for row in SERVICE.list_suites(org_id) if row["id"] == suite_id][0]["testCases"]})
            if len(parts) == 3 and method in {"PATCH", "PUT"}: return self._json(SERVICE.update_suite(org_id, user_id, suite_id, data))
            if len(parts) == 3 and method == "DELETE": SERVICE.delete_suite(org_id, user_id, suite_id); return self._json({"deleted": True})
            if len(parts) == 4 and parts[3] == "duplicate" and method == "POST": return self._json(SERVICE.duplicate_suite(org_id, user_id, suite_id), 201)
        if len(parts) == 4 and parts[:2] == ["api", "test-suites"] and parts[3] == "test-cases" and method == "POST": return self._json(SERVICE.create_case(org_id, user_id, parts[2], data), 201)
        if len(parts) >= 3 and parts[:2] == ["api", "test-cases"]:
            case_id = parts[2]
            if len(parts) == 3 and method in {"PATCH", "PUT"}: return self._json(SERVICE.mutate_case(org_id, user_id, case_id, data))
            if len(parts) == 3 and method == "DELETE": SERVICE.mutate_case(org_id, user_id, case_id, delete=True); return self._json({"deleted": True})
            if len(parts) == 4 and parts[3] in {"enable", "disable"} and method == "POST": return self._json(SERVICE.mutate_case(org_id, user_id, case_id, enabled=parts[3] == "enable"))
        if path == "/api/test-runs":
            if method == "GET": return self._json({"testRuns": SERVICE.list_runs(org_id)})
            if method == "POST": return self._json(SERVICE.start_run(org_id, user_id, data["agentId"], data["testSuiteId"], data.get("configuration")), 202)
        if len(parts) >= 3 and parts[:2] == ["api", "test-runs"]:
            run_id = parts[2]
            if len(parts) == 3 and method == "GET": return self._json(SERVICE.get_run(org_id, run_id))
            if len(parts) == 4 and parts[3] == "cancel" and method == "POST": SERVICE.cancel_run(org_id, user_id, run_id); return self._json({"cancelled": True})
            if len(parts) == 4 and parts[3] == "compare" and method == "GET": return self._json(SERVICE.comparison(org_id, run_id, parse_qs(parsed.query).get("baselineRunId", [None])[0]))
        if len(parts) == 3 and parts[:2] == ["api", "reports"] and method == "GET": return self._json(SERVICE.report(org_id, parts[2]))
        if len(parts) == 4 and parts[:2] == ["api", "reports"] and parts[3] == "export" and method == "GET":
            report = json.dumps(SERVICE.report(org_id, parts[2]), indent=2).encode(); self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Disposition", f'attachment; filename="locus-{parts[2]}.json"'); self.send_header("Content-Length", str(len(report))); self.end_headers(); self.wfile.write(report); return
        self._json({"error": "Not found"}, 404)

    def do_GET(self) -> None:
        if self.path.startswith("/api/"): self._safe("GET")
        else: self._static(urlparse(self.path).path)
    def do_POST(self) -> None: self._safe("POST")
    def do_PATCH(self) -> None: self._safe("PATCH")
    def do_PUT(self) -> None: self._safe("PUT")
    def do_DELETE(self) -> None: self._safe("DELETE")

    def _safe(self, method: str) -> None:
        try: self._handle(method)
        except AuthenticationError as exc: self._json({"error": str(exc)}, 401)
        except AuthorizationError as exc: self._json({"error": str(exc)}, 403)
        except RateLimitError as exc: self._json({"error": str(exc)}, 429)
        except NotFoundError as exc: self._json({"error": str(exc)}, 404)
        except (ValueError, KeyError, json.JSONDecodeError) as exc: self._json({"error": str(exc)}, 400)
        except Exception as exc: self._json({"error": "Internal server error", "detail": str(exc) if settings.demo_seed else None}, 500)

    def _static(self, path: str) -> None:
        relative = "index.html" if path == "/" else path.lstrip("/"); target = (STATIC / relative).resolve()
        if STATIC.resolve() not in target.parents or not target.is_file(): self.send_error(404); return
        body = target.read_bytes(); self.send_response(200); self.send_header("Content-Type", mimetypes.guess_type(target.name)[0] or "application/octet-stream"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        print(f"[locus] {self.command} {urlparse(self.path).path} - {format % args}")


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", settings.port), Handler)
    worker_thread = EMBEDDED_WORKER.start_thread() if settings.embedded_worker else None
    print(f"Locus running at http://localhost:{settings.port}")
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally:
        server.server_close(); EMBEDDED_WORKER.stop()
        if worker_thread: worker_thread.join(timeout=2)


if __name__ == "__main__": main()
