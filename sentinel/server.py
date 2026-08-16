from __future__ import annotations

import json
import mimetypes
import signal
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .auth import AuthenticationError, SessionService, TokenService
from .config import settings
from .database import Database
from .limits import RateLimitError, SlidingWindowLimiter
from .jobs import Worker
from .observability import Metrics, log_event, request_id, route_name
from .security import CredentialVault
from .seed import DEMO_ORG_ID, DEMO_USER_ID, seed_demo, seed_suites_for_org, sync_builtin_suites
from .service import AuthorizationError, ConflictError, LocusService, NotFoundError


STATIC = settings.static_dir
settings.validate()
DB = Database(settings.database_dsn)
sync_builtin_suites(DB, settings.default_timeout_ms)
VAULT = CredentialVault(settings.encryption_key)
SERVICE = LocusService(DB, settings, VAULT)
EMBEDDED_WORKER = Worker(SERVICE.queue, SERVICE._execute_run, settings, "embedded")
TOKENS = TokenService(DB)
SESSIONS = SessionService(DB)
LIMITER = SlidingWindowLimiter()
METRICS = Metrics()
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

    def end_headers(self) -> None:
        self.send_header("X-Request-ID", getattr(self, "request_id", "unknown"))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
        if settings.environment == "production": self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        super().end_headers()

    def _json(self, payload: object, status: int = 200, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.response_status = status
        self.send_response(status); self.send_header("Content-Type", "application/json; charset=utf-8"); self.send_header("Content-Length", str(len(body))); self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items(): self.send_header(name, value)
        self.end_headers(); self.wfile.write(body)

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
        user = TOKENS.authenticate(authorization) if authorization else SESSIONS.authenticate(self._session_token())
        return user["id"], user["organization_id"]

    def _session_token(self) -> str | None:
        cookie = SimpleCookie(); cookie.load(self.headers.get("Cookie", "")); value = cookie.get("locus_session")
        return value.value if value else None

    def _session_cookie(self, token: str) -> str:
        secure = "; Secure" if settings.environment == "production" else ""
        return f"locus_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=1209600{secure}"

    def _handle(self, method: str) -> None:
        parsed = urlparse(self.path); path = parsed.path.rstrip("/") or "/"; parts = path.strip("/").split("/")
        if path == "/health/live" and method == "GET": return self._json({"status":"ok","service":"locus"})
        if path == "/health/ready" and method == "GET":
            ready = DB.ping(); return self._json({"status":"ready" if ready else "unavailable","database":ready}, 200 if ready else 503)
        if path == "/metrics" and method == "GET":
            if settings.metrics_token and self.headers.get("Authorization") != f"Bearer {settings.metrics_token}": raise AuthenticationError("Metrics authentication is required")
            counts = {row["status"]: row["count"] for row in DB.all("SELECT status,COUNT(*) AS count FROM jobs GROUP BY status")}
            body = METRICS.render(counts); self.response_status = 200; self.send_response(200); self.send_header("Content-Type","text/plain; version=0.0.4"); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body); return
        if not path.startswith("/api/") and method == "GET": return self._static(path)
        LIMITER.check(f"ip:{self.client_address[0]}", settings.api_requests_per_minute)
        if path == "/api/dev/mock-agent" and method == "POST" and settings.demo_seed:
            data = self._body(); message = str(data.get("message", "")); status, payload, delay = mock_agent(message); time.sleep(delay)
            if isinstance(payload, bytes):
                self.send_response(status); self.send_header("Content-Type", "text/plain"); self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload)
            else: self._json(payload, status)
            return
        if path == "/api/auth/signup" and method == "POST":
            LIMITER.check(f"auth:{self.client_address[0]}",settings.auth_attempts_per_minute)
            data = self._body(); user, token = SESSIONS.signup(str(data.get("name","")),str(data.get("email","")),str(data.get("password","")),str(data.get("organizationName",""))); seed_suites_for_org(DB,user["organizationId"],settings.default_timeout_ms)
            return self._json({"user":user,"onboarding":True},201,{"Set-Cookie":self._session_cookie(token)})
        if path == "/api/auth/login" and method == "POST":
            LIMITER.check(f"auth:{self.client_address[0]}",settings.auth_attempts_per_minute)
            data = self._body(); user, token = SESSIONS.login(str(data.get("email","")),str(data.get("password","")))
            return self._json({"user":user},headers={"Set-Cookie":self._session_cookie(token)})
        if path == "/api/auth/logout" and method == "POST":
            SESSIONS.revoke(self._session_token()); return self._json({"signedOut":True},headers={"Set-Cookie":"locus_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"})
        if path == "/api/auth/me" and method == "GET":
            if settings.demo_seed and not self.headers.get("Authorization") and not self._session_token():
                user = DB.one("SELECT u.*,o.name AS organization_name FROM users u JOIN organizations o ON o.id=u.organization_id WHERE u.id=?",(DEMO_USER_ID,)); return self._json({"user":SESSIONS.public_user(user or {})})
            user = TOKENS.authenticate(self.headers.get("Authorization")) if self.headers.get("Authorization") else SESSIONS.authenticate(self._session_token()); return self._json({"user":user})
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
        self._safe("GET")
    def do_POST(self) -> None: self._safe("POST")
    def do_PATCH(self) -> None: self._safe("PATCH")
    def do_PUT(self) -> None: self._safe("PUT")
    def do_DELETE(self) -> None: self._safe("DELETE")

    def _safe(self, method: str) -> None:
        self.request_id = request_id(self.headers.get("X-Request-ID")); self.response_status = 500; started = time.monotonic()
        try: self._handle(method)
        except AuthenticationError as exc: self._json({"error": str(exc)}, 401)
        except AuthorizationError as exc: self._json({"error": str(exc)}, 403)
        except ConflictError as exc: self._json({"error": str(exc)}, 409)
        except RateLimitError as exc: self._json({"error": str(exc)}, 429)
        except NotFoundError as exc: self._json({"error": str(exc)}, 404)
        except (ValueError, KeyError, json.JSONDecodeError) as exc: self._json({"error": str(exc)}, 400)
        except Exception as exc: self._json({"error": "Internal server error", "detail": str(exc) if settings.demo_seed else None}, 500)
        finally:
            duration = time.monotonic()-started; route = route_name(self.path); METRICS.observe_request(method,route,self.response_status,duration)
            log_event("http_request",request_id=self.request_id,method=method,path=urlparse(self.path).path,route=route,status=self.response_status,duration_ms=round(duration*1000,2),client=self.client_address[0])

    def _static(self, path: str) -> None:
        relative = "index.html" if path == "/" else path.lstrip("/"); target = (STATIC / relative).resolve()
        if STATIC.resolve() not in target.parents or not target.is_file(): self.response_status = 404; self.send_error(404); return
        body = target.read_bytes(); self.response_status = 200; self.send_response(200); self.send_header("Content-Type", mimetypes.guess_type(target.name)[0] or "application/octet-stream"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        return


def main() -> None:
    server = ThreadingHTTPServer((settings.host, settings.port), Handler)
    def terminate(*_: object) -> None: raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,terminate)
    worker_thread = EMBEDDED_WORKER.start_thread() if settings.embedded_worker else None
    print(f"Locus running at http://localhost:{settings.port}")
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally:
        server.server_close(); EMBEDDED_WORKER.stop()
        if worker_thread: worker_thread.join(timeout=2)


if __name__ == "__main__": main()
