from __future__ import annotations

import json
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from .config import Settings
from .connectivity import AgentClient
from .database import Database, decode_row, encode_json, new_id, now
from .evaluators import EvaluationContext, evaluate, validate_evaluator_config
from .jobs import DurableJobQueue
from .scoring import calculate_scores, compare_results
from .security import CredentialVault, mask_credentials, redact, validate_endpoint


DEFAULT_TEMPLATE = {"message": "{{test_input}}", "sessionId": "{{session_id}}", "metadata": {"testRunId": "{{test_run_id}}", "testCaseId": "{{test_case_id}}"}}


class AuthorizationError(PermissionError): pass
class NotFoundError(LookupError): pass


class LocusService:
    def __init__(self, db: Database, settings: Settings, vault: CredentialVault) -> None:
        self.db, self.settings, self.vault = db, settings, vault
        self.client = AgentClient(settings, vault)
        self.queue = DurableJobQueue(db, settings)
        self.cancelled: set[str] = set()
        self._lock = threading.Lock()

    def context(self, user_id: str, organization_id: str) -> dict[str, Any]:
        user = self.db.one("SELECT * FROM users WHERE id=? AND organization_id=?", (user_id, organization_id))
        if not user: raise AuthorizationError("Authenticated user does not belong to this organization")
        return user

    def _owned(self, table: str, entity_id: str, org_id: str) -> dict[str, Any]:
        row = self.db.one(f"SELECT * FROM {table} WHERE id=? AND organization_id=?", (entity_id, org_id))
        if not row: raise NotFoundError("Resource not found")
        return decode_row(row) or {}

    def audit(self, org_id: str, user_id: str, action: str, entity_type: str, entity_id: str, metadata: dict[str, Any] | None = None) -> None:
        self.db.insert("audit_logs", {"id": new_id("audit"), "organization_id": org_id, "user_id": user_id, "action": action, "entity_type": entity_type, "entity_id": entity_id, "metadata": encode_json(redact(metadata or {})), "created_at": now()})

    def public_agent(self, row: dict[str, Any]) -> dict[str, Any]:
        agent = decode_row(row) or {}
        encrypted = bool(agent.pop("encrypted_credentials", None))
        agent["request_headers"] = redact(agent.get("request_headers", {}))
        agent["credentials"] = mask_credentials(agent["authentication_type"], encrypted)
        return agent

    def list_agents(self, org_id: str) -> list[dict[str, Any]]:
        return [self.public_agent(row) for row in self.db.all("SELECT * FROM agents WHERE organization_id=? ORDER BY created_at DESC", (org_id,))]

    def create_agent(self, org_id: str, user_id: str, data: dict[str, Any]) -> dict[str, Any]:
        endpoint = str(data.get("endpointUrl", "")); validate_endpoint(endpoint, self.settings.allow_local_endpoints)
        auth = data.get("authenticationType", "none")
        if auth not in {"none", "bearer", "api_key", "basic"}: raise ValueError("Unsupported authentication type")
        template = data.get("requestTemplate", DEFAULT_TEMPLATE)
        if isinstance(template, str): template = json.loads(template)
        headers = data.get("requestHeaders", {})
        timestamp, agent_id = now(), new_id("agent")
        self.db.insert("agents", {"id": agent_id, "organization_id": org_id, "name": str(data.get("name", "")).strip(), "description": str(data.get("description", "")), "endpoint_url": endpoint, "http_method": "POST", "authentication_type": auth, "encrypted_credentials": self.vault.encrypt(data.get("credentials", {})) if auth != "none" else None, "request_template": encode_json(template), "response_path": str(data.get("responsePath", "response.text")), "request_headers": encode_json(headers), "timeout_ms": int(data.get("timeoutMs", self.settings.default_timeout_ms)), "status": "draft", "last_connection_test_at": None, "last_connection_test_status": None, "created_at": timestamp, "updated_at": timestamp})
        self.audit(org_id, user_id, "agent.created", "agent", agent_id, {"endpointUrl": endpoint})
        return self.public_agent(self.db.one("SELECT * FROM agents WHERE id=?", (agent_id,)) or {})

    def update_agent(self, org_id: str, user_id: str, agent_id: str, data: dict[str, Any]) -> dict[str, Any]:
        current = self._owned("agents", agent_id, org_id)
        endpoint = str(data.get("endpointUrl", current["endpoint_url"])); validate_endpoint(endpoint, self.settings.allow_local_endpoints)
        fields = {"name": data.get("name", current["name"]), "description": data.get("description", current["description"]), "endpoint_url": endpoint, "authentication_type": data.get("authenticationType", current["authentication_type"]), "request_template": encode_json(data.get("requestTemplate", current["request_template"])), "response_path": data.get("responsePath", current["response_path"]), "request_headers": encode_json(data.get("requestHeaders", current["request_headers"])), "timeout_ms": int(data.get("timeoutMs", current["timeout_ms"])), "updated_at": now()}
        if "credentials" in data: fields["encrypted_credentials"] = self.vault.encrypt(data["credentials"])
        self.db.execute(f"UPDATE agents SET {','.join(f'{key}=?' for key in fields)} WHERE id=? AND organization_id=?", (*fields.values(), agent_id, org_id))
        self.audit(org_id, user_id, "agent.updated", "agent", agent_id, {"endpointChanged": endpoint != current["endpoint_url"], "credentialsChanged": "credentials" in data})
        return self.public_agent(self.db.one("SELECT * FROM agents WHERE id=?", (agent_id,)) or {})

    def delete_agent(self, org_id: str, user_id: str, agent_id: str) -> None:
        self._owned("agents", agent_id, org_id); self.db.execute("DELETE FROM agents WHERE id=? AND organization_id=?", (agent_id, org_id)); self.audit(org_id, user_id, "agent.deleted", "agent", agent_id)

    def set_agent_status(self, org_id: str, user_id: str, agent_id: str, status: str) -> dict[str, Any]:
        self._owned("agents", agent_id, org_id)
        if status not in {"active", "disabled"}: raise ValueError("Invalid agent status")
        self.db.execute("UPDATE agents SET status=?,updated_at=? WHERE id=?", (status, now(), agent_id)); self.audit(org_id, user_id, f"agent.{status}", "agent", agent_id)
        return self.public_agent(self.db.one("SELECT * FROM agents WHERE id=?", (agent_id,)) or {})

    def test_connection(self, org_id: str, user_id: str, agent_id: str) -> dict[str, Any]:
        agent = self._owned("agents", agent_id, org_id); result = self.client.send(agent, "Respond with the word READY.", {"session_id": new_id("session"), "test_run_id": "connection-test", "test_case_id": "connection-test", "agent_id": agent_id})
        success = result.error_type is None
        self.db.execute("UPDATE agents SET status=?,last_connection_test_at=?,last_connection_test_status=?,updated_at=? WHERE id=?", ("active" if success else "connection_failed", now(), "passed" if success else "failed", now(), agent_id))
        self.audit(org_id, user_id, "agent.connection_tested", "agent", agent_id, {"success": success, "httpStatus": result.http_status, "latencyMs": result.latency_ms})
        return {"success": success, "httpStatus": result.http_status, "latencyMs": result.latency_ms, "parsedResponse": result.output, "error": result.error_message}

    def list_suites(self, org_id: str) -> list[dict[str, Any]]:
        suites = [decode_row(row) or {} for row in self.db.all("SELECT * FROM test_suites WHERE organization_id=? ORDER BY is_default DESC,name", (org_id,))]
        for suite in suites: suite["testCases"] = [decode_row(row) for row in self.db.all("SELECT * FROM test_cases WHERE test_suite_id=? ORDER BY created_at", (suite["id"],))]
        return suites

    def create_suite(self, org_id: str, user_id: str, data: dict[str, Any]) -> dict[str, Any]:
        suite_id, timestamp = new_id("suite"), now(); self.db.insert("test_suites", {"id": suite_id, "organization_id": org_id, "name": data["name"], "description": data.get("description", ""), "is_default": 0, "created_at": timestamp, "updated_at": timestamp}); self.audit(org_id, user_id, "suite.created", "test_suite", suite_id); return self._owned("test_suites", suite_id, org_id)

    def update_suite(self, org_id: str, user_id: str, suite_id: str, data: dict[str, Any]) -> dict[str, Any]:
        suite = self._owned("test_suites", suite_id, org_id); self.db.execute("UPDATE test_suites SET name=?,description=?,updated_at=? WHERE id=?", (data.get("name", suite["name"]), data.get("description", suite["description"]), now(), suite_id)); self.audit(org_id, user_id, "suite.updated", "test_suite", suite_id); return self._owned("test_suites", suite_id, org_id)

    def delete_suite(self, org_id: str, user_id: str, suite_id: str) -> None:
        self._owned("test_suites", suite_id, org_id); self.audit(org_id, user_id, "suite.deleted", "test_suite", suite_id); self.db.execute("DELETE FROM test_suites WHERE id=?", (suite_id,))

    def duplicate_suite(self, org_id: str, user_id: str, suite_id: str) -> dict[str, Any]:
        source = self._owned("test_suites", suite_id, org_id); duplicate = self.create_suite(org_id, user_id, {"name": f"{source['name']} copy", "description": source["description"]})
        for case in self.db.all("SELECT * FROM test_cases WHERE test_suite_id=?", (suite_id,)):
            decoded = decode_row(case) or {}; self.create_case(org_id, user_id, duplicate["id"], {"name": decoded["name"], "description": decoded["description"], "category": decoded["category"], "defaultSeverity": decoded["default_severity"], "input": decoded["input"], "expectedBehavior": decoded["expected_behavior"], "evaluatorType": decoded["evaluator_type"], "evaluatorConfig": decoded["evaluator_config"], "timeoutMs": decoded["timeout_ms"], "enabled": decoded["enabled"]})
        return duplicate

    def create_case(self, org_id: str, user_id: str, suite_id: str, data: dict[str, Any]) -> dict[str, Any]:
        self._owned("test_suites", suite_id, org_id); kind = data["evaluatorType"]; config = data.get("evaluatorConfig", {}); validate_evaluator_config(kind, config); case_id, timestamp = new_id("case"), now()
        self.db.insert("test_cases", {"id": case_id, "test_suite_id": suite_id, "name": data["name"], "description": data.get("description", ""), "category": data["category"], "default_severity": data.get("defaultSeverity", "medium"), "input": data["input"], "expected_behavior": data["expectedBehavior"], "evaluator_type": kind, "evaluator_config": encode_json({**config, "severity": data.get("defaultSeverity", "medium")}), "timeout_ms": int(data.get("timeoutMs", self.settings.default_timeout_ms)), "enabled": int(data.get("enabled", True)), "created_at": timestamp, "updated_at": timestamp}); self.audit(org_id, user_id, "test_case.created", "test_case", case_id); return decode_row(self.db.one("SELECT * FROM test_cases WHERE id=?", (case_id,))) or {}

    def mutate_case(self, org_id: str, user_id: str, case_id: str, data: dict[str, Any] | None = None, enabled: bool | None = None, delete: bool = False) -> dict[str, Any] | None:
        row = self.db.one("SELECT c.* FROM test_cases c JOIN test_suites s ON s.id=c.test_suite_id WHERE c.id=? AND s.organization_id=?", (case_id, org_id))
        if not row: raise NotFoundError("Resource not found")
        current = decode_row(row) or {}
        if delete: self.db.execute("DELETE FROM test_cases WHERE id=?", (case_id,)); self.audit(org_id, user_id, "test_case.deleted", "test_case", case_id); return None
        data = data or {}; kind = data.get("evaluatorType", current["evaluator_type"]); config = data.get("evaluatorConfig", current["evaluator_config"]); validate_evaluator_config(kind, config)
        fields = {"name":data.get("name",current["name"]),"description":data.get("description",current["description"]),"category":data.get("category",current["category"]),"default_severity":data.get("defaultSeverity",current["default_severity"]),"input":data.get("input",current["input"]),"expected_behavior":data.get("expectedBehavior",current["expected_behavior"]),"evaluator_type":kind,"evaluator_config":encode_json(config),"timeout_ms":int(data.get("timeoutMs",current["timeout_ms"])),"enabled":int(enabled if enabled is not None else data.get("enabled",current["enabled"])),"updated_at":now()}
        self.db.execute(f"UPDATE test_cases SET {','.join(f'{key}=?' for key in fields)} WHERE id=?", (*fields.values(), case_id)); self.audit(org_id, user_id, "test_case.updated", "test_case", case_id); return decode_row(self.db.one("SELECT * FROM test_cases WHERE id=?", (case_id,)))

    def start_run(self, org_id: str, user_id: str, agent_id: str, suite_id: str, configuration: dict[str, Any] | None = None) -> dict[str, Any]:
        agent = self._owned("agents", agent_id, org_id); self._owned("test_suites", suite_id, org_id)
        if agent["status"] != "active": raise ValueError("Agent must pass its connection test before a run")
        active = self.db.one("SELECT COUNT(*) AS count FROM test_runs WHERE organization_id=? AND status IN ('queued','running')", (org_id,))
        if active and active["count"] >= self.settings.worker_concurrency * 2: raise ValueError("Organization execution limit reached; wait for an active run to finish")
        cutoff = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        recent = self.db.one("SELECT COUNT(*) AS count FROM test_runs WHERE organization_id=? AND created_at>=?", (org_id, cutoff))
        if recent and recent["count"] >= self.settings.organization_runs_per_hour: raise ValueError("Organization hourly test-run limit reached")
        baseline = self.db.one("SELECT id FROM test_runs WHERE organization_id=? AND agent_id=? AND test_suite_id=? AND status='completed' ORDER BY completed_at DESC LIMIT 1", (org_id, agent_id, suite_id))
        run_id, timestamp = new_id("run"), now(); self.db.insert("test_runs", {"id": run_id, "organization_id": org_id, "agent_id": agent_id, "test_suite_id": suite_id, "status": "queued", "progress": 0, "overall_score": None, "security_score": None, "reliability_score": None, "compliance_score": None, "started_at": None, "completed_at": None, "duration_ms": None, "error_message": None, "configuration": encode_json(configuration or {}), "baseline_run_id": baseline["id"] if baseline else None, "created_at": timestamp, "updated_at": timestamp})
        self.audit(org_id, user_id, "run.started", "test_run", run_id); self.queue.enqueue(run_id); return decode_row(self.db.one("SELECT * FROM test_runs WHERE id=?", (run_id,))) or {}

    def _execute_run(self, run_id: str) -> None:
        started = time.monotonic(); run = decode_row(self.db.one("SELECT * FROM test_runs WHERE id=?", (run_id,))) or {}; agent = self._owned("agents", run["agent_id"], run["organization_id"])
        cases = [decode_row(row) or {} for row in self.db.all("SELECT * FROM test_cases WHERE test_suite_id=? AND enabled=1 LIMIT ?", (run["test_suite_id"], self.settings.max_tests_per_run))]
        self.db.execute("UPDATE test_runs SET status='running',started_at=?,updated_at=? WHERE id=?", (now(), now(), run_id))
        try:
            for index, case in enumerate(cases):
                if run_id in self.cancelled: self.db.execute("UPDATE test_runs SET status='cancelled',completed_at=?,updated_at=? WHERE id=?", (now(), now(), run_id)); return
                response = self.client.send(agent, case["input"], {"session_id": new_id("session"), "test_run_id": run_id, "test_case_id": case["id"], "agent_id": agent["id"]})
                evaluation = evaluate(case["evaluator_type"], EvaluationContext(case["input"], case["expected_behavior"], case["evaluator_config"], response.output, response.raw_response, response.http_status, response.latency_ms, response.error_message, {"attempts": response.attempts}))
                self.db.insert("test_results", {"id": new_id("result"), "test_run_id": run_id, "test_case_id": case["id"], "status": evaluation.status, "category": case["category"], "severity": evaluation.severity, "score": evaluation.score, "input": case["input"], "expected_behavior": case["expected_behavior"], "actual_behavior": response.output, "evidence": encode_json(evaluation.evidence), "remediation": encode_json(evaluation.remediation), "latency_ms": response.latency_ms, "http_status": response.http_status, "error_type": response.error_type, "raw_response": encode_json(response.raw_response), "response_metadata": encode_json({"attempts": response.attempts}), "created_at": now()})
                self.db.execute("UPDATE test_runs SET progress=?,updated_at=? WHERE id=?", (round(((index+1)/max(1,len(cases)))*100), now(), run_id))
            results = [decode_row(row) or {} for row in self.db.all("SELECT * FROM test_results WHERE test_run_id=?", (run_id,))]; scores = calculate_scores(results)
            self.db.execute("UPDATE test_runs SET status='completed',progress=100,overall_score=?,security_score=?,reliability_score=?,compliance_score=?,completed_at=?,duration_ms=?,updated_at=? WHERE id=?", (scores["overallScore"], scores["securityScore"], scores["reliabilityScore"], scores["complianceScore"], now(), round((time.monotonic()-started)*1000), now(), run_id))
        except Exception as exc:
            self.db.execute("UPDATE test_runs SET status='failed',error_message=?,completed_at=?,updated_at=? WHERE id=?", (str(exc), now(), now(), run_id))

    def cancel_run(self, org_id: str, user_id: str, run_id: str) -> None:
        self._owned("test_runs", run_id, org_id); self.cancelled.add(run_id); self.queue.cancel(run_id); self.db.execute("UPDATE test_runs SET status='cancelled',completed_at=?,updated_at=? WHERE id=? AND status='queued'", (now(),now(),run_id)); self.audit(org_id, user_id, "run.cancelled", "test_run", run_id)

    def get_run(self, org_id: str, run_id: str) -> dict[str, Any]:
        run = self._owned("test_runs", run_id, org_id); run["results"] = [decode_row(row) for row in self.db.all("SELECT r.*,c.name AS test_name FROM test_results r JOIN test_cases c ON c.id=r.test_case_id WHERE r.test_run_id=? ORDER BY r.created_at", (run_id,))]; return run

    def list_runs(self, org_id: str) -> list[dict[str, Any]]:
        return [decode_row(row) or {} for row in self.db.all("SELECT r.*,a.name AS agent_name,s.name AS suite_name FROM test_runs r JOIN agents a ON a.id=r.agent_id JOIN test_suites s ON s.id=r.test_suite_id WHERE r.organization_id=? ORDER BY r.created_at DESC LIMIT 100", (org_id,))]

    def comparison(self, org_id: str, run_id: str, baseline_id: str | None = None) -> dict[str, Any]:
        run = self._owned("test_runs", run_id, org_id); baseline_id = baseline_id or run.get("baseline_run_id")
        if not baseline_id: return {"available": False}
        baseline = self._owned("test_runs", baseline_id, org_id); current_results = [decode_row(r) or {} for r in self.db.all("SELECT * FROM test_results WHERE test_run_id=?", (run_id,))]; baseline_results = [decode_row(r) or {} for r in self.db.all("SELECT * FROM test_results WHERE test_run_id=?", (baseline_id,))]
        return {"available": True, "baselineRunId": baseline_id, **compare_results(current_results, baseline_results, run.get("overall_score") or 0, baseline.get("overall_score") or 0)}

    def report(self, org_id: str, run_id: str) -> dict[str, Any]:
        run = self.get_run(org_id, run_id); agent = self._owned("agents", run["agent_id"], org_id); suite = self._owned("test_suites", run["test_suite_id"], org_id); results = run.pop("results")
        counts = {status: sum(r["status"] == status for r in results) for status in ("passed", "failed", "warning", "error", "skipped")}
        return {"agent": {"id": agent["id"], "name": agent["name"], "description": agent["description"]}, "testSuite": {"id": suite["id"], "name": suite["name"]}, "run": run, "counts": counts, "regression": self.comparison(org_id, run_id), "results": [redact(r) for r in results]}

    def dashboard(self, org_id: str) -> dict[str, Any]:
        agents = self.list_agents(org_id); runs = self.list_runs(org_id); completed = [r for r in runs if r["status"] == "completed"]; results = self.db.all("SELECT tr.status,tr.severity,tr.category FROM test_results tr JOIN test_runs r ON r.id=tr.test_run_id WHERE r.organization_id=?", (org_id,))
        return {"totalAgents": len(agents), "activeAgents": sum(a["status"] == "active" for a in agents), "totalRuns": len(runs), "averageScore": round(sum(r["overall_score"] or 0 for r in completed)/max(1,len(completed)),1), "failedTests": sum(r["status"] == "failed" for r in results), "criticalFindings": sum(r["severity"] == "critical" and r["status"] == "failed" for r in results), "recentRuns": runs[:10], "scoreTrend": [{"runId": r["id"], "score": r["overall_score"], "createdAt": r["created_at"]} for r in reversed(completed[:10])], "findingsBySeverity": {s: sum(r["severity"] == s for r in results) for s in ("critical","high","medium","low")}, "findingsByCategory": {c: sum(r["category"] == c for r in results) for c in sorted({r["category"] for r in results})}}
