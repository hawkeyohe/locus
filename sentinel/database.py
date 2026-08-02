from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS organizations (id TEXT PRIMARY KEY, name TEXT NOT NULL, plan TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, organization_id TEXT NOT NULL REFERENCES organizations(id), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id), name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', endpoint_url TEXT NOT NULL, http_method TEXT NOT NULL DEFAULT 'POST', authentication_type TEXT NOT NULL, encrypted_credentials TEXT, request_template TEXT NOT NULL, response_path TEXT NOT NULL, request_headers TEXT NOT NULL DEFAULT '{}', timeout_ms INTEGER NOT NULL, status TEXT NOT NULL, last_connection_test_at TEXT, last_connection_test_status TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS test_suites (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id), name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', is_default INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS test_cases (id TEXT PRIMARY KEY, test_suite_id TEXT NOT NULL REFERENCES test_suites(id) ON DELETE CASCADE, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', category TEXT NOT NULL, default_severity TEXT NOT NULL, input TEXT NOT NULL, expected_behavior TEXT NOT NULL, evaluator_type TEXT NOT NULL, evaluator_config TEXT NOT NULL DEFAULT '{}', timeout_ms INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS test_runs (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id), agent_id TEXT NOT NULL REFERENCES agents(id), test_suite_id TEXT NOT NULL REFERENCES test_suites(id), status TEXT NOT NULL, progress INTEGER NOT NULL DEFAULT 0, overall_score REAL, security_score REAL, reliability_score REAL, compliance_score REAL, started_at TEXT, completed_at TEXT, duration_ms INTEGER, error_message TEXT, configuration TEXT NOT NULL DEFAULT '{}', baseline_run_id TEXT REFERENCES test_runs(id), created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS test_results (id TEXT PRIMARY KEY, test_run_id TEXT NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE, test_case_id TEXT NOT NULL REFERENCES test_cases(id), status TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL, score REAL NOT NULL, input TEXT NOT NULL, expected_behavior TEXT NOT NULL, actual_behavior TEXT, evidence TEXT NOT NULL, remediation TEXT NOT NULL, latency_ms INTEGER, http_status INTEGER, error_type TEXT, raw_response TEXT, response_metadata TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_logs (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, user_id TEXT NOT NULL, action TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, metadata TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS job_claims (run_id TEXT PRIMARY KEY, claimed_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_agents_org ON agents(organization_id);
CREATE INDEX IF NOT EXISTS idx_runs_org_agent ON test_runs(organization_id, agent_id, created_at);
CREATE INDEX IF NOT EXISTS idx_results_run ON test_results(test_run_id);
"""


def now() -> str:
    return datetime.now(UTC).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        self.initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self._lock, self.connect() as connection:
            connection.executescript(SCHEMA)

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        with self._lock, self.connect() as connection:
            return connection.execute(sql, params).rowcount

    def one(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(sql, params).fetchone()
        return dict(row) if row else None

    def all(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self.connect() as connection:
            return [dict(row) for row in connection.execute(sql, params).fetchall()]

    def insert(self, table: str, data: dict[str, Any]) -> None:
        keys = list(data)
        sql = f"INSERT INTO {table} ({','.join(keys)}) VALUES ({','.join('?' for _ in keys)})"
        self.execute(sql, tuple(data[key] for key in keys))


JSON_FIELDS = {"request_template", "request_headers", "evaluator_config", "configuration", "evidence", "remediation", "raw_response", "response_metadata", "metadata"}


def decode_row(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    result = dict(row)
    for key in JSON_FIELDS & result.keys():
        if result[key] is not None and isinstance(result[key], str):
            try:
                result[key] = json.loads(result[key])
            except json.JSONDecodeError:
                pass
    for key in ("is_default", "enabled"):
        if key in result:
            result[key] = bool(result[key])
    return result


def encode_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
