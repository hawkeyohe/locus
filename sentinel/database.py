from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator


MIGRATIONS = Path(__file__).resolve().parent / "migrations"


def now() -> str:
    return datetime.now(UTC).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


class Database:
    """Small database abstraction supporting SQLite locally and PostgreSQL in production."""

    def __init__(self, dsn: str | Path) -> None:
        raw = str(dsn)
        if raw.startswith(("postgres://", "postgresql://")):
            self.backend, self.dsn = "postgresql", raw
        else:
            self.backend = "sqlite"
            self.dsn = raw.removeprefix("sqlite:///")
        self.path = self.dsn  # Compatibility for local tooling.
        self._lock = threading.RLock()
        self.initialize()

    def _sql(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.backend == "postgresql" else sql

    @contextmanager
    def connect(self) -> Iterator[Any]:
        if self.backend == "postgresql":
            try:
                import psycopg
                from psycopg.rows import dict_row
            except ImportError as exc:
                raise RuntimeError("Install psycopg to use PostgreSQL") from exc
            connection = psycopg.connect(self.dsn, row_factory=dict_row)
        else:
            connection = sqlite3.connect(self.dsn, timeout=15)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = WAL")
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
            connection.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)")
            applied_rows = connection.execute("SELECT version FROM schema_migrations").fetchall()
            applied = {int(row["version"] if isinstance(row, (dict, sqlite3.Row)) else row[0]) for row in applied_rows}
            for path in sorted(MIGRATIONS.glob("*.sql")):
                version = int(path.name.split("_", 1)[0])
                if version in applied:
                    continue
                statements = [statement.strip() for statement in path.read_text().split(";") if statement.strip()]
                for statement in statements:
                    connection.execute(statement)
                connection.execute(self._sql("INSERT INTO schema_migrations(version,name,applied_at) VALUES (?,?,?) ON CONFLICT(version) DO NOTHING"), (version, path.name, now()))

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        with self._lock, self.connect() as connection:
            cursor = connection.execute(self._sql(sql), params)
            return cursor.rowcount

    def one(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(self._sql(sql), params).fetchone()
        return dict(row) if row else None

    def all(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self.connect() as connection:
            return [dict(row) for row in connection.execute(self._sql(sql), params).fetchall()]

    def insert(self, table: str, data: dict[str, Any]) -> None:
        keys = list(data)
        sql = f"INSERT INTO {table} ({','.join(keys)}) VALUES ({','.join('?' for _ in keys)})"
        self.execute(sql, tuple(data[key] for key in keys))

    def ping(self) -> bool:
        return bool(self.one("SELECT 1 AS ok"))


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
