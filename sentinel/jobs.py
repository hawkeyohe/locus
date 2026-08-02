from __future__ import annotations

import socket
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Callable

from .config import Settings
from .database import Database, new_id, now


class DurableJobQueue:
    def __init__(self, db: Database, settings: Settings) -> None:
        self.db, self.settings = db, settings

    def enqueue(self, run_id: str) -> dict:
        existing = self.db.one("SELECT * FROM jobs WHERE run_id=?", (run_id,))
        if existing:
            return existing
        timestamp = now()
        try:
            self.db.insert("jobs", {"id":new_id("job"),"run_id":run_id,"status":"queued","attempts":0,"available_at":timestamp,"claimed_at":None,"lease_expires_at":None,"worker_id":None,"last_error":None,"created_at":timestamp,"updated_at":timestamp})
        except Exception:
            existing = self.db.one("SELECT * FROM jobs WHERE run_id=?", (run_id,))
            if existing:
                return existing
            raise
        return self.db.one("SELECT * FROM jobs WHERE run_id=?", (run_id,)) or {}

    def claim(self, worker_id: str) -> dict | None:
        current, lease = now(), (datetime.now(UTC) + timedelta(seconds=self.settings.job_lease_seconds)).isoformat()
        with self.db._lock, self.db.connect() as connection:
            if self.db.backend == "sqlite":
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("UPDATE jobs SET status='queued',worker_id=NULL,claimed_at=NULL,lease_expires_at=NULL,updated_at=? WHERE status='running' AND lease_expires_at<?", (current, current))
                row = connection.execute("SELECT * FROM jobs WHERE status='queued' AND available_at<=? ORDER BY created_at LIMIT 1", (current,)).fetchone()
                if not row: return None
                connection.execute("UPDATE jobs SET status='running',attempts=attempts+1,worker_id=?,claimed_at=?,lease_expires_at=?,updated_at=? WHERE id=? AND status='queued'", (worker_id,current,lease,current,row["id"]))
            else:
                connection.execute("UPDATE jobs SET status='queued',worker_id=NULL,claimed_at=NULL,lease_expires_at=NULL,updated_at=%s WHERE status='running' AND lease_expires_at<%s", (current,current))
                row = connection.execute("SELECT * FROM jobs WHERE status='queued' AND available_at<=%s ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1", (current,)).fetchone()
                if not row: return None
                connection.execute("UPDATE jobs SET status='running',attempts=attempts+1,worker_id=%s,claimed_at=%s,lease_expires_at=%s,updated_at=%s WHERE id=%s", (worker_id,current,lease,current,row["id"]))
            result = dict(row); result.update({"status":"running","worker_id":worker_id,"claimed_at":current,"lease_expires_at":lease,"attempts":int(row["attempts"])+1}); return result

    def heartbeat(self, job_id: str, worker_id: str) -> None:
        lease = (datetime.now(UTC) + timedelta(seconds=self.settings.job_lease_seconds)).isoformat()
        if not self.db.execute("UPDATE jobs SET lease_expires_at=?,updated_at=? WHERE id=? AND worker_id=? AND status='running'", (lease,now(),job_id,worker_id)):
            raise RuntimeError("Job lease was lost")

    def complete(self, job_id: str, worker_id: str) -> None:
        if not self.db.execute("UPDATE jobs SET status='completed',lease_expires_at=NULL,updated_at=? WHERE id=? AND worker_id=? AND status='running'", (now(),job_id,worker_id)):
            raise RuntimeError("Job completion rejected because its lease was lost")

    def fail(self, job: dict, worker_id: str, error: str) -> None:
        attempts = int(job["attempts"]); terminal = attempts >= self.settings.job_max_attempts
        delay = min(60, 2 ** max(0, attempts - 1)); available = (datetime.now(UTC) + timedelta(seconds=delay)).isoformat()
        self.db.execute("UPDATE jobs SET status=?,available_at=?,lease_expires_at=NULL,worker_id=NULL,last_error=?,updated_at=? WHERE id=? AND worker_id=?", ("failed" if terminal else "queued",available,error[:1000],now(),job["id"],worker_id))

    def cancel(self, run_id: str) -> None:
        self.db.execute("UPDATE jobs SET status='cancelled',lease_expires_at=NULL,updated_at=? WHERE run_id=? AND status IN ('queued','running')", (now(),run_id))


class Worker:
    def __init__(self, queue: DurableJobQueue, handler: Callable[[str], None], settings: Settings, worker_id: str | None = None) -> None:
        self.queue, self.handler, self.settings = queue, handler, settings
        self.worker_id = worker_id or f"{socket.gethostname()}-{uuid.uuid4().hex[:8]}"
        self._stop = threading.Event()

    def run_once(self) -> bool:
        job = self.queue.claim(self.worker_id)
        if not job: return False
        heartbeat_stop = threading.Event()
        heartbeat_error: list[Exception] = []
        def renew() -> None:
            interval = max(1, self.settings.job_lease_seconds // 3)
            while not heartbeat_stop.wait(interval):
                try: self.queue.heartbeat(job["id"], self.worker_id)
                except Exception as exc: heartbeat_error.append(exc); return
        heartbeat = threading.Thread(target=renew, name=f"heartbeat-{job['id']}", daemon=True); heartbeat.start()
        try:
            self.handler(job["run_id"])
            if heartbeat_error: raise heartbeat_error[0]
            self.queue.complete(job["id"], self.worker_id)
        except Exception as exc:
            self.queue.fail(job, self.worker_id, str(exc))
        finally:
            heartbeat_stop.set(); heartbeat.join(timeout=1)
        return True

    def run_forever(self) -> None:
        while not self._stop.is_set():
            if not self.run_once(): self._stop.wait(self.settings.job_poll_interval_ms / 1000)

    def start_thread(self) -> threading.Thread:
        thread = threading.Thread(target=self.run_forever, name=f"locus-{self.worker_id}", daemon=True); thread.start(); return thread

    def stop(self) -> None:
        self._stop.set()
