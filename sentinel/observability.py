from __future__ import annotations

import json
import re
import threading
import time
import uuid
from collections import Counter, defaultdict
from typing import Any
from urllib.parse import urlparse


ID_SEGMENT = re.compile(r"^(agent|suite|case|run|result|token|job)_[a-zA-Z0-9]+$")
REQUEST_ID = re.compile(r"^[a-zA-Z0-9._-]{8,128}$")


def request_id(value: str | None) -> str:
    return value if value and REQUEST_ID.fullmatch(value) else uuid.uuid4().hex


def route_name(path: str) -> str:
    segments = urlparse(path).path.strip("/").split("/")
    normalized = [":id" if ID_SEGMENT.fullmatch(segment) else segment for segment in segments]
    return "/" + "/".join(normalized) if normalized and normalized[0] else "/"


def log_event(event: str, **fields: Any) -> None:
    print(json.dumps({"timestamp": time.time(), "level": "info", "event": event, **fields}, separators=(",", ":"), default=str), flush=True)


class Metrics:
    def __init__(self) -> None:
        self._requests: Counter[tuple[str, str, int]] = Counter()
        self._duration_sum: dict[tuple[str, str], float] = defaultdict(float)
        self._duration_count: Counter[tuple[str, str]] = Counter()
        self._lock = threading.Lock()

    def observe_request(self, method: str, route: str, status: int, duration_seconds: float) -> None:
        with self._lock:
            self._requests[(method, route, status)] += 1
            self._duration_sum[(method, route)] += duration_seconds
            self._duration_count[(method, route)] += 1

    def render(self, queue_counts: dict[str, int] | None = None) -> bytes:
        lines = ["# HELP locus_http_requests_total HTTP requests.", "# TYPE locus_http_requests_total counter"]
        with self._lock:
            for (method, route, status), value in sorted(self._requests.items()):
                lines.append(f'locus_http_requests_total{{method="{method}",route="{route}",status="{status}"}} {value}')
            lines.extend(["# HELP locus_http_request_duration_seconds_sum Total HTTP request duration.", "# TYPE locus_http_request_duration_seconds_sum counter"])
            for (method, route), value in sorted(self._duration_sum.items()):
                lines.append(f'locus_http_request_duration_seconds_sum{{method="{method}",route="{route}"}} {value:.6f}')
                lines.append(f'locus_http_request_duration_seconds_count{{method="{method}",route="{route}"}} {self._duration_count[(method, route)]}')
        lines.extend(["# HELP locus_jobs Jobs by state.", "# TYPE locus_jobs gauge"])
        for status, value in sorted((queue_counts or {}).items()):
            lines.append(f'locus_jobs{{status="{status}"}} {value}')
        return ("\n".join(lines) + "\n").encode()
