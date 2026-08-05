from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class RateLimitError(RuntimeError):
    pass


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_seconds: int = 60) -> None:
        if limit <= 0:
            return
        current = time.monotonic()
        with self._lock:
            events = self._events[key]
            while events and events[0] <= current - window_seconds:
                events.popleft()
            if len(events) >= limit:
                raise RateLimitError("Request rate limit exceeded")
            events.append(current)
