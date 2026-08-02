from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    database_path: Path = Path(os.getenv("LOCUS_DATABASE_PATH", "locus.db"))
    encryption_key: str = os.getenv("LOCUS_ENCRYPTION_KEY", "development-only-change-me")
    app_url: str = os.getenv("LOCUS_APP_URL", "http://127.0.0.1:8000")
    port: int = int(os.getenv("LOCUS_PORT", "8000"))
    default_timeout_ms: int = int(os.getenv("LOCUS_DEFAULT_TIMEOUT_MS", "10000"))
    max_response_bytes: int = int(os.getenv("LOCUS_MAX_RESPONSE_BYTES", "1048576"))
    max_request_bytes: int = int(os.getenv("LOCUS_MAX_REQUEST_BYTES", "262144"))
    allow_local_endpoints: bool = _bool("LOCUS_ALLOW_LOCAL_ENDPOINTS")
    demo_seed: bool = _bool("LOCUS_DEMO_SEED", True)
    worker_concurrency: int = max(1, int(os.getenv("LOCUS_WORKER_CONCURRENCY", "2")))
    max_tests_per_run: int = int(os.getenv("LOCUS_MAX_TESTS_PER_RUN", "100"))
    max_redirects: int = int(os.getenv("LOCUS_MAX_REDIRECTS", "0"))


settings = Settings()
