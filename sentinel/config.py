from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def load_env(path: Path = Path(".env")) -> None:
    """Load a local dotenv file without overriding process-level secrets."""
    if not path.is_file():
        return
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if value[:1] == value[-1:] and value[:1] in {"'", '"'}:
            value = value[1:-1]
        if key and key.replace("_", "").isalnum():
            os.environ.setdefault(key, value)


load_env()


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    environment: str = os.getenv("LOCUS_ENV", "development")
    database_path: Path = Path(os.getenv("LOCUS_DATABASE_PATH", "locus.db"))
    database_url: str = os.getenv("LOCUS_DATABASE_URL", "")
    encryption_key: str = os.getenv("LOCUS_ENCRYPTION_KEY", "development-only-change-me")
    app_url: str = os.getenv("LOCUS_APP_URL", "http://127.0.0.1:8000")
    host: str = os.getenv("LOCUS_HOST", "127.0.0.1")
    port: int = int(os.getenv("LOCUS_PORT", "8000"))
    static_dir: Path = Path(os.getenv("LOCUS_STATIC_DIR", str(Path(__file__).resolve().parent.parent / "web")))
    default_timeout_ms: int = int(os.getenv("LOCUS_DEFAULT_TIMEOUT_MS", "10000"))
    max_response_bytes: int = int(os.getenv("LOCUS_MAX_RESPONSE_BYTES", "1048576"))
    max_request_bytes: int = int(os.getenv("LOCUS_MAX_REQUEST_BYTES", "262144"))
    allow_local_endpoints: bool = _bool("LOCUS_ALLOW_LOCAL_ENDPOINTS")
    demo_seed: bool = _bool("LOCUS_DEMO_SEED", True)
    worker_concurrency: int = max(1, int(os.getenv("LOCUS_WORKER_CONCURRENCY", "2")))
    max_tests_per_run: int = int(os.getenv("LOCUS_MAX_TESTS_PER_RUN", "100"))
    max_redirects: int = int(os.getenv("LOCUS_MAX_REDIRECTS", "0"))
    api_requests_per_minute: int = int(os.getenv("LOCUS_API_REQUESTS_PER_MINUTE", "120"))
    auth_attempts_per_minute: int = int(os.getenv("LOCUS_AUTH_ATTEMPTS_PER_MINUTE", "10"))
    metrics_token: str = os.getenv("LOCUS_METRICS_TOKEN", "")
    organization_requests_per_minute: int = int(os.getenv("LOCUS_ORG_REQUESTS_PER_MINUTE", "300"))
    organization_runs_per_hour: int = int(os.getenv("LOCUS_ORG_RUNS_PER_HOUR", "30"))
    embedded_worker: bool = _bool("LOCUS_EMBEDDED_WORKER", True)
    single_service_mode: bool = _bool("LOCUS_SINGLE_SERVICE_MODE", False)
    job_poll_interval_ms: int = int(os.getenv("LOCUS_JOB_POLL_INTERVAL_MS", "500"))
    job_lease_seconds: int = int(os.getenv("LOCUS_JOB_LEASE_SECONDS", "60"))
    job_max_attempts: int = int(os.getenv("LOCUS_JOB_MAX_ATTEMPTS", "3"))

    @property
    def database_dsn(self) -> str:
        return self.database_url or f"sqlite:///{self.database_path}"

    def validate(self) -> None:
        if self.environment not in {"development", "test", "production"}:
            raise ValueError("LOCUS_ENV must be development, test, or production")
        if self.environment == "production":
            if self.demo_seed or self.allow_local_endpoints:
                raise ValueError("Demo seed and local endpoints must be disabled in production")
            if self.embedded_worker and not self.single_service_mode:
                raise ValueError(
                    "The embedded worker requires LOCUS_SINGLE_SERVICE_MODE in production"
                )
            if not self.database_url.startswith(("postgres://", "postgresql://")):
                raise ValueError("Production requires LOCUS_DATABASE_URL with PostgreSQL")
            if not self.encryption_key or self.encryption_key == "development-only-change-me":
                raise ValueError("A production LOCUS_ENCRYPTION_KEY is required")
            if not self.metrics_token:
                raise ValueError("A production LOCUS_METRICS_TOKEN is required")


settings = Settings()
