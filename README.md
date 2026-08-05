# Locus

> Continuous security and reliability testing for AI agents.

Locus connects to authenticated HTTP agent endpoints, runs deterministic security,
reliability, and business-rule checks, stores evidence-backed reports, and compares
new runs with historical baselines to surface regressions. Locus does not upload or
execute customer agent source code.

## Local setup

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
cp .env.example .env
```

Locus loads `.env` automatically without overriding variables already supplied by
the process. Generate a production-grade encryption key with:

```bash
.venv/bin/python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Run migrations and optional demo seed data:

```bash
.venv/bin/python -m scripts.migrate
.venv/bin/python -m scripts.seed
```

Start the application:

```bash
.venv/bin/python -m sentinel.server
```

Open [http://localhost:8000](http://localhost:8000).

Development starts an embedded durable worker by default. Production runs workers as
separate processes backed by the shared database:

```bash
.venv/bin/python -m scripts.worker
```

## Containers

For a production-shaped local environment with PostgreSQL and a separate worker:

```bash
docker compose up --build
```

The Compose stack includes PostgreSQL with persistent storage, a one-shot migration
service, the web service, and a standalone durable worker. Its checked-in database
password and development encryption key are local-only defaults; replace them with
managed secrets in any shared environment.

## Render staging deployment

The repository includes `render.yaml`, which provisions a private-network
PostgreSQL database, a public web service, and a separate background worker. It
also runs migrations before each web deployment and generates independent
encryption and metrics-access secrets.

1. Merge the deployment branch into `main`.
2. In Render, create a new Blueprint and connect `hawkeyohe/locus`.
3. Review the selected service and database plans before applying the Blueprint.
4. After deployment, open `https://locus-staging.onrender.com/health/ready` and
   confirm the database reports ready.
5. Open the staging URL, create the first owner account, and complete the
   agent-to-report smoke test.

If Render assigns a different hostname because the service name is already in
use, update `LOCUS_APP_URL` to the actual HTTPS service URL. Do not rotate
`LOCUS_ENCRYPTION_KEY` after storing agent credentials or request headers unless
the encrypted data is migrated to the new key first.

## Architecture

```text
Browser UI
  -> organization-scoped JSON API
     -> agent connection service -> SSRF guard -> customer HTTPS endpoint
     -> SQLite or PostgreSQL repositories
     -> durable database job queue
        -> leased standalone workers
        -> template renderer
        -> HTTP execution + retry policy
        -> deterministic evaluator registry
        -> scoring + regression comparison
        -> redacted report service
```

Core modules:

- `sentinel/database.py`: versioned migrations and SQLite/PostgreSQL access
- `sentinel/jobs.py`: durable queue, atomic claims, leases, heartbeats, retry backoff,
  duplicate prevention, recovery, and cancellation
- `sentinel/security.py`: Fernet credential vault, SSRF validation, safe templates,
  response-path extraction, header validation, and recursive secret redaction
- `sentinel/connectivity.py`: bounded HTTP client, DNS revalidation, redirects disabled,
  response limits, timeouts, and transient retry behavior
- `sentinel/evaluators.py`: extensible deterministic evaluator registry
- `sentinel/scoring.py`: centralized severity deductions and regression comparison
- `sentinel/service.py`: organization authorization, CRUD, connection tests, jobs,
  audit records, reports, and dashboard aggregation
- `sentinel/server.py`: HTTP routing and static UI delivery

The workspace includes saved-agent management and a deterministic test library.
Agents can be edited, retested, enabled or disabled, and have credentials rotated
without exposing stored values. Test suites can be created, duplicated, updated,
and populated with editable, individually enabled checks. Each run can select a
subset of enabled checks, set bounded request concurrency and timeout overrides,
stream stored partial results through polling, and cooperatively cancel remaining
work without discarding completed evidence.

## Browser and API identity

Browser users can create an organization and owner account, sign in with a password,
and sign out. Passwords use salted scrypt hashes. Browser sessions are random,
revocable, expire after 14 days, and are stored in HttpOnly, SameSite cookies with
the Secure flag in production. New organizations receive the built-in deterministic
test suites and enter the first-agent onboarding flow.

API clients can use an opaque bearer token. Only a SHA-256 token digest is stored,
and the server derives the user and organization from that record. Browser-provided
organization IDs are not trusted. Demo mode supplies the seeded identity when no
browser session or bearer token is present.

Issue a token for an existing user:

```bash
.venv/bin/python -m scripts.create_token user_demo --name "Local browser"
```

The plaintext token is displayed only once. API clients send it as
`Authorization: Bearer <token>`.

## Security defaults

- Only HTTP(S) POST endpoints are accepted.
- Redirects are disabled.
- Every resolved IP is checked; private, loopback, link-local, multicast, reserved,
  metadata, and internal destinations are blocked.
- DNS is resolved and checked again immediately before requests.
- Local endpoints require `LOCUS_ALLOW_LOCAL_ENDPOINTS=true`, intended only for
  the built-in development mock agent.
- Credentials and all custom request-header values are encrypted with Fernet and
  never returned after storage. Saved header names remain visible with masked values.
- Unsafe headers are rejected and response secrets are recursively redacted.
- Request/response sizes, timeouts, retries, worker concurrency, and organization
  execution counts are bounded.
- Per-client and per-organization sliding-window API limits are enabled.
- Production startup rejects demo data, local endpoints, and the development key.
- Production startup also rejects the embedded worker so web and worker processes
  remain independently scalable.

## PostgreSQL and workers

SQLite remains the zero-configuration development database. For staging or
production, set:

```dotenv
LOCUS_DATABASE_URL=postgresql://USER:PASSWORD@HOST:5432/locus
LOCUS_EMBEDDED_WORKER=false
```

Apply numbered migrations before starting either process:

```bash
.venv/bin/python -m scripts.migrate
```

Then start the web process and one or more workers:

```bash
.venv/bin/python -m sentinel.server
.venv/bin/python -m scripts.worker
```

Each run has one database-enforced job. Workers claim jobs atomically, heartbeat
their leases, recover expired leases after process failure, and retry infrastructure
failures with bounded exponential backoff. Application-level HTTP retries remain in
the agent connectivity service.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v
node --check web/app.js
```

GitHub Actions runs installation, migrations, Python compilation, all automated
tests, and frontend JavaScript validation for pull requests and pushes to `main`.

## Health and observability

- `GET /health/live` confirms the process is serving requests.
- `GET /health/ready` verifies database connectivity and returns `503` when the
  service should not receive traffic.
- `GET /metrics` exposes request totals, request-duration aggregates, and job counts
  in Prometheus text format. Production requires `Authorization: Bearer` with the
  generated `LOCUS_METRICS_TOKEN`.
- Every response includes `X-Request-ID`; safe incoming IDs are preserved.
- Logs are newline-delimited JSON and include request ID, normalized route, status,
  duration, and client address without query strings or authorization headers.
- Responses include CSP, clickjacking, MIME-sniffing, referrer, permissions-policy,
  and production HSTS headers.

The suite covers template substitution, response paths, credential encryption and
masking, organization isolation, SSRF policy, redaction, deterministic evaluators,
refusal evidence, scoring, regression comparison, and the agent-to-report happy path.

## Environment

See `.env.example` for database, encryption, application URL, worker, request limit,
local-endpoint, demo seed, and future optional LLM-evaluator settings. Never use the
checked-in development encryption fallback outside local development.

## Known Version 1 limitations

- SQLite is intended for local development; production PostgreSQL deployment and
  backup infrastructure must be provisioned by the operator.
- Email/password login is available, but email verification, password recovery,
  SSO, invitations, and organization administration remain future identity work.
- Redirects are disabled rather than revalidated through a redirect chain.
- Cancellation is cooperative between test cases, not during an active HTTP request.
- Tool-call evaluation is reserved for a future optional response-path configuration.
- Hallucination checks are deterministic only; Locus does not claim universal
  hallucination detection and has no required LLM judge.
- JSON export is available; PDF export is intentionally deferred.

Recommended production upgrades are SSO/OIDC, a managed key-encryption service,
distributed rate limiting, outbound network egress controls, structured metrics,
database backups, and deployment-specific audit retention.
