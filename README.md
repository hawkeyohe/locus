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

Export the values from `.env` in your shell. Generate a production-grade encryption
key with:

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

The development worker is an in-process, bounded thread pool, so no separate worker
command is needed. Production should replace it with a durable external queue.

## Architecture

```text
Browser UI
  -> organization-scoped JSON API
     -> agent connection service -> SSRF guard -> customer HTTPS endpoint
     -> SQLite repositories
     -> bounded background worker
        -> template renderer
        -> HTTP execution + retry policy
        -> deterministic evaluator registry
        -> scoring + regression comparison
        -> redacted report service
```

Core modules:

- `sentinel/database.py`: schema, migration initialization, and SQLite access
- `sentinel/security.py`: Fernet credential vault, SSRF validation, safe templates,
  response-path extraction, header validation, and recursive secret redaction
- `sentinel/connectivity.py`: bounded HTTP client, DNS revalidation, redirects disabled,
  response limits, timeouts, and transient retry behavior
- `sentinel/evaluators.py`: extensible deterministic evaluator registry
- `sentinel/scoring.py`: centralized severity deductions and regression comparison
- `sentinel/service.py`: organization authorization, CRUD, connection tests, jobs,
  audit records, reports, and dashboard aggregation
- `sentinel/server.py`: HTTP routing and static UI delivery

## API identity

The current development server uses `X-Locus-User` and `X-Locus-Organization`
headers and validates that the user belongs to the organization on every operation.
Demo mode supplies the seeded identity automatically. Replace this development
identity adapter with production SSO/session authentication before deployment.

## Security defaults

- Only HTTP(S) POST endpoints are accepted.
- Redirects are disabled.
- Every resolved IP is checked; private, loopback, link-local, multicast, reserved,
  metadata, and internal destinations are blocked.
- DNS is resolved and checked again immediately before requests.
- Local endpoints require `LOCUS_ALLOW_LOCAL_ENDPOINTS=true`, intended only for
  the built-in development mock agent.
- Credentials are encrypted with Fernet and never returned after storage.
- Unsafe headers are rejected and response secrets are recursively redacted.
- Request/response sizes, timeouts, retries, worker concurrency, and organization
  execution counts are bounded.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v
node --check web/app.js
```

The suite covers template substitution, response paths, credential encryption and
masking, organization isolation, SSRF policy, redaction, deterministic evaluators,
refusal evidence, scoring, regression comparison, and the agent-to-report happy path.

## Environment

See `.env.example` for database, encryption, application URL, worker, request limit,
local-endpoint, demo seed, and future optional LLM-evaluator settings. Never use the
checked-in development encryption fallback outside local development.

## Known Version 1 limitations

- SQLite and the in-process worker target a single application instance.
- Development header identity is not production authentication.
- Redirects are disabled rather than revalidated through a redirect chain.
- Cancellation is cooperative between test cases, not during an active HTTP request.
- Tool-call evaluation is reserved for a future optional response-path configuration.
- Hallucination checks are deterministic only; Locus does not claim universal
  hallucination detection and has no required LLM judge.
- JSON export is available; PDF export is intentionally deferred.

Recommended production upgrades are PostgreSQL, durable queue workers with leases,
SSO/OIDC, a managed key-encryption service, distributed rate limiting, outbound
network egress controls, structured metrics, and deployment-specific audit retention.
