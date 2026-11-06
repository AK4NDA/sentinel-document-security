# 0001. Adopt a Python FastAPI backend stack for the classified document system

**Date**: 2026-11-06
**Status**: In Progress

## Summary

This spec records the foundational stack for the backend of the classified document access control system. The product brief already pointed at Python, FastAPI, PostgreSQL, and Docker; this decision ratifies that direction and pins down the finer choices: async SQLAlchemy for data access, server side sessions stored in Postgres, Argon2id password hashing, AES-GCM file encryption with the master key from the environment, and structured JSON logging. The frontend is deferred to a later scope, so this pass scaffolds the API only. Every later feature (policy engine, audit log, MFA, search, sharing) builds on these choices.

## Decision

**Chosen option**: Option 1: Python backend on FastAPI with async SQLAlchemy and PostgreSQL

A layered monolith API: FastAPI on Python 3.12, SQLAlchemy 2.0 async through asyncpg, Alembic for migrations, Postgres in compose with SQLite via aiosqlite for local dev and tests, server side opaque sessions in a Postgres table, argon2-cffi for Argon2id password hashing, pyotp for TOTP MFA (built in slice 2), the `cryptography` package for AES-GCM file encryption, pydantic-settings for configuration, slowapi for rate limiting, structlog for JSON logs, pytest with pytest-asyncio and httpx for tests, and Docker compose packaging. REST endpoints live under a `/v1` prefix with FastAPI's default error shape.

**Implementation skills**: `fastapi` (`fastapi/fastapi`, `.agents/skills/fastapi/`) · `pydantic` (`pydantic/skills`, `.agents/skills/pydantic/`) · `sqlalchemy-alembic-expert-best-practices-code-review` (`wispbit-ai/skills`, `.agents/skills/sqlalchemy-alembic-expert-best-practices-code-review/`) · `pytest-coverage` (`github/awesome-copilot`, `.agents/skills/pytest-coverage/`) · `reviewing-cryptography` (`trilwu/secskills`, `.agents/skills/reviewing-cryptography/`) · `docker-compose-patterns` (`docker/skills`, `.agents/skills/docker-compose-patterns/`)

## Proposed stack

| Layer | Choice | Reason |
|---|---|---|
| Language | Python 3.12 | Pinned recent stable; broad wheel coverage for asyncpg, cryptography, and the auth libraries. |
| Framework | FastAPI + Pydantic v2 | Async native, typed request validation, automatic OpenAPI docs, matches the product brief. |
| Architecture pattern | Layered monolith | Controllers to services to repositories in one deployable unit; no service split until a real bottleneck forces it. |
| Primary DB | PostgreSQL 16 in compose; SQLite via aiosqlite for dev and tests | ACID and relational integrity for the audit log; SQLite keeps local runs and tests dependency free. |
| ORM and migrations | SQLAlchemy 2.0 async style + Alembic | Async engine with asyncpg; Alembic is the standard migration path and supports async environments. |
| Auth and sessions | Custom session layer: opaque random token, stored hashed in a `sessions` Postgres table with expiry and revocation | Instant revocation and full audit visibility; chosen over JWT because this system's security model depends on being able to kill a session. |
| Password hashing | argon2-cffi (Argon2id) | Current best practice memory hard hashing; the direct maintained binding. |
| MFA | pyotp (TOTP), built in slice 2 | Matches the product brief; slice 2 owns enrollment and challenge flow. |
| Encryption | `cryptography` AES-GCM, master key from env var or mounted Docker secret | Authenticated encryption for stored files; key never in the repo or database. |
| File storage | Local filesystem, encrypted blobs, metadata and path in Postgres | Self contained for compose with a volume; object storage noted as a follow up if deployment moves off a single host. |
| API shape | REST under `/v1` prefix, FastAPI default `{detail}` errors, `/docs` enabled in dev only, CORS origins from env | Industry standard versioning; keeps the surface simple for the deferred UI. |
| Configuration | pydantic-settings `BaseSettings` from env vars and `.env`; Docker secrets supported | Typed, validated config with secrets kept out of the repo. |
| Rate limiting | slowapi, in memory store | Single node compose needs no shared store; swap to Redis only if multi worker lands. |
| Logging and observability | structlog routed to JSON through stdlib logging, plus a `/healthz` endpoint | Structured logs greppable in compose output; no external observability service yet. |
| Testing | pytest + pytest-asyncio + httpx `AsyncClient` | Standard FastAPI async test stack; runs against SQLite. |
| Dependency management | `uv` for lockfile and installs | Fast, standard in 2026, reproducible `uv.lock`. |
| Packaging | Dockerfile for the API plus `docker-compose.yml` (api, postgres, volume) | One command runs the whole prototype, per the product brief. |
| Frontend | Deferred | The web UI is a later scope feature; this pass scaffolds the backend only. |
| Background jobs | None | Alerts are in app records, not pushed jobs; a queue is added only if a slice needs it. |

## Scaffold contract

The pinned details `/develop` scaffolds from; each is a decision, not a suggestion.

- **Layout**: `pyproject.toml` + committed `uv.lock` at repo root; `app/` package split into `api/`, `core/`, `models/`, `schemas/`, `services/`, `repositories/`, `security/`; `alembic/` for migrations; `tests/`; `data/` gitignored for blobs and dev DB files. Dependency groups: runtime deps in `[project]`, dev tools (pytest, pytest-asyncio, httpx, ruff) in `dependency-groups`.
- **Lint**: ruff is the expected default so feature 2 confirms rather than decides; configure rules that catch blocking calls inside async functions.
- **Env vars** (validated by pydantic-settings at startup, `.env` for dev, Docker secrets supported): `DATABASE_URL` (`postgresql+asyncpg://` in compose, `sqlite+aiosqlite:///./data/dev.db` for local dev), `MASTER_KEY` (base64, 32 bytes, validated at startup), `SESSION_COOKIE_NAME`, `SESSION_TTL_SECONDS`, `UPLOAD_DIR`, `CORS_ORIGINS` (comma separated, empty by default), `LOG_LEVEL`, `RATE_LIMIT_*`, `ENV` (`dev`/`prod`).
- **Sessions**: token from `secrets.token_urlsafe(32)`; store only `SHA-256(token)` in the `sessions` table with `user_id`, `created_at`, `last_seen_at`, `expires_at`, `revoked_at`; sliding expiry with an absolute cap (8h idle, 24h absolute); cookie `HttpOnly; Secure; SameSite=Lax`; also accept `Authorization: Bearer` for API clients and tests. Cookie based sessions carry CSRF exposure for the future SPA; the auth spec must address it (SameSite plus origin checks).
- **Alembic**: `alembic/env.py` uses `create_async_engine` and `connection.run_sync(do_run_migrations)`; migrations run via a small async entry point.
- **Blobs**: content addressed layout `UPLOAD_DIR/<first 2 hex of sha256>/<sha256>.enc` storing `{nonce, tag, ciphertext}`; the data model spec must reserve a `key_id`/`key_version` column on file records now so master key rotation never needs a schema change.
- **Blocking work**: Argon2 hashing and AES-GCM encrypt/decrypt of large files run via `anyio.to_thread`, never on the event loop; enforce a max upload size (25 MB) before buffering.
- **Health**: `GET /healthz` returns `{"status": "ok"}`; `GET /readyz` runs `SELECT 1` and is the compose readiness check.
- **Docker**: `python:3.12-slim` base, non root user, multi stage build running `uv sync --frozen`; compose services `api` + `postgres` with `depends_on: condition: service_healthy` (pg_isready healthcheck), a named volume for `UPLOAD_DIR`, and `API_PORT` env (default 8000).
- **Portability rule**: migrations and queries use portable types only (`JSON` not `JSONB`, `DateTime(timezone=True)` with UTC enforced in the app layer); postgres only constructs are banned so SQLite tests match production.

## Consequences

**Positive**:
- One coherent async stack end to end, so every feature slice (policy, audit, MFA, search) inherits the same patterns instead of mixing sync and async.
- Server side sessions give the revocation and audit properties the security model needs without extra infrastructure.
- SQLite for dev and tests means contributors and CI need no database service; Postgres stays the production shape.
- The stack matches the product brief, so the spec ratifies rather than reopens the engineer's stated direction.

**Negative / tradeoffs**:
- Custom auth code (sessions, later TOTP) carries more risk than adopting an auth framework; mitigated by the dedicated MFA spec, the `reviewing-cryptography` skill, and GA tier review on the auth slices.
- Async SQLAlchemy has a steeper learning curve and punishes accidental sync calls inside async endpoints; the sqlalchemy skill and lint rules must enforce the discipline.
- Local filesystem storage ties the deployment to a single host with a persistent volume; moving to object storage later means a storage abstraction now or a migration then.
- SQLite and Postgres are not identical; queries must stick to portable constructs (no JSONB only features) or tests will drift from production, enforced by the portability rule in the scaffold contract.
- A single env var master key means rotation requires re encrypting every blob; the reserved `key_id` column makes rotation cheap later but the re encryption job itself is future work.
- The planned hash chained audit log proves entries were not edited, but a database admin can still rewrite or truncate the log tail. An external anchor (periodic signed checkpoint or append only export) is required for real tamper evidence and is owned by the auditor spec (scope slice 4), not this stack.

**Neutral**:
- The deferred frontend means CORS and API ergonomics are designed for a future React client, not exercised yet.
- No background job runner exists yet; the audit log and alerts are synchronous writes.
- `/docs` being dev only means production debugging relies on logs and the health endpoint.

## Follow-up

- [ ] Run `/audit` after the scaffold exists to capture stack conventions into root `AGENTS.md`, including the installed skills list and the declined MCP servers line.
- [ ] Add the `fastapi`, `pydantic`, `sqlalchemy-alembic-expert-best-practices-code-review`, `pytest-coverage`, `reviewing-cryptography`, and `docker-compose-patterns` skills to the `## Agent skills` section of `AGENTS.md` during `/audit`.
- [ ] Real deployments should replace the env var master key with a KMS or HSM backed key management approach; record this when deployment leaves the prototype stage.
- [ ] If the service ever runs multi worker, move slowapi to a Redis backed store and revisit session storage scale.
- [ ] Object storage (S3 compatible) becomes worth revisiting if the deployment target stops being a single Docker host.
- [ ] The audit log spec (scope slice 4) must include an external anchor for the hash chain (signed checkpoint or append only export) so a database admin cannot silently rewrite history.

## Rationale

Reasoning, options considered, and references: see [rationale.md](rationale.md).
