# Classified Document Access Control

Backend for a classified document access control system: Bell LaPadula rules plus role based access control, deny by default, AES-GCM encrypted file storage, and a hash chained audit log. Backend only for now; the React frontend is a deferred scope.

## Stack

- **Language / Runtime**: Python 3.12, async end to end
- **Framework**: FastAPI + Pydantic v2, REST under `/v1`
- **Key dependencies**: SQLAlchemy 2.x async, Alembic, argon2-cffi, pyotp (TOTP), `cryptography` (AES-GCM), structlog, slowapi, pydantic-settings, pypdf/python-docx/openpyxl/python-pptx (search text extraction)
- **Databases**: PostgreSQL 16 in compose, SQLite via aiosqlite for dev and tests
- **Package manager**: `uv` (committed `uv.lock`)

## Build approach

Tracer Bullet: prove the whole pipe works before building any part of it fully; each feature is one thin real slice end to end.

## Commands

```bash
# Install
uv sync

# Dev server (needs .env with MASTER_KEY)
uv run uvicorn app.main:app --reload

# Full stack with Postgres
cp .env.example .env   # set MASTER_KEY
docker compose up --build

# Migrations
uv run alembic upgrade head

# Tests (in memory SQLite, rate limits off)
uv run pytest

# Lint and format
uv run ruff check .
uv run ruff format .

# Git hooks (ruff check + format)
uv run pre-commit install

# Bootstrap the first admin (only way to create admins)
uv run python -m app create-admin --username ... --email ...
```

## Specs

Stored in `docs/specs/NNNN-title/`. Feature scope lives in `docs/scope/scope.md`; workflow is GA (`/check verify`, `/test`, fresh model `/check review`, `/document`).

## Rules

- Layered monolith: `api/` routers stay thin, business logic in `services/`, queries in `repositories/`, validation shapes in `schemas/`, crypto primitives in `security/`, env config in `core/config.py`.
- Deny by default: every document action passes `services/policy.py`; only the `user` role touches documents, auditors authenticate but reach nothing.
- Audit in the same transaction: every allowed or denied attempt after identity is established appends to the hash chained `audit_log` via `services/audit.py`; never audit outside the business transaction.
- Async discipline: no blocking calls on the event loop; Argon2 and AES-GCM on large files go through `anyio.to_thread`. Ruff `ASYNC*` rules enforce this.
- Portability: migrations and queries use portable types only (`JSON` not `JSONB`); SQLite tests must match Postgres behavior.
- Secrets: `MASTER_KEY` is a base64 32 byte `SecretStr` from env; never in repo, DB, logs, or audit details. Store only hashes of tokens (sessions, MFA challenges).
- Uploads: validate size first (25 MB cap, chunked), then MIME allowlist, encrypt AES-GCM, store content addressed under `UPLOAD_DIR`.
- Sessions are opaque tokens stored as SHA-256 hashes with sliding expiry, revocation, and per request user re-reads so disable and privilege changes apply immediately.

## Agent skills

Project skills live in `.agents/skills/` (lockfile: `skills-lock.json`).

- [fastapi](.agents/skills/fastapi/): `fastapi/fastapi`, FastAPI routes, dependencies, streaming, serving frontends
- [pydantic](.agents/skills/pydantic/): `pydantic/skills`, data modeling and validation
- [python-configuration](.agents/skills/python-configuration/): `wshobson/agents`, pydantic-settings and env config
- [sqlalchemy](.agents/skills/sqlalchemy/): `TerminalSkills/skills`, SQLAlchemy 2.x ORM, async sessions, Alembic basics
- [alembic](.agents/skills/alembic/): `TerminalSkills/skills`, Alembic migrations for SQLAlchemy
- [sqlalchemy-alembic-expert-best-practices-code-review](.agents/skills/sqlalchemy-alembic-expert-best-practices-code-review/): `wispbit-ai/skills`, model and migration review
- [postgresql-table-design](.agents/skills/postgresql-table-design/): `wshobson/agents`, Postgres schema design
- [sql-optimization-patterns](.agents/skills/sql-optimization-patterns/): `wshobson/agents`, query optimization and indexing
- [async-python-patterns](.agents/skills/async-python-patterns/): `wshobson/agents`, asyncio and async API patterns
- [auth-implementation-patterns](.agents/skills/auth-implementation-patterns/): `wshobson/agents`, JWT, OAuth2, sessions, RBAC
- [reviewing-cryptography](.agents/skills/reviewing-cryptography/): `trilwu/secskills`, crypto misuse review
- [api-security-review](.agents/skills/api-security-review/): `OWASP/secure-agent-playbook`, OWASP API Top 10 review
- [pytest-asyncio-patterns](.agents/skills/pytest-asyncio-patterns/): `testland/qa`, async pytest setup and FastAPI test clients
- [pytest-coverage](.agents/skills/pytest-coverage/): `github/awesome-copilot`, coverage to 100%
- [structlog-python](.agents/skills/structlog-python/): `TerminalSkills/skills`, structured logging
- [docker-compose-patterns](.agents/skills/docker-compose-patterns/): `docker/skills`, compose services, healthchecks, volumes
- [docker-helper](.agents/skills/docker-helper/): `TerminalSkills/skills`, Dockerfiles and compose debugging
- [python-packaging](.agents/skills/python-packaging/): `wshobson/agents`, packaging Python projects
- [totp](.agents/skills/totp/): `bytesagain/ai-skills`, TOTP RFC 6238, pyotp, otpauth URIs, replay protection
- [uv](.agents/skills/uv/): `mitsuhiko/agent-stuff`, uv package manager and script workflows
- [pytest-fastapi-pattern](.agents/skills/pytest-fastapi-pattern/): `saintgo7/claude-skills`, FastAPI pytest integration patterns
- [pdf](.agents/skills/pdf/): `anthropics/skills`, PDF read, extract, merge, split, forms
- [docx](.agents/skills/docx/): `anthropics/skills`, Word document create, read, edit
- [xlsx](.agents/skills/xlsx/): `anthropics/skills`, spreadsheet read, write, analysis
- [pptx](.agents/skills/pptx/): `anthropics/skills`, PowerPoint create, read, edit
- [documents](.agents/skills/documents/): `magnus919/agent-skills`, office document generate, inspect, validate, fix
- [document-generator](.agents/skills/document-generator/): `lirrensi/skills-hoard`, create, read, edit, convert office docs and PDFs
- [py-git-hooks](.agents/skills/py-git-hooks/): `l-mb/python-refactoring-skills`, Python pre-commit hooks with ruff and type checkers
- [git-hooks-setup](.agents/skills/git-hooks-setup/): `wu529778790/shenzjd-skills`, git hooks setup including secret scanning
- [git-hooks](.agents/skills/git-hooks/): `narenaryan/agent-skills`, git hook mechanics reference
- [setup-pre-commit](.agents/skills/setup-pre-commit/): `andrewsrigom/agent-skills`, pre-commit automation (JavaScript centric)
- Workflow skills: `scope`, `architect`, `develop`, `check`, `test`, `debug`, `document`, `sync`, `audit` (`JavaScript-Mastery-Pro/skills` in `.agents/skills/`)

Declined: rate-limiting (yonatangross/orchestkit, no matching skill exists in that repo).
MCP servers: postgres-mcp (recommended, connect via `claude mcp add` or your MCP settings with `uvx postgres-mcp --access-mode=restricted`); mcp-docgen, doc-toolkit-mcp, mcp-documents-reader (recommended, office document reading).

## Context files

- [app/AGENTS.md](app/AGENTS.md): package map, security invariants, and gotchas inside `app/`

_Drafted by /audit from the repo, worth a quick human pass. Edit freely: once a line stops matching this draft, later runs treat it as curated and will flag rather than overwrite it._
