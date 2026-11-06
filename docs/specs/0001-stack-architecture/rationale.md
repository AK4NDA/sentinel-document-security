# Rationale: 0001 stack and architecture

## Context

The classified document access control system needs a backend that can enforce a deny by default policy engine, store encrypted files, keep a tamper evident audit log, and serve a deferred React frontend later. The product brief already names the direction: Python 3.11 or newer, FastAPI, Pydantic, PostgreSQL with SQLite for development, SQLAlchemy and Alembic, Argon2 password hashing, TOTP MFA, AES-GCM encryption, slowapi rate limiting, pytest, and Docker compose. The scope fixes the delivery shape: backend first, Tracer Bullet slices, GA workflow tier, one Docker command for the demo.

> ⚠️ Premise note: this stack builds custom authentication (session issuance, storage, revocation, and later TOTP enrollment) rather than adopting an auth framework. That is a deliberate trade: the role and clearance model, the audit log, and the separation of duties are bespoke enough that a general auth framework would still need a custom policy layer on top, and the MFA flow gets its own spec in slice 2. The risk is real (session fixation, token leakage, timing attacks are each a breach), so the GA tier review and the `reviewing-cryptography` skill apply to every auth touching slice, and `/develop` must follow current OWASP session guidance. If this premise feels wrong, the alternative is adopting a proven auth library now and constraining it; the engineer chose the custom path knowingly through the product brief.

The decision this spec records is the ratification of that direction plus the finer choices the brief leaves open: sync versus async data access, the session mechanism, where the encryption master key lives, how configuration and secrets are handled, logging shape, API versioning, and packaging.

## Options considered

### Option 1: Python backend on FastAPI with async SQLAlchemy and PostgreSQL

The stack the product brief describes, made precise: FastAPI and Pydantic v2 on Python 3.12, SQLAlchemy 2.0 in its async style over asyncpg, Alembic migrations, Postgres in compose with SQLite through aiosqlite for dev and tests, server side opaque sessions in a Postgres table, argon2-cffi for Argon2id hashing, pyotp for TOTP, `cryptography` for AES-GCM, pydantic-settings for config, slowapi for rate limits, structlog for JSON logs, pytest for tests, uv for dependency management, and Docker compose for packaging.

**Pros**:
- Matches the stated direction, so nothing is reopened; every library named in the brief has a current, maintained release.
- Async end to end suits an IO heavy API (file encryption, DB writes per request) without mixing sync and async styles.
- Server side sessions give instant revocation, which the security model needs; Postgres is already required, so no new infrastructure.
- Boring, well documented components with large communities; operable at 2am.

**Cons**:
- Custom auth code carries more risk than a framework, as noted in the premise.
- Async SQLAlchemy punishes accidental blocking calls and has a learning curve.
- SQLite dev diverges from Postgres in subtle ways; discipline is required to stay portable.

### Option 2: Django with Django REST Framework

A batteries included Python framework: built in admin, ORM, auth, and migrations in one package.

**Pros**:
- Auth, admin, and ORM come integrated; less custom security code to get wrong.
- Massive ecosystem and documentation.

**Cons**:
- Async support is partial and historically second class; the modern async SQLAlchemy path is cleaner for this API shape.
- The built in admin and auth opinions do not map onto the clearance and role model; much of it would be bypassed anyway.
- Heavier runtime and request model than needed for a JSON API serving a deferred SPA.

### Option 3: TypeScript backend (NestJS or Hono) on Node

One language across backend and the deferred React frontend.

**Pros**:
- Shared language and types with the future frontend; large hiring pool.
- Mature ecosystem for JWT auth and validation.

**Cons**:
- The product brief explicitly chose Python; reversing that is a bigger decision than this spec should carry.
- The crypto, TOTP, and audit hashing libraries are first class in Python and merely adequate in Node.
- Two reasonable stacks means the team context, not the technology, should decide; nothing in the brief suggests the Python choice was wrong.

### Option 4: Go backend

A compiled service known for concurrency and operational simplicity.

**Pros**:
- Excellent concurrency and a single static binary; strong for high throughput APIs.
- Good standard library crypto.

**Cons**:
- Slower iteration for CRUD heavy feature work; more boilerplate per endpoint.
- Thinner ecosystem for the specific pieces (TOTP helpers, ORM maturity, Alembic equivalents) compared to Python.
- Same objection as Option 3: the brief chose Python deliberately.

## Rationale

The product brief already made the language and framework call, and nothing surfaced in the design conversation gives a reason to reopen it; this spec ratifies that call and resolves the open finer decisions. Async SQLAlchemy was chosen over sync because the API is IO bound (encryption, DB writes, file reads per request) and the modern recommended default, with the caveat that sync calls inside async endpoints must be avoided; the runner up, sync SQLAlchemy in FastAPI's threadpool, remains viable if async friction proves heavy during the build. Server side opaque sessions in Postgres beat JWT because revocation is a first class requirement of this system's security model, and they reuse the database that must exist anyway. The master encryption key lives in the environment or a mounted Docker secret because that is the correct prototype boundary; the spec records KMS or HSM as the production follow up rather than building key hierarchy now. SQLite for dev and tests keeps the inner loop fast while Postgres remains the real target, provided queries stay portable.

The landscape check (web verified, late 2026) confirmed the chosen libraries are current: SQLAlchemy's asyncio extension is first class, pydantic-settings is actively maintained, slowapi ships regular releases, and structlog's stdlib interop is the documented path to JSON logs. The FastAPI OAuth2 JWT tutorial now uses PyJWT, which informed the session decision only by contrast: even the official JWT path requires a server side store for revocation in this threat model.

## References

**Project sources** (verifiable, in this repo):
- `docs/scope/scope.md`: the feature scope this spec serves (feature 1, Stack & architecture; build approach Tracer Bullet; workflow GA)
- The product brief supplied with `/scope`: stated stack (Python, FastAPI, Pydantic, PostgreSQL/SQLite, SQLAlchemy, Alembic, Argon2, pyotp, AES-GCM, slowapi, pytest, Docker compose)
- Installed community skills under `.agents/skills/`: `fastapi`, `pydantic`, `sqlalchemy-alembic-expert-best-practices-code-review`, `pytest-coverage`, `reviewing-cryptography`, `docker-compose-patterns`

**Practices & standards**:
- Layered monolith before services: extract only on measured bottleneck or ownership boundary
- Boring technology: proven tools with large communities over novel ones absent a forcing constraint
- Server side sessions for revocation sensitive systems, per OWASP session management guidance
- Secrets via environment or mounted secret, never in the repo or database
- Authenticated encryption (AES-GCM) for stored sensitive files

**Links** (web verified only):
- SQLAlchemy asyncio extension docs: https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html
- pydantic-settings on PyPI: https://pypi.org/project/pydantic-settings/
- structlog standard library interop: https://structlog.org/en/stable/standard-library.html
- slowapi on PyPI: https://pypi.org/project/slowapi/
- argon2-cffi docs: https://argon2-cffi.readthedocs.io
- FastAPI OAuth2 JWT tutorial (informed the session tradeoff): https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/
