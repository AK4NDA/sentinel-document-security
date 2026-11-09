# app/

The whole backend lives here: one FastAPI app (`main.py`), a management CLI (`cli.py` / `__main__.py`, `python -m app create-admin` is the only way to create admin accounts), and six packages.

## Overview

Layered monolith. Routers in `api/` are thin: they parse requests, call one service function, and map results to responses. All policy, crypto, audit, and session logic lives in `services/`. `models/` holds SQLAlchemy declarative tables plus shared column helpers in `common.py` and enums in `enums.py`. `schemas/` holds Pydantic request/response shapes. `security/` holds crypto primitives (passwords, TOTP, blob encryption). `core/` holds settings, the async engine/session factory, and logging.

## Key files

| File | Owns |
|---|---|
| `main.py` | App factory, middleware, router registration, lifespan |
| `api/deps.py` | Session auth dependencies: cookie and Bearer, per request user re-read, MFA enrollment gate |
| `services/policy.py` | Deny by default access checks (clearance, role) |
| `services/audit.py` | Hash chained audit append, canonical hashing, `verify_chain`, `verify_summary`, `list_entries` |
| `services/documents.py` | Document loop: upload, read, version, delete with policy + audit |
| `services/mfa.py` | TOTP enrollment, pending challenge tokens, verify exchange |
| `services/sessions.py` | Opaque token issue, SHA-256 storage, sliding expiry, revocation |
| `security/encryption.py` | AES-GCM master key blob encryption |
| `models/audit_log.py` | Append only audit table; `prev_hash` unique prevents chain forks |
| `cli.py` | `create-admin` bootstrap command |

## Conventions

- Async everywhere: services take `AsyncSession`, endpoints use `Depends`; blocking crypto goes through `anyio.to_thread`.
- One audited behavior per route: success, denial, and enrollment gate share one action name; allow and deny commit in the same transaction as the mutation.
- Audit actor is stored as a snapshot (id, username, role), never a live FK, so records survive deletes.
- Classification is an `IntEnum` rank 1 to 5 (`UNCLASSIFIED` to `TOP_SECRET`); read allowed when `user.clearance >= classification`, writes pinned to the writer's clearance (strict no write down).
- `mfa_challenges` and sessions store only SHA-256 token hashes; TOTP secrets are AES-GCM sealed on the user row.
- Account lockout (5 failures, 15 minutes) is shared across login, MFA verify, and enroll confirm via `services/lockout.py`.

## Gotchas

- The audit chain genesis `prev_hash` is 64 zero characters, not NULL; `prev_hash` has a unique constraint, so concurrent appends retry on `AuditChainFork`.
- Enabling a disabled account revives its unexpired sessions; revoke sessions before re-enabling if the disable was for compromise.
- Tests override `get_db` with an in memory SQLite factory from `tests/conftest.py`; set env vars before importing `app` modules.
- `MASTER_KEY` must be base64 of exactly 32 bytes or settings validation fails at startup.

## Related specs

- [0001 stack and architecture](../docs/specs/0001-stack-architecture/index.md)
- [0002 data model](../docs/specs/0002-data-model/index.md)
- [0003 core classified document loop](../docs/specs/0003-core-classified-document-loop/index.md)
- [0004 MFA and login protection](../docs/specs/0004-mfa-login-protection/index.md)
- [0005 administration and account lifecycle](../docs/specs/0005-administration-account-lifecycle/index.md)
- [0006 auditor access and log verification](../docs/specs/0006-auditor-access-log-verification.md)

_Drafted by /audit from the repo, worth a quick human pass. Edit freely: once a line stops matching this draft, later runs treat it as curated and will flag rather than overwrite it._
