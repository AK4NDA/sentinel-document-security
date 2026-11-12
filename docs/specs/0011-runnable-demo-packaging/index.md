# 0011. Runnable demo packaging

**Date**: 2026-11-11
**Status**: Accepted

## Summary

This feature makes the whole system demoable with one Docker Compose command plus two short commands. A new `seed-demo` CLI command creates a fixed cast of demo users (admin, auditor, and three officers across the clearance range) with documented passwords and enrolled TOTP secrets, and a Python walkthrough script drives a live API through every feature surface including the MFA login challenge, ending with a verified audit trail. No schema changes and no new API endpoints; the feature is packaging and scripting around what already exists.

## Requirements

**User stories**:

- As an evaluator or presenter, I want one compose command to boot the full system so that I can demo without setup steps.
- As a demo runner, I want seeded users covering every role and clearance plus a scripted walkthrough so that the tour is repeatable and shows both allow and deny paths.

**Acceptance criteria** (the contract, each criterion is IDed and independently checkable):

- **AC-1**: `docker compose up --build` from a clean checkout, with `MASTER_KEY` set, brings up Postgres and the API; the API container runs `alembic upgrade head` on boot and then serves `/healthz` and `/readyz` successfully.
- **AC-2**: `python -m app seed-demo` creates the demo cast defined in Feature design: one admin, one auditor, and three `user` role officers at Confidential, Secret, and Top Secret clearances, each with a fixed documented password and a fixed documented TOTP secret enrolled; every account can complete the full login flow (password login returning the MFA pending token, then TOTP verify) and read its own profile.
- **AC-3**: `seed-demo` is idempotent: a second run against the same database exits successfully, creates no duplicates, and tops up only missing pieces.
- **AC-4**: `seed-demo` refuses to run unless `ENV` is `dev` (the only non production value `core/config.py` accepts besides `prod`), exiting nonzero with a clear message otherwise.
- **AC-5**: every account `seed-demo` creates produces `user.create` audit entries (marked as seeded) in the hash chained audit log, and chain verification passes after seeding.
- **AC-6**: demo credentials (usernames, passwords, roles, clearances) are defined once in a shared module imported by both the seed command and the walkthrough script, so the two cannot drift apart.
- **AC-7**: `scripts/walkthrough.py` runs the full feature tour against a live API: password plus TOTP logins for the seeded roles; document upload, read, edit (new version), and delete across multiple classifications by the officer personas; at least one denied read by the under cleared officer against a higher classified document; a version restore; a search that does not leak higher classified content; a share grant and revoke; alert listing and acknowledge by admin or auditor; and audit entries listing plus chain verify. Each step prints a clear label and its result.
- **AC-8**: the walkthrough stops at the first failed step, prints the step name plus expected versus actual, and exits nonzero.
- **AC-9**: the walkthrough waits for the API to become ready before starting (bounded polling of `GET /readyz`) and, on any 429 response, prints a clear hint naming `RATE_LIMIT_ENABLED=false` for repeated demos and exits nonzero like any other failed step.
- **AC-10**: the walkthrough generates its sample upload files at runtime into a temporary directory (at least one plain text file and one Office document so search extraction is exercised), sends explicit MIME types on the multipart parts, gives every uploaded document a per run unique title so repeat runs never collide, and removes the temp files when finished; `--base-url` or `WALKTHROUGH_BASE_URL` selects the target, defaulting to `http://localhost:8000`.
- **AC-11**: the walkthrough warns and requires an explicit `--allow-remote` flag when the base URL host is not localhost, so demo passwords are not sent to arbitrary hosts by accident.
- **AC-12**: `docs/demo/walkthrough.md` documents the full quickstart: environment setup, compose up, the seed command, the walkthrough run, the demo credential table, what each tour step demonstrates, and the note that rate limits can be disabled for repeated demos.
- **AC-13**: after a full walkthrough run, audit chain verification reports valid and the log contains entries covering both allowed and denied actions from the tour.

## Decision

**Chosen option**: Option 1: Manual seed CLI plus host run Python walkthrough

Seeding is an explicit `python -m app seed-demo` subcommand (run inside the container via `docker compose exec`, or locally via `uv run`), and the tour is `scripts/walkthrough.py`, a Python httpx client run from the host against `localhost:8000`, with a markdown quickstart in `docs/demo/`. (basis: project AGENTS.md CLI convention from spec 0003; httpx already a project dependency; scope feature 12 asks for one compose command plus seeded users and a scripted walkthrough)

**Implementation skills**: `docker-compose-patterns` (`docker/skills`, `.agents/skills/docker-compose-patterns/`) · `pytest-asyncio-patterns` (`testland/qa`, `.agents/skills/pytest-asyncio-patterns/`) · `uv` (`mitsuhiko/agent-stuff`, `.agents/skills/uv/`)

## Feature design

**Data model sketch**:

No new tables, columns, or migrations. The feature writes only through existing surfaces: `users` rows via the same creation path style as `create-admin`, `sessions` via the normal login endpoint, `audit_log` entries via `services/audit.append`, and whatever business rows the walkthrough creates through the API. The demo cast itself is code, not schema: a shared constants module (see below) plus the seed function.

**Demo cast** (the shared constants module, imported by `cli.py` and `scripts/walkthrough.py`; usernames unique, emails `demo-<name>@example.invalid`, display names human readable, all passwords at least 12 characters, all TOTP secrets fixed base32 strings documented alongside):

| Username | Role | Clearance | Tour role |
|---|---|---|---|
| `demo-admin` | admin | Top Secret | login, profile, user list, alerts, audit entries and verify; cannot touch documents by design |
| `demo-auditor` | auditor | Unclassified | login, alerts list and acknowledge, audit entries and verify; reaches nothing else by design |
| `demo-officer-low` | user | Confidential | denied read of the Secret document, search that must not leak, share grantee |
| `demo-officer-mid` | user | Secret | uploads the Secret document that `demo-officer-low` is denied, edits and restores it |
| `demo-officer-high` | user | Top Secret | uploads the Top Secret document, exercises the sensitive read alert, owns the delete demo |

The cast needs at least two `user` role officers because admins and auditors are hard denied on every document route (`require_role(UserRole.USER)`), and the denied read needs a named owner above a named reader below.

**State transitions**:

None. Seeded users start `is_active=True` with `totp_enabled_at` set and the TOTP secret AES-GCM sealed on the user row, matching the state a normally enrolled user reaches through `mfa/enroll/confirm`. The MFA enrollment gate in `api/deps.py` therefore never triggers for demo users: password login returns the MFA pending token and `mfa/verify` completes the session, which is exactly the flow a real enrolled user follows.

**API surface**:

No new HTTP endpoints. The feature adds two command surfaces:

| Surface | Kind | Key inputs | Key outputs | Auth |
|---|---|---|---|---|
| `python -m app seed-demo` | CLI subcommand in `app/cli.py` | env: `DATABASE_URL`, `ENV`, `MASTER_KEY`; no flags required | per user `created`, `repaired`, or `exists` line, summary count, exit code | runs with the app's own DB session, same trust level as `create-admin` |
| `uv run python -m scripts.walkthrough` | Python module (`scripts/__init__.py` added so `app.*` imports resolve) | `--base-url` (opt), `WALKTHROUGH_BASE_URL` (opt), `--allow-remote` (flag) | labeled step log, pass/fail exit code | logs in as each seeded user: `POST /v1/auth/login` returns the MFA pending token, `POST /v1/auth/mfa/verify` exchanges it for the `session` cookie |

The walkthrough runs as `uv run python -m scripts.walkthrough` from the repo root (never `python scripts/walkthrough.py`, which would not put the repo root on `sys.path`). It keeps one `httpx.Client` per persona so session cookies never bleed between users, and every step asserts on live responses. Wire details the steps rely on: upload is `POST /v1/documents` multipart with fields `file`, `title`, `description`; edit is `POST /v1/documents/{id}/versions` (there is no PATCH); version content is `GET /v1/documents/{id}/versions/{n}/content`; restore is `POST /v1/documents/{id}/versions/{n}/restore`; share grant is `POST /v1/documents/{id}/shares` with body `{"user_id": <uuid>}` after resolving the grantee via `GET /v1/users/lookup?username=demo-officer-low` (prefix match returning a list; take the first hit) as an officer; document ids come from create responses, never from assumptions about empty state. The full step map lives in `docs/demo/walkthrough.md`; the script implements it against these existing endpoints (prefix `/v1`): `auth/login`, `auth/mfa/verify`, `auth/logout`, `auth/me`, `documents` upload/read/edit/delete plus `/{id}/content`, `documents/{id}/versions` list, version content download, and restore, `documents/search`, `documents/{id}/shares` grant/list/revoke, `shares/mine`, `users/lookup`, `alerts` list and `/{id}/acknowledge`, `audit/entries` and `audit/verify`. Exact paths are already defined by specs 0003 through 0010; the script consumes them, it does not extend them.

**Value sourcing**:

| Action | Value produced / displayed | Source |
|---|---|---|
| seed demo users | usernames, emails, display names, passwords, roles, clearances, TOTP secrets | shared demo constants module (single source per AC-6), imported by `cli.py` and `scripts/walkthrough.py` |
| seed demo users | password hash, sealed TOTP secret, `totp_enabled_at` | `security/passwords.hash_password_async` and the MFA secret seal helper, same primitives as `create-admin` and enroll confirm |
| seed demo users | `user.create` audit details | `details={"via": "seed-demo", "role": ..., "clearance": ...}` mirroring the `create-admin` `"via": "cli"` convention; actor columns stay null (system action) |
| seed idempotency | create vs repair vs skip decision | `SELECT` by username; missing users are created, existing users whose role, clearance, or TOTP state drifted from the constants are repaired to match, matching users are skipped |
| walkthrough login | MFA pending token | `pending_token` field of the `POST /v1/auth/login` response when `totp_enabled_at` is set |
| walkthrough login | TOTP code | `pyotp.TOTP(<fixed secret from constants>).now()` (pyotp already a dependency) |
| walkthrough login | session | `session` cookie set by `POST /v1/auth/mfa/verify`, held per persona `httpx.Client` |
| walkthrough base URL | request target | `--base-url` arg, else `WALKTHROUGH_BASE_URL` env, else `http://localhost:8000` |
| walkthrough readiness | API up signal | bounded polling of `GET /readyz` (runs `SELECT 1`, semantically correct) before the first step |
| walkthrough sample files | upload bytes | generated at runtime into a temp dir: `.txt` (`text/plain`) and `.docx` via `python-docx` (already a dependency); explicit `content_type` set on each multipart part so the mime allowlist accepts them |
| walkthrough document identity | doc ids, version numbers, share target user id | captured from create/upload/lookup response bodies and threaded through later steps; titles carry a per run unique suffix |
| walkthrough step expectations | pass/fail per step | live API responses asserted inline per step (status code plus key field) |
| walkthrough remote guard | allow/deny decision | parsed host of base URL; non localhost requires `--allow-remote` |
| walkthrough rate limit hint | operator guidance | any HTTP 429 response triggers the printed `RATE_LIMIT_ENABLED=false` hint and a nonzero exit |
| docs credential table | demo usernames, passwords, TOTP secrets | same shared constants module, transcribed into `docs/demo/walkthrough.md` |

**Key invariants**:

- `seed-demo` is the only path that creates the demo admin; it is guarded by the `ENV` check (AC-4, dev only since `core/config.py` accepts just `dev` and `prod`) so it cannot run against a production configured environment, and `create-admin` remains the tool for real admins.
- Demo passwords and TOTP secrets are intentionally public and committed; they protect only a local demo instance and are never valid elsewhere because of the ENV guard on seed and the localhost guard on the walkthrough.
- Every seeded user has TOTP enrolled with a fixed secret, so the MFA enrollment gate never triggers and the walkthrough exercises the real `login` to `mfa/verify` challenge every enrolled user goes through.
- Seeding is idempotent and self healing: keyed on username, it creates missing users and repairs drifted role, clearance, or MFA state back to the constants, all in one transaction so a mid seed failure leaves no partial cast.
- The audit chain must verify after seeding and after the full walkthrough; every tour action lands in the same chained log as real usage because the script only calls public endpoints.
- The walkthrough uses per run unique document titles and captured ids, so repeat runs against the same database never depend on empty state; uploaded documents persist by design (no delete all step).
- One `httpx.Client` per persona; session cookies never cross users.
- No schema migration, no new env var on the app, no new dependency (`httpx` is a dev dependency used from the host via `uv run`; `pyotp` and `python-docx` are already main dependencies).

**Security model**:

The demo credentials (passwords and TOTP secrets) are a deliberate, documented exception to secret hygiene: they are fake, local only, and meaningless against any non demo deployment. Three guards keep that honest: `seed-demo` refuses any `ENV` other than `dev`, the walkthrough refuses non localhost base URLs without `--allow-remote`, and both live behind the same repo access as the code itself. The script must never log passwords, TOTP secrets, pending tokens, or session cookies beyond what a failed step needs to debug. Rate limits are part of the demo reality: the auth bucket is per client IP so all localhost logins share it, which is why the docs tell repeat presenters to set `RATE_LIMIT_ENABLED=false`. No regulated data is involved; uploaded demo files contain only innocuous placeholder text.

**Configuration required**:

- No new application environment variables. `.env.example` and compose are unchanged.
- Script level only: `WALKTHROUGH_BASE_URL` (optional env, same role as `--base-url`), `--allow-remote` (flag). Documented in `docs/demo/walkthrough.md`.

**Critical test scenarios** (each maps to an acceptance criterion in ## Requirements):

- Happy path: clean compose up, `seed-demo`, full `walkthrough.py` run green end to end including TOTP verify on every login, audit verify valid, verifying **AC-1** through **AC-3**, **AC-5** through **AC-10**, **AC-13**
- Idempotency: run `seed-demo` twice against the same database; second run reports all users exist, creates nothing, exit 0; a drifted user (wrong clearance or missing MFA) is repaired to the constants, verifying **AC-3**
- Guard: `ENV=prod python -m app seed-demo` exits nonzero with the refusal message and creates nothing, verifying **AC-4**
- Guard: `walkthrough.py --base-url http://example.com` exits with the remote warning unless `--allow-remote` is passed, verifying **AC-11**
- Failure case: walkthrough against a stopped API exhausts `/readyz` polling with a clear timeout message; a mid tour step returning an unexpected status stops the run naming the step; a 429 prints the rate limit hint and exits nonzero, verifying **AC-8**, **AC-9**
- Ordering: alert steps run after the denied read so an open `denied_access` alert exists; the acknowledger is admin or auditor, never the denied officer (self acknowledge is 403 by design), verifying **AC-7**

## Build plan

Tracer Bullet ordering: the thinnest real slice is seed plus one login proven end to end, then thicken to the full tour and docs.

1. Shared demo constants module (the full cast: usernames, emails, display names, passwords, roles, clearances, fixed TOTP secrets) plus `seed-demo` subcommand in `app/cli.py` with the dev only ENV guard, username keyed create/repair/skip logic in one transaction, password hashing, TOTP secret sealing with `totp_enabled_at` set, `user.create` audit entries, and console summary, satisfies **AC-2**, **AC-3**, **AC-4**, **AC-5**, **AC-6**
2. Pytest suite for the seed path: creates the full cast with working password plus TOTP login, idempotent re-run, drift repair, ENV refusal, audit entries present and chain verifies, satisfies **AC-3**, **AC-4**, **AC-5**
3. `scripts/__init__.py` plus `scripts/walkthrough.py` skeleton: argument parsing, base URL resolution, localhost guard, `/readyz` polling, per persona `httpx.Client` login helper performing `login` then `mfa/verify` with a `pyotp` generated code, and the labeled step runner that stops on first failure and maps 429 to the rate limit hint, satisfies **AC-8**, **AC-9**, **AC-11**
4. Walkthrough tour steps in dependency order: all seeded logins, officer document lifecycle across classifications including the denied read (which must precede the alert steps), version list/download/restore, search including the non leak check, share lookup/grant/revoke, alert list and acknowledge by auditor, audit entries and verify; runtime fixture generation with explicit MIME types, per run unique titles, id threading, and temp cleanup, satisfies **AC-7**, **AC-10**
5. `docs/demo/walkthrough.md` quickstart with credential table (usernames, passwords, TOTP secrets), the step map, compose and seed commands, the `uv run python -m scripts.walkthrough` invocation, the `.env`/`MASTER_KEY` note for local runs, and the rate limit note, satisfies **AC-12**
6. End to end proof: `docker compose up --build`, `docker compose exec api python -m app seed-demo`, `uv run python -m scripts.walkthrough` from the host, final audit verify, satisfying **AC-1**, **AC-13**; fold any compose or Dockerfile gap found into this task

## Consequences

**Positive**:

- The entire product becomes demoable in minutes: one compose command, one seed command, one script, and the audit trail shows the whole story.
- The walkthrough doubles as living API documentation; when an endpoint changes, the script breaks loudly instead of docs drifting silently.
- Seed logic reuses the CLI and audit conventions, so demo users are indistinguishable from real ones in the data model.

**Negative / tradeoffs**:

- Fixed demo passwords and TOTP secrets live in the repo forever; the ENV and localhost guards bound the blast radius but a determined attacker who reaches a dev instance seeded this way gets known credentials plus working second factors. Accepted because the demo is local only; the secrets are fake by design.
- The walkthrough couples to the current `/v1` surface; every future endpoint change can break the script, which is intended (loud failure) but adds a maintenance surface.
- `seed-demo` creates an admin without the interactive `create-admin` flow and can repair drifted users; the dev only ENV guard is the only thing standing between it and a real environment, so it must stay strict.
- The walkthrough depends on the auth rate limit bucket shared per client IP; repeat demos need `RATE_LIMIT_ENABLED=false` or patience, documented rather than engineered around.
- Compose boot (AC-1) is largely already built by spec 0001; this spec verifies and documents it rather than adding machinery, so surprises there are possible but unlikely.

**Neutral**:

- New directories `scripts/` and `docs/demo/`; no changes to app config, schema, or dependencies.
- The demo cast is code, so changing demo users is a code change reviewed like any other.

## Follow-up

- [ ] If the demo grows, consider a `make demo` or compose profile wrapping the three commands; deferred until the manual flow proves awkward.
- [ ] The deferred scope item "email alert channel" remains out; the demo shows in app alerts only.

## Rationale

Reasoning and options: see [rationale.md](rationale.md)
