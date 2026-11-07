# Review, feature/core-document-loop, 2026-11-07

**Reviewed by**: Devin review subagent (author on Devin)
**Scope**: 28 files, branch vs main (merge-base f296c79) plus uncommitted working-tree changes
**Verdict**: Changes requested

## Summary

This change implements spec 0003 end to end: session auth (cookie + Bearer), admin user management plus the `create-admin` CLI, the six document endpoints behind strict Bell-LaPadula plus role gates, AES-GCM content-addressed blob storage, and a hash-chained audit log with bounded fork retry and canonical JSON hashing per AC-15. The code is well structured, the audit fail-closed semantics are genuinely enforced inside the business transaction, and the 75-test suite passes cleanly (verified locally). The headline issues are two contract gaps: size/mime-rejected uploads escape the audit trail that AC-14 requires, and the 25 MB cap is enforced only after the entire upload has been buffered into memory, contrary to the spec 0001 "before buffering" rule.

## Major

### 🟠 413/415 upload rejections are not audited, `app/services/documents.py:53`

**Problem**: `check_upload()` raises 413/415 before any `audit.append`/`record_denial` call in both `upload()` (line 129) and `edit()` (line 297). AC-14 requires an `audit_log` row for "every call to a protected endpoint that reaches authorization," and explicitly exempts only pre-identity rejections (missing/invalid session, 422 validation, 429). A 413 or 415 happens after a valid session and the officer role gate, i.e. after authorization was reached, so it is a denied `document.upload`/`document.edit` attempt that currently leaves no audit trace.

**Why it matters**: The product's core promise is "audit every allowed and denied attempt." A user probing the upload surface with oversized or disallowed files produces zero forensic record, and this is a silent divergence from the written contract that a slice-4 auditor would trip over.

**Suggested fix**: Catch the `HTTPException` from `check_upload` (or move the check inside the audited unit) and write a `denied` audit row with `reason` like `too_large`/`unsupported_media_type` before re-raising, mirroring how `_deny` handles 403/404.

### 🟠 Upload size cap enforced after full buffering, `app/api/documents.py:39`

**Problem**: Both `upload_document` (line 39) and `create_version` (line 100) call `await file.read()`, which loads the entire request body into memory, and only then does `check_upload` compare `len(content)` against `MAX_UPLOAD_BYTES`. Spec 0001 states the 25 MB maximum must be "enforced before buffering."

**Why it matters**: Any authenticated officer (or anyone who obtains a session) can POST an arbitrarily large body and force full in-memory buffering per request — an easy memory-exhaustion DoS on an API that has rate limiting only on `/v1/auth/*`. Starlette's spooled temp file mitigates disk usage but `file.read()` still materializes all bytes as a Python `bytes`.

**Suggested fix**: Check `file.size` (or stream chunks up to `MAX_UPLOAD_BYTES + 1` and abort early) before reading the full payload, and reject with 413 without buffering the whole body.

## Minor

### 🟡 Session sliding expiry is never committed on `/v1/auth/me`, `app/services/sessions.py:72`

**Problem**: `sessions.validate` updates `last_seen_at`/`expires_at` via `db.flush()`, but `get_db` (`app/core/database.py:22`) never commits — persistence depends entirely on the endpoint's service committing later. `/v1/auth/me` has no service write, so the slide is rolled back on session close. Auditors, whose only endpoint is `/me` (AC-19), get a fixed 8-hour session that expires on schedule even under active use, and any future read-only endpoint silently inherits the same bug.

**Why it matters**: AC-3 requires `expires_at` to slide per request. It fails safe (sessions expire sooner, not later) but it is a real contract deviation and a fragile implicit-commit design.

**Suggested fix**: Commit the session slide explicitly — e.g. `await db.commit()` after `validate`'s flush, or make `get_db` commit on clean exit — rather than relying on downstream services.

### 🟡 Edit accepts an empty-string title, `app/api/documents.py:90`

**Problem**: `create_version` declares `title: str | None = Form(default=None, max_length=300)` with no `min_length`, and `edit()` applies it whenever `title is not None`. `title=""` therefore overwrites `documents.title` with an empty string, violating the 1–300 character contract that upload enforces.

**Suggested fix**: Add `min_length=1` to the edit form field (or treat empty as "unchanged" in the service).

### 🟡 `logout` audit append has no chain-fork retry, `app/services/auth.py:86`

**Problem**: Unlike every other audited write, `logout` calls `audit.append` directly with a single `db.commit()` and no `AuditChainFork` retry. On a fork the exception propagates as a 500 and the whole transaction — including `sessions.revoke` — rolls back, so the user is told the logout failed while remaining logged in (retrying will likely succeed).

**Suggested fix**: Route logout through `audit.transact` like the other services, or catch `AuditChainFork` and retry the revoke+audit unit.

### 🟡 Policy module and helpers are dead code duplicating live logic, `app/services/policy.py:1`

**Problem**: `policy.can_access_documents`/`can_read`/`write_classification` are never called by request-path code — enforcement is inlined in `deps.require_role` and `documents._readable_document`/`edit`. `audit.append_with_retry` (`app/services/audit.py:196`) and `DocumentUploadForm` (`app/schemas/documents.py:23`) are likewise unused. Two sources of truth for the BLP read rule will drift.

**Suggested fix**: Either wire `policy.py` into the request path (preferred — it is the spec's "small deny by default policy module") or delete it and the other dead helpers.

### 🟡 Login allows username enumeration via timing, `app/services/auth.py:52`

**Problem**: Unknown usernames return after a fast DB lookup; known usernames pay an argon2id verify (~tens of ms). The response-time difference reliably distinguishes valid usernames, which matters for a system whose audit log records `attempted_username`.

**Suggested fix**: Run a dummy `verify_password` against a fixed hash when the user is not found (or not active) so both paths cost the same.

### 🟡 Rate limiting covers only `/login`, `app/api/auth.py:32`

**Problem**: AC-17 says "auth endpoints are rate limited via slowapi using `RATE_LIMIT_AUTH`"; only `POST /v1/auth/login` carries the limiter. `/v1/auth/logout` and `/v1/auth/me` are unlimited. Low risk, but the contract says endpoints plural and `settings.rate_limit_default` exists unused.

**Suggested fix**: Apply the limiter to the whole auth router (or document that only login is intentionally limited).

### 🟡 Missing/corrupt blob paths produce unaudited 500s, `app/services/documents.py:242`

**Problem**: `read_content` calls `blob_store.load` before writing any audit row; a missing file (`FileNotFoundError`) or GCM `InvalidTag` escapes as an unaudited 500. Only the post-decrypt sha256 mismatch path is audited. Edge case, but it is another hole in "every attempt reaching authorization is audited."

**Suggested fix**: Wrap the load/decrypt in the same audited-denial pattern used for the integrity mismatch.

### 🟡 Coverage gaps against the spec's critical scenarios

**Problem**: The suite is strong (27 API + 16 service tests, all passing — verified), but: (a) no test exercises the AC-1 migration upgrade/downgrade; (b) the "two concurrent edits → loser gets 409" critical scenario has no test (understandable on SQLite, but the 409 mapping in `edit` is untested); (c) nothing asserts whether 413/415 attempts should be audited, which is exactly the gap in the first Major finding.

**Suggested fix**: Add an alembic upgrade/downgrade round-trip test and a service-level test forcing `uq_document_versions_number` to verify the 409 path.

## Nits

- ⚪ `app/services/auth.py:7` — service layer imports `AuthContext` from `app.api.deps`, inverting the usual api→services dependency direction; pass primitives or move `AuthContext` to a neutral module.
- ⚪ `app/cli.py:54` — `audit.append` can raise `AuditChainFork` (not `IntegrityError`), which escapes the `except IntegrityError` handler as an unhandled traceback; also `--username`/`--email` get no format validation.
- ⚪ `app/core/config.py:27` — `rate_limit_default` is defined but never wired to a limiter.
- ⚪ `app/services/sessions.py:14` — `ABSOLUTE_CAP` is hardcoded at 24h while spec 0002 allows config override of the idle/absolute values; only the idle TTL is configurable.
- ⚪ `app/api/deps.py:57` — `require_role` denials record `target_type="user"`, `target_id=<self>`; a null/document-agnostic target would better match the audited-action vocabulary.
- ⚪ `app/api/documents.py:30` — `title` min_length=1 still accepts whitespace-only titles.
- ⚪ `app/services/documents.py:350` — the broad `except IntegrityError → 409` in `edit` would also mislabel a non-version integrity failure as a version conflict.

## Strengths

- Audit fail-closed is real, not aspirational: allowed-operation audit rows are appended inside the same transaction as the business write, actor snapshots are taken as primitives before any rollback (`actor_kwargs`), and denials commit independently via `record_denial`.
- The chain-fork retry design is correct and subtle: `prev_hash` uniqueness plus whole-unit retry with `occurred_at` preserved, `_is_chain_fork` discrimination, and `verify_chain` recomputing from canonical fields — all verified by tests including a tamper-detection test.
- Security details are right: argon2id, AES-GCM with random 12-byte nonces, SHA-256 session token hashes, HttpOnly/SameSite=Lax cookie with Secure gated on `ENV=prod`, content-addressed blob paths matching spec 0001, sanitized download filenames, and the user row re-read per request so `is_active`/role/clearance changes take effect immediately.
- The edit path correctly closes the downgrade hole (read predicate as edit precondition) and computes `version_number` inside the transaction with a clean 409 mapping.

## Test coverage

75 tests pass (verified by running `pytest`): 27 API acceptance tests covering every AC's happy and deny paths, plus 16 service unit tests for crypto, canonicalization, sessions, and document helpers, plus 32 pre-existing model tests. Notable untested surface: the Alembic migration round-trip (AC-1), the concurrent-edit 409 path (AC-10 critical scenario), audit behavior on 413/415 rejections (the Major finding above), session-slide persistence through `/me`, and bearer-token access on document endpoints (only `/me` is tested with Bearer).
