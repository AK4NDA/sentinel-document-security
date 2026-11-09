# Review, stack-architecture (spec 0001 scaffold), 2026-11-09

**Reviewed by**: SWE-2 Flash (author on SWE-2 Flash — same model family, so the cross-model blind-spot guarantee is degraded; this review shares the author's priors)
**Scope**: ~20 scaffold files at HEAD (pyproject/uv.lock, Dockerfile, docker-compose.yml, .env.example, app/core, app/api/{health,deps}, app/security, app/services/{sessions,blob_store,audit}, app/models, alembic/, tests/conftest), reviewed against the spec 0001 "Scaffold contract" and "Proposed stack" sections
**Verdict**: Changes requested

## Summary

The scaffold is faithful to the spec in almost every particular: content-addressed `UPLOAD_DIR/<2hex>/<sha256>.enc` blob layout, `key_id`/`key_version` reserved on `document_versions`, SHA-256-only session and MFA token storage, 8h/24h sliding-plus-absolute session expiry, portable `audit_seq` BigInteger/Integer dialect variant, async Alembic env, non-root multi-stage Dockerfile with `uv sync --frozen`, pg_isready healthcheck, and chunked 25 MB-capped uploads. The headline problem is that Argon2id hashing/verification runs synchronously on the event loop in the login and user-management paths, which the scaffold contract explicitly forbids (`anyio.to_thread`), and that session sliding-expiry writes are only flushed, never committed, on non-audited routes. Neither is catastrophic, but both are contract deviations that will bite under load and should be fixed before later slices build on them.

## Blockers

None.

## Major

### 🟠 Argon2id runs on the event loop, violating the scaffold contract, `app/services/auth.py:77`, `app/services/users.py:178`, `app/services/users.py:217`, `app/cli.py:36`

**Problem**: `passwords.verify_password` is called inside `audit.transact`'s `attempt` closure during login, and `passwords.hash_password` is called inside async service functions in `users.py` (reset_password, create_user). Argon2id with default parameters costs roughly 50–300 ms of pure CPU per call; `security/passwords.py` exposes only synchronous functions and no call site wraps them in `anyio.to_thread`/`asyncio.to_thread`.

**Why it matters**: The scaffold contract states "Argon2 hashing and AES-GCM encrypt/decrypt of large files run via `anyio.to_thread`, never on the event loop." Every login, password reset, and user creation blocks the entire event loop for the hashing duration — a single-digit number of concurrent logins can stall all requests, and the login endpoint is already the most abuse-prone surface (it carries the strictest rate limit for a reason). The AGENTS.md async-discipline rule repeats the same requirement.

**Suggested fix**: Make `hash_password`/`verify_password` async wrappers that delegate to `anyio.to_thread.run_sync`, or add `await anyio.to_thread.run_sync(...)` at each call site, and update `cli.py` (its `asyncio.run` loop blocks identically, though impact is lower for a one-shot CLI). Keep the sync primitives for tests if useful.

## Minor

### 🟡 Sliding session expiry is only flushed, never committed, on routes that don't write, `app/services/sessions.py:73-76`, `app/api/deps.py:73-98`, `app/core/database.py:22-24`

**Problem**: `sessions.validate` updates `last_seen_at`/`expires_at` and calls `db.flush()`, but `get_db` yields a session that is only committed if the route's service layer commits. Routes that audit and commit (all document/user/audit mutations) incidentally persist the slide; `/v1/auth/me` and any future read-only or non-audited route silently discard it. Additionally, `audit.record_denial` begins with `await db.rollback()` (`app/services/audit.py:177`), which discards the pending `last_seen` update on every denied request — defensible, but it means "last activity" means "last *successful audited* activity," not what the column name implies.

**Why it matters**: The spec's "sliding expiry" semantics are only approximately delivered: an idle user who polls `/v1/auth/me` (or any future cheap read endpoint) will still be logged out at the original `expires_at` rather than having it extended. The behavior is correct-by-accident on audited routes and will confuse the first feature that adds an unaudited read path.

**Suggested fix**: Either commit the slide explicitly in `validate` (a dedicated short commit, accepting the extra write per minute-throttled request), or document that `last_seen` persistence rides on the business transaction and add a comment in `sessions.py` so the next slice doesn't assume otherwise.

### 🟡 Blob writes are non-atomic and the existence check is racy, `app/services/blob_store.py:19-22`

**Problem**: `store` checks `path.exists()`, then encrypts and `write_bytes` directly to the final path. A crash or kill mid-write leaves a truncated `.enc` file that `load` will later fail to decrypt (500 on download), and two concurrent stores of the same plaintext can interleave writes since AES-GCM uses a fresh random nonce per `seal`.

**Why it matters**: Content-addressed storage exists precisely so a path is immutable once written; a partial file at a "final" name breaks that invariant permanently (the digest still matches, so nothing ever rewrites it). Low probability, high annoyance — a corrupt blob is indistinguishable from tampering at read time.

**Suggested fix**: Write to a temp file in the same directory and `os.replace` it into place (atomic on POSIX), and/or have `load` treat `InvalidTag`/short reads as a missing-blob error rather than a 500.

### 🟡 `rate_limit_default` setting is dead config, `app/core/config.py:27`, `docker-compose.yml:19`, `.env.example:12`

**Problem**: `RATE_LIMIT_DEFAULT` is plumbed through env, compose, and `.env.example`, but no `Limiter` is constructed with `default_limits` — only the per-route `rate_limit_auth` and `rate_limit_audit` values are used (`app/api/auth.py:38`, `app/api/audit.py:31`). The knob does nothing.

**Why it matters**: Operators will reasonably expect `RATE_LIMIT_DEFAULT` to apply to endpoints without an explicit limit (e.g., document routes appear to have no rate limit at all beyond auth); today it silently doesn't. Either wire it as `Limiter(default_limits=[...])` or drop the setting.

**Suggested fix**: Pass `default_limits=[settings.rate_limit_default]` when constructing the shared limiter, or remove the env var from all three places.

## Nits

- ⚪ `app/services/documents.py:186-187,363-364`: `key_id="master"`, `key_version="1"` are hardcoded strings duplicated from `app/security/encryption.py:10-11` (`KEY_ID`, `KEY_VERSION`). Import the constants so key rotation has one source of truth.
- ⚪ `app/api/audit.py:31` + `app/main.py:47`: `audit_limiter` is a second `Limiter` instance never assigned to `app.state.limiter`; enforcement still works (the decorator binds its own instance), but the 429 handler at `slowapi`'s `_rate_limit_exceeded_handler` injects headers via the auth limiter's storage, so `X-RateLimit-*` headers on audit 429s are wrong/missing. Cosmetic.
- ⚪ `docker-compose.yml` / `.env.example`: `RATE_LIMIT_AUDIT` (used by `app/api/audit.py:34-36`) is not exposed in either file, unlike the other `RATE_LIMIT_*` vars.
- ⚪ `app/services/blob_store.py:17`: `hashlib.sha256` over up to 25 MB runs on the event loop (~30–80 ms). Cheap enough to ignore, but it's the same class of blocking work the contract polices; a `to_thread` would future-proof it.
- ⚪ `alembic/env.py:19-28`: offline mode passes the async `postgresql+asyncpg://` URL to `context.configure(url=...)`, which Alembic's offline renderer may not handle; tests don't exercise it. Low risk since migrations run online.

## Strengths

- Blob layout matches the contract exactly (`<first 2 hex>/<sha256>.enc`, nonce-prefixed AES-GCM payload) and `key_id`/`key_version` were reserved on `document_versions` at scaffold time, exactly as the spec demanded — most scaffolds skip this and pay for it at rotation time.
- Session design is genuinely good: `secrets.token_urlsafe(32)`, SHA-256-only storage, 1-minute write throttle on `last_seen`, absolute 24h cap layered over configurable idle TTL, and cookie flags (`HttpOnly`, `SameSite=Lax`, `Secure` in prod) match the contract including the deferred-CSRF note.
- `audit_seq()`'s `BigInteger().with_variant(Integer, "sqlite")` is the right portable-PK solution, and the hash-chain fork handling (`prev_hash` unique + `AuditChainFork` retry that rebuilds from primitive snapshots) is more careful than most first-pass audit implementations.
- Upload path validates size while streaming (`read_capped` rejects past 25 MB before buffering completes) then enforces the MIME allowlist — the contract's "size first, then MIME" ordering is honored.
- Docker packaging is clean: multi-stage `uv sync --frozen`, non-root user, `depends_on: condition: service_healthy` with pg_isready, named `UPLOAD_DIR` volume, `/docs` gated to `env == "dev"`.

## Test coverage

Test signal is `configured` (pytest + pytest-asyncio + httpx, 180 tests, in-memory SQLite). Coverage of the scaffold surface is reasonable: `test_session_sliding_expiry` exercises the slide (though it commits explicitly, so it does not catch the uncommitted-flush gap above), session revocation/expiry rejection, config validation, and health endpoints are tested. Gaps worth noting: no test asserts that Argon2 calls are off the event loop (hard to test, but a regression here is invisible), and no test covers `blob_store` concurrent/partial-write behavior or `readyz`'s 503 path.
