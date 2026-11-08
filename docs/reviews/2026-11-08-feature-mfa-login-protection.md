# Review, feature/mfa-login-protection, 2026-11-08, administration & account lifecycle (spec 0005)

**Reviewed by**: fresh context reviewer (author on SWE-2 Flash, degraded same model review)
**Scope**: 7 tracked files uncommitted (`.gitignore`, `app/api/deps.py`, `app/api/users.py`, `app/schemas/users.py`, `app/services/users.py`, `docs/scope/scope.md`, `tests/test_api.py`) plus 3 untracked spec 0005 docs; feature-scoped uncommitted change set only. The committed MFA feature (spec 0004) is excluded; it has its own review at `docs/reviews/2026-11-07-feature-mfa-login-protection.md`.
**Verdict**: Approve with nits

## Summary

Five admin routes (privilege patch, disable, enable, session revoke-all, password reset) built cleanly on the existing session, lockout, challenge, and hash-chained audit machinery, with no migration. The implementation matches spec 0005's contract closely: exact 409 reason envelopes, denials audited inside the same retried transaction, one action name per route across gate/success/denial, a single-UPDATE revoke with rowcount-exact counting, and no password material anywhere. Test coverage is strong and behavior-level. The only gaps are a missing durable test for the PATCH 404 branch and a synchronous Argon2 hash on the event loop (an inherited pattern, newly instantiated here).

## Minor

### 🟡 PATCH unknown-user 404 has no durable test, `app/services/users.py:54-56`, `tests/test_api.py:352`

**Problem**: The `not_found` denial branch of `patch_user` is never exercised by the suite. The other four routes' 404 paths are tested (`tests/test_api.py:352-353`, `:717-726`), and `verify.md` records a live manual check of all five routes, but no pytest locks the PATCH wiring.

**Why it matters**: A regression that drops the existence check or the denial audit in `patch_user` (e.g., returning 422/500 for absent ids, or skipping the audit row) would pass the suite. The rubric's default for untested error handling is Major; I downgrade to Minor because the identical two-line pattern calling the tested `_append_denial` helper is covered on four sibling routes and was live-verified per `verify.md`.

**Suggested fix**: Add one test: PATCH a well-formed absent UUID, assert 404 and a `user.privilege_update` denial row with `details == {"reason": "not_found"}` and `target_id` equal to the path id.

### 🟡 Synchronous Argon2 hash blocks the event loop, and runs before the 404 check, `app/services/users.py:178`

**Problem**: `reset_password` calls `passwords.hash_password` (argon2-cffi, default ~64 MiB / 3 passes) directly in async code, blocking the loop for tens of milliseconds per call, and does so before the target-existence check, so even unknown-user requests pay the full hash cost.

**Why it matters**: Under concurrent admin activity (or a compromised admin session spamming resets) this stalls all requests on the worker. It is an inherited pattern — `create_user` (`app/services/users.py:217`) and login verify (`app/services/auth.py:77`) do the same — and the route is admin-only and MFA-gated, so impact is bounded; but this diff adds a new instance, and the repo already knows the fix (`asyncio.to_thread` in `app/services/blob_store.py:21-31`).

**Suggested fix**: Hash via `asyncio.to_thread(passwords.hash_password, new_password)` (ideally across all three call sites as a follow-up), and move the hash after the target lookup or accept the wasted work on 404 consciously.

## Nits

- ⚪ `app/services/users.py:17`, `PATCH_ACTION` is a named constant while the other four actions are inline strings; pick one style.
- ⚪ `app/services/users.py:85`, `assert target is not None` in a production path disappears under `python -O`; an explicit guard (or returning the profile fields) would be sturdier. Matches the existing `mfa.py` pattern, so author's discretion.
- ⚪ `app/schemas/users.py:41`, `clearance` lax-coerces `true` → 1 and `"2"` → 2 (verified empirically). Consistent with `UserCreate`, and AC-1's 422 list names out-of-range values, not type coercion, but strict int validation would match the "int 1 to 5" contract more literally.
- ⚪ `app/schemas/users.py:59-60`, `ResetPasswordRequest` silently ignores unknown fields while `UserAdminPatch` forbids them; the spec doesn't require `extra="forbid"` here, but the asymmetry could hide client typos.
- ⚪ `tests/test_api.py:1`, module docstring still says "core classified document loop (spec 0003)" though the file now carries the spec 0005 acceptance suite.
- ⚪ `tests/test_api.py:471`, `pending_login` is a misleading name — it is a locked-out login attempt (429), not a pending MFA challenge.
- ⚪ `docs/scope/scope.md:123`, the "Spec [0005]" line is indented six spaces as if nested under the "Document it" checkbox; incidental formatting.
- ⚪ `.gitignore:16`, `.idea` added without a trailing newline; incidental.

## Strengths

- The shared `_revoke_all_sessions` helper (`app/services/users.py:130-142`) is exactly the spec's single UPDATE over `revoked_at IS NULL AND expires_at > now` with rowcount as the audited count, and the tests prove it: two live tokens counted as 2, expired sessions left untouched, repeat call audits 0 (`tests/test_api.py` revoke tests).
- Retry-safe audit design: actor snapshots are taken before `audit.transact`, and every state check, self-guard, and old-value read happens inside the retried closure against a freshly read row, so a chain-fork retry re-evaluates instead of replaying stale values — precisely the spec 0005 invariant.
- Denial hygiene is excellent and asserted, not assumed: 404/409 denials commit in the same transaction with exact `details` shapes, role and enrollment-gate denials land under each route's own action via the new `GATE_ACTIONS` entries, and the 422 test asserts that validation failures write no audit rows and change nothing.
- Tests exercise real session semantics (401 on next request, revival on enable, revoked-stays-dead, next-request privilege enforcement, bystander challenge isolation, actor snapshot surviving later demotion) rather than status codes alone.

## Test coverage

24 new spec 0005-tagged tests cover AC-1 through AC-9 at the behavior level: patch happy path and audit shape, all nine 422 bodies, no-op idempotence, self-demotion (blocked for self, allowed for another admin), disable/enable conflicts with exact audited details, self-disable, challenge deletion on disable and reset (including bystander isolation), exact revoke rowcounts and expired-session exclusion, lockout clear (including below-threshold failure counts), reset on disabled accounts, enable preserving lockout, MFA enrollment surviving reset (via `mfa_required` on fresh login), Argon2id rehash, self revoke/reset, role and gate denials on all five routes, and AC-7 next-request effects. Suite reported at 147 passing; `ruff check --no-cache app tests` passes (re-run by this reviewer). The one durable gap is the PATCH 404 branch (Minor above). The chain-fork-exhaustion 500 path is untested, as in the rest of the codebase; not flagged given the established pattern.