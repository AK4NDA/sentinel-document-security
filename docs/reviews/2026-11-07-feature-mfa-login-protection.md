# Review, feature/mfa-login-protection, 2026-11-07

**Reviewed by**: SWE-2 Flash (author on SWE-2 Flash, degraded same model review)
**Scope**: 14 source files plus tests and migration, feature branch vs main merge-base 65be673, including uncommitted test additions
**Verdict**: Approve with nits

## Summary

Mandatory TOTP MFA lands as a coherent slice: pending token challenges, encrypted secrets, replay guard, shared lockout, limited session gate, and admin reset. The concurrency and rate limit edges are the weak spots; everything else is careful work with strong test coverage.

## Major

### 🟠 Enroll confirm has no lockout check and no rate limit, app/services/mfa.py:105-157, app/api/auth.py:120-133

**Problem**: `confirm_enrollment` calls `lockout.record_failure` on bad codes but never calls `lockout.is_locked` first, and the route carries no `@limiter.limit`. Failed guesses keep incrementing `failed_login_attempts` and keep pushing `locked_until` forward (rolling lockout), but nothing on this path ever enforces it.

**Why it matters**: an attacker holding a limited session (valid password, no authenticator) can grind 6 digit TOTP codes unbounded. Every other credential guessing surface (login, mfa/verify) is rate limited and lockout enforced; this one is not.

**Suggested fix**: check `lockout.is_locked(fresh)` inside `confirm_enrollment` before verifying the code and return the locked outcome, and add `@limiter.limit(_auth_limit)` to `mfa_enroll_confirm` (and consider `mfa_enroll_start` for symmetry).

## Minor

### 🟡 Challenge consumption is not revalidated inside the transaction, app/services/mfa.py:226-244

**Problem**: `verify_challenge` checks `_challenge_usable` on the row read before the transaction, but `attempt()` re-fetches the challenge and sets `consumed_at` unconditionally without rechecking `consumed_at`, expiry, or attempts. Two concurrent verifies with the same pending token and code can both reach `attempt()`; the second overwrites `consumed_at` and issues a second session. The TOTP replay guard is bypassed the same way because `totp_last_counter` is overwritten, not compared.

**Why it matters**: single use and replay protection are the security properties this table exists for. Impact is bounded (multiple sessions are allowed anyway, and the caller already holds token plus code), but the audit trail will show two "allowed" verifies for one challenge.

**Suggested fix**: inside `attempt()`, recheck `fresh_challenge.consumed_at is None` and expiry before consuming, returning invalid otherwise; or guard the consume with a conditional UPDATE.

### 🟡 Verify denial reason `user_unavailable` is not in the spec vocabulary, app/services/mfa.py:209

**Problem**: spec 0004 lists denial reasons `invalid_code`, `expired_challenge`, `challenge_consumed`, `locked`, `mfa_enrollment_required`, `not_enrolled`. The code emits `user_unavailable` for inactive users, missing TOTP state, and missing user alike.

**Why it matters**: auditors filtering on the documented vocabulary will miss these rows. Minor since the reason is still descriptive.

**Suggested fix**: split the cases or rename to a documented reason.

### 🟡 Gate action map falls back silently, app/api/deps.py:44-58

**Problem**: `GATE_ACTIONS` covers today's routes, but any future protected route added without a map entry gets its gate denial audited as `mfa.enrollment_gate`, reintroducing the exact deviation the verify run caught.

**Why it matters**: silent mislabeling of audit rows on future endpoints.

**Suggested fix**: fail loudly (500 or a distinct reason) on unmapped routes, or derive the action from the route's own dependency metadata.

## Nits

- ⚪ `app/api/auth.py:66-69`, `pending_token or ""` / `expires_in or 0` defaults are unreachable; returning the raw outcome fields would fail louder if the invariant ever broke.
- ⚪ `app/api/auth.py:55`, dropping `response_model` on `/login` loses the OpenAPI union documentation; `UserProfile | MfaRequiredResponse` would document both shapes.
- ⚪ `alembic/versions/b2c3d4e5f6a7_mfa_challenges.py`, `attempts` is `nullable=False` with no server default while the model relies on the Python side `default=0`; fine for a new table, worth knowing if the column is ever added elsewhere.

## Strengths

- Lockout counter resets only on full authentication; the password success no longer clears it, which the test suite proved was a real exploit path.
- TOTP replay guard stores the matched step explicitly rather than trusting `pyotp.verify`'s boolean.
- Challenge lifecycle is tight: hash only storage, single active challenge per user, attempt cap, expiry, consumed marking.
- Gate denials now audit under each endpoint's own action, verified live for `document.list`, `document.read`, `user.list`, and `mfa.reset`.
- Test suite is genuinely strong: 121 tests including skew boundaries, malformed codes, replay, lockout non extension, challenge cap, and audit vocabulary.

## Test coverage

`TESTS = configured` (pytest, 121 passing). All spec 0004 ACs have automated coverage except the live rate limit behavior on `/mfa/verify`, deferred to the verify.md manual step. The enroll confirm lockout gap above is exactly the kind of branch the suite does not yet reach.
