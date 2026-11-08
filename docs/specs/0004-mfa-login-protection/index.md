# 0004. Add TOTP multi factor authentication and login lockout

**Date**: 2026-11-07
**Status**: In Progress

## Summary

This spec adds mandatory TOTP multi factor authentication to every account. After a correct password, enrolled users get a short lived pending token and must exchange it plus a valid authenticator code for a real session. Users who have not enrolled yet get a limited session that can only reach the enrollment endpoints. Failed password and code attempts lock the account for fifteen minutes, and admins can reset a lost authenticator, which revokes every session the user holds.

## Requirements

**User stories**:
- As any user, I want to enroll my authenticator app once so that my account is protected by a second factor.
- As an enrolled user, I want login to ask for my authenticator code so that a stolen password alone cannot get in.
- As an administrator, I want to reset a user's authenticator when they lose their device so that they can re-enroll, without me touching document content.
- As the system, I want repeated failures to lock the account and every MFA event written to the audit log, so that guessing is bounded and provable.

**Acceptance criteria** (the contract, each criterion is IDed and independently checkable):
- **AC-1**: A new Alembic migration adds the `mfa_challenges` table and the `users.totp_last_counter` column; upgrade and downgrade run cleanly on SQLite (and Postgres when available).
- **AC-2**: `POST /v1/auth/mfa/enroll/start` requires a valid session whose user has `totp_enabled_at` NULL; it generates a fresh TOTP secret, stores it AES GCM encrypted in `users.totp_secret_encrypted`, returns the secret, an `otpauth://` provisioning URI whose account field is `users.username` URL encoded, and a `qr_svg` string field containing an SVG render of that URI, and leaves `totp_enabled_at` NULL. Calling it again regenerates the secret; the latest secret wins and earlier unconfirmed secrets are overwritten (accepted behavior, covered by a test).
- **AC-3**: `POST /v1/auth/mfa/enroll/confirm` takes a 6 digit code; a valid code within the skew window sets `totp_enabled_at`, records the accepted step in `totp_last_counter`, resets `failed_login_attempts` to 0 and clears `locked_until` (confirm counts as successful authentication), and the session becomes fully usable. An invalid code returns 401, is audited as denied, and counts toward lockout.
- **AC-4**: A session whose user has `totp_enabled_at` NULL may call only `/v1/auth/mfa/enroll/*` and `/v1/auth/me`/`logout`; every other endpoint returns 403, is audited as denied under the request's normal authorization action with `details.reason = mfa_enrollment_required`, and the `pending_token` value never appears in audit `details` or logs.
- **AC-5**: `POST /v1/auth/login` with valid credentials for an enrolled user returns 200 with `{mfa_required: true, pending_token, expires_in}` and sets no cookie; it creates an `mfa_challenges` row storing only the SHA-256 token hash with a 5 minute expiry, and issuing a new challenge deletes that user's prior unconsumed challenges (one active challenge per user).
- **AC-6**: `POST /v1/auth/mfa/verify` accepts `{pending_token, code}`; it first validates the challenge (unknown, expired, or consumed tokens return 401 before any user state is revealed), then re-reads the user and applies the same `locked_until`, `totp_enabled_at`, and `is_active` checks as login, then checks the code. A valid unused challenge plus a valid TOTP code (current step plus or minus 1) consumes the challenge (`consumed_at` set), creates a normal session, sets the cookie, and returns the profile. Wrong codes return 401, are audited denied, count toward lockout, and increment `mfa_challenges.attempts`; a challenge reaching 5 attempts is invalidated (subsequent verifies return 401 with reason `challenge_consumed`).
- **AC-7**: TOTP replay protection: the verifier computes the current counter (`int(time.time() // 30)`) and tests each candidate step in the ±`TOTP_SKEW_STEPS` window to find the matching step; that step is stored in `users.totp_last_counter` and any code whose step is less than or equal to the stored value is rejected, so the same code cannot be used twice inside its validity window.
- **AC-8**: Login lockout: the `locked_until` check runs before credential verification on both login and verify, returning an identical 429 regardless of credential validity; a locked attempt does not extend `locked_until` or increment `failed_login_attempts`. 5 failed password or TOTP attempts set `locked_until` to now plus 15 minutes; `locked_until` expiring naturally does not clear `failed_login_attempts`, only a successful authentication (login, verify, or enroll confirm) resets the counter to 0 and clears `locked_until`. The 429 response follows the spec 0003 error envelope and carries `retry_after_seconds` computed from `locked_until - now`.
- **AC-9**: `POST /v1/users/{id}/mfa/reset` is admin only; it clears `totp_secret_encrypted`, `totp_enabled_at`, and `totp_last_counter`, revokes all of the user's sessions, deletes their pending challenges, and is audited as `mfa.reset`. The affected user must log in and re-enroll before accessing anything beyond the enrollment endpoints.
- **AC-10**: `POST /v1/auth/mfa/verify` carries the same slowapi auth rate limit as login, and `mfa_enrolled` appears in the login profile and `GET /v1/auth/me` responses.
- **AC-11**: New audit actions `mfa.enroll`, `mfa.verify`, and `mfa.reset` are written allowed or denied per the spec 0003 AC-14 rules (post identity failures exempt).
- **AC-12**: Existing users with `totp_enabled_at` NULL keep working through the limited enrollment session; no data migration or forced password reset is required.

**Audited action vocabulary** (additions): `mfa.enroll`, `mfa.verify`, `mfa.reset`. Denial `details` carry the reason (`invalid_code`, `expired_challenge`, `challenge_consumed`, `locked`, `mfa_enrollment_required`, `not_enrolled`).

## Decision

**Chosen option**: Option 1: Mandatory TOTP with pending token challenge and admin reset

TOTP via `pyotp` (already a dependency) with secrets AES GCM encrypted under `MASTER_KEY` using the existing `seal`/`open_blob` helpers. Enrollment reuses the existing `totp_secret_encrypted`/`totp_enabled_at` columns; a new `mfa_challenges` table holds pending login tokens as SHA-256 hashes mirroring the session pattern. QR codes are rendered server side by `segno` (new dependency, pure Python, no system libraries). Login lockout enforces the already present `failed_login_attempts`/`locked_until` columns at 5 attempts / 15 minutes. New configuration: `TOTP_ISSUER`, `MFA_CHALLENGE_TTL_SECONDS` (300), `TOTP_SKEW_STEPS` (1), `LOGIN_MAX_ATTEMPTS` (5), `LOGIN_LOCKOUT_SECONDS` (900).

**Implementation skills**: `fastapi` (`wispbit-ai/skills`, `.agents/skills/fastapi/`) · `auth-implementation-patterns` (`wispbit-ai/skills`, `.agents/skills/auth-implementation-patterns/`) · `reviewing-cryptography` (`wispbit-ai/skills`, `.agents/skills/reviewing-cryptography/`) · `alembic` (`wispbit-ai/skills`, `.agents/skills/alembic/`)

## Feature design

**Data model sketch**:

New table `mfa_challenges`:

| Column | Type | Notes |
|---|---|---|
| id | UUID PK | |
| user_id | UUID FK → users.id ON DELETE CASCADE, indexed | |
| token_hash | String(64) unique | SHA-256 hex of pending token |
| created_at | DateTime(tz) | |
| expires_at | DateTime(tz), indexed | created_at + `MFA_CHALLENGE_TTL_SECONDS` |
| attempts | Integer default 0 | failed verify attempts on this challenge |
| consumed_at | DateTime(tz) NULL | set on successful exchange |

New column on `users`: `totp_last_counter` Integer NULL, the last accepted TOTP time step.

Reused unchanged: `totp_secret_encrypted` (written at enroll start, `totp_enabled_at` stays NULL until confirm), `totp_enabled_at`, `failed_login_attempts`, `locked_until`, `sessions` (issued only after full authentication).

**State transitions**:

- `users` MFA: unenrolled (`totp_enabled_at` NULL) → pending (`totp_secret_encrypted` set, still NULL `totp_enabled_at`) → enrolled (`totp_enabled_at` set) → reset by admin back to unenrolled.
- `mfa_challenges`: issued → consumed (success) | expired (time) | deleted (admin reset or user disabled cascade).
- `users` lockout: clear → locked (`locked_until` future) → clear on success or expiry.

**API surface**:

| Endpoint | Method | Key inputs | Key outputs | Auth | Key errors |
|---|---|---|---|---|---|
| /v1/auth/login | POST | username, password | profile + cookie, or `{mfa_required, pending_token, expires_in}` | public, rate limited | 401 bad credentials, 429 locked |
| /v1/auth/mfa/verify | POST | pending_token:str (req), code:str 6 digits (req) | profile + cookie | public, rate limited | 401 bad/expired/used token or code, 429 locked |
| /v1/auth/mfa/enroll/start | POST | none | secret, otpauth_uri, qr_svg | limited session | 403 already enrolled, 401 no session |
| /v1/auth/mfa/enroll/confirm | POST | code:str 6 digits (req) | profile | limited session | 401 invalid code, 403 already enrolled |
| /v1/users/{id}/mfa/reset | POST | none | 204 | admin | 403 non admin, 404 unknown user |
| /v1/auth/me | GET | none | profile incl. `mfa_enrolled` | any session | 401, 403 enrollment pending on guarded routes |

**Value sourcing** (name the source of every value each action produces, computes, or displays; a required value with no named source is an undecided input to resolve now, never one for the build to invent):

| Action | Value produced / displayed | Source |
|---|---|---|
| login (enrolled) | pending_token | generated server side (32 byte urlsafe), only SHA-256 stored in `mfa_challenges.token_hash`; issuing it deletes the user's prior unconsumed challenges |
| login (enrolled) | expires_in | `MFA_CHALLENGE_TTL_SECONDS` setting |
| login (enrolled) | mfa_required | `users.totp_enabled_at IS NOT NULL` |
| enroll/start | secret | generated server side (`pyotp.random_base32`), stored encrypted in `totp_secret_encrypted`; latest start wins, prior unconfirmed secret overwritten |
| enroll/start | otpauth_uri | derived: issuer `TOTP_ISSUER`, account `users.username` URL encoded, secret |
| enroll/start | qr_svg | `segno` SVG render of the otpauth URI, returned as a string field |
| verify | challenge validity | `mfa_challenges` row: hash match, `expires_at` future, `consumed_at` NULL, `attempts` < 5 |
| verify | user state at exchange | re-read `users` row: `locked_until`, `totp_enabled_at`, `is_active`, same checks as login |
| verify | valid code check | per candidate step counter in ±`TOTP_SKEW_STEPS` window around `int(time.time() // 30)`, `pyotp` HOTP comparison per step, matched step stored in `totp_last_counter` |
| verify | session token | same session issue path as login |
| any profile | mfa_enrolled | `users.totp_enabled_at IS NOT NULL` |
| locked response | retry_after_seconds | `users.locked_until - now`, in the spec 0003 error envelope |

**Key invariants**:

- `totp_enabled_at` is set only after a valid code confirms against the stored secret; no path enables MFA without proof of possession.
- A pending token is single use (`consumed_at`), expires after `MFA_CHALLENGE_TTL_SECONDS`, allows at most 5 code attempts, and is stored only as a SHA-256 hash; at most one unconsumed challenge exists per user.
- A TOTP code is accepted at most once per user (`totp_last_counter` monotonic).
- Lockout counts both password and TOTP failures against the same `failed_login_attempts` counter; the lockout check precedes credential verification so a 429 never confirms credentials, and attempts while locked change nothing.
- `failed_login_attempts` resets to 0 and `locked_until` clears only on successful authentication (password login, MFA verify, or enroll confirm); `locked_until` expiring on its own does not clear the counter.
- Admin reset leaves the user with no usable credential path except password login into the limited enrollment session.
- Deny by default holds: unenrolled sessions reach only the enrollment endpoints.

**Security model**:

TOTP secrets are encrypted at rest with AES GCM under `MASTER_KEY` (same as document blobs, `key_id`/`key_version` pattern not needed since `MASTER_KEY` is single). Pending tokens and session tokens are stored only as SHA-256 hashes. The enrollment gate keys off `totp_enabled_at IS NULL`, enforced in the auth dependency so every protected route denies limited sessions except the two enroll routes, `/me`, and `/logout`. Admin reset is admin role only. All MFA mutations and denials write audit rows per spec 0003 AC-14. No new secrets beyond config values; `MASTER_KEY` already exists.

**Configuration required**:

- `TOTP_ISSUER`: display name in authenticator apps (default `Sentinel`)
- `MFA_CHALLENGE_TTL_SECONDS`: pending token lifetime (default 300)
- `TOTP_SKEW_STEPS`: accepted clock drift in 30 second steps (default 1)
- `LOGIN_MAX_ATTEMPTS`: failures before lockout (default 5)
- `LOGIN_LOCKOUT_SECONDS`: lockout duration (default 900)

**Critical test scenarios** (each maps to an acceptance criterion in ## Requirements):
- Happy path: password login → pending token → valid code → session cookie → `/me` shows `mfa_enrolled: true`, verifies **AC-5**, **AC-6**, **AC-10**
- Failure case: wrong code burns a challenge attempt and counts toward lockout; 5 failures produce 429 until `locked_until` passes, verifies **AC-6**, **AC-8**
- Auth/permission: unenrolled session calling `GET /v1/documents` gets 403 `mfa_enrollment_required`; non admin calling `mfa/reset` gets 403; auditor can enroll like any role, verifies **AC-4**, **AC-9**
- Replay: the same TOTP code submitted twice is rejected the second time, including the code just used at enroll confirm (users must wait for the next code on first login), verifies **AC-7**
- Ordering: a locked account returns identical 429 for wrong and right passwords, and locked attempts do not extend the lockout, verifies **AC-8**

## Build plan

1. Migration and model: `mfa_challenges` table, `users.totp_last_counter`, `MfaChallenge` ORM model, Alembic upgrade/downgrade, satisfies **AC-1**
2. TOTP service: secret generation, AES GCM seal/open of `totp_secret_encrypted`, `pyotp` verify with skew window and `totp_last_counter` replay check, satisfies **AC-2**, **AC-3**, **AC-7**
3. Enrollment endpoints and limited session gate: `enroll/start`, `enroll/confirm`, dependency that restricts `totp_enabled_at` NULL sessions to enroll routes plus `/me`/`logout`, satisfies **AC-2**, **AC-3**, **AC-4**
4. Login challenge: `login` returns pending token for enrolled users, `mfa/verify` exchanges it for a session, satisfies **AC-5**, **AC-6**
5. Lockout enforcement: shared failure counter for password and TOTP, `locked_until` check returning 429, reset on success, satisfies **AC-8**
6. Admin reset endpoint `POST /v1/users/{id}/mfa/reset` with session revocation and challenge cleanup, satisfies **AC-9**
7. Audit actions `mfa.enroll`, `mfa.verify`, `mfa.reset` wired through the existing audit service, profile schema gains `mfa_enrolled`, rate limit on verify, satisfies **AC-10**, **AC-11**
8. Test suite covering every AC plus the critical scenarios, satisfies all ACs; existing unenrolled users keep working per **AC-12**

## Consequences

**Positive**:
- Every account, including admins and auditors, gets a real second factor; a phished password alone no longer yields access.
- Pending tokens reuse the proven hashed token pattern from sessions, so no new token machinery.
- Lockout finally enforces the `failed_login_attempts`/`locked_until` columns the data model reserved, closing the unlimited guessing gap.
- Admin reset gives a clean recovery story without recovery codes or a support runbook.
- The enrollment gate is one dependency check on `totp_enabled_at`, so deny by default extends to the pre-MFA state for free.

**Negative / tradeoffs**:
- Mandatory MFA adds friction to every login and a hard dependency on users owning a phone or hardware token; lost-device recovery is entirely manual via an admin.
- TOTP is phishable in real time (a proxy can relay both factors); this slice does not address session hijack beyond the existing 24 hour cap.
- The limited session state is a new auth mode the dependency layer must handle; a missed route registration would either over-block or under-block. The design has two restricted auth paths (limited session and pending token challenge), so the dependency layer must keep both explicit.
- Users who enroll and immediately log in will see the same authenticator code rejected once, because confirm already burned that time step; documentation or UI copy should tell them to wait for the next code.
- `segno` adds one dependency for a cosmetic QR; the otpauth URI alone would work but is worse UX.
- Account lockout is per account, not per IP plus account jointly, so a distributed attack still hits the IP rate limit only.

**Neutral**:
- Existing users are unenrolled by default and must enroll on next login; no forced migration or password reset.
- `mfa_challenges` rows are small and short lived; cleanup of expired rows can ride a later housekeeping job.
- Audit vocabulary grows by three actions; spec 0003's canonical hashing covers them unchanged.
- Spec 0002 stands; this spec adds one table and one column via a single additive migration.
- Operational note: if the sole admin loses their authenticator and fumbles re-enrollment, no admin remains to reset accounts; keep a second admin enrolled in any real deployment.

**Follow-up**:

- [ ] `/audit` has not run yet; root `AGENTS.md` does not exist (scope feature 2).
- [ ] Consider WebAuthn or hardware keys as a later spec if phishing resistance becomes a requirement; TOTP remains phishable.
- [ ] Recovery codes were deliberately deferred; if admin reset proves too slow for the demo, a later spec can add them.
- [ ] Expired `mfa_challenges` and consumed rows need a retention/cleanup policy; candidate for a housekeeping spec.
- [ ] Postgres side of the new migration should be exercised when Docker compose is available.

## Rationale

Reasoning, options considered, and references: see [rationale.md](rationale.md).
