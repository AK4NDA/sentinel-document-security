# Verify: MFA & login protection · spec 0004 · updated 2026-11-07

_Steps derived from spec 0004 acceptance criteria. `/check verify` runs these; `/test` locks the durable ones._

## Commands

- [ ] `uv run alembic upgrade head` → `mfa_challenges` table and `users.totp_last_counter` created → AC-1
- [ ] `uv run alembic downgrade -1` then `uv run alembic upgrade head` → clean round trip on SQLite → AC-1
- [ ] `uv run pytest -q` → all tests pass including `tests/test_mfa.py` → all ACs

## UI / manual (API calls)

- [ ] Unenrolled user logs in → session issued, `GET /v1/auth/mfa/enroll/start` returns `secret`, `otpauth_uri` (account = username), `qr_svg` containing `<svg`; DB shows encrypted secret, `totp_enabled_at` NULL → AC-2
- [ ] `POST /v1/auth/mfa/enroll/confirm` with a valid code → `mfa_enrolled: true`, `totp_enabled_at` and `totp_last_counter` set; bad code → 401 + denied `mfa.enroll` audit row → AC-3
- [ ] Unenrolled session calls `GET /v1/documents` → 403; `/v1/auth/me` and `/v1/auth/logout` still work; denial audited with reason `mfa_enrollment_required` → AC-4
- [ ] Enrolled user logs in → 200 `{mfa_required: true, pending_token, expires_in: 300}`, no session cookie; `mfa_challenges` row stores only a 64 char hash → AC-5
- [ ] `POST /v1/auth/mfa/verify` with pending token + valid code → session cookie + profile; unknown/expired/consumed token → 401; wrong code → 401 audited `mfa.verify` denied → AC-6
- [ ] Submit the same TOTP code twice → second use rejected; a new login deletes the prior pending token → AC-6, AC-7
- [ ] 5 failed passwords → next login returns 429 with `retry_after_seconds`; attempts while locked do not extend `locked_until`; correct password after lockout expiry works and resets the counter → AC-8
- [ ] Admin `POST /v1/users/{id}/mfa/reset` → target's TOTP fields cleared, all sessions revoked, pending challenges deleted, `mfa.reset` audited; non admin gets 403 → AC-9
- [ ] `POST /v1/auth/mfa/verify` is rate limited like login (same `rate_limit_auth` setting) → AC-10
- [ ] Audit log contains `mfa.enroll`, `mfa.verify`, `mfa.reset` rows for allowed and denied outcomes → AC-11
- [ ] A pre-existing unenrolled user logs in and enrolls with no password reset or migration → AC-12

## Value sourcing spot checks

- [ ] `pending_token` appears only in the login response body, never in audit `details` or logs → AC-4
- [ ] `expires_in` equals `MFA_CHALLENGE_TTL_SECONDS` (default 300); change the setting and confirm the value follows → AC-5
- [ ] `otpauth_uri` account field is the user's `username`, issuer is `TOTP_ISSUER` → AC-2
- [ ] `retry_after_seconds` equals `locked_until - now` at response time → AC-8
- [ ] `mfa_enrolled` in `/v1/auth/me` flips false → true exactly when `totp_enabled_at` is set → AC-3, AC-10

## Acceptance-criteria coverage

- AC-1 … migration commands · AC-2 … enroll start · AC-3 … enroll confirm · AC-4 … limited gate · AC-5 … login challenge · AC-6 … verify exchange · AC-7 … replay · AC-8 … lockout · AC-9 … admin reset · AC-10 … rate limit + profile flag · AC-11 … audit actions · AC-12 … unenrolled migration path
