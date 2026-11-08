# Verify: Administration and account lifecycle · spec 0005 · updated 2026-11-08

_Steps derived from spec 0005 acceptance criteria. `/check verify` runs these; `/test` locks the durable ones._

## UI / manual

Backend only feature, so these are API steps against a running server (`uv run uvicorn app.main:app`), using an admin session that has completed MFA enrollment.

- [x] PATCH a user with `role` and `clearance` → 200, the profile shows the new values, and the `user.privilege_update` audit row carries old and new for both fields → AC-1, AC-2
- [x] PATCH with an unknown field, an empty body, an explicit null, `is_active`, `password`, clearance 0, or clearance 6 → 422 each time, and no audit row is written → AC-1
- [x] PATCH a field to its current value → 200, and the audit row shows old equal to new, so the call is safe to retry → AC-1
- [x] PATCH your own role to anything but `admin` → 409 `self_demotion`, audited as a denial, nothing changed; a second admin performing the same change succeeds → AC-8
- [x] Disable a logged in user → their next request returns 401 and login is denied; enable the account → the same session token works again → AC-3, AC-7
- [x] Disable your own admin account → 409 `self_disable`, audited as a denial, you stay active → AC-3
- [x] Disable an already disabled account, then enable an already enabled one → 409 `already_disabled` and `already_enabled`, each audited with `{"reason": <reason>, "is_active": <current>}` → AC-6
- [x] Start a login and stop at the MFA prompt, then disable the account → the pending token can no longer be exchanged (401) → AC-3
- [x] Revoke sessions for a user holding two live tokens → both tokens stop working, and the `session.revoke_all` audit row shows `revoked_count: 2`; repeating the call audits count 0 → AC-4
- [x] Lock an account with 5 bad passwords, then reset its password → login works right away with the new password, and the audit row shows `lockout_cleared: true`; a second reset with no failures shows `lockout_cleared: false` → AC-5
- [x] Reset the password of a disabled account → 204, but login still fails until the account is enabled; enabling alone does not clear a live lockout → AC-5, AC-7
- [x] Reset a password while a pending MFA challenge exists → the challenge cannot be exchanged afterwards (401) → AC-5
- [x] Reset with a password shorter than 12 characters → 422; inspect the response and the audit row → no password or hash material anywhere → AC-5
- [x] Call all five routes as an officer and as an auditor → 403 each, with an audited role denial under the route's action → AC-9
- [x] Call the routes as an admin who has not enrolled in MFA → 403 at the enrollment gate, denial audited under the route's action → AC-9
- [x] Call every route with an unknown user id → 404, audited as a `not_found` denial, `target_id` equal to the path id, actor stored as a snapshot → AC-9
- [x] Change a target's role and clearance while their session is live → the next request enforces the new privileges (auditor loses documents, lowered clearance loses a read), and the session is never revoked → AC-7
- [x] Disable a user, revoke their sessions, then enable → the old token stays dead (401) → AC-7

## Commands

- [x] `uv run pytest tests/ -q` → the full suite passes (142 tests at build time) → AC-1 through AC-9
- [x] `uv run ruff check app tests` → no findings → build hygiene

## Value sourcing checks

One step per row of the spec's value sourcing table, exercising the source itself.

- [x] Old role and clearance come from the row, not the request: PATCH only `role`, and the audit row still shows the true previous clearance → AC-2
- [x] New values come from the body: PATCH clearance 2 and read the profile plus the audit row, both show 2 → AC-1, AC-2
- [x] The response profile is the updated row: after PATCH, GET the user list and confirm the same values without re reading the request → AC-1
- [x] The self demotion check compares actor to path: admin A patching admin B's role to `user` succeeds, admin A patching their own fails → AC-8
- [x] Disable and enable audit the true prior state: disable after a fresh create shows `old: true`, enable shows `old: false` → AC-3
- [x] The self disable check compares actor to path: admin A disabling admin B succeeds, disabling themselves fails → AC-3
- [x] `revoked_count` is the UPDATE rowcount: create two sessions, expire or revoke one beforehand, revoke all → the count matches only the live rows → AC-4
- [x] The new hash comes from the password service: after reset, the old password fails and the new one logs in, and the stored hash verifies with Argon2id → AC-5
- [x] `sessions_revoked` uses the same helper as revoke: reset a user with one live session → audit shows `sessions_revoked: 1` and that session dies → AC-5
- [x] `lockout_cleared` reflects the pre reset state: reset with `failed_login_attempts` at 2 (below the lockout threshold) → still `true`; reset a clean account → `false` → AC-5
- [x] Challenge deletion targets the right user: two users hold pending challenges, disable one → only that user's challenge dies, the other still exchanges → AC-3, AC-5
- [x] The actor is a snapshot: after the action, rename or demote the actor → the audit row still shows the username and role at action time → AC-9
- [x] `target_id` is the path id: every audit row for a route carries the id from the URL, including 404s → AC-9
- [x] The 404 check is a real lookup: a well formed but absent UUID returns 404 on all five routes, each audited `not_found` → AC-9

## Acceptance-criteria coverage

- AC-1 covered by PATCH happy path, 422 cases, and the no op retry step
- AC-2 covered by the PATCH audit shape and the old value sourcing checks
- AC-3 covered by disable and enable, self disable, challenge deletion, and state sourcing checks
- AC-4 covered by the revoke count steps and the rowcount sourcing check
- AC-5 covered by lockout clear, disabled account reset, challenge deletion, validation, and no leak checks
- AC-6 covered by the duplicate state conflict step
- AC-7 covered by session revival, revoked sessions staying dead, and next request privilege steps
- AC-8 covered by self demotion and self action steps
- AC-9 covered by role denials, gate denials, 404 auditing, and snapshot sourcing checks