# 0005. Administration and account lifecycle

**Date**: 2026-11-08
**Status**: Accepted

## Summary

This spec gives admins a safe control plane for the user base: change a role or clearance, disable or re enable an account, revoke all of a user's sessions, and reset a password. Each change has exactly one endpoint, and every change writes a before and after record into the hash chained audit log (the tamper evident log from spec 0003) in the same transaction. No new tables or migrations are needed. The build reuses the existing session, lockout, and audit machinery.

## Requirements

**User stories**:
- As an administrator, I want to change a user's role or clearance so that access matches the current assignment.
- As an administrator, I want to disable or re enable a user so that a person can be removed from the system without deleting their history.
- As an administrator, I want to revoke a user's active sessions so that a stale or compromised login stops working immediately.
- As an administrator, I want to reset a user's credential so that password recovery works without touching document data.
- As the system, I want every privilege change and lifecycle event recorded with before and after values so the audit log proves what happened and when.

**Acceptance criteria** (the contract, each criterion is independently checkable):
- **AC-1**: `PATCH /v1/users/{user_id}` is admin only and accepts exactly two optional fields, `role` and `clearance`. Unknown fields, explicit nulls, out of range values, and a body carrying neither field return 422. Setting a field to its current value is valid: it returns 200 and audits old equal to new, so the call is safe to retry. The response is the updated user profile with the new values visible.
- **AC-2**: When an admin changes a user's `role` or `clearance`, the system writes an audit entry with action `user.privilege_update`, `outcome = allowed`, `target_type = user`, `target_id = user_id`, and `details` shaped as `{"role": {"old": <previous role>, "new": <new role>}, "clearance": {"old": <previous clearance>, "new": <new clearance>}}`, carrying both fields even when only one changed. The entry commits in the same transaction as the update, so the change never lands without its audit record, and the new values are visible on the next user read.
- **AC-3**: `POST /v1/users/{user_id}/disable` and `POST /v1/users/{user_id}/enable` are admin only and return 204. A disabled account cannot log in, and its existing sessions fail validation (401) on every protected request starting with the next one, because session validation already rejects inactive users. Disable also deletes the target's pending MFA challenges in the same transaction, so a login already past the password step cannot complete while the account is disabled. Enable restores the account state only: it does not clear the login lockout and does not revoke or create sessions. The toggle is audited as `user.disabled` or `user.enabled` with `details` shaped as `{"is_active": {"old": <previous>, "new": <new>}}`. An admin cannot disable their own account: that call returns 409 with reason `self_disable`, changes nothing, and is audited as a denial.
- **AC-4**: `POST /v1/users/{user_id}/sessions/revoke` is admin only, returns 204, and immediately revokes every active session of the target user by setting `revoked_at`. Active means `revoked_at IS NULL` and `expires_at` in the future; expired sessions are left alone. The revoke runs as a single UPDATE over that predicate and the count comes from its rowcount, so the number stays exact under concurrent logins. All of that user's live tokens become invalid on subsequent requests. The action is audited as `session.revoke_all` with `details` shaped as `{"revoked_count": <rowcount of the revoke UPDATE>}`.
- **AC-5**: `POST /v1/users/{user_id}/reset-password` is admin only, accepts `new_password` (12 to 256 characters, the existing password schema bounds, otherwise 422), and returns 204. It works on disabled accounts too. It stores a new Argon2id hash, revokes all of the user's active sessions (same predicate and rowcount as AC-4), deletes the target's pending MFA challenges so a login already past the password step cannot complete with the old credential, and clears the login lockout (`failed_login_attempts` back to 0, `locked_until` back to null) so an active account can log in right away with the new password; a disabled account still needs enable first. It does not touch the user's MFA enrollment; `POST /v1/users/{user_id}/mfa/reset` (spec 0004) remains the only MFA reset path. The action is audited as `user.password_reset` with `details` shaped as `{"sessions_revoked": <count>, "lockout_cleared": <true if a lockout or failure count was present, else false>}`. Neither the new password nor any password hash appears in the response or in any log or audit record.
- **AC-6**: Disabling an already disabled account returns 409 with reason `already_disabled`; enabling an already enabled account returns 409 with reason `already_enabled`. Neither call changes state, and each denial is audited with outcome `denied` and `details` shaped as `{"reason": <reason>, "is_active": <current state>}`.
- **AC-7**: Role and clearance changes take effect on the next authorization check, because every request re reads the user. They do not revoke existing sessions and do not alter document ownership or shares. Existing sessions of a disabled account stay in the table but fail validation while the account is disabled; if the account is re enabled, those sessions work again unless they expired or were revoked in the meantime.
- **AC-8**: An admin cannot remove their own admin role: a PATCH on their own account that sets `role` to anything other than `admin` returns 409 with reason `self_demotion`, changes nothing, and is audited as a denial. Another admin may perform the same change. Self enable, self session revoke, and self password reset are allowed.
- **AC-9**: Every allow and deny event in this feature follows the existing audit rule: the actor is stored as a snapshot (plain values via `audit.actor_kwargs`), the target is stored as `target_type` plus `target_id` with the before and after values in `details` captured before the mutation, the entry commits in the same transaction as the mutation it describes, and the audit log stays append only and hash chained. Denials use outcome `denied` with the reason in `details`. Unknown user 404s are audited as denials with reason `not_found`. Each route has one action name used for its success, its denials, and its gate mapping alike: `user.privilege_update`, `user.disabled`, `user.enabled`, `session.revoke_all`, `user.password_reset`.

## Decision

**Chosen option**: Option 2: narrow patch plus explicit action endpoints.

`PATCH /v1/users/{user_id}` changes only `role` and `clearance`. Account state changes go through `disable` and `enable`, session invalidation through `sessions/revoke`, and credential rotation through `reset-password`. Each change has one endpoint with one defined behavior, and every endpoint writes its audit entry in the same transaction as the mutation.

**Implementation skills**: `fastapi` (`wispbit-ai/skills`, `.agents/skills/fastapi/`) · `auth-implementation-patterns` (`wispbit-ai/skills`, `.agents/skills/auth-implementation-patterns/`) · `sqlalchemy` (`wispbit-ai/skills`, `.agents/skills/sqlalchemy/`)

## Feature design

**Data model sketch**:

No new table and no migration. The feature uses columns that already exist:

- `users.role`, `users.clearance`, `users.is_active`: the mutable privilege and state fields
- `users.password_hash`: replaced on reset, never read back out
- `users.failed_login_attempts`, `users.locked_until`: cleared on password reset (AC-5)
- `sessions.revoked_at`: set on revoke all and on password reset
- `audit_log`: before and after snapshots in the existing chained table (spec 0002, spec 0003)

**State transitions**:

- `active` to `disabled` via disable; `disabled` to `active` via enable. Repeating the current state returns 409 (AC-6).
- Password reset revokes all sessions, deletes pending MFA challenges, and clears the lockout, forcing a fresh login. It works on disabled accounts, does not change `is_active`, and does not touch MFA enrollment.
- Session revoke revokes all active sessions without changing account state.
- Role and clearance changes adjust privileges within the same account state. They create no new state.

**API surface**:

| Endpoint | Method | Key inputs | Key outputs | Auth | Key errors |
|---|---|---|---|---|---|
| /v1/users/{user_id} | PATCH | role (opt, one of admin, user, auditor), clearance (opt, int 1 to 5); at least one required | 200, updated UserProfile | admin, fully MFA enrolled | 404 unknown user, 422 unknown or empty fields, 409 self_demotion |
| /v1/users/{user_id}/disable | POST | none | 204 | admin | 404, 409 already_disabled, 409 self_disable |
| /v1/users/{user_id}/enable | POST | none | 204 | admin | 404, 409 already_enabled |
| /v1/users/{user_id}/sessions/revoke | POST | none | 204 | admin | 404 |
| /v1/users/{user_id}/reset-password | POST | new_password (req, 12 to 256 chars) | 204 | admin | 404, 422 invalid password |

All routes require a live session and pass the existing enrollment gate, so an admin who has not completed MFA enrollment is denied and audited before reaching any of them. All 409 responses use FastAPI's default envelope with `detail: {"reason": <reason>}`, the same shape the lockout 429 already uses.

**Value sourcing** (every value each action produces names where it comes from):

| Action | Value produced / displayed | Source |
|---|---|---|
| user patch | old role and old clearance | current `users.role` and `users.clearance`, read inside the transaction before the update |
| user patch | new role and new clearance | request body fields |
| user patch | response profile | the updated user row, serialized by the existing UserProfile schema |
| user patch | self_demotion check | actor id from the session compared with the path `user_id`, and the requested role |
| disable / enable | old and new state | current `users.is_active` and the action being performed |
| disable | self_disable check | actor id from the session compared with the path `user_id` |
| revoke sessions | revoked_count | rowcount of the single revoke UPDATE over `revoked_at IS NULL` and `expires_at > now` |
| reset password | new password hash | `passwords.hash_password(new_password)` from the existing password service (spec 0003) |
| reset password | sessions_revoked | rowcount of the shared revoke all helper, same predicate as revoke sessions |
| reset password | lockout_cleared | true when `failed_login_attempts > 0` or `locked_until` is set before the reset, else false |
| disable / reset password | pending challenge deletion | `mfa_challenges` rows for the target, the same delete the mfa/reset endpoint uses (spec 0004) |
| every audit entry | actor snapshot | `audit.actor_kwargs(actor)` from spec 0003 |
| every audit entry | target_id | the path `user_id` |
| every 404 | existence check | `users` row lookup by id, same pattern as the existing mfa/reset route |

**Key invariants**:
- Only admins reach these routes; officers and auditors are denied with 403 and an audited role denial.
- Unknown user ids return 404 on every route, audited as a `not_found` denial.
- Every mutation writes its audit entry in the same transaction, before commit, using `audit.transact` so a chain fork retries the whole unit (spec 0003). Every state check, self guard, and old value read happens against a freshly read target row inside that retried closure, so a retry re evaluates the checks instead of replaying stale values.
- An admin cannot disable their own account or remove their own admin role. Another admin can.
- Password reset and session revoke always invalidate live sessions immediately. Disable blocks validation without rewriting session rows. Disable and password reset also delete pending MFA challenges; enable and privilege patch do not.
- Password values and password hashes never appear in responses, logs, or audit details.
- MFA enrollment is untouched by every endpoint in this spec.

**Security model**:

The admin gate stays in the dependency stack: `require_role(action, UserRole.ADMIN)` with the route's own audit action, exactly like the existing `user.create`, `user.list`, and `mfa.reset` routes. Each route has one action name for gate, success, and denial alike: `user.privilege_update`, `user.disabled`, `user.enabled`, `session.revoke_all`, and `user.password_reset`; each new route also gets an entry in `GATE_ACTIONS` in `app/api/deps.py` under that same name so enrollment gate denials read consistently. Session validation re reads the user on every request (spec 0003), so privilege changes and disable take effect on the next request without any cache to invalidate. Handlers snapshot the target row's old values inside the transaction, mutate, audit, and commit; they never audit from a live object that a rollback could erase.

Operator warning: enable revives any unexpired, unrevoked sessions of the account (AC-7). When handling a suspected compromise, revoke sessions before re enabling, or the old access comes back.

**Configuration required**:

None. The feature uses the existing password hashing, session, lockout, and audit machinery with current settings.

**Critical test scenarios** (each maps to an acceptance criterion in ## Requirements):
- Happy path: admin patches role and clearance, sees both in the profile, and the `user.privilege_update` audit row carries the old and new values for both fields; verifies **AC-1**, **AC-2**
- Happy path: disable blocks the target's live session on the next request, enable restores access, and both toggles are audited with before and after state; verifies **AC-3**, **AC-7**
- Failure case: disable on a disabled account and enable on an enabled account return 409 with the reason and an audited denial, no state change; verifies **AC-6**
- Happy path: revoke all invalidates every live token and audits the count; verifies **AC-4**
- Happy path: reset password revokes sessions, clears a live lockout, the old password fails and the new one logs in, and no password material appears in the audit row; verifies **AC-5**
- Failure case: PATCH with an unknown field, with neither field, with an explicit null, or with `is_active` or `password` returns 422; a PATCH setting the current role returns 200 with old equal to new in the audit row; verifies **AC-1**
- Failure case: a pending MFA challenge issued before a disable or a password reset cannot be exchanged afterwards; verifies **AC-3**, **AC-5**
- Failure case: reset on a disabled account succeeds, but login still fails until enable; enable does not clear a live lockout; verifies **AC-5**, **AC-7**
- Auth/permission: officer and auditor calls to every route return 403 with an audited role denial; verifies **AC-9**
- Failure case: admin disabling their own account or demoting their own role gets 409, audited, with no change; verifies **AC-3**, **AC-8**
- Auth/permission: an unenrolled admin is held at the enrollment gate and the denial is audited under the route's action; verifies **AC-9**

## Build plan

Tracer Bullet order: the first task stands up one complete thread through schema, service, audit, route, gate mapping, and test, then each later task adds one more endpoint pair on the same pattern. No migration task exists because the schema is unchanged.

1. [x] Build the PATCH thread end to end: request schema that forbids extra fields and requires at least one of `role` or `clearance`, service with before and after audit under `user.privilege_update`, self demotion guard, route, `GATE_ACTIONS` entry, and tests; satisfies **AC-1**, **AC-2**, **AC-8**, **AC-9**
2. [x] Add disable and enable with the 409 duplicate state checks, the self disable guard, pending challenge deletion on disable, and `user.disabled` / `user.enabled` audit entries; satisfies **AC-3**, **AC-6**, **AC-9**
3. [x] Add sessions/revoke and reset-password, sharing one revoke all helper (single UPDATE, count from rowcount), with the lockout clear and pending challenge deletion on reset and the `session.revoke_all` / `user.password_reset` audit entries; satisfies **AC-4**, **AC-5**, **AC-9**
4. [x] Align the draft tests already in `tests/test_api.py` with the narrowed contract (move the `is_active` change out of the PATCH test into the disable call) and add the remaining scenarios: 422 cases, self guards, lockout clear, non admin denials; satisfies **AC-1**, **AC-3**, **AC-5**, **AC-6**, **AC-8**, **AC-9**
5. [x] Verify the AC-7 behaviors against the live session path: privilege change visible on the next request without revocation, disabled sessions failing validation and reviving on enable, re run the full suite; satisfies **AC-7**

## Consequences

**Positive**:
- Admins get a complete account control plane with no second identity system and no migration.
- One endpoint per change means one audited behavior per change, with no ambiguous second path.
- Password reset doubles as lockout recovery, and the self guards protect the admin plane from accidental lockout.

**Negative / tradeoffs**:
- Five endpoints instead of one generic patch means more surface to test and document.
- Privilege changes do not revoke sessions by design; an operator handling a suspected compromise must also call disable or sessions/revoke, and must revoke before re enabling, because enable revives old sessions.
- The self guards mean a lone admin who needs their own role changed must ask another admin, which is the intended safety property but can surprise.
- The self guards do not stop two admins from disabling or demoting each other, which could leave zero active admins; recovery is the `python -m app create-admin` CLI, the only source of admin accounts (the API forbids creating them).

**Neutral**:
- No schema migration; the feature builds entirely on the current `users`, `sessions`, and `audit_log` tables.
- The audit log remains the authoritative record of every privilege and lifecycle change.
- Disabled accounts keep their session rows; the rows simply fail validation until the account is re enabled or the sessions are revoked.

## Follow-up

- [x] The draft PATCH test in `tests/test_api.py` still sends `is_active` in the PATCH body; build task 4 moves that change to the disable endpoint so the suite matches AC-1. (Done during the build: the PATCH test sends only `role` and `clearance`, and the disable call carries the state change.)
- [ ] The `fastapi`, `auth-implementation-patterns`, and `sqlalchemy` skill conventions are not yet captured in a root `AGENTS.md` (none exists); they belong at root level when the standards and tooling feature runs `/audit`.
- [ ] Consider an explicit `password_reset_required` flag later if operations need a permanent "must change password" state; the current reset forces a fresh login by revoking sessions instead.
- [ ] Consider step up re authentication (a fresh password or TOTP prompt) for destructive admin actions; an MFA gated admin session is the current protection.

## Rationale

Reasoning, options considered, and references: see [rationale.md](rationale.md).