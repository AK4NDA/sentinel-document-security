# 0005. Administration and account lifecycle: rationale

## Context

Admins can currently create accounts, list them, and reset a user's MFA (specs 0003 and 0004). They cannot change a role or clearance after creation, disable a compromised account, force logout, or rotate a password. In a classified document system those are core operational needs: assignments change, people leave, and credentials leak.

The building blocks already exist. Session validation re reads the user on every request, so any change to role, clearance, or active state takes effect on the next request with no cache to invalidate. Sessions carry `revoked_at` for instant invalidation. The user row carries the lockout counters from spec 0004. The audit chain from spec 0003 commits an entry in the same transaction as the business write and retries the whole unit on a chain fork. The gap is a safe admin workflow over these parts, not new infrastructure.

The forces that shaped the choice: every privilege change must be provable after the fact (before and after values in an append only log), a compromised account must be stoppable immediately, recovery from lockout must actually work, and the admin plane must not be able to lock itself out by accident.

## Options considered

### Option 1: One generic PATCH for all four mutable fields

A single `PATCH /v1/users/{user_id}` accepts `role`, `clearance`, `is_active`, and `password`, with no separate action endpoints.

**Pros**:
- Smallest API surface, one validation schema, one handler.

**Cons**:
- State and credential changes hide inside a generic mutation, meaning the audit action, the session revocation rule, and the lockout behavior all become conditional branches that callers cannot see from the URL.
- A password changed through a generic patch either revokes sessions (duplicating a reset flow that does not exist yet) or does not (a security hole). Either answer is a trap.

### Option 2: Narrow patch plus explicit action endpoints (chosen)

PATCH changes only `role` and `clearance`. Disable, enable, sessions/revoke, and reset-password are separate POST action endpoints, each with one defined behavior and one audit action.

**Pros**:
- One safe path per change; the URL tells the operator exactly what side effects to expect.
- Conflict semantics (409 on repeated state) and self guards live naturally on the action endpoints.

**Cons**:
- Five endpoints instead of one, so more routes, gate mappings, and tests.

### Sub decision: lockout on password reset

- **Clear the lockout (chosen)**: reset is a recovery action; leaving the user locked for the remainder of the 15 minutes defeats the purpose of an admin reset.
- **Leave it untouched**: simpler, but a locked out user stays locked out even after the admin "fixed" the credential.

### Sub decision: self actions

- **Block self disable and self demotion (chosen)**: a single mistaken call cannot remove the acting admin's access; another admin can still perform the change.
- **No guards**: simpler rules, but one mistake can strand the admin plane, and recovery then needs direct database access.

## Rationale

Option 2 wins because the system's security model depends on being able to prove and to stop access changes (basis: spec 0003, the audit chain and per request user re read). Explicit action endpoints make each side effect (session revocation, lockout clear, state toggle) a visible, separately audited contract instead of a branch inside a generic patch. The narrow PATCH keeps the common privilege change compact while the action endpoints carry the operational semantics, and the 409 conflict checks make repeated calls safe to retry.

Clearing the lockout on reset follows from the same recovery story: spec 0004 built the lockout to stop brute force, not to block an admin assisted recovery, and the reset is itself audited so the clear is provable (basis: spec 0004, the shared lockout policy). The self guards follow from the classified system's deny by default posture applied to the admin plane itself: the cost of a 409 is trivial next to the cost of losing all admin access (basis: least privilege and fail safe defaults).

No new storage is justified: every value the feature needs already lives on the `users`, `sessions`, and `audit_log` tables, and adding a shadow admin table would duplicate state the audit chain already records (basis: spec 0002, the seven table data model).

An independent cross check before confirmation shaped four refinements. Disable and password reset now delete pending MFA challenges, because a challenge issued before the change sits past the password step and would otherwise survive it; the delete mirrors the existing mfa/reset endpoint (basis: spec 0004, challenge lifecycle). The revoke count comes from the rowcount of a single UPDATE over the active predicate (unrevoked and unexpired), so the audited number cannot drift under concurrent logins (basis: atomic count and write in one statement). Every state check and old value read runs inside the retried transaction closure against a freshly read row, so an audit chain retry re evaluates 409 and self guard checks instead of replaying stale snapshots (basis: spec 0003, the documents.edit retry pattern). And there is no last admin guard: two admins can still disable each other, but the create-admin CLI is the recovery path and the only source of admin accounts, since the API forbids creating them (basis: spec 0003 AC-16, the CLI bootstrap; the UserAdminCreate validator).

## References

**Project sources** (verifiable, in this repo):
- Spec 0003, core classified document loop: the audit chain, `audit.transact`, actor snapshots, per request user re reads, and the admin route pattern
- Spec 0004, MFA and login protection: the shared lockout policy, the MFA reset endpoint, and the enrollment gate
- Spec 0002, data model: the `users`, `sessions`, and `audit_log` tables this feature reuses
- `app/api/deps.py`: `require_role` and `GATE_ACTIONS`, the gate pattern the new routes extend
- `tests/test_api.py`: the draft admin lifecycle tests that seeded the response codes and audit details shape

**Practices & standards**:
- One safe path per state change, explicit action endpoints for operations with side effects
- Fail safe defaults and least privilege applied to the admin plane (self guards)
- Audit before commit, snapshots over live objects, from the project's existing audit rule