# 0010. Access alerts

**Date**: 2026-11-09
**Status**: Accepted

## Summary

This feature adds an alert feed for the events an operator most needs to see: denied access attempts, reads of Top Secret documents, admin changes to user privileges, and failed audit chain verification. Alerts are rows in a new table, each pointing back to the audit log entry that caused it, and they are written in the same transaction as that audit entry so an alert can never exist without its audit record. Admins and auditors can list alerts with filters and acknowledge them, but nobody can acknowledge an alert they triggered themselves.

## Requirements

**User stories**:

- As an admin, I want denied access attempts surfaced as alerts so that I can spot probing or privilege abuse without reading the whole audit log.
- As an auditor, I want reads of Top Secret documents and failed chain verifications raised as alerts so that the most sensitive activity is easy to review.
- As an admin or auditor, I want to acknowledge alerts so that the feed reflects what has been triaged.

**Acceptance criteria** (the contract, each criterion is IDed and independently checkable):

- **AC-1**: A denied outcome on any policy surface (document, document version, share, or admin user action) creates one `alerts` row of type `denied_access` in the same transaction as its audit entry.
- **AC-2**: An allowed read of document content or version content whose classification is Top Secret (rank 5) creates one `alerts` row of type `sensitive_read`, including reads granted through a per user share.
- **AC-3**: Each admin user mutation (role or clearance change, disable or enable, password reset, MFA reset, forced session revocation) creates one `alerts` row of type `privilege_change`.
- **AC-4**: When audit chain verification reports the chain invalid, the verify call creates one `alerts` row of type `chain_tamper`.
- **AC-5**: Every alert creation also appends an `alert.raise` audit entry in the same transaction, and every successful acknowledge appends an `alert.acknowledge` audit entry.
- **AC-6**: Alert creation is capped at 20 rows per actor per alert type per rolling hour (configurable); events beyond the cap still write their normal audit entry but create no alert row and no `alert.raise` entry.
- **AC-7**: `GET /v1/alerts` returns alerts newest first with cursor pagination and filters for state, alert type, actor username, and creation time range; both `admin` and `auditor` roles receive the full unscoped set.
- **AC-8**: `POST /v1/alerts/{id}/acknowledge` moves an `open` alert to `acknowledged`, recording who acknowledged it and when; acknowledging an already acknowledged alert returns 409.
- **AC-9**: A user cannot acknowledge an alert whose `actor_id` matches their own id; the attempt returns 403 and is audited as a denied `alert.acknowledge`. The `user` role cannot list or acknowledge alerts at all, and unauthenticated requests receive 401.
- **AC-10**: An alert row always carries a `summary` snapshot (actor username, action, outcome, target type, target id, and the denial reason or key detail) and an `audit_seq` pointing at the triggering audit entry, so reviewers get context without a second lookup being mandatory.
- **AC-11**: Alert generation failures never silently swallow the underlying business action: the alert insert participates in the caller's transaction, so a failure rolls back together with the audit entry rather than committing a half state.

## Decision

**Chosen option**: Option 2: In app alert records fed from the audit pipeline

Alerts are first class rows in a new `alerts` table, raised by a classifier hooked inside `audit.append` so every append path (business transactions, independent denials, fork retries, the verify path) is covered centrally, reviewable through a small REST surface for admins and auditors. (basis: project AGENTS.md audit in the same transaction rule; scope feature 11 recommends in app records to keep the demo self contained)

**Implementation skills**: `fastapi` (`fastapi/fastapi`, `.agents/skills/fastapi/`) · `sqlalchemy` (`TerminalSkills/skills`, `.agents/skills/sqlalchemy/`) · `alembic` (`TerminalSkills/skills`, `.agents/skills/alembic/`) · `pytest-asyncio-patterns` (`testland/qa`, `.agents/skills/pytest-asyncio-patterns/`)

## Feature design

**Data model sketch**:

New table `alerts` (one Alembic migration):

| Column | Type | Null | Notes |
|---|---|---|---|
| id | Uuid PK | no | default uuid4 |
| alert_type | String(30) | no | CheckConstraint in (`denied_access`, `sensitive_read`, `privilege_change`, `chain_tamper`) |
| state | String(20) | no | CheckConstraint in (`open`, `acknowledged`), default `open` |
| actor_id | Uuid | yes | snapshot of triggering actor id; null only for system raised alerts (none expected today) |
| actor_username | String(64) | yes | snapshot column mirroring `audit_log.actor_username`; backs the AC-7 filter without JSON path queries |
| summary | JSON | no | compact snapshot: action, outcome, target_type, target_id, plus reason or key details (actor fields live on the columns) |
| audit_seq | Integer | no | FK to `audit_log.seq`, the triggering entry; unique, monotonic, doubles as the list cursor |
| acknowledged_by_id | Uuid | yes | |
| acknowledged_by_username | String(64) | yes | snapshot, matches audit actor style |
| acknowledged_at | DateTime(tz) | yes | |
| created_at | DateTime(tz) | no | shared `created_at` column helper |

Indexes: `(state, audit_seq)` for the list endpoint, `(actor_id, alert_type, created_at)` for the hourly cap count. Portable types only per project rules.

**State transitions**:

`alerts.state`: `open` to `acknowledged` (one way; no reopen in this slice). The transition is a conditional `UPDATE ... WHERE id = :id AND state = 'open'` checked by rowcount, so two concurrent acknowledges cannot both succeed; rowcount 0 after the row exists returns 409. Only admin or auditor may transition, never the alert's own actor.

**Alert generation hook**:

The classifier lives in `services/alerts.py` and is invoked from inside `audit.append`, after the entry's hash is computed and before it returns, so it runs on every append path: `transact` business commits, `record_denial` independent commits (after its rollback, inside its retry loop), `append_with_retry`, and role gate denials. On `AuditChainFork` retries the whole unit replays, so the alert insert and its `alert.raise` append are rebuilt with primitives exactly like the audit entry itself (the `actor_kwargs` pattern). The classifier short circuits on `action` starting with `alert.` so `alert.raise` and `alert.acknowledge` entries can never recurse into alert generation.

Trigger mapping (the classifier inspects the full appended entry: action, outcome, and `details`):

| Condition | alert_type |
|---|---|
| `outcome="denied"` and action in the policy surfaces (`document.*`, `document_version.*`/version actions, `share.*`, admin `user.*`, `session.*`, `mfa.*` admin actions) | `denied_access` |
| `outcome="allowed"` and action in (`document.download`, `document.version_download`) and the target document's classification is 5 | `sensitive_read` |
| `outcome="allowed"` and action in (`user.privilege_update`, `user.disabled`, `user.enabled`, `user.password_reset`, `mfa.reset`, `session.revoke_all`) | `privilege_change` |
| the verify path appends `audit.verify` with `details.valid == false` | `chain_tamper` |

Denied admin mutations produce `denied_access` only, never `privilege_change` (privilege alerts are for changes that took effect). Auth surface actions (`login.*`, `mfa.*` user facing) are excluded from `denied_access`; they have their own lockout story. `alert.*` actions are always excluded.

For `chain_tamper`: `/v1/audit/verify` currently appends `audit.verify` through `append_with_retry` in its own session after `verify_summary` reads on the request session. The alert insert and its `alert.raise` append happen inside that same `append_with_retry` transaction before commit, with `actor_id`/`actor_username` copied from the verifying auditor (consistent with the `audit.verify` snapshot). Consequence: the verifying auditor cannot self acknowledge that alert. If `append_with_retry` exhausts its fork retries the request fails and no alert is raised; the invalid chain itself remains the record.

The `alert.raise` audit entry shape: `action="alert.raise"`, `outcome="allowed"`, `actor_*` copied from the triggering entry's actor snapshot, `target_type="alert"`, `target_id=<new alert uuid>`, `details={"alert_type": <type>, "trigger_action": <triggering action>, "trigger_seq": <triggering audit seq>}`.

The hourly cap: before inserting, count `alerts` rows where `actor_id` equals the triggering actor (NULL actors all group together under `IS NULL`), `alert_type` equals the candidate type, and `created_at` is within the trailing hour; at or above `ALERT_HOURLY_CAP` the classifier returns without inserting. The cap is best effort: two concurrent transactions can both pass the count and both insert, so the true bound is the cap plus in flight transactions. This is accepted because the audit log retains every event regardless; the cap exists to keep the feed readable, not to guarantee a hard maximum.

**API surface**:

| Endpoint | Method | Key inputs | Key outputs | Auth | Key errors |
|---|---|---|---|---|---|
| /v1/alerts | GET | state, alert_type (enum Literal, opt, 422 on bad value); actor_username, created_after, created_before (`AwareDatetime`, opt); cursor (int, opt), limit (opt, same bounds as audit list) | `AlertOut` items[], next_cursor | admin or auditor session | 401, 403 (audited denied `alert.list`) |
| /v1/alerts/{id}/acknowledge | POST | id (path, Uuid; non UUID gives 422) | `AlertOut` with state acknowledged | admin or auditor session | 401, 403 self or wrong role (audited denied `alert.acknowledge`), 404 unknown id (audited denied `alert.acknowledge` with `reason="not_found"`), 409 already acknowledged |

`AlertOut` fields: `id`, `alert_type`, `state`, `actor_id`, `actor_username`, `summary`, `audit_seq`, `acknowledged_by_id`, `acknowledged_by_username`, `acknowledged_at`, `created_at`.

List ordering and cursor: `ORDER BY audit_seq DESC`, `WHERE audit_seq < :cursor` when a cursor is given, `next_cursor` is the last row's `audit_seq` when the page is full, exactly mirroring `services/audit.list_entries`. Both roles see the identical unscoped set.

Both routes get `GATE_ACTIONS` entries for the MFA enrollment gate, and the role gate uses `require_role` with `alert.list` / `alert.acknowledge` as the audit action names. List calls append an `alert.list` audit entry with `outcome="allowed"` on success, matching the one audited behavior per route convention. No slowapi rate limit on these endpoints; the queries are indexed and cheap, and `/v1/audit/entries` sets the precedent of leaving list endpoints unlimited.

**Value sourcing**:

| Action | Value produced / displayed | Source |
|---|---|---|
| classify trigger | alert_type | classifier mapping table above, from the appended audit entry's action, outcome, and details |
| raise alert | summary fields | copied from the triggering audit entry columns (`action`, `outcome`, `target_type`, `target_id`, `details` reason) |
| raise alert | actor_id, actor_username | triggering audit entry actor snapshot columns |
| raise alert | audit_seq | `seq` of the triggering audit entry appended earlier in the same transaction |
| cap check | alerts in trailing hour for actor+type | COUNT over `alerts` where `actor_id` (NULL groups via `IS NULL`), `alert_type`, `created_at > now - 1h` |
| list alerts | state, alert_type, actor_username, created_at filters | query params bound to the matching columns; invalid enum values rejected 422 by the Literal types |
| list alerts | next_cursor | last row's `audit_seq` when the page is full |
| list alerts | alert.list audit entry | `append` inside the request transaction, actor from session user |
| acknowledge | acknowledged_by_id, acknowledged_by_username | current session user (per request re read in `api/deps.py`) |
| acknowledge | acknowledged_at | server clock at request time |
| acknowledge | 404 vs 409 | row lookup by id; conditional UPDATE rowcount distinguishes not found, wrong state, and success |

**Key invariants**:

- An alert row and its `alert.raise` audit entry commit or roll back together with the triggering audit entry, on every append path including independent denials and fork retries.
- `audit_seq` always references an existing `audit_log.seq`; audit rows are append only so the reference cannot dangle.
- The hourly cap is best effort per `(actor_id, alert_type)`; it bounds feed volume but is not a hard guarantee under concurrency.
- `state` only moves `open` to `acknowledged` via the conditional update; acknowledged rows have no mutation path.
- The `user` role can never read or acknowledge alerts; admins and auditors see the identical unfiltered set.
- `alert.*` audit actions never produce alerts (no recursion).

**Security model**:

Alert content is derived from audit data, which already snapshots actor identity without secrets; `summary` must never copy credential material, tokens, or document content. Access is role gated: `admin` and `auditor` only, enforced in the router via the same `require_role` dependency pattern as `/v1/audit`, with `alert.list` and `alert.acknowledge` audited on both allow and deny. Self acknowledge is a second guard on top of the role gate. No regulated data scope beyond the project's existing classification handling; alert rows carry no classification and are visible to both privileged roles by design.

**Configuration required**:

- `ALERT_HOURLY_CAP`: maximum alerts per actor per alert type per rolling hour, integer, default 20. Wired through `core/config.py`, `.env.example`, and compose like the existing `RATE_LIMIT_*` settings.

**Critical test scenarios** (each maps to an acceptance criterion in ## Requirements):

- Happy path: user with too low clearance attempts a document read; audit entry denied lands, one `denied_access` alert exists pointing at its seq, and `alert.raise` is in the chain; admin lists and acknowledges it, verifying **AC-1**, **AC-5**, **AC-7**, **AC-8**
- Happy path: Top Secret cleared user downloads a Top Secret document; one `sensitive_read` alert appears; same for a version content download and a share granted read, verifying **AC-2**
- Happy path: admin changes a user's clearance; one `privilege_change` alert appears; a denied privilege attempt produces `denied_access` only, verifying **AC-3**
- Failure case: auditor runs chain verify after a tampered row; verify reports invalid and one `chain_tamper` alert exists attributed to the auditor, verifying **AC-4**
- Failure case: 21 denied attempts by one actor within an hour produce 20 alerts, 21 audit entries, and 20 `alert.raise` entries, verifying **AC-6**
- Failure case: rollback of the business transaction (including a `record_denial` path and an `AuditChainFork` retry) leaves no alert and no `alert.raise` entry, verifying **AC-11**
- Auth/permission: the triggering user (or any `user` role account) gets 403 on list and acknowledge with audited denials; self acknowledge returns 403 audited; second acknowledge returns 409; unknown id returns audited 404, verifying **AC-9**, **AC-8**
- Recursion guard: `alert.raise` and `alert.acknowledge` entries themselves produce no alerts, verifying the no recursion invariant

## Build plan

Tracer Bullet ordering: one thin real slice end to end first (schema plus classifier plus list), then thicken triggers and acknowledge.

1. Alembic migration and `alerts` model (enums as checked strings, indexes, `actor_username` column) plus `ALERT_HOURLY_CAP` setting through config, env, and compose, satisfies **AC-6** (cap storage basis), **AC-10**
2. `services/alerts.py` classifier plus hook inside `audit.append`: trigger mapping, hourly cap count, alert insert plus `alert.raise` append, `alert.*` recursion short circuit, satisfies **AC-1**, **AC-5**, **AC-6**, **AC-11**
3. `sensitive_read` classification lookup for `document.download` and `document.version_download` (target classification 5, share granted reads included), satisfies **AC-2**
4. `privilege_change` trigger confirmation on the six allowed admin mutation actions, satisfies **AC-3**
5. `chain_tamper` wiring inside the verify path's `append_with_retry` transaction when `details.valid` is false, satisfies **AC-4**
6. `GET /v1/alerts` route, `AlertOut` schema, filters, `audit_seq` cursor pagination, role gate with `alert.list` audit entries, `GATE_ACTIONS` entries, satisfies **AC-7**, **AC-9** (read side), **AC-5**
7. `POST /v1/alerts/{id}/acknowledge` with conditional update, self acknowledge block, 404 and 409 handling, `alert.acknowledge` audit entries, satisfies **AC-8**, **AC-9**, **AC-5**
8. Full test suite covering every AC including cap boundary, fork retry rebuild, concurrent acknowledge, and recursion guard, satisfies all ACs

## Consequences

**Positive**:

- Operators get a triageable feed instead of mining the audit log, and every alert is provably tied to a chained audit entry because both are written by the same append path.
- Hooking the classifier inside `audit.append` covers every present and future append path centrally; a new audited action only needs a classifier rule, not new wiring.
- The hourly cap keeps alert volume bounded during brute force or probing without losing the audit record.

**Negative / tradeoffs**:

- `audit.append` now does extra work on qualifying entries (cap count query plus two inserts), adding latency inside business transactions, and `services/audit.py` gains a dependency on the alerts service (mitigated by keeping the classifier in `services/alerts.py` and calling it lazily).
- `summary` duplicates a small snapshot of audit data; it is deliberately compact and never authoritative, the audit entry remains the source of truth.
- The trigger classifier must be kept in sync as new audited actions are added; a forgotten action silently produces no alert.
- The cap is best effort under concurrency, so alert volume can exceed the configured cap by the number of in flight transactions.

**Neutral**:

- New table, new router, new audit action names (`alert.list`, `alert.raise`, `alert.acknowledge`) join `GATE_ACTIONS`.
- No email or external channel; delivery stays in app per the scope recommendation.

## Follow-up

- [ ] Consider an alert type for auth failures (bad passwords, MFA failures) in a later slice; this spec deliberately excludes them per the confirmed denial scope.
- [ ] Revisit unacknowledge or assignment workflow if triage needs ownership tracking.
- [ ] Email or webhook delivery of alerts remains a deferred scope item.

## Rationale

Reasoning and options: see [rationale.md](rationale.md)
