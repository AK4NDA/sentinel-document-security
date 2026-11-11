# Scope: Classified Document Access Control System

A web application that controls who can read, edit, and share classified documents. Each document carries a classification level (Unclassified, Restricted, Confidential, Secret, Top Secret) and each user carries a clearance and a role. The system enforces Bell LaPadula rules combined with role based access control, deny by default, and records every access attempt in a tamper evident audit log. This pass is backend first: the policy engine, data model, encryption, and audit trail proven through the API, with the web UI deferred to a later scope.

**Build approach:** Tracer Bullet (prove the whole pipe works before building any part of it fully; each feature is one thin real slice end to end).
**Workflow:** GA (`/check verify`, `/test`, a fresh model `/check review`, then `/document` after `/develop`; most features need a spec). The project default level of rigor. `/architect` is the recommended first stop for a feature with a real decision, but skippable when you already know the build. Any feature can carry its own tag to do more or less.

_These are recommendations to keep your build orderly, not requirements. Skip anything that does not fit: if you already know how to build a feature, use `/develop` and skip `/architect`. You decide when a feature is `done`._

## At a glance

| #   | Feature                            | Phase      | Status      |
| --- | ---------------------------------- | ---------- | ----------- |
| 1   | Stack & architecture               | Foundation | done        |
| 2   | Coding standards & tooling         | Foundation | done        |
| 3   | Data model                         | Foundation | done        |
| 4   | Core classified document loop      | Slice 1    | done        |
| 5   | MFA & login protection             | Slice 2    | done        |
| 6   | Administration & account lifecycle | Slice 3    | done        |
| 7   | Auditor access & log verification  | Slice 4    | done        |
| 8   | Document version history           | Slice 5    | done        |
| 9   | Full text search                   | Slice 6    | done        |
| 10  | Per user sharing                   | Slice 7    | done        |
| 11  | Access alerts                      | Slice 8    | done |
| 12  | Runnable demo packaging · Alpha    | Slice 9    | planned     |
| 13  | Maintenance & retention            | Hardening  | planned     |
| 14  | Audit log export                   | Hardening  | planned     |

## Foundations

### 1. Stack & architecture · done

Ratify the stated stack (Python, FastAPI, Pydantic, PostgreSQL with SQLite for development, SQLAlchemy and Alembic, React TypeScript Vite Tailwind held for the later UI scope) and decide the internal boundaries: where the policy engine lives, how encryption keys are managed, how the audit log is chained. Scaffold only the backend skeleton this pass needs.
**Done when:** the stack and architecture are recorded in a spec, and the backend scaffold boots locally with a database connection and a clean migration.

- [x] Decide the stack (spec): `/architect stack & architecture`
- [x] Scaffold from the decision: `/develop stack & architecture`
- [x] Verify it: `/check verify stack & architecture`
- [x] Test it: `/test stack & architecture`
- [x] Review it (fresh model): `/check review stack & architecture`
- [x] Document it: `/document stack & architecture`
      Spec [0001](../specs/0001-stack-architecture/index.md)

### 2. Coding standards & tooling · done

Capture conventions from the real scaffolded project, then install lint, format, type strictness, and pre commit enforcement so every later slice follows the same rules.
**Done when:** root `AGENTS.md` reflects the real stack, and lint, format, and pre commit hooks run clean on the scaffold.

- [x] Capture conventions and tooling choices: `/audit`

### 3. Data model · done

Core entities every feature builds on: users, roles, clearances, classification levels, documents, versions, per user shares, MFA secrets, sessions, and audit log entries, with the relationships and constraints the policy engine needs.
**Done when:** entities and relationships support every later slice (versioning, sharing, search, alerts) without a breaking migration.

- [x] Design it (spec): `/architect data model`
- [x] Build it: `/develop data model`
  - [x] Models and shared column helpers (enums, UUID PKs, timestamps)
  - [x] Alembic migration for all seven tables including the circular FK
  - [x] Constraint, cascade, and ordering tests on SQLite and Postgres
- [x] Verify it: `/check verify data model`
- [x] Test it: `/test data model`
- [x] Review it (fresh model): `/check review data model`
- [x] Document it: `/document data model`
      Spec [0002](../specs/0002-data-model/index.md)

## Slice 1: Core classified document loop

### 4. Core classified document loop · done

The walking skeleton and the heart of the product: local accounts with Argon2 passwords and sessions, admins creating users with a role and clearance, uploading, reading, editing, and deleting documents that carry a classification level. Every action passes a deny by default policy check combining clearance, classification, and role, file bytes are stored AES-GCM encrypted, and every attempt allowed or denied lands in the hash chained audit log. Exposed as a REST API with tests; no UI yet.
**Done when:** through the API, a user cleared for Secret can upload and read a Secret document, a user cleared only for Confidential is denied, the denial is recorded, and the audit chain verifies.

- [x] Design it (spec): `/architect core classified document loop`
- [x] Build it: `/develop core classified document loop`
  - [x] Audit chain: prev_hash unique migration, canonical hash service, verify function (AC-1, AC-14, AC-15)
  - [x] Security plumbing: password hashing, AES GCM blob store, session helpers (AC-2, AC-3, AC-6, AC-10)
  - [x] Auth surface: login, logout, me, cookie and Bearer dependencies, rate limit (AC-2, AC-3, AC-12, AC-17, AC-18, AC-19)
  - [x] Admin surface: user create and list endpoints plus create-admin CLI (AC-4, AC-5, AC-16)
  - [x] Document loop: policy engine and all six document endpoints (AC-6 through AC-14)
- [x] Verify it: `/check verify core classified document loop`
- [x] Test it: `/test core classified document loop`
- [x] Review it (fresh model): `/check review core classified document loop`
- [x] Document it: `/document core classified document loop`
      Spec [0003](../specs/0003-core-classified-document-loop/index.md)

## Slice 2: MFA & login protection

### 5. MFA & login protection · done

Thicken the auth strand: TOTP multi factor enrollment and login challenge, rate limiting on credential endpoints, and session revocation so a stolen or stale session cannot keep working.
**Done when:** login requires a valid TOTP code after enrollment, repeated failures are throttled, and revoked sessions stop working immediately.

- [x] Design it (spec): `/architect MFA & login protection`
- [x] Build it: `/develop MFA & login protection`
  - [x] Schema and TOTP core: mfa_challenges migration, model, secret seal/open, step verify with replay guard (AC-1, AC-2, AC-3, AC-7)
  - [x] Enrollment surface: enroll/start, enroll/confirm, limited session gate (AC-2, AC-3, AC-4)
  - [x] Login challenge: pending token on login, mfa/verify exchange, challenge lifecycle (AC-5, AC-6)
  - [x] Lockout and admin reset: failure counter policy, 429 path, mfa/reset endpoint (AC-8, AC-9)
  - [x] Audit actions, profile mfa_enrolled, rate limit on verify, full test suite (AC-10, AC-11, AC-12)
- [x] Verify it: `/check verify MFA & login protection`
- [x] Test it: `/test MFA & login protection`
- [x] Review it (fresh model): `/check review MFA & login protection`
- [x] Document it: `/document MFA & login protection`
      Spec [0004](../specs/0004-mfa-login-protection/index.md)

## Slice 3: Administration & account lifecycle

### 6. Administration & account lifecycle · done

Let admins run the user base: change roles and clearances, disable and re-enable accounts, force logout, and reset credentials, with every privilege change itself written to the audit log and its effect on live sessions and existing shares defined.
**Done when:** an admin can change a user's clearance or role, disable the account, and every one of those actions is audited with the before and after values.

- [x] Design it (spec): `/architect administration & account lifecycle`
- [x] Build it: `/develop administration & account lifecycle`
  - [x] PATCH thread end to end: role and clearance mutation, before and after audit, self demotion guard (AC-1, AC-2, AC-8, AC-9)
  - [x] Disable and enable: conflict checks, self disable guard, pending challenge deletion (AC-3, AC-6, AC-9)
  - [x] Session revoke and password reset: shared revoke helper, lockout clear, challenge deletion (AC-4, AC-5, AC-9)
  - [x] Test alignment and session behavior verification across the full suite (AC-1, AC-3, AC-5, AC-6, AC-7, AC-8, AC-9)
- [x] Verify it: `/check verify administration & account lifecycle`
- [x] Test it: `/test administration & account lifecycle`
- [x] Review it (fresh model): `/check review administration & account lifecycle`
- [x] Document it: `/document administration & account lifecycle`
      Spec [0005](../specs/0005-administration-account-lifecycle/index.md) · code in `app/api/users.py`, `app/services/users.py`

## Slice 4: Auditor access & log verification

### 7. Auditor access & log verification · done

Give the auditor role its own surface: read access to the audit log, an endpoint or report that recomputes the hash chain and proves no entry was edited or deleted, and hard separation so auditors cannot touch documents at all.
**Done when:** an auditor can browse and verify the log, a tampered entry is detected by verification, and any auditor attempt to read a document is denied and logged.

- [x] Design it (spec): `/architect auditor access & log verification`
- [x] Build it: `/develop auditor access & log verification`
  - [x] Audit query and verify services: filtered cursor paginated list, single pass verify summary (AC-1 to AC-4, AC-10)
  - [x] API surface: `/v1/audit` router, schemas, role gates, `GATE_ACTIONS` entries (AC-6, AC-8)
  - [x] Verify self audit and rate limit: `audit.verify` row, `RATE_LIMIT_AUDIT` setting (AC-5, AC-9)
  - [x] Test suite: filters, pagination, tamper detection, role denials, MFA gate, rate limit (AC-1 to AC-10)
- [x] Verify it: `/check verify auditor access & log verification`
- [x] Test it: `/test auditor access & log verification`
- [x] Review it (fresh model): `/check review auditor access & log verification`
- [x] Document it: `/document auditor access & log verification`
      Spec [0006](../specs/0006-auditor-access-log-verification.md)

## Slice 5: Document version history

### 8. Document version history · done

Keep every prior version of a document on edit, each with its own classification and authorship, support reading and restoring an older version, and audit every version event. Decide how classification changes across versions interact with the write down rule.
**Done when:** editing a document preserves the old version, each version carries its own classification, a user can restore an earlier version, and the chain of custody stays intact in the log.

- [x] Design it (spec): `/architect document version history`
- [x] Build it: `/develop document version history`
  - [x] Version list endpoint with per version clearance filter and audit (AC-1 to AC-3, AC-9)
  - [x] Per version content download with hash verify (AC-4, AC-5, AC-9)
  - [x] Restore endpoint appending a new version (AC-6 to AC-8, AC-9)
  - [x] Route registration, `GATE_ACTIONS`, full test suite (AC-1 to AC-10)
- [x] Verify it: `/check verify document version history`
- [x] Test it: `/test document version history`
- [x] Review it (fresh model): `/check review document version history`
- [x] Document it: `/document document version history`
      Spec [0007](../specs/0007-document-version-history/index.md) · code in `app/api/documents.py`, `app/services/documents.py`

## Slice 6: Full text search

### 9. Full text search · done

Let users find documents by content, with results filtered by the caller's clearance so a search never reveals the existence of a document above it. Decide the indexing approach and how encrypted content is indexed without weakening encryption.
**Done when:** a user can search and only sees documents their clearance and role permit, and searching for a term that only exists in a higher classified document returns nothing.

- [x] Design it (spec): `/architect full text search`
- [x] Build it: `/develop full text search`
  - [x] Extraction pipeline: deps, `text_extract` module, `search_text` migration, wire into upload/edit/restore (AC-5, AC-6, AC-9, AC-10)
  - [x] Rate limit setting: `RATE_LIMIT_SEARCH` through config, env, compose (AC-13)
  - [x] Search endpoint: service, route, schema, audit action, role and clearance gates (AC-1 to AC-4, AC-7, AC-8, AC-11, AC-12)
  - [x] Test suite: match semantics, clearance non leak, version and type edges, pagination, rate limit (all ACs)
- [x] Verify it: `/check verify full text search`
- [x] Test it: `/test full text search`
- [x] Review it (fresh model): `/check review full text search`
- [x] Document it: `/document full text search`
      Spec [0008](../specs/0008-full-text-search/index.md)

## Slice 7: Per user sharing

### 10. Per user sharing · done

Layer named user grants on top of the policy model so a document can be shared with specific people beyond the default clearance rules, with grant and revoke audited and the interaction with classification levels defined.
**Done when:** a user can share a document with a named colleague who could not otherwise read it, the grant appears in the audit log, revoking it blocks further access, and grants never override a lower classification ceiling.

- [x] Design it (spec): `/architect per user sharing`
- [x] Build it: `/develop per user sharing`
  - [x] Share management: grant, revoke, and list endpoints with eligibility checks and audit actions (AC-1, AC-3 to AC-5, AC-8 to AC-10, AC-12)
  - [x] Grantee read paths: share aware policy for document meta, content, and all versions with `via_share` audit details (AC-2, AC-3, AC-7, AC-15)
  - [x] Discovery surfaces: `GET /v1/shares/mine` and `GET /v1/users/lookup` with rate limit setting (AC-6, AC-13)
  - [x] Test suite: all AC scenarios including admin interaction, search non leak, concurrency, and audit assertions (AC-1 to AC-15)
- [x] Verify it: `/check verify per user sharing`
- [x] Test it: `/test per user sharing`
- [x] Review it (fresh model): `/check review per user sharing`
- [x] Document it: `/document per user sharing`
      Spec [0009](../specs/0009-per-user-document-sharing/index.md) · code in `app/services/shares.py`, `app/api/shares.py`, `app/api/documents.py`, `app/api/users.py`

## Slice 8: Access alerts

### 11. Access alerts · done

Surface the interesting events: denied attempts, access to the most sensitive classifications, privilege changes, and failed audit chain verifications generate alert records that admins and auditors can review. The channel decision (in app records versus email) is the open question; recommend in app records to keep the demo self contained.
**Done when:** a denied access attempt and a Top Secret read each produce an alert record visible to admins and auditors, and alert generation is itself audited.

- [x] Design it (spec): `/architect access alerts`
- [x] Build it: `/develop access alerts`
  - [x] Schema and classifier core: `alerts` migration and model, `ALERT_HOURLY_CAP` setting, classifier hooked inside `audit.append` with `alert.raise` entries (AC-1, AC-5, AC-6, AC-10, AC-11)
  - [x] Remaining triggers: `sensitive_read` on Top Secret content downloads, `privilege_change` on allowed admin mutations, `chain_tamper` on failed verify (AC-2, AC-3, AC-4)
  - [x] Alert list API: `GET /v1/alerts` with filters, `audit_seq` cursor pagination, role gates and `alert.list` audit entries (AC-7, AC-9 read side)
  - [x] Acknowledge API and test suite: conditional update, self acknowledge block, 404/409 handling, `alert.acknowledge` entries, full AC coverage (AC-8, AC-9, all ACs)
- [x] Verify it: `/check verify access alerts`
- [x] Test it: `/test access alerts`
- [x] Review it (fresh model): `/check review access alerts`
- [ ] Document it: `/document access alerts`
      Spec [0010](../specs/0010-access-alerts/index.md)

## Slice 9: Runnable demo packaging · Alpha

### 12. Runnable demo packaging

Make the whole thing boot with one Docker command: container images for the API and database, compose wiring, seed data covering every role and clearance, and a short scripted walkthrough that exercises allow and deny paths for a demo.
**Done when:** one compose command starts the system, seeded users can log in and hit the documented walkthrough, and the audit log shows the full trail.

- [ ] Build it: `/develop runnable demo packaging`

## Hardening

### 13. Maintenance & retention · needs a decision

Keep the system tidy over time: expired and consumed `mfa_challenges` rows, stale sessions, and orphaned encrypted blobs left behind by document deletes and version churn get a cleanup story, either a scheduled job or an explicit retention policy. Blob collection must dedupe by `blob_path` across all `document_versions` rows since restores share paths. Surfaced by spec 0004, spec 0003, and spec 0007 follow ups.
**Done when:** expired challenges and orphaned blobs are removed by a defined mechanism, the cleanup itself is audited or logged, and no live data is ever collected.

- [ ] Design it (spec): `/architect maintenance & retention`

### 14. Audit log export

Let auditors pull a filtered slice of the audit log as a file (CSV or JSON) for offline evidence, reusing the same filters as the entries endpoint. Surfaced by spec 0006 follow-up; the in app verify already exposes `head_hash` for external checkpointing.
**Done when:** an auditor can export a filtered audit range to a file, the export is itself audited, and auditors remain the only role that can do it.

- [ ] Design it (spec): `/architect audit log export`

## Deferred

Out of scope for the current build pass, kept so the plan stays honest.

- **Web UI**: the React, TypeScript, Vite, and Tailwind frontend for all of the above · needs a decision · GA
- **SSO and enterprise IdP**: single sign on for defence organisations · needs a decision
- **Email alert channel**: deliver access alerts by email in addition to in app records · needs a decision
- **Document export and printing**: controlled export of documents out of the system · needs a decision · GA
- **WebAuthn or hardware keys**: phishing resistant second factor to replace or augment TOTP · needs a decision
- **MFA recovery codes**: backup codes for lost authenticators; admin reset covers this for now · needs a decision
- **Search at scale**: blind index or per clearance tier indexes plus relevance ranking if the corpus outgrows the current scan · from spec 0008 · needs a decision
- **Auth failure alerts**: extend the alert classifier to login and MFA failures · from spec 0010 · needs a decision
- **Alert triage workflow**: unacknowledge, assignment, or severity on alert records · from spec 0010 · needs a decision
- **Production deployment hardening**: KMS or HSM key management, object storage, and a shared rate limit store for multi worker deploys · from spec 0001 · needs a decision
- **Step up re authentication for admin actions**: a fresh password or TOTP prompt before destructive admin operations · from spec 0005 · needs a decision
- **Forced password change flag**: a permanent "must change password" account state for operations · from spec 0005 · needs a decision

## Legend

**The decision box.** Every feature carries exactly one, the sub-task whose label ends with `(spec)`. Its wording varies (`Design it (spec)` normally, `Decide the stack (spec)` on Stack & architecture), so skills locate it by that `(spec)` suffix, never by an exact label. Every other box is an execution box and `/architect` never ticks one.

**Feature lifecycle**: the scope updates as a feature moves; each row is what it shows and who sets it:

| State                        | Set by                                                                                 | The feature shows                                                                                                                                                                                                                            |
| ---------------------------- | -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `planned` · needs a decision | `/scope`                                                                               | one box: `Design it (spec): /architect <feature>`                                                                                                                                                                                            |
| `in-progress` (designed)     | **`/architect` at spec capture**                                                       | `Design it` ticked; spec linked; `Build it: /develop <feature>` + **2 to 5 milestones**; the tier's closing boxes (`Verify it` Alpha+, `Test it` Beta+, `Review it` + `Document it` GA); any surfaced follow-up enrolled                     |
| `in-progress` (building)     | `/develop`                                                                             | milestone sub-boxes tick one by one; code pointer filled                                                                                                                                                                                     |
| `in-progress` (verified)     | `/check verify`                                                                        | `Build it` + milestones ticked; `Verify it` ticked                                                                                                                                                                                           |
| `done`                       | **you, when you decide it is** (any skill sets it when you say so); `/sync` reconciles | boxes you ran ticked, skipped ones marked skipped; the tier's last stage (`Prototype` → after `/develop`; `Alpha` → after `/check verify`; `Beta`/`GA` → after `/test`) is the suggested point to call it done; `/sync` captures conventions |

- **Next step** = the first unticked box (always a command or a tracked milestone).
- **needs a decision** = run `/architect` first; otherwise straight to `/develop` (or `/audit` for standards & tooling). The tag drops once the spec is captured.
- **Atomic build tasks live in the spec's `## Build plan`, not here**: the scope carries only the milestone rollup.
- **Status** `planned` → `in-progress` → `done`, plus `existing` (pre-workflow) and `dropped` (de-scoped, kept for history).
- **Approach tag** beside a heading (e.g. `· Facade`) overrides the project default for that feature; no tag = inherits it.
- **Workflow tier tag** beside a heading (e.g. `· GA`, `· Prototype`) sets that one feature's rigor above or below the project default; no tag inherits the default. It decides the feature's check boxes and each skill's next suggestion.
- **Workflow** (header line) is the project default, what runs after `/develop`: **Prototype** = nothing (trust develop's own build time self check); **Alpha** = `/check verify`; **Beta** = `/check verify` then `/test`; **GA** = adds a fresh model `/check review` then `/document`. A feature built on an unratified decision (an `Assumed` spec) stays flagged, but that never blocks `done`.
- **Pointer line** (`spec <n> · code in <path>`): the spec link added by `/architect`, the code path by `/develop`.
