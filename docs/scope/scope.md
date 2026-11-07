# Scope: Classified Document Access Control System

A web application that controls who can read, edit, and share classified documents. Each document carries a classification level (Unclassified, Restricted, Confidential, Secret, Top Secret) and each user carries a clearance and a role. The system enforces Bell LaPadula rules combined with role based access control, deny by default, and records every access attempt in a tamper evident audit log. This pass is backend first: the policy engine, data model, encryption, and audit trail proven through the API, with the web UI deferred to a later scope.

**Build approach:** Tracer Bullet (prove the whole pipe works before building any part of it fully; each feature is one thin real slice end to end).
**Workflow:** GA (`/check verify`, `/test`, a fresh model `/check review`, then `/document` after `/develop`; most features need a spec). The project default level of rigor. `/architect` is the recommended first stop for a feature with a real decision, but skippable when you already know the build. Any feature can carry its own tag to do more or less.

_These are recommendations to keep your build orderly, not requirements. Skip anything that does not fit: if you already know how to build a feature, use `/develop` and skip `/architect`. You decide when a feature is `done`._

## At a glance

| # | Feature | Phase | Status |
|---|---------|-------|--------|
| 1 | Stack & architecture | Foundation | in-progress |
| 2 | Coding standards & tooling | Foundation | planned |
| 3 | Data model | Foundation | done |
| 4 | Core classified document loop | Slice 1 | in-progress |
| 5 | MFA & login protection | Slice 2 | planned |
| 6 | Administration & account lifecycle | Slice 3 | planned |
| 7 | Auditor access & log verification | Slice 4 | planned |
| 8 | Document version history | Slice 5 | planned |
| 9 | Full text search | Slice 6 | planned |
| 10 | Per user sharing | Slice 7 | planned |
| 11 | Access alerts | Slice 8 | planned |
| 12 | Runnable demo packaging · Alpha | Slice 9 | planned |

## Foundations

### 1. Stack & architecture · in-progress
Ratify the stated stack (Python, FastAPI, Pydantic, PostgreSQL with SQLite for development, SQLAlchemy and Alembic, React TypeScript Vite Tailwind held for the later UI scope) and decide the internal boundaries: where the policy engine lives, how encryption keys are managed, how the audit log is chained. Scaffold only the backend skeleton this pass needs.
**Done when:** the stack and architecture are recorded in a spec, and the backend scaffold boots locally with a database connection and a clean migration.
- [x] Decide the stack (spec): `/architect stack & architecture`
- [ ] Scaffold from the decision: `/develop stack & architecture`
- [ ] Verify it: `/check verify stack & architecture`
- [ ] Test it: `/test stack & architecture`
- [ ] Review it (fresh model): `/check review stack & architecture`
- [ ] Document it: `/document stack & architecture`
Spec [0001](../specs/0001-stack-architecture/index.md)

### 2. Coding standards & tooling
Capture conventions from the real scaffolded project, then install lint, format, type strictness, and pre commit enforcement so every later slice follows the same rules.
**Done when:** root `AGENTS.md` reflects the real stack, and lint, format, and pre commit hooks run clean on the scaffold.
- [ ] Capture conventions and tooling choices: `/audit`

### 3. Data model · done
Core entities every feature builds on: users, roles, clearances, classification levels, documents, versions, per user shares, MFA secrets, sessions, and audit log entries, with the relationships and constraints the policy engine needs.
**Done when:** entities and relationships support every later slice (versioning, sharing, search, alerts) without a breaking migration.
- [x] Design it (spec): `/architect data model`
- [x] Build it: `/develop data model`
  - [x] Models and shared column helpers (enums, UUID PKs, timestamps)
  - [x] Alembic migration for all seven tables including the circular FK
  - [x] Constraint, cascade, and ordering tests on SQLite and Postgres
- [ ] Verify it: `/check verify data model`
- [x] Test it: `/test data model`
- [x] Review it (fresh model): `/check review data model`
- [x] Document it: `/document data model`
Spec [0002](../specs/0002-data-model/index.md)

## Slice 1: Core classified document loop

### 4. Core classified document loop · in-progress
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

### 5. MFA & login protection · needs a decision
Thicken the auth strand: TOTP multi factor enrollment and login challenge, rate limiting on credential endpoints, and session revocation so a stolen or stale session cannot keep working.
**Done when:** login requires a valid TOTP code after enrollment, repeated failures are throttled, and revoked sessions stop working immediately.
- [ ] Design it (spec): `/architect MFA & login protection`

## Slice 3: Administration & account lifecycle

### 6. Administration & account lifecycle · needs a decision
Let admins run the user base: change roles and clearances, disable and re-enable accounts, force logout, and reset credentials, with every privilege change itself written to the audit log and its effect on live sessions and existing shares defined.
**Done when:** an admin can change a user's clearance or role, disable the account, and every one of those actions is audited with the before and after values.
- [ ] Design it (spec): `/architect administration & account lifecycle`

## Slice 4: Auditor access & log verification

### 7. Auditor access & log verification · needs a decision
Give the auditor role its own surface: read access to the audit log, an endpoint or report that recomputes the hash chain and proves no entry was edited or deleted, and hard separation so auditors cannot touch documents at all.
**Done when:** an auditor can browse and verify the log, a tampered entry is detected by verification, and any auditor attempt to read a document is denied and logged.
- [ ] Design it (spec): `/architect auditor access & log verification`

## Slice 5: Document version history

### 8. Document version history · needs a decision
Keep every prior version of a document on edit, each with its own classification and authorship, support reading and restoring an older version, and audit every version event. Decide how classification changes across versions interact with the write down rule.
**Done when:** editing a document preserves the old version, each version carries its own classification, a user can restore an earlier version, and the chain of custody stays intact in the log.
- [ ] Design it (spec): `/architect document version history`

## Slice 6: Full text search

### 9. Full text search · needs a decision
Let users find documents by content, with results filtered by the caller's clearance so a search never reveals the existence of a document above it. Decide the indexing approach and how encrypted content is indexed without weakening encryption.
**Done when:** a user can search and only sees documents their clearance and role permit, and searching for a term that only exists in a higher classified document returns nothing.
- [ ] Design it (spec): `/architect full text search`

## Slice 7: Per user sharing

### 10. Per user sharing · needs a decision
Layer named user grants on top of the policy model so a document can be shared with specific people beyond the default clearance rules, with grant and revoke audited and the interaction with classification levels defined.
**Done when:** a user can share a document with a named colleague who could not otherwise read it, the grant appears in the audit log, revoking it blocks further access, and grants never override a lower classification ceiling.
- [ ] Design it (spec): `/architect per user sharing`

## Slice 8: Access alerts

### 11. Access alerts · needs a decision
Surface the interesting events: denied attempts, access to the most sensitive classifications, and privilege changes generate alert records that admins and auditors can review. The channel decision (in app records versus email) is the open question; recommend in app records to keep the demo self contained.
**Done when:** a denied access attempt and a Top Secret read each produce an alert record visible to admins and auditors, and alert generation is itself audited.
- [ ] Design it (spec): `/architect access alerts`

## Slice 9: Runnable demo packaging · Alpha

### 12. Runnable demo packaging
Make the whole thing boot with one Docker command: container images for the API and database, compose wiring, seed data covering every role and clearance, and a short scripted walkthrough that exercises allow and deny paths for a demo.
**Done when:** one compose command starts the system, seeded users can log in and hit the documented walkthrough, and the audit log shows the full trail.
- [ ] Build it: `/develop runnable demo packaging`

## Deferred

Out of scope for the current build pass, kept so the plan stays honest.

- **Web UI**: the React, TypeScript, Vite, and Tailwind frontend for all of the above · needs a decision · GA
- **SSO and enterprise IdP**: single sign on for defence organisations · needs a decision
- **Email alert channel**: deliver access alerts by email in addition to in app records · needs a decision
- **Document export and printing**: controlled export of documents out of the system · needs a decision · GA

## Legend

**The decision box.** Every feature carries exactly one, the sub-task whose label ends with `(spec)`. Its wording varies (`Design it (spec)` normally, `Decide the stack (spec)` on Stack & architecture), so skills locate it by that `(spec)` suffix, never by an exact label. Every other box is an execution box and `/architect` never ticks one.

**Feature lifecycle**: the scope updates as a feature moves; each row is what it shows and who sets it:

| State | Set by | The feature shows |
|---|---|---|
| `planned` · needs a decision | `/scope` | one box: `Design it (spec): /architect <feature>` |
| `in-progress` (designed) | **`/architect` at spec capture** | `Design it` ticked; spec linked; `Build it: /develop <feature>` + **2 to 5 milestones**; the tier's closing boxes (`Verify it` Alpha+, `Test it` Beta+, `Review it` + `Document it` GA); any surfaced follow-up enrolled |
| `in-progress` (building) | `/develop` | milestone sub-boxes tick one by one; code pointer filled |
| `in-progress` (verified) | `/check verify` | `Build it` + milestones ticked; `Verify it` ticked |
| `done` | **you, when you decide it is** (any skill sets it when you say so); `/sync` reconciles | boxes you ran ticked, skipped ones marked skipped; the tier's last stage (`Prototype` → after `/develop`; `Alpha` → after `/check verify`; `Beta`/`GA` → after `/test`) is the suggested point to call it done; `/sync` captures conventions |

- **Next step** = the first unticked box (always a command or a tracked milestone).
- **needs a decision** = run `/architect` first; otherwise straight to `/develop` (or `/audit` for standards & tooling). The tag drops once the spec is captured.
- **Atomic build tasks live in the spec's `## Build plan`, not here**: the scope carries only the milestone rollup.
- **Status** `planned` → `in-progress` → `done`, plus `existing` (pre-workflow) and `dropped` (de-scoped, kept for history).
- **Approach tag** beside a heading (e.g. `· Facade`) overrides the project default for that feature; no tag = inherits it.
- **Workflow tier tag** beside a heading (e.g. `· GA`, `· Prototype`) sets that one feature's rigor above or below the project default; no tag inherits the default. It decides the feature's check boxes and each skill's next suggestion.
- **Workflow** (header line) is the project default, what runs after `/develop`: **Prototype** = nothing (trust develop's own build time self check); **Alpha** = `/check verify`; **Beta** = `/check verify` then `/test`; **GA** = adds a fresh model `/check review` then `/document`. A feature built on an unratified decision (an `Assumed` spec) stays flagged, but that never blocks `done`.
- **Pointer line** (`spec <n> · code in <path>`): the spec link added by `/architect`, the code path by `/develop`.
