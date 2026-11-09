# 0009. Per user document sharing

**Date**: 2026-11-09
**Status**: In Progress


## Summary

Document owners can grant named users read access to their documents, including documents classified above the grantee's clearance. A share is a discretionary grant: it lets a specific person read a document and all of its versions, but never lets them edit, delete, or pass it on. Only the owner manages shares, shares last until revoked, and every grant, revoke, and shared read lands in the audit log. The `document_shares` table already exists from spec 0002, so this feature is policy, service, and API work with no migration.


## Requirements

**User stories**:
- As a document owner, I want to share a document with a named colleague so that they can read it even when their clearance is below the document's classification.
- As a document owner, I want to see who a document is shared with, including past revocations, so that I can manage and explain access.
- As a grantee, I want a list of documents shared with me so that I can find them without links.
- As an owner, I want to look up users by username so that I can pick a grantee without admin help.
- As an auditor, I want every grant, revoke, and shared read recorded so that discretionary access is fully reconstructable.

**Acceptance criteria** (the contract, each criterion is IDed and independently checkable):
- **AC-1**: An owner with the `user` role can grant a read share on their own document to an eligible grantee via `POST /v1/documents/{id}/shares` with body `{"user_id": "<uuid>"}` (extra fields ignored); a new share returns 201 with a `ShareOut` body, and the grant appends an audit entry with action `document.share_grant`, outcome allowed, targeting the document, with `share_id` and the grantee id in details.
- **AC-2**: A grantee with an active share can read the shared document's metadata (`GET /v1/documents/{id}`) and content (`GET /v1/documents/{id}/content`) even when the document's classification exceeds their clearance; each allowed access appends the existing audit action (`document.read`, `document.download`) with `details.via_share = true` and `details.share_id` set only when the share is what admitted the caller (clearance alone would have denied).
- **AC-3**: The owner can revoke a share via `DELETE /v1/documents/{id}/shares/{user_id}`; afterwards the grantee's read, download, and version accesses are denied and audited, and the revoke appends `document.share_revoke` with outcome allowed and `share_id` plus grantee id in details.
- **AC-4**: Regranting a revoked share via POST clears `revoked_at` and `revoked_by`, updates `granted_by`, preserves `created_at` as first grant time, returns 200 with `ShareOut`, and appends `document.share_grant`; POSTing when an active share already exists returns 200 with the existing share unchanged and appends no audit entry.
- **AC-5**: `GET /v1/documents/{id}/shares` (owner only) returns a `ShareListResponse` containing every share row for the document, active and revoked, each `ShareOut` carrying share `id`, grantee `user_id` and username, `access_level`, `granted_by` username, `created_at`, `revoked_at`, and `revoked_by` username when set; the call itself is audited as `document.shares_list`.
- **AC-6**: `GET /v1/shares/mine` returns a `SharedDocumentListResponse` of `SharedDocumentOut` rows (document id, title, description, classification, owner username, `shared_at` from `document_shares.created_at`), ordered by `shared_at` descending then document id, including documents above the caller's clearance and excluding documents with no current version; the call is audited as `document.list_shared`.
- **AC-7**: A grantee can list (`GET /v1/documents/{id}/versions`) and download (`GET /v1/documents/{id}/versions/{n}/content`) every version of a shared document regardless of each version's classification; allows and denials audit under `document.versions_list` and `document.version_download` with the same `via_share`/`share_id` rule as AC-2.
- **AC-8**: Only the document owner can grant, revoke, or list shares; any other caller, including a user whose clearance meets the document's, receives 404 and an audited denial with reason `not_owner_or_missing`, matching the edit endpoint's convention of not revealing existence.
- **AC-9**: Grant rejects with an audited denial each of: grantee equal to owner (reason `self_share`, 409), disabled account (`grantee_disabled`, 409), account without the `user` role (`grantee_role`, 409), and nonexistent user id (`user_not_found`, 404).
- **AC-10**: `DELETE` on a share that is already revoked or never existed returns 404 with an audited denial reason `share_not_active`.
- **AC-11**: Full text search is unchanged: a document shared with a caller but classified above their clearance does not appear in that caller's `GET /v1/documents/search` results, and `GET /v1/documents` remains own documents only.
- **AC-12**: Share management endpoints require the `user` role; admin and auditor callers are denied by the role gate under the actions named in Feature design. An auditor can never hold an effective share because grant rejects non `user` roles, and auditor document denials continue to be logged.
- **AC-13**: `GET /v1/users/lookup?username=<prefix>` returns at most `limit` (query param, default 20, capped at 20) active accounts holding the `user` role matching a case insensitive username prefix of at least 2 characters, ordered by username ascending, each as `{id, username}` only, rate limited by `RATE_LIMIT_USER_LOOKUP`, and appends an audit entry `user.lookup` per handled call (429s are not audited).
- **AC-14**: Admin actions never modify shares: changing a user's clearance, role, or disabled state, or disabling the share owner, leaves share rows untouched; access still flows through the existing account gates, so a disabled grantee cannot use sessions, a grantee demoted to auditor is blocked by the role gate, and grantees of a disabled owner retain access.
- **AC-15**: A share grants read only: grantee attempts at edit, delete, version restore, or creating versions are denied by the existing owner and clearance checks and audited; a share never permits write, reclassification, or onward sharing.


## Decision

**Chosen option**: Option 1: Discretionary per user read grant (share overrides clearance)

A document share is a discretionary, read only, owner managed grant that lets one named `user` role account read the document and all of its versions regardless of the document's classification, lasting until revoked, with every grant, revoke, and shared access audited.

**Implementation skills**: `fastapi` (`fastapi/fastapi`, `.agents/skills/fastapi/`) · `sqlalchemy` (`TerminalSkills/skills`, `.agents/skills/sqlalchemy/`)

## Feature design

**Data model sketch**:
No schema change. The existing `document_shares` table from spec 0002 is the whole model:

| Column | Type | Notes |
|---|---|---|
| `id` | uuid pk | share row id, surfaced as `share_id` in audit details and `ShareOut.id` |
| `document_id` | uuid fk → documents, cascade, indexed | the shared document |
| `user_id` | uuid fk → users, cascade, indexed | the grantee |
| `granted_by` | uuid fk → users, restrict | always the owner at grant time |
| `access_level` | string(20), default `read` | only `read` exists; enforced in the service layer, never accepted in request bodies |
| `created_at` | timestamptz | first grant time; preserved across regrants |
| `revoked_at` | timestamptz null | set on revoke; null means active |
| `revoked_by` | uuid fk → users, restrict, null | set on revoke; cleared on regrant |

Unique on (`document_id`, `user_id`): one row per pair, regrant reactivates. Relationships `document`, `grantee`, `granter`, `revoker` exist but are all `lazy="raise"`, so every share query must `selectinload` or join explicitly; touching `.grantee.username` style attributes without a load raises. `Document.shares` is also `lazy="raise"`. No expiry column; shares live until revoked. Self share rows are prevented at the API layer (AC-9) rather than by constraint.

**State transitions**:
`document_shares`: none (never granted) → active (`revoked_at` null) → revoked (`revoked_at` set) → active again on regrant (which also clears `revoked_by` and updates `granted_by`). The document cascades shares on delete; user deletion cascades grantee rows while `granted_by`/`revoked_by` are RESTRICT per spec 0002.

**API surface**:

| Endpoint | Method | Key inputs | Key outputs | Auth | Key errors |
|---|---|---|---|---|---|
| /v1/documents/{id}/shares | GET | none | `ShareListResponse { shares: ShareOut[] }` | `require_role("document.shares_list", OFFICER)` + owner | 404 not owner or missing |
| /v1/documents/{id}/shares | POST | user_id:uuid (req), extra fields ignored | 201 `ShareOut` on create, 200 `ShareOut` on regrant or already active | `require_role("document.share_grant", OFFICER)` + owner | 404 doc missing/not owner, 404 `user_not_found`, 409 `self_share`/`grantee_disabled`/`grantee_role` |
| /v1/documents/{id}/shares/{user_id} | DELETE | none | 204 | `require_role("document.share_revoke", OFFICER)` + owner | 404 not owner, doc missing, or `share_not_active` |
| /v1/shares/mine | GET | none | `SharedDocumentListResponse { documents: SharedDocumentOut[] }` | `require_role("document.list_shared", OFFICER)` | none beyond auth |
| /v1/users/lookup | GET | username:string prefix (req, min 2 chars), limit:int ≤ 20 (default 20) | `{ users: [{id, username}] }` | `require_role("user.lookup", OFFICER)` + `RATE_LIMIT_USER_LOOKUP` | 422 missing/short prefix |

Grantee read paths reuse the existing document endpoints unchanged: `GET /v1/documents/{id}`, `/{id}/content`, `/{id}/versions`, `/{id}/versions/{n}/content`. The policy layer admits the caller when an active share exists even if clearance fails.

**Response schemas** (Pydantic, in `app/schemas/`):
- `ShareOut`: `id`, `user_id`, `username` (grantee), `access_level`, `granted_by` (username), `created_at`, `revoked_at`, `revoked_by` (username or null)
- `ShareListResponse`: `shares: list[ShareOut]`
- `SharedDocumentOut`: `id`, `title`, `description`, `classification`, `owner` (username), `shared_at`
- `SharedDocumentListResponse`: `documents: list[SharedDocumentOut]`
- `UserLookupOut`: `id`, `username`; wrapped as `{ users: [...] }`

**Audit actions** (all appended inside the same transaction as the change; denials via `record_denial`):

| Action | Endpoint / path | target_type | target_id | details |
|---|---|---|---|---|
| `document.share_grant` | POST shares | `document` | doc id | `share_id`, `grantee_id` |
| `document.share_revoke` | DELETE shares | `document` | doc id | `share_id`, `grantee_id` |
| `document.shares_list` | GET shares | `endpoint` | request path | none beyond actor snapshot |
| `document.list_shared` | GET /v1/shares/mine | `endpoint` | request path | none beyond actor snapshot |
| `user.lookup` | GET /v1/users/lookup | `endpoint` | request path | `username` prefix, `limit` |
| `document.read` / `document.download` / `document.versions_list` / `document.version_download` | existing read paths | `document` | doc id | existing details plus `via_share: true`, `share_id` when share admitted |

`require_role` action strings per route are listed in the API table; each new action is added to `GATE_ACTIONS` in `app/api/deps.py` so MFA enrollment gate denials record the right action. Denial `reason` values: `not_owner_or_missing`, `self_share`, `grantee_disabled`, `grantee_role`, `user_not_found`, `share_not_active`.

**Value sourcing**:

| Action | Value produced / displayed | Source |
|---|---|---|
| grant share | grantee identity | `user_id` request body, resolved against `users.id` |
| grant share | document identity | `documents.id` path param |
| grant share | `granted_by` | `actor.id` from the session |
| grant share | `share_id` in audit | `document_shares.id` of the row created or reactivated |
| list shares | grantee username | `users.username` via `document_shares.user_id` join |
| list shares | granted_by / revoked_by usernames | `users.username` via `granted_by` / `revoked_by` joins |
| list shares | revoked_at | `document_shares.revoked_at` column |
| shares/mine | document title, description | `documents` columns |
| shares/mine | classification | `document_versions.classification` of `documents.current_version_id`; rows with NULL `current_version_id` are excluded |
| shares/mine | owner username | `users.username` via `documents.owner_id` join |
| shares/mine | shared_at | `document_shares.created_at` |
| user lookup | id, username | `users.id`, `users.username` where role = user, `is_active` true, username ILIKE `prefix%` |
| shared read audit | via_share, share_id | derived inside the audit transaction: `document_shares.id` for (doc, actor) with `revoked_at` null, consulted when clearance fails |

**Key invariants**:
- An active share (`revoked_at` null) always points at an eligible grantee at grant time: self, disabled (`is_active` false), and non `user` role targets are rejected; eligibility is not rechecked on access (admin actions govern that instead).
- A share never authorizes write: edit, delete, restore, and new versions remain owner plus clearance (and officer role) gated exactly as today.
- Share override applies to read paths only and covers all versions of the document; search and the owned document list never consider shares.
- `(document_id, user_id)` uniqueness holds at the database level; a concurrent grant that loses the insert race catches `IntegrityError`, re reads the row, and returns it with 200.
- `via_share` and `share_id` are computed inside the same transaction snapshot as the allowed audit append, so a mid request revoke cannot produce an audit entry claiming a share that was already gone; POST versus DELETE races resolve as last writer wins on `revoked_at`.
- Share management requires ownership plus the `user` role but never the owner's own clearance: an owner whose clearance dropped below the document's classification can still grant, revoke, and list shares, because managing shares exposes no content.
- Every share mutation and every shared read or denied share relevant attempt appends to the audit log inside the same transaction as the change.

**Security model**:
Roles: only `user` role accounts hold or use shares; admin and auditor are excluded at both grant time and the role gate on share endpoints. Ownership: only `documents.owner_id == actor.id` manages shares, enforced in the service layer with the same 404 not revealing convention as edit. Confidentiality: a share deliberately overrides `clearance >= classification` for read of the document and all its versions; this is the audited exception to Bell LaPadula, not a silent hole. Write side unchanged: strict no write down still applies and grantees cannot write at all. Grantee eligibility at grant: active account (`is_active` true), `user` role, not the owner. `GET /v1/users/lookup` lives in `app/api/users.py` alongside admin only routes; the router has no router level role guard today, so the route carries its own `require_role` and no blanket admin guard may be added later. Compliance scope: none beyond the existing classified document handling; the audit trail is the control that makes discretionary access reviewable.

**Configuration required**:
- `RATE_LIMIT_USER_LOOKUP`: per client rate limit for `GET /v1/users/lookup` (default `30/minute`), because username prefix search is an enumeration surface; follows the existing `rate_limit_audit` / `rate_limit_search` settings pattern through `core/config.py`, `.env.example`, and compose. Runner up was reusing `rate_limit_default`; a dedicated tighter setting matches how search and audit already get their own limits.

**Critical test scenarios** (each maps to an acceptance criterion in ## Requirements):
- Happy path: owner grants share to a below clearance user, grantee reads meta and content with `via_share` audit entries, owner revokes and grantee is denied, verifies **AC-1**, **AC-2**, **AC-3**
- Happy path: grantee lists and downloads an old version classified above their clearance through the share, verifies **AC-7**
- Failure case: two concurrent grants for the same pair produce one row and consistent responses (IntegrityError recheck returns 200), verifies **AC-4**
- Auth/permission: non owner with sufficient clearance gets 404 on grant, revoke, and list; auditor and admin are role denied; verifies **AC-8**, **AC-12**
- Failure case: grant to self, disabled user, admin, auditor, and unknown id each returns the specified error with audited denial, verifies **AC-9**
- Failure case: revoke of already revoked or missing share returns 404 audited, verifies **AC-10**
- Boundary: shared above clearance document absent from grantee search results and absent from `GET /v1/documents`, verifies **AC-11**
- Lifecycle: admin lowers grantee clearance, changes role, disables grantee and owner; shares persist and access follows existing gates, verifies **AC-14**
- Write denial: grantee attempts edit, delete, restore are denied and audited, verifies **AC-15**
- Lookup: prefix matching is case insensitive, min length enforced, results capped and rate limited, verifies **AC-13**

## Build plan

Tracer Bullet ordering: stand up the thinnest grant to read to revoke loop end to end first, then thicken with versions, listing, discovery, and lookup. No migration; the table exists.

1. Share service and policy hook: active share lookup returning the share row, share aware read check in `services/policy.py` or `services/documents.py`, grant and revoke service functions with audit actions `document.share_grant` / `document.share_revoke` including the IntegrityError recheck, satisfies **AC-1**, **AC-3**, **AC-4**
2. Owner endpoints and schemas: `GET/POST /v1/documents/{id}/shares` and `DELETE .../shares/{user_id}` with `ShareOut`/`ShareListResponse`, eligibility checks (self, disabled, role, existence), `document.shares_list` audit, `require_role` actions and `GATE_ACTIONS` entries, satisfies **AC-1**, **AC-4**, **AC-5**, **AC-8**, **AC-9**, **AC-10**, **AC-12**
3. Grantee read paths: change `_readable_document` (and the version content clearance check) to return the admitting share so audit details can carry `share_id`; compute `via_share` inside the audit transaction for meta and content reads, satisfies **AC-2**, **AC-3**
4. Version paths: make `list_versions` (per version classification filter) and `read_version_content` share aware for reads while write paths stay owner gated, satisfies **AC-7**, **AC-15**
5. Discovery endpoints: `GET /v1/shares/mine` and `GET /v1/users/lookup` with join queries, response schemas, audit actions `document.list_shared` and `user.lookup`, `selectinload` for all share relationships, and the `RATE_LIMIT_USER_LOOKUP` setting through config, env, and compose, satisfies **AC-6**, **AC-13**
6. Test suite: all AC scenarios including admin interaction persistence, search non leak, idempotent regrant, concurrent grant, lookup limits, and audit detail assertions, satisfies **AC-1** through **AC-15**

## Consequences

**Positive**:
- Owners gain the missing discretionary access capability the scope planned for slice 7
- The audit log gains a complete, distinguishable record of who shared what with whom and every use
- No migration and no new dependencies; the feature rides the existing policy, audit, and session machinery

**Negative / tradeoffs**:
- Confidentiality now depends on audit completeness: a missed `via_share` flag would hide discretionary reads, so the audit assertions are load bearing tests, not nice to haves
- An admin lowering a user's clearance will not revoke documents already shared to them; revocation is owner or document deletion only
- The user lookup endpoint widens username visibility to all officers; mitigated by minimal fields, active user role filter, rate limit, and audit
- Share management stays available to an owner whose own clearance dropped below the document, so a non reader can enumerate grantees; accepted because revocation must never be blocked

**Neutral**:
- `access_level` stays a plain string storing only `read` and is never accepted in request bodies; introducing edit or comment levels later is a new spec, not a config flip
- `GET /v1/documents` remains own documents only; shared documents surface exclusively through `/v1/shares/mine`
- Shares to accounts later demoted to auditor become inert rather than revoked, keeping rows honest about what was granted
- `api/users.py` becomes a mixed role router (admin routes plus the officer lookup); each route keeps its own `require_role`

## Follow-up

- [ ] When a future spec adds share edit or comment levels, `access_level` needs a real enum or CHECK constraint; today the service layer is the only enforcement
- [ ] If sharing to groups or roles is ever wanted, spec 0002's per user rows would need a group entity; that is a separate decision
- [ ] Consider whether owner share management should emit an access alert once the alerts feature (scope slice 8) exists, since grants above clearance are exactly the events an alert rule would want
