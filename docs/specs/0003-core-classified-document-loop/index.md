# 0003. Build the core classified document loop

**Date**: 2026-11-06
**Status**: In Progress

## Summary

This spec turns the data model into a working API: accounts, login with session cookies, admin user creation, and document upload, read, edit, and delete behind a deny by default policy engine. Files are stored AES GCM encrypted and every attempt, allowed or denied, lands in the hash chained audit log. The policy is strict Bell LaPadula: no read up, no write down, so a user can only create or revise content at exactly their own clearance level. Role rules are strict too: only the user role touches documents, admins manage accounts only, and auditors can log in but reach nothing.

## Requirements

**User stories**:
- As an officer (the `user` role), I want to upload a document at my clearance, read documents I am cleared for, edit my own, and delete my own, so that classified work flows through one controlled channel.
- As an administrator, I want to create officer and auditor accounts with a role and clearance, so that I can run the user base without touching document content.
- As an auditor, I want to authenticate so that my account exists and is ready for the slice 4 audit surface.
- As the system, I want every allowed and denied attempt written to a tamper evident hash chained log, so that access is provable.

**Acceptance criteria** (the contract, each criterion is IDed and independently checkable):
- **AC-1**: A new Alembic migration adds a UNIQUE constraint on `audit_log.prev_hash` so two writers cannot fork the chain; upgrade and downgrade run cleanly on SQLite (and Postgres when available).
- **AC-2**: `POST /v1/auth/login` with valid credentials creates a `sessions` row (SHA-256 token hash, sliding expiry per spec 0001), sets an HttpOnly SameSite cookie, and returns the user profile; invalid credentials or a disabled account return 401 and are audited as denied.
- **AC-3**: Every protected endpoint requires a valid session, accepted either as the session cookie or as `Authorization: Bearer <token>` per the spec 0001 contract; missing, expired, or revoked sessions return 401. `expires_at` slides per the spec 0002 formula, `last_seen_at` is written at most once per minute, and the user row is re-read on every request so `is_active=false` or a role or clearance change takes effect immediately.
- **AC-4**: `POST /v1/users` (admin only) creates a user with role `user` or `auditor` (role `admin` is rejected with 422), password of at least 12 characters, and clearance 1 through 5; the creation is audited.
- **AC-5**: `GET /v1/users` (admin only) returns the user list.
- **AC-6**: `POST /v1/documents` (officer only) accepts a multipart upload of file, title (1 to 300 characters), and optional description (up to 2000 characters); the file is encrypted AES GCM before storage at a content addressed path under `UPLOAD_DIR` (path derived from the plaintext SHA-256 per spec 0001), the document, version 1, and current version pointer are written in one transaction, and the version classification equals the uploader's clearance; the upload is audited in the same transaction.
- **AC-7**: Uploads are checked size first: over 25 MB returns 413, then a mime type outside the allowlist returns 415. Allowlist: `application/pdf`, `image/png`, `image/jpeg`, `image/gif`, `image/webp`, `text/plain`, `text/markdown`, `text/csv`, and the three OOXML document types (`wordprocessingml.document`, `spreadsheetml.sheet`, `presentationml.presentation`). The client supplied `Content-Type` is validated against this list; no content sniffing.
- **AC-8**: `GET /v1/documents` (officer only) returns the caller's own documents with metadata. No pagination in slice 1.
- **AC-9**: `GET /v1/documents/{id}` returns metadata and `GET /v1/documents/{id}/content` returns decrypted bytes with an `attachment` Content-Disposition, but only when the caller's clearance is at least the current version's classification; otherwise 403 and an audited denial. Reading does not require ownership. On read, `content_sha256` is verified after decryption; a mismatch returns 500.
- **AC-10**: `POST /v1/documents/{id}/versions` requires ownership AND `clearance >= current_version.classification` (the read predicate; this closes the downgrade hole where a lowered clearance could push a low classified version). It appends a new version with `version_number = max + 1` computed inside the transaction, classification equal to the editor's clearance, moves `current_version_id`, bumps `documents.updated_at`, applies optional `title`/`description` updates to the document row, and retains all prior versions; audited in the same transaction. A unique constraint violation on `(document_id, version_number)` returns 409; there is no automatic retry.
- **AC-11**: `DELETE /v1/documents/{id}` (owner only) hard deletes the document, cascading versions and shares per spec 0002. Encrypted blob files on disk are never deleted in slice 1 (content addressed paths may be shared; garbage collection is deferred). Audited.
- **AC-12**: Admin and auditor roles receive 403 on every document endpoint, and the denial is audited; auditors can still log in and call `GET /v1/auth/me`.
- **AC-13**: A non owner officer cannot edit or delete another user's document (404 with an audited denial); reading is governed by clearance alone, not ownership.
- **AC-14**: Every authentication attempt and every call to a protected endpoint that reaches authorization writes an `audit_log` row carrying the actor snapshot (id, username, role), action, outcome (`allowed` or `denied`), target, and a `prev_hash` equal to the previous entry's `hash`. This includes denied calls to `/v1/users` and failed logins for unknown usernames (null actor columns, attempted username recorded in `details`). Requests rejected before identity exists (missing or invalid session, 422 validation, 429 rate limit) are not audited.
- **AC-15**: The audit chain is verifiable: each entry's SHA-256 is computed over canonical JSON of exactly these fields: `occurred_at`, `actor_id`, `actor_username`, `actor_role`, `action`, `outcome`, `target_type`, `target_id`, `details`, `prev_hash` (`seq`, `id`, `hash`, and `created_at` are excluded). Canonical form: `json.dumps` with `sort_keys=True`, `separators=(",", ":")`, `ensure_ascii=False`, UTF-8 encoded; timestamps as ISO-8601 UTC with `Z`; UUIDs as lowercase strings; `details` recursively canonicalized the same way. The genesis entry uses 64 zero characters as `prev_hash`. This amends spec 0002, which reserved the format for slice 4 and allowed NULL genesis.
- **AC-16**: `python -m app create-admin --username <name> --email <email>` creates an admin account (additional admins may be created later by this command; it is the only way to make admins). Password is read via a hidden prompt, never argv; the 12 character minimum applies. `clearance` defaults to UNCLASSIFIED and `display_name` is optional. Duplicate username or email exits nonzero.
- **AC-17**: Auth endpoints are rate limited via slowapi using the existing `RATE_LIMIT_AUTH` setting.
- **AC-18**: `POST /v1/auth/logout` revokes the session (`revoked_at` set) and clears the cookie; subsequent requests with that token return 401.
- **AC-19**: `GET /v1/auth/me` returns the caller's profile for any authenticated role including auditor.

**Audited action vocabulary** (the `action` column values): `auth.login`, `auth.logout`, `user.create`, `user.list`, `document.upload`, `document.list`, `document.read`, `document.download`, `document.edit`, `document.delete`. `details` carries minimal context per action: denial reason for denials, attempted username for failed logins, filename and size for uploads, version_number for edits.

## Decision

**Chosen option**: Option 1: Full slice one loop on the existing stack

One FastAPI surface under `/v1` backed by the spec 0002 schema plus one additive migration (unique `audit_log.prev_hash`), with services for passwords (argon2-cffi), sessions (opaque cookie tokens), encryption (AES GCM via `cryptography`), audit chaining, and a small deny by default policy module. Bearer tokens are accepted alongside the cookie per the spec 0001 contract. No new dependencies are required; `python-multipart`, `argon2-cffi`, `cryptography`, `slowapi`, and `pyotp` are already installed. `EmailStr` is not used because `email-validator` is not a dependency; email is a plain string of at most 320 characters containing `@`.

**Implementation skills**: `fastapi` (`wispbit-ai/skills`, `.agents/skills/fastapi/`) · `sqlalchemy` (`wispbit-ai/skills`, `.agents/skills/sqlalchemy/`) · `alembic` (`wispbit-ai/skills`, `.agents/skills/alembic/`) · `auth-implementation-patterns` (`wispbit-ai/skills`, `.agents/skills/auth-implementation-patterns/`) · `reviewing-cryptography` (`wispbit-ai/skills`, `.agents/skills/reviewing-cryptography/`)

## Feature design

**Data model sketch**:

No new tables. Spec 0002 stands as accepted. One additive migration adds `UniqueConstraint` on `audit_log.prev_hash` (name `uq_audit_log_prev_hash`). All slice 1 values map to existing columns:

- Login writes `sessions.token_hash` (SHA-256 hex of a 32 byte urlsafe token), `ip_address`, `user_agent`, `created_at`, `last_seen_at`, `expires_at` per the spec 0002 sliding formula. Failed logins increment `users.failed_login_attempts`; success resets it to 0. No lockout in slice 1 (slice 2 owns the policy).
- Upload/edit writes `documents` plus `document_versions` (`version_number`, `classification`, `content_sha256` of the plaintext, `blob_path`, `size_bytes`, `mime_type`, `key_id` = `master`, `key_version` = `1`, `created_by`) in one transaction with the audit row.
- Every attempt writes `audit_log` (`seq`, `id`, `occurred_at`, actor snapshots, `action`, `outcome`, `target_type`, `target_id`, `details`, `prev_hash`, `hash`).

**State transitions**:
- `sessions`: none → active on login (`revoked_at` null, `expires_at` future) → expired (time) or revoked (logout, `revoked_at` set).
- `users`: `is_active` true → false blocks new logins and invalidates live sessions via the per request user re-read; no endpoint flips it in slice 1.
- `documents`/`document_versions`: append only; delete removes the document row and cascades. Blobs on disk persist.

**API surface**:

| Endpoint | Method | Key inputs | Key outputs | Auth | Key errors |
|---|---|---|---|---|---|
| /v1/auth/login | POST | username:str (req), password:str (req) | UserProfile, Set-Cookie | public, rate limited | 401 invalid or disabled |
| /v1/auth/logout | POST | none | 204, clears cookie | session | 401 |
| /v1/auth/me | GET | none | UserProfile | session | 401 |
| /v1/users | POST | username:str 3-64, email:str ≤320 with @, password:str ≥12, role:`user`/`auditor`, clearance:int 1-5, display_name? ≤200 | UserProfile | admin | 403, 422, 409 duplicate |
| /v1/users | GET | none | UserProfile[] | admin | 403 |
| /v1/documents | POST | multipart: file (req), title 1-300 (req), description? ≤2000 | DocumentMeta | officer session | 403, 409?, 413, 415, 422 |
| /v1/documents | GET | none | DocumentMeta[] | officer session | 403 |
| /v1/documents/{id} | GET | none | DocumentMeta | officer session + read rule | 403, 404 |
| /v1/documents/{id}/content | GET | none | decrypted bytes, attachment Content-Disposition | officer session + read rule | 403, 404, 500 integrity |
| /v1/documents/{id}/versions | POST | multipart: file (req), title?, description? | DocumentMeta | owner session + read + write rule | 403, 404, 409, 413, 415 |
| /v1/documents/{id} | DELETE | none | 204 | owner session | 403, 404 |

**Response shapes**:
- `UserProfile`: `id`, `username`, `email`, `display_name`, `role`, `clearance`, `is_active`, `created_at`.
- `DocumentMeta`: `id`, `title`, `description`, `owner_id`, `classification` (current version's), `created_at`, `updated_at`.
- Content download filename: `attachment` disposition; filename is the title sanitized to `[A-Za-z0-9._-]` (max 100 chars, fallback `document`) plus an extension mapped from the stored `mime_type`.

**Value sourcing** (every value each action produces, computes, or displays names where it comes from):

| Action | Value produced / displayed | Source |
|---|---|---|
| login | session token, token_hash, expiry | token generated server side (secrets); hash = SHA-256; expiry = spec 0002 formula from settings |
| login | actor snapshots on audit row | users row at time of attempt; unknown usernames leave actor columns null and put the attempted name in `details` |
| create user | role, clearance, password_hash | request body; hash = argon2id of password |
| upload | classification | derived: uploader's `clearance` (forced equal, AC-6) |
| upload | content_sha256 | SHA-256 of plaintext bytes; also the blob path component per spec 0001 |
| upload | blob_path, key_id, key_version | derived: content addressed path under `UPLOAD_DIR`; `master` / `1` constants |
| upload | version_number | derived: 1 for new document, `max + 1` inside the edit transaction |
| read/content | plaintext bytes | decrypt blob with `MASTER_KEY` after authorization; verify `content_sha256` |
| edit | new version classification | derived: editor's `clearance` |
| edit | title, description | request body when provided, else unchanged |
| audit append | prev_hash, hash | derived: previous entry's `hash` (64 zeros for genesis); SHA-256 over the canonical field JSON in AC-15 |
| audit append | occurred_at | server UTC now, preserved across chain retries |
| all | timestamps | server UTC now |

**Key invariants**:
- Policy is deny by default: role `admin` and `auditor` get 403 on every document endpoint; only role `user` performs document operations. Denied `/v1/users` calls by non admins are audited.
- Read rule: `clearance >= current_version.classification`, enforced on metadata, content, and as a precondition of edit. Write rule: upload and each new version use `classification = actor.clearance`, satisfying strict no write down.
- Edit and delete require `documents.owner_id = caller.id`; delete does not re-check the read predicate (removing content cannot leak it).
- `version_number` is unique per document; conflicts return 409 with no retry.
- `content_sha256` always hashes plaintext and is verified after decryption on every content read.
- Audit `prev_hash` chain is linear; appends for allowed operations run inside the same transaction as the business write and retry the whole unit (bounded at 5 attempts, then 500) on unique violation; denied-attempt rows commit independently. If the audit row cannot be written, the operation fails (fail closed).
- Encrypted blobs are content addressed and never deleted in slice 1; a repeated identical upload reuses the existing blob path.
- Secrets never stored plaintext: password Argon2id, session token SHA-256, file bytes AES GCM.

**Security model**:

- Authentication: opaque session token accepted via the session cookie (HttpOnly, SameSite=Lax, Path=/, Secure when `ENV=prod`, session cookie with no Max-Age since server expiry is authoritative) or `Authorization: Bearer <token>` for API clients per spec 0001. Token lookup is exact match on `token_hash`.
- Authorization order per request: valid session (user row re-read, `is_active` required) → role gate → ownership gate for edit/delete → BLP read/write rule → audit the outcome either way.
- Denied attempts return 403 (404 for non owner edit/delete to avoid leaking existence; the read path's 403 does reveal a document exists above the caller's clearance, an accepted tradeoff since AC-9 mandates it) and write an audit row with `outcome=denied`.
- Login failures increment `failed_login_attempts` and are audited; lockout policy is slice 2.
- Rate limiting on `/v1/auth/*` via slowapi `RATE_LIMIT_AUTH`.
- Compliance scope: classified data handling; audit logging is mandatory per project scope.

**Configuration required**:

- No new environment variables. `SESSION_COOKIE_NAME`, `SESSION_TTL_SECONDS`, `UPLOAD_DIR`, `MASTER_KEY`, `RATE_LIMIT_AUTH`, `ENV` already exist.

**Critical test scenarios** (each maps to an acceptance criterion in ## Requirements):
- Happy path: officer uploads a Secret document, reads it back decrypted, edits to version 2, deletes it; every step appears in the audit chain in order, verifies **AC-6**, **AC-9**, **AC-10**, **AC-11**, **AC-14**, **AC-15**
- Deny path: Confidential officer reads a Secret document and gets 403 plus an audited denial; admin hits a document endpoint and gets 403; officer calls `POST /v1/users` and gets 403 plus an audited denial, verifies **AC-9**, **AC-12**, **AC-14**
- Downgrade path: officer clearance lowered below their document's classification can no longer edit it (read predicate blocks), verifies **AC-10**
- Failure case: two concurrent edits to one document cannot both succeed; the loser gets 409, verifies **AC-10**
- Auth case: login, logout revocation, bearer token login, expired session, disabled user, and rate limit each behave per contract, verifies **AC-2**, **AC-3**, **AC-17**, **AC-18**
- Bootstrap case: CLI creates an admin, admin creates an officer via API, officer logs in and calls `/me`, verifies **AC-4**, **AC-16**, **AC-19**

## Build plan

1. Migration: add `UniqueConstraint` on `audit_log.prev_hash`; verify upgrade/downgrade round trip, satisfies **AC-1**
2. Audit service: canonical field JSON per AC-15, genesis `prev_hash` of 64 zeros, SHA-256 chain append with bounded retry (5) inside the caller's transaction for allowed operations and independent commit for denials, plus a `verify_chain` function, satisfies **AC-14**, **AC-15**
3. Security plumbing: argon2id password hash/verify, AES GCM seal/open with `MASTER_KEY`, content addressed blob store under `UPLOAD_DIR` (plaintext sha256 paths per spec 0001), session issue/validate/slide/revoke helpers with per request user re-read, satisfies **AC-2**, **AC-3**, **AC-6**, **AC-10**
4. Auth endpoints and dependencies: `POST /v1/auth/login`, `POST /v1/auth/logout`, `GET /v1/auth/me`, cookie plus Bearer session dependency, role dependencies, slowapi wiring on auth routes, satisfies **AC-2**, **AC-3**, **AC-12**, **AC-17**, **AC-18**, **AC-19**
5. Admin endpoints and CLI: `POST /v1/users`, `GET /v1/users`, `create-admin` command, satisfies **AC-4**, **AC-5**, **AC-16**
6. Policy module and document endpoints: deny by default checks, `POST /v1/documents`, `GET /v1/documents`, `GET /v1/documents/{id}`, `GET /v1/documents/{id}/content`, `POST /v1/documents/{id}/versions`, `DELETE /v1/documents/{id}`, satisfies **AC-6** through **AC-14**
7. Test suite covering every AC plus the critical scenarios, satisfies all ACs

## Consequences

**Positive**:
- The product's core promise is provable on day one: encrypted storage, deny by default policy, and a verifiable audit chain, not just schema.
- Strict no write down removes an entire class of downgrade leaks; the read predicate on edit closes the clearance lowered hole completely.
- No new dependencies and no new tables beyond one constraint; the build is almost entirely service and route code on proven libraries.
- Audit chain format is finalized here with an explicit canonicalization, so slice 4 only needs the verify endpoint surface and any external anchor.
- Fail closed audit semantics mean the log can never silently miss an operation.

**Negative / tradeoffs**:
- Strict no write down is unusual: a Top Secret cleared user cannot create an Unclassified document, and classification is not a free choice, it is pinned to clearance.
- Cookie sessions reintroduce CSRF surface; SameSite=Lax plus JSON API conventions mitigate but do not eliminate it for unsafe methods.
- Audit on every authenticated call including list and metadata reads is write heavy; acceptable at demo scale, revisit if volume grows.
- Blobs are never deleted in slice 1, so disk grows monotonically; content addressing keeps duplicates shared but there is no reclamation yet.
- Read denials return 403 which confirms a document exists above the caller's clearance; chosen over 404 for consistency with AC-9.

**Neutral**:
- `content_sha256` hashes plaintext while `blob_path` stores ciphertext; verification requires decryption, which is intentional for integrity of the real content.
- Shares, MFA, lockout enforcement, version restore, search, and alert generation remain owned by later slices; the schema already reserves their columns.
- The unique `prev_hash` constraint makes audit append retry on conflict; this is the chosen serialization mechanism and resolves the deferral in spec 0002.
- Spec 0002's "prev_hash null on genesis" sketch is amended to 64 zeros here; noted in AC-15.

**Follow-up**:

- [ ] `/audit` has not run yet; root `AGENTS.md` does not exist and should capture conventions plus the installed skill list (scope feature 2).
- [ ] Postgres side of the new migration and the full suite has not been exercised; verify when Docker compose is available.
- [ ] Slice 2 owns login throttling policy on top of `failed_login_attempts`/`locked_until` and TOTP MFA; slice 1 increments the counter but never locks.
- [ ] Slice 4 owns the audit verify endpoint surface and any external anchor; the chain format itself is decided here.
- [ ] Slice 5 owns version restore semantics and reading non current versions; slice 1 serves current version content only.
- [ ] Blob garbage collection (refcount or mark and sweep) is unowned; candidate for a later hardening spec.
- [ ] If strict no write down proves too restrictive in practice, a later spec may relax the write rule; the audit log will show every classification decision either way.

## Rationale

Reasoning, options considered, and references: see [rationale.md](rationale.md).
