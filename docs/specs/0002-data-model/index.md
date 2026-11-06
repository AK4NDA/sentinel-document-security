# 0002. Define the core data model for the classified document system

**Date**: 2026-11-06
**Status**: Proposed

## Summary

This spec fixes the database shape every later feature builds on: users, sessions, documents, document versions, per user shares, the hash chained audit log, and access alerts. All tables live in one Alembic migration on the SQLAlchemy async stack from spec 0001, using only portable column types so SQLite tests match Postgres. Classification levels are a single ordered enum shared by user clearance and document versions, which makes the Bell LaPadula check a simple rank comparison. The audit log stores actor and target as plain id snapshots with no foreign keys, so entries survive deletion of the things they describe.

## Requirements

**User stories**:
- As a developer building slice 1 (the classified document loop), I want every entity and constraint already migrated so that I write services and endpoints, not schema.
- As a developer building slices 2 through 8, I want shares, MFA fields, audit chain columns, and alerts already present so that no later slice needs a breaking migration.
- As the policy engine, I want clearance and classification stored as comparable ranks so that allow/deny checks are a single integer comparison.

**Acceptance criteria** (the contract, each criterion is IDed and independently checkable):
- **AC-1**: One Alembic migration creates all seven tables (`users`, `sessions`, `documents`, `document_versions`, `document_shares`, `audit_log`, `alerts`) with the columns, nullability, and types specified in Feature design, and it upgrades and downgrades cleanly on both SQLite and Postgres.
- **AC-2**: `users.clearance` and `document_versions.classification` both use the shared `ClassificationLevel` ordered enum (Unclassified=1 through Top Secret=5), stored portably so `clearance >= classification` is a plain comparison, with a database CHECK constraint limiting stored values to 1 through 5.
- **AC-3**: Every table uses a UUID primary key generated app side with `uuid.uuid4`, mapped through SQLAlchemy's portable `Uuid` type.
- **AC-4**: Uniqueness is enforced at the database level: `users.username`, `users.email`, `sessions.token_hash`, `document_versions(document_id, version_number)`, `document_shares(document_id, user_id)`.
- **AC-5**: Foreign keys behave as specified: deleting a document cascades to its versions and shares; sessions and shares cascade on user deletion; `documents.owner_id`, `document_versions.created_by`, `document_shares.granted_by`, and `sessions.user_id` references are enforced.
- **AC-6**: `audit_log` has a `seq` autoincrement column as strict chain order (BIGINT on Postgres, INTEGER on SQLite via a type variant so both auto increment), `prev_hash` and `hash` columns for the chain, `details` as portable JSON, and actor plus target stored as plain UUID/string snapshot columns with no foreign keys.
- **AC-7**: No plaintext secrets are stored: `users.password_hash` holds an Argon2id hash, `users.totp_secret_encrypted` holds an AES-GCM blob, and `sessions.token_hash` holds a SHA-256 hash of the session token.
- **AC-8**: The circular reference between `documents.current_version_id` and `document_versions.document_id` is resolved so the migration applies on both databases.
- **AC-9**: Lookup columns carry indexes: `documents.owner_id`, `documents.current_version_id`, `document_versions.document_id`, `document_versions.created_by`, `document_shares.document_id`, `document_shares.user_id`, `sessions.user_id` and `expires_at`, `audit_log.occurred_at` and `target_id`, `alerts.created_at`.
- **AC-10**: The model layer imports cleanly under `app/models/` and is registered in `alembic/env.py` target metadata so autogenerate sees all tables.

## Decision

**Chosen option**: Option 1: Single normalized relational schema with enum columns and a separate versions table

Seven tables in one migration on the existing SQLAlchemy 2.0 async stack: `users`, `sessions`, `documents`, `document_versions`, `document_shares`, `audit_log`, and `alerts`. Fixed value sets are enum columns, not lookup tables: `UserRole` as a string enum with a CHECK constraint, `ClassificationLevel` as an IntEnum 1 to 5 stored on integer columns so ordering works in SQL and in Python. Blob bytes stay out of the database per spec 0001; `document_versions` carries the content hash, storage path, size, mime type, and the reserved `key_id`/`key_version` columns for future key rotation. The audit log is append only by convention with `seq` ordering and hash chain columns, and it references nothing by foreign key.

**Implementation skills**: `sqlalchemy` (`sqlalchemy`, `.agents/skills/sqlalchemy/`) · `sqlalchemy-alembic-expert-best-practices-code-review` (`wispbit-ai/skills`, `.agents/skills/sqlalchemy-alembic-expert-best-practices-code-review/`) · `alembic` (`wispbit-ai/skills`, `.agents/skills/alembic/`) · `postgresql-table-design` (`wispbit-ai/skills`, `.agents/skills/postgresql-table-design/`)

## Feature design

**Data model sketch**:

`users`
- `id` UUID PK, app side `uuid4`
- `username` String, unique, not null (login identifier)
- `email` String, unique, not null
- `display_name` String, nullable
- `password_hash` String, not null (Argon2id)
- `role` `UserRole` enum (`admin`, `user`, `auditor`), VARCHAR plus CHECK via `Enum(native_enum=False)`, not null, default `user`
- `clearance` `ClassificationLevel` IntEnum on Integer, not null, default `UNCLASSIFIED` (1), with CHECK constraint restricting values to 1 through 5
- `is_active` Boolean, not null, default true (disable/enable arrives in slice 3)
- `failed_login_attempts` Integer, not null, default 0 (counter for slice 2 throttling; the lockout policy itself lives in that spec)
- `locked_until` DateTime(timezone=True), nullable (set by the slice 2 auth spec when throttling trips)
- `totp_secret_encrypted` LargeBinary, nullable (AES-GCM blob of nonce, tag, and ciphertext, populated in slice 2)
- `totp_enabled_at` DateTime(timezone=True), nullable
- `created_at`, `updated_at` DateTime(timezone=True), not null. The service layer sets `updated_at` explicitly on every mutation; inserting a new `document_versions` row also bumps the parent `documents.updated_at`.

`sessions` (fields per spec 0001 scaffold contract, plus audit friendly extras)
- `id` UUID PK
- `user_id` UUID FK → `users.id`, not null, ondelete CASCADE
- `token_hash` String(64), unique, not null (SHA-256 hex of the opaque token)
- `created_at`, `last_seen_at`, `expires_at` DateTime(timezone=True), not null
- `revoked_at` DateTime(timezone=True), nullable
- `ip_address` String, nullable; `user_agent` String, nullable
- Expiry is computed in the service layer, no extra column: on each authenticated request set `last_seen_at = now` and `expires_at = min(now + SESSION_TTL_SECONDS, created_at + 24h absolute cap)` per the spec 0001 contract. `last_seen_at` may be written at most once per minute to avoid write amplification; the spec 0001 idle and absolute values (8h idle, 24h absolute) are the defaults unless config overrides them.

`documents`
- `id` UUID PK
- `title` String, not null
- `description` Text, nullable
- `owner_id` UUID FK → `users.id`, not null, ondelete RESTRICT
- `current_version_id` UUID FK → `document_versions.id`, nullable, ondelete SET NULL (circular FK, see Build plan)
- `created_at`, `updated_at` DateTime(timezone=True), not null (`updated_at` is set by the service layer on every mutation, same rule as `users`)

`document_versions`
- `id` UUID PK
- `document_id` UUID FK → `documents.id`, not null, ondelete CASCADE
- `version_number` Integer, not null
- `classification` `ClassificationLevel` IntEnum on Integer, not null, with CHECK constraint restricting values to 1 through 5
- `content_sha256` String(64), not null
- `blob_path` String, not null (content addressed path under `UPLOAD_DIR`)
- `size_bytes` BigInteger, not null
- `mime_type` String, not null
- `key_id` String, nullable; `key_version` String, nullable (reserved per spec 0001 so master key rotation never needs a schema change)
- `created_by` UUID FK → `users.id`, not null, ondelete RESTRICT
- `created_at` DateTime(timezone=True), not null
- Unique constraint on (`document_id`, `version_number`)

`document_shares`
- `id` UUID PK
- `document_id` UUID FK → `documents.id`, not null, ondelete CASCADE
- `user_id` UUID FK → `users.id`, not null, ondelete CASCADE (the grantee)
- `granted_by` UUID FK → `users.id`, not null, ondelete RESTRICT (records the latest granter; full grant history lives in `audit_log`)
- `access_level` String, not null, default `'read'` (reserves read vs edit grants for slice 7 without a breaking migration)
- `created_at` DateTime(timezone=True), not null (first grant time; the row is reused across re grants)
- `revoked_at` DateTime(timezone=True), nullable; `revoked_by` UUID FK → `users.id`, nullable, ondelete RESTRICT
- Unique constraint on (`document_id`, `user_id`); re granting an active share clears `revoked_at` and updates `granted_by`

`audit_log`
- `seq` autoincrement PK, strict chain order on both databases: `BigInteger` with `with_variant(Integer, "sqlite")` so Postgres gets BIGINT and SQLite gets INTEGER (plain BIGINT does not auto increment on SQLite)
- `id` UUID, unique, not null, app side `uuid4` default like every other UUID column (external reference handle)
- `occurred_at` DateTime(timezone=True), not null
- `actor_id` UUID, nullable, plain column no FK; `actor_username` String, nullable; `actor_role` String, nullable (snapshots survive user deletion)
- `action` String, not null (e.g. `document.read`, `auth.login`)
- `outcome` String, not null, CHECK constraint limiting values to `allowed` or `denied`
- `target_type` String, nullable; `target_id` String, nullable, plain columns no FK
- `details` JSON, nullable (portable JSON per spec 0001)
- `prev_hash` String(64), nullable (null on the genesis entry)
- `hash` String(64), not null (SHA-256 over the canonical entry fields, chain format finalized by the slice 4 audit spec)

`alerts`
- `id` UUID PK
- `alert_type` String, not null (e.g. `access.denied`, `document.top_secret_read`, `admin.privilege_change`)
- `severity` String, not null (app level constants, finalized by slice 8)
- `document_id` UUID, nullable, plain column no FK; `actor_id` UUID, nullable, plain column no FK
- `details` JSON, nullable
- `fingerprint` String, nullable (dedup key reserved for slice 8 alert throttling)
- `created_at` DateTime(timezone=True), not null
- `acknowledged_at` DateTime(timezone=True), nullable; `acknowledged_by` UUID, nullable, plain column no FK

**State transitions**:
- `sessions`: active (`revoked_at` null, `expires_at` in future) → expired (time passes) or revoked (`revoked_at` set, slice 2 owns session revocation)
- `document_shares`: active (`revoked_at` null) → revoked (`revoked_at` set); re grant returns to active
- `users`: active (`is_active` true) → disabled (`is_active` false, slice 3 administration owns disable/enable); sessions of a disabled user are revoked by the service layer, not the schema
- `alerts`: new (`acknowledged_at` null) → acknowledged (`acknowledged_at` and `acknowledged_by` set)
- `documents`/`document_versions`: append only history; a document is hard deleted (row removed, versions and shares cascade), the audit log retains the evidence as snapshots

**API surface**: none. This feature ships schema only; endpoints arrive with slice 1.

**Value sourcing**:
| Action | Value produced / displayed | Source |
|---|---|---|
| n/a (no runtime surface) | All values are columns written by later slices; defaults (`role`, `clearance`, `is_active`, timestamps) are set by model layer defaults, not request input | DB columns and model defaults per the sketch above |

**Key invariants**:
- `document_versions.version_number` is unique per document; concurrent edits cannot produce two versions with the same number (the unique constraint is the enforcement, services retry on conflict)
- `documents.current_version_id` always points at a version of that same document (enforced in the service layer; the FK only guarantees the version exists)
- A share's `user_id` never equals its document's `owner_id` is allowed but meaningless; the policy layer ignores self shares (noted for slice 7)
- `audit_log.seq` is monotonically increasing and defines hash chain order; entries are never updated or deleted by application code
- `users.clearance` rank must be >= any classification the user should ever touch; downgrading a user's clearance does not retroactively hide already read content but blocks future access (policy rule, enforced in slice 1, not the schema)
- TOTP secrets and session tokens never appear in any column in plaintext (AC-7)
- Document creation is a single transaction: insert the `documents` row, insert `document_versions` with `version_number = 1`, then set `current_version_id`. `version_number` starts at 1 and increments per edit. A NULL `current_version_id` is only ever transient inside that transaction; there is no draft state
- `audit_log` appends must be serialized so two writers cannot read the same tail and fork the chain; the slice 4 spec chooses the mechanism (row lock, advisory lock, or single writer queue)
- `updated_at` on `users` and `documents` is owned by the service layer, set explicitly on every mutation; a new `document_versions` row also bumps the parent `documents.updated_at`
- User lifecycle is disable, not delete: the RESTRICT foreign keys on `document_versions.created_by`, `document_shares.granted_by`, and `document_shares.revoked_by` mean any user who ever authored content or granted a share can never be hard deleted, which is intentional
- SQLite returns naive datetimes for `DateTime(timezone=True)` columns; the app layer must normalize reads to aware UTC so tests and Postgres behave identically

**Security model**:
- Schema level: secrets are stored only as hashes or encrypted blobs; the audit log carries no foreign keys so it cannot be cascade erased; `token_hash` is unique so token lookup is exact match only.
- Application level (owned by later specs, recorded here so the schema supports it): deny by default policy combining role, clearance, and classification; auditors get no document access; every access attempt writes an audit row.
- Compliance scope: this system handles classified data by design; audit logging is mandatory and non optional per the project scope.

**Configuration required**: none. All columns reuse existing settings (`DATABASE_URL`, `MASTER_KEY`, `UPLOAD_DIR` from spec 0001).

**Critical test scenarios** (each maps to an acceptance criterion in ## Requirements):
- Happy path: migration `upgrade` then `downgrade` then `upgrade` runs clean on SQLite and Postgres, and a script can insert one row per table and read it back, verifies **AC-1**, **AC-3**, **AC-10**
- Failure case: inserting a second `document_versions` row with the same `(document_id, version_number)`, a duplicate `users.username`, or a duplicate active `document_shares(document_id, user_id)` raises an integrity error, verifies **AC-4**
- Constraint case: deleting a document removes its versions and shares but leaves `audit_log` and `alerts` rows intact (no FK), and deleting a user removes sessions and shares while `document_versions.created_by` blocks the delete, verifies **AC-5**, **AC-6**
- Ordering case: two `ClassificationLevel` values compare correctly (`SECRET > CONFIDENTIAL`) both in Python and in a SQL `WHERE clearance >= :level` clause, verifies **AC-2**

## Build plan

1. Define `ClassificationLevel` (IntEnum 1 to 5) and `UserRole` (str enum) plus shared column helpers (UUID PK default, UTC timestamp) in `app/models/`, satisfies **AC-2**, **AC-3**
2. Implement the seven model classes exactly per the Feature design sketch, including all unique constraints, foreign keys with the stated delete behaviors, and indexes, satisfies **AC-4**, **AC-5**, **AC-6**, **AC-7**, **AC-9**
3. Write the Alembic migration creating all tables; create `documents` first without the `current_version_id` FK, create `document_versions`, then add the FK constraint in the same migration using `batch_alter_table` (required on SQLite, which cannot `ALTER TABLE ADD CONSTRAINT`), satisfies **AC-1**, **AC-8**
4. Verify `alembic upgrade head` and `downgrade` round trip on SQLite and Postgres, and confirm `alembic check` or autogenerate reports no drift, satisfies **AC-1**, **AC-10**
5. Add tests under `tests/` covering the critical scenarios (migration round trip, uniqueness violations, cascade behavior, enum ordering), satisfies **AC-1**, **AC-2**, **AC-4**, **AC-5**, **AC-6**

## Consequences

**Positive**:
- Every later slice (auth, MFA, audit, versioning, sharing, search, alerts) builds on tables that already exist, so no slice needs a breaking migration.
- Storing classification as an integer rank makes the core security check (`clearance >= classification`) trivially correct and testable in both Python and SQL.
- Snapshot columns in `audit_log` and `alerts` mean the evidentiary record survives hard deletes, which matters for a system whose whole point is provable access history.
- Reserving `key_id`/`key_version` now means file encryption key rotation is a data change, not a schema change, per spec 0001.

**Negative / tradeoffs**:
- Seven tables up front is more schema than slice 1 strictly uses (shares, alerts, MFA columns sit empty until their slices); the cost is a wider first migration reviewed once instead of many small ones.
- IntEnum classification is less readable in raw SQL than string labels (`3` vs `secret`); mitigated by the enum name living in Python and queries going through the ORM.
- Plain UUID snapshot columns in `audit_log`/`alerts` are not enforced by the database, so a buggy writer could store a malformed id; acceptable because the audit spec owns write paths and can validate there.
- Hard deleting documents (engineer's choice) means recovery is impossible without backups; the audit log proves what happened but cannot restore content.

**Neutral**:
- Full text search (slice 6) is deliberately not modeled here; the portability rule bans Postgres only `tsvector`, so slice 6 must pick a portable indexing strategy or accept a documented divergence.
- MFA backup codes, `password_changed_at`, and admin disable fields are deferred to slices 2, 3, and 5 as additive columns; they are not breaking changes.
- The hash chain format itself (canonical serialization, genesis value, anchor strategy) is decided by the slice 4 auditor spec; this spec only reserves the columns.

## Follow-up

- [ ] `/audit` has not run yet; root `AGENTS.md` does not exist, so conventions and the `## Agent skills` list still need capturing (scope feature 2).
- [ ] The `sqlalchemy`, `alembic`, `sqlalchemy-alembic-expert-best-practices-code-review`, and `postgresql-table-design` skills are installed but not yet referenced in `AGENTS.md`; they belong in root `AGENTS.md` `## Agent skills` once it exists.
- [ ] Slice 6 (full text search) must decide how to index encrypted content under the portable types rule; this spec intentionally reserves nothing for it.
- [ ] Slice 4 owns the audit hash chain format, genesis entry, append serialization mechanism, and external anchor; this spec only fixes the columns.
- [ ] Slice 2 owns MFA backup codes and the login lockout policy that reads `failed_login_attempts` and `locked_until`.
- [ ] Slice 3 owns `password_changed_at` and the admin disable/enable flow on top of `is_active`.
- [ ] Slice 5 owns version restore semantics (recommended: restore inserts a new version copying the old content, preserving append only history; deleting the current version is forbidden).
- [ ] Slice 8 owns alert dedup and throttle policy on top of the reserved `fingerprint` column.

## Rationale

Reasoning, options considered, and references: see [rationale.md](rationale.md).
