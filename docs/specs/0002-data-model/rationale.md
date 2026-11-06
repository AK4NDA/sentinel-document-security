# 0002 rationale: core data model

## Context

Scope feature 3 asks for the entities every later feature builds on: users, roles, clearances, classification levels, documents, versions, per user shares, MFA secrets, sessions, and audit log entries, with the relationships and constraints the policy engine needs. The done condition is that the model supports every later slice (versioning, sharing, search, alerts) without a breaking migration.

The stack is already fixed by spec 0001: Python 3.12, FastAPI, SQLAlchemy 2.0 async, Alembic, Postgres in compose with SQLite for dev and tests, and a portability rule banning Postgres only constructs so the two databases behave identically. The scaffold exists but contains no models yet, so this is a clean design, not a retrofit.

The product is a classified document system enforcing Bell LaPadula plus role based access control, deny by default, with every access attempt recorded in a tamper evident audit log. That makes three properties load bearing in the schema: the clearance versus classification comparison must be cheap and correct, secrets must never sit in plaintext, and the audit record must survive deletion of the things it describes.

## Options considered

### Option 1: Single normalized relational schema with enum columns and a separate versions table

Seven tables in one migration on the existing SQLAlchemy stack. Fixed value sets are enum columns rather than lookup tables. `ClassificationLevel` is an IntEnum 1 to 5 stored on integer columns so ordering works identically in Python and SQL. Documents point at a current version row that carries its own blob metadata, classification, author, and timestamp, so every edit produces a new immutable version. The audit log is append only with a `seq` identity column for chain order, hash columns, and plain snapshot references with no foreign keys.

**Pros**:
- One coherent migration covers every later slice; nothing needs a breaking change.
- Integer rank classification makes the core security check a trivial, testable comparison.
- Snapshot audit columns preserve evidence across hard deletes.
- Fully portable across Postgres and SQLite per the spec 0001 rule.

**Cons**:
- Wider first migration than slice 1 strictly needs; shares, alerts, and MFA columns sit unused until their slices.
- IntEnum values are less readable in raw SQL than string labels.
- Plain UUID snapshots in `audit_log`/`alerts` are not database enforced.

### Option 2: Lookup tables for roles, clearances, and classification levels

Model the three fixed value sets as real tables with foreign keys from `users` and `document_versions`, ordering carried by a `rank` column on the classification table.

**Pros**:
- Values become editable data; adding a sixth classification level is an INSERT, not a deploy.
- Referents are enforced by foreign keys everywhere.

**Cons**:
- Every policy check and document query pays join or extra lookup cost for a set that has never changed in the history of such systems.
- Ordering still needs a rank column, so the "enum plus rank" benefit is only partially realized while paying full join cost.
- The five levels are fixed by the product brief; flexibility nobody asked for.

### Option 3: Document style storage (JSON blobs per entity)

Store users, documents, and audit entries as JSON documents, either in JSON columns or a document database, avoiding the relational schema entirely.

**Pros**:
- Schema flexibility; each feature can evolve its payload without migrations.

**Cons**:
- Loses the constraints this system lives on: uniqueness, foreign keys, cascade behavior, and ordered audit sequencing all become application code that can be got wrong.
- Directly violates the spec 0001 portability rule if it pulls in Postgres JSONB features, and fights the relational grain of clearances, versions, and shares.
- Tamper evident audit logging is harder to reason about without enforced structure.

### Option 4: Minimal slice 1 schema only

Create only what the walking skeleton needs (users, sessions, documents, one content table) and let slices 2 through 8 add their tables later.

**Pros**:
- Smallest possible first migration; least upfront review surface.

**Cons**:
- Directly violates the scope done condition, which requires the model to support every later slice without a breaking migration. Versions and shares in particular reshape `documents` if deferred, turning additive work into rewrites.
- The engineer chose the all entities now option explicitly during the design conversation.

## Rationale

Option 1 wins because the scope's done condition is explicitly "support every later slice without a breaking migration," and a single normalized schema with enum columns is the boring, proven shape for exactly this domain. The forces from Context decide each sub choice: integer rank classification exists because the Bell LaPadula check must be correct and cheap; snapshot audit columns exist because hard deletes (the engineer's choice over soft delete) must not erase evidence; enum columns over lookup tables exist because the value sets are fixed by the product brief and joins would tax every policy check for flexibility nobody requested.

Two engineer preferences were honored over my recommendations where they diverged: hard delete for documents (I recommended soft delete for audit completeness; the audit log's snapshot design keeps evidence intact regardless, so the tradeoff is acceptable) and title plus description on documents (I recommended title only; a nullable description column is cheap and the engineer wants it). Both are recorded in Consequences.

## References

None. The engineer chose no references for this spec; reasoning rests on spec 0001, the scope document, and standard relational design practice.
