# Rationale, core classified document loop

## Context

Spec 0002 fixed the schema and spec 0001 fixed the stack, so slice 1 is mostly a build, not a design. What remained genuinely open were the product rules the schema cannot express: who may touch documents, how strict the Bell LaPadula write rule is, how the audit hash chain is actually formatted (spec 0002 deferred it), how the first admin comes to exist, and how sessions are carried. The scope row's Done-when adds one hard requirement: the audit chain must verify, which pulled the deferred chain-format decision into this slice.

Forces shaping the choices:

- Deny by default is the product's reason to exist; every ambiguity should resolve toward denial plus an audit row, never silent allowance.
- The demo must boot and prove allow and deny paths through the API with no UI, so bootstrap (first admin) and session transport had to be decided now.
- Strict Bell LaPadula was explicitly requested by the engineer, including the awkward consequence that write access is narrower than read access.
- Spec 0002 already reserved every column later slices need, so the cheapest correct path adds almost no schema.

## Options considered

### Option 1: Full slice one loop on the existing stack (chosen)

Build auth, admin user creation, document CRUD, encryption, policy, and the real audit chain in one pass on FastAPI, SQLAlchemy, argon2-cffi, and `cryptography`.

**Pros**:
- The Done-when is fully provable: upload, read, deny, audit verify, all through the API.
- The audit chain format is settled once, correctly, before slice 4 builds on it.
- No new dependencies; every library was already pinned in spec 0001.

**Cons**:
- Largest single build so far; more surface to review at once.
- Strict no write down makes the classification rules stricter than most teams expect.

### Option 2: Thinner MVP, defer audit chain and admin endpoints

Ship only officer upload/read with placeholder audit rows and no user management; bootstrap by SQL insert.

**Pros**:
- Fastest path to a demoable read/write loop.

**Cons**:
- The Done-when explicitly requires a verifying audit chain, so the thinnest version fails the contract.
- Bootstrap by SQL is fragile and unaudited; admin creation is core to the product story.
- Rejected: it saves days at the cost of the feature's actual promise.

### Option 3: Practical BLP variant (no read up, write at or below clearance)

Relax the write rule so users can classify documents anywhere up to their clearance.

**Pros**:
- Familiar behavior; classification becomes a real per document choice.
- No surprising "Top Secret user cannot file an Unclassified memo" cases.

**Cons**:
- Deviates from the textbook Bell LaPadula the engineer asked for.
- Rejected after the engineer chose strict no write down explicitly.

### Session transport alternatives

Bearer token in an Authorization header versus an HttpOnly SameSite cookie. The engineer chose the cookie for browser friendliness later; SameSite=Lax and JSON conventions carry the CSRF mitigation, and the Secure flag derives from `ENV=prod` so no new setting was needed.

### Audit fork prevention alternatives

Unique constraint on `prev_hash` versus a lock table row versus an in process queue. The unique constraint won because it is portable across SQLite and Postgres, needs no new table, and turns a race into a retryable integrity error rather than silent divergence. This resolves the mechanism spec 0002 deferred.

### Delete policy alternatives

Soft delete versus spec 0002's hard delete. The engineer confirmed hard delete stands; the audit log's snapshot columns already preserve the evidence, which is the design's intent.

## Rationale

The chosen path is the boring one: every hard problem (encryption, hashing, sessions, migrations) was already decided in specs 0001 and 0002, so slice 1 spends its complexity budget only where the product actually lives, the policy rules and the audit chain. Strict no write down was the engineer's explicit call and it is defensible: it makes leakage through misclassification structurally impossible rather than procedurally discouraged. Forcing classification to equal clearance is the simplest rule that satisfies both no read up and no write down simultaneously; anything looser reintroduces a choice the policy then has to police. The unique `prev_hash` constraint is the smallest possible serialization mechanism and it doubles as a tamper tripwire. Cookie sessions were the engineer's pick; the CSRF cost is real but bounded for a JSON API behind SameSite=Lax.

