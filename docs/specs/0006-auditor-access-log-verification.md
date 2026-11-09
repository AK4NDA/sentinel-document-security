# 0006. Auditor access and log verification

**Date**: 2026-11-08
**Status**: Accepted

## Summary

This gives the auditor role its own API surface: a filtered, cursor paginated read of the audit log plus an endpoint that recomputes the hash chain and reports whether any entry was edited or removed. Verification runs synchronously and writes its own audit entry. Auditors still cannot touch documents or user administration; every blocked attempt stays denied and logged. No schema changes; the audit table and chain code from spec 0003 already carry everything needed.

## Context

Spec 0003 built the hash chained audit log and the `verify_chain` service function, but nothing exposes either to a caller. Spec 0005 confirmed the auditor role exists and is denied documents and admin routes, yet today an auditor can log in and reach nothing. Slice 4 of the scope exists to make the auditor role real: browse the trail, prove it was not tampered with, and keep hard separation from document access.

The audit log is append only and chain verified internally, but two properties need a decision. First, the chain only proves internal consistency: deleting entries from the tail is undetectable without an externally recorded head hash, so the verify response must expose one. Second, browsing the log is itself activity: auditing every page read would grow the chain with audit noise and bury the events an auditor is looking for, so what gets self audited is a real choice.

## Requirements

**User stories**:
- As an auditor, I want to browse audit log entries with filters and pagination so that I can investigate who attempted what and when.
- As an auditor, I want to run a chain verification that reports validity, counts, and the head hash so that I can prove no entry was edited or deleted.
- As the system owner, I want auditors hard separated from documents and administration so that the auditor role can inspect the trail without ever touching content.

**Acceptance criteria** (the contract, each criterion is IDed and independently checkable):
- **AC-1**: An MFA enrolled auditor calling `GET /v1/audit/entries` receives 200 with entries ordered newest first (seq descending), each carrying seq, id, occurred_at, actor_id, actor_username, actor_role, action, outcome, target_type, target_id, details, prev_hash, and hash; the response also carries `next_cursor`, null when no older entries remain. Default page size is 50 and the maximum accepted limit is 200.
- **AC-2**: The list endpoint accepts filters `actor_username`, `action`, `outcome` (allowed or denied only), `target_type`, `target_id`, `occurred_after`, and `occurred_before`; filters combine with AND; an invalid outcome value, unparseable datetime, or out of range limit returns 422.
- **AC-3**: `next_cursor` is the seq of the last entry on the page; passing it as `cursor` returns the next older page; a cursor older than every entry returns an empty page with `next_cursor` null; a malformed cursor returns 422.
- **AC-4**: `POST /v1/audit/verify` recomputes the full chain synchronously and returns 200 with `valid`, `checked_count`, `head_hash`, and `bad_seq_numbers`. On a clean chain `valid` is true; after any stored field of a middle entry is edited or a middle entry is deleted, `valid` is false and `bad_seq_numbers` lists the seqs of stored rows that fail verification (for a deletion the flagged seq is the successor row, since the deleted row no longer exists; a single tamper may legitimately produce multiple flagged seqs). `bad_seq_numbers` is computed over rows read before the verify self audit append, and `head_hash` is the `hash` of the highest seq row in that same snapshot, so it is unaffected by the audit row this call adds. On an empty log `valid` is true, `checked_count` is 0, and `head_hash` is null.
- **AC-5**: Every verify call appends exactly one audit entry with action `audit.verify`, outcome `allowed`, and details carrying `valid`, `checked_count`, and `bad_count`; routine list calls append no audit entries.
- **AC-6**: Admin and user roles calling either endpoint receive 403 with an audited role denial recorded under the endpoint's action name (`audit.entries_list` for the list, `audit.verify` for verify). The test fixtures for this must be MFA enrolled, because the enrollment gate runs before the role check and an unenrolled admin would get the AC-8 denial instead.
- **AC-7**: Auditor calls to document endpoints remain 403 with an audited denial (regression of the separation spec 0005 verified).
- **AC-8**: An auditor who has not completed MFA enrollment receives 403 `mfa_enrollment_required` on both endpoints, with the denial audited under the endpoint's action name.
- **AC-9**: `POST /v1/audit/verify` is rate limited through the existing slowapi limiter, keyed on the SHA-256 of the session token (the raw token is never used as a key) with client IP as fallback for unauthenticated calls, so the limit is effectively per user. The limit value comes from a new `RATE_LIMIT_AUDIT` setting defaulting to `30/minute` and the existing `RATE_LIMIT_ENABLED` kill switch applies; exceeding the limit returns 429.
- **AC-10**: A tampered entry is still returned by the list endpoint with its stored (corrupted) values; verification is the mechanism that detects it, browsing does not filter or hide it.

## Options considered

### Option 1: Auditor REST surface with synchronous verify (chosen)

Two thin endpoints on a new `/v1/audit` router: a filtered cursor paginated list and a POST that runs `verify_chain` inline and returns a summary plus head hash. Everything needed already exists in `services/audit.py`.

**Pros**:
- Smallest possible surface; reuses the chain code and role gate verbatim
- Synchronous result is trivially testable and demoable
- Head hash in the response enables external checkpoint comparison

**Cons**:
- Full chain scan is O(n) per call; fine at demo scale, needs a job later if the log grows

### Option 2: Async verification job

Verify runs as a background job writing a result row; auditors poll a status endpoint.

**Pros**:
- Scales to large logs without blocking a request

**Cons**:
- New job infrastructure, result storage, and polling surface for a table that holds thousands of rows at most today
- Solves a scale problem the project does not have

### Option 3: CLI or report only verification

Expose verification through `python -m app` or a generated report file; no browse API.

**Pros**:
- No new HTTP surface at all

**Cons**:
- Fails the scope's "auditor can browse" requirement and pushes verification off the API the rest of the system uses

## Decision

**Chosen option**: Option 1: Auditor REST surface with synchronous verify.

Add `GET /v1/audit/entries` (filtered, seq cursor paginated) and `POST /v1/audit/verify` (synchronous full chain recompute returning valid, checked_count, head_hash, bad_seq_numbers), both gated to the auditor role with MFA enrollment required, verify rate limited and self audited.

**Implementation skills**: `fastapi` (`fastapi/fastapi`, `.agents/skills/fastapi/`) · `sqlalchemy` (`TerminalSkills/skills`, `.agents/skills/sqlalchemy/`) · `pytest-asyncio-patterns` (`testland/qa`, `.agents/skills/pytest-asyncio-patterns/`)

## Feature design

**Data model sketch**:
No schema changes and no migration. The existing `audit_log` table supplies every field: `seq` (cursor and ordering), `id`, `occurred_at` (indexed, filter bounds), `actor_id`, `actor_username`, `actor_role`, `action`, `outcome`, `target_type`, `target_id` (indexed), `details`, `prev_hash`, `hash`. Filter columns `action`, `actor_username`, and `outcome` are unindexed and seq scan; acceptable at demo scale.

**API surface**:
| Endpoint | Method | Key inputs | Key outputs | Auth | Key errors |
|---|---|---|---|---|---|
| /v1/audit/entries | GET | cursor:int positive (opt), limit:int 1..200 default 50 (opt), actor_username, action, outcome, target_type, target_id, occurred_after, occurred_before (all opt, exact match) | AuditEntryPage: entries[] of AuditEntry, next_cursor:int\|null | auditor, MFA enrolled | 401, 403, 422 |
| /v1/audit/verify | POST | none | VerifyResult: valid:bool, checked_count:int, head_hash:str\|null, bad_seq_numbers:int[] | auditor, MFA enrolled, 30/min per user | 401, 403, 429 |

Action names: the list route uses `audit.entries_list` and the verify route uses `audit.verify`. Allowed list calls are not audited; the names exist for role denials via `require_role` and for `GATE_ACTIONS` entries keyed `("GET", "/v1/audit/entries")` and `("POST", "/v1/audit/verify")` so enrollment gate denials read correctly. Verify's own success row also uses `audit.verify`.

**Response shapes**:
- `AuditEntry`: seq:int, id:uuid as string, occurred_at:ISO 8601, actor_id:uuid\|null as string, actor_username:str\|null, actor_role:str\|null, action:str, outcome:str, target_type:str\|null, target_id:str\|null, details:object\|null passthrough, prev_hash:str\|null, hash:str
- `AuditEntryPage`: entries:AuditEntry[], next_cursor:int\|null
- `VerifyResult`: valid:bool, checked_count:int, head_hash:str\|null, bad_seq_numbers:int[]

**Filter and cursor semantics**:
- All filters are exact equality except `occurred_after`/`occurred_before`, which are inclusive bounds on `occurred_at`; datetimes parse as tz aware ISO 8601 and normalize to UTC for comparison on both SQLite and Postgres. An inverted range (`occurred_after` later than `occurred_before`) returns an empty page, not an error.
- `cursor` must be a positive integer seq; 0, negative, or non integer values return 422. `limit` outside 1..200 returns 422.
- Pagination needs no count query: fetch `limit` rows ordered `seq` descending with `seq < cursor` when a cursor is given; `next_cursor` is the last row's seq, or null when fewer than `limit` rows come back.

**Verify mechanics**:
- `verify_summary` reuses the single row load inside `verify_chain` (refactor it to expose rows plus bad seqs, or compute count and head from the same scan) so verification is one pass, not three queries.
- After computing the result, the audit row is appended with `audit.append_with_retry` on the app session factory in its own transaction, so a chain fork retries only the append, not the verification read.
- `head_hash` and `bad_seq_numbers` describe the snapshot read before that append; a concurrent append between read and audit commit can make them stale by one row, which is accepted at this scale.

**Value sourcing**:
| Action | Value produced / displayed | Source |
|---|---|---|
| list entries | every entry field | `audit_log` columns, returned as stored including corrupted values |
| list entries | next_cursor | derived: `seq` of last entry in page, null when page is short or empty |
| list entries | filtered subset | query params combined with AND against the columns above |
| verify | valid, bad_seq_numbers | computed by `verify_chain` over all `audit_log` rows ordered by seq; bad seqs are stored rows that fail, successor flagged on deletion |
| verify | checked_count | count of rows examined in the same `verify_chain` scan |
| verify | head_hash | `hash` column of the highest seq row in the pre-append snapshot; null when the table is empty |
| verify | audit details {valid, checked_count, bad_count} | derived from the verify result of the same call |

**Key invariants**:
- `verify_chain` semantics are unchanged; verification reports, it never repairs or filters.
- List reads are side effect free: no audit row is appended for a successful browse.
- Verify appends exactly one `audit.verify` row per call, inside its own transaction via the existing audit helpers.
- Chain append rules from spec 0003 are untouched; `prev_hash` uniqueness and fork retry still govern every writer.

**Security model**:
Auditor role only on both endpoints; admin and user get an audited 403 through `require_role`. Auditors remain unable to reach documents (`can_access_documents` is false for the role) and admin user routes; those denials keep their existing audited behavior. Entries are returned in full including `details`; project rules already keep secrets out of audit details. MFA enrollment gate applies to both routes like every other protected route. No regulated data scope beyond the audit integrity mission itself.

**Configuration required**:
- `RATE_LIMIT_AUDIT`: per user limit for `POST /v1/audit/verify`, default `30/minute`; honors the existing `RATE_LIMIT_ENABLED` kill switch used by tests

**Critical test scenarios** (each maps to an acceptance criterion in ## Requirements):
- Happy path: enrolled auditor lists entries, filters `outcome=denied`, paginates with the cursor, then POSTs verify on a clean chain and gets `valid=true` with the correct head hash, verifies **AC-1**, **AC-2**, **AC-3**, **AC-4**
- Failure case: a test edits a middle entry's `details` directly in the DB (or deletes a middle row), then verify returns `valid=false` naming the broken seqs while the list still returns the tampered row, verifies **AC-4**, **AC-10**
- Auth/permission: MFA enrolled admin and user get 403 with audited role denials on both endpoints; an unenrolled auditor gets 403 `mfa_enrollment_required`; an auditor hitting `GET /v1/documents` still gets 403, verifies **AC-6**, **AC-7**, **AC-8**
- Self audit: verify calls each append one `audit.verify` row carrying the result, list calls append none, verifies **AC-5**

## Build plan

1. Add `list_entries` to `services/audit.py`: filter predicates, `seq < cursor` ordering descending, bounded limit, returns rows plus next_cursor, satisfies **AC-1**, **AC-2**, **AC-3**
2. Add `verify_summary` to `services/audit.py`: single pass over `audit_log` rows returning valid, checked_count, head_hash (pre append snapshot), bad_seq_numbers, satisfies **AC-4**
3. Add `schemas/audit.py` and `api/audit.py` with both endpoints, `require_role("audit.entries_list", AUDITOR)` and `require_role("audit.verify", AUDITOR)`, register the router in `main.py`, and add both routes to `GATE_ACTIONS` in `api/deps.py`, satisfies **AC-6**, **AC-8**
4. Wire verify's audit append via `audit.append_with_retry` (action `audit.verify`, details with result) and the `RATE_LIMIT_AUDIT` slowapi limit keyed on the session token hash; add the `RATE_LIMIT_AUDIT` setting; confirm list appends nothing, satisfies **AC-5**, **AC-9**, **AC-10**
5. Tests: filter and pagination coverage, tamper detection on edited and deleted middle entries, empty log verify, role denials, MFA gate, rate limit, and the no self audit on list rule, satisfies **AC-1** through **AC-10**

## Consequences

**Positive**:
- The auditor role becomes functional end to end: browse, verify, and provable separation from content
- `head_hash` gives auditors an external checkpoint to compare against, the only defense against tail truncation
- Verification results land in the same hash chained log they verify, so the checking itself is tamper evident

**Negative / tradeoffs**:
- Full chain verification is O(n) synchronous work per call; the rate limit bounds abuse but a very large log will eventually need the async job option deferred here
- Unindexed filter columns seq scan; fine now, needs indexes if the log grows
- Tail deletion remains undetectable without an externally recorded head hash; documented, accepted for this slice. `head_hash` is only meaningful if the auditor persists it outside the database, since hashes are unkeyed SHA-256 over public fields and an attacker with DB write access could recompute a whole chain
- A concurrent append between the verify read and its audit commit can leave `head_hash` and counts stale by one row; accepted at this scale
- The audit row verify appends moves the true chain head, so `head_hash` in the response intentionally describes the pre verify state and will differ from a later verify's head even with no tampering

**Neutral**:
- No migration, no new dependencies; one new setting (`RATE_LIMIT_AUDIT`) with a safe default
- New router follows the existing thin router, fat service layering

## Follow-up

- [ ] If the log grows large, revisit async verification (Option 2) and indexes on `action`, `actor_username`, and `outcome`
- [ ] When slice 8 (access alerts) lands, consider raising a tamper alert on `valid=false` verify results
- [ ] If auditors need offline evidence, consider a filtered export endpoint (CSV or JSON) as a later addition

## Rationale

Reasoning and options: see the sections above; this is a single file spec so Context, Options considered, and Rationale stay inline.

## References

**Project sources** (verifiable, in this repo):
- `AGENTS.md` deny by default and audit in the same transaction rules
- `app/AGENTS.md` layered monolith conventions and audit actor snapshot rule
- spec 0003 core classified document loop (hash chain, `verify_chain`, audit append helpers)
- spec 0005 administration and account lifecycle (auditor role denials already verified)
- `app/services/audit.py`, `app/api/deps.py`, `app/services/policy.py` as built

**Practices & standards**:
- Separation of duties between operational and audit roles
- Tamper evident logging via hash chains (each entry commits to its predecessor)
- Deny by default authorization with audited denials
