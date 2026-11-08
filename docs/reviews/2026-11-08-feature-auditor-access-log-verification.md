# Review, feature/auditor-access-log-verification, 2026-11-08

**Reviewed by**: fresh-eyes review subagent (author on Devin)
**Scope**: 12 files, branch vs `main` (merge base `1e4422a`)
**Verdict**: Changes requested

## Summary

The change adds the auditor surface from spec 0006: `GET /v1/audit/entries` (filtered, seq-cursor paginated) and `POST /v1/audit/verify` (synchronous chain recompute + self audit + per-session-token rate limit), plus `verify_summary`/`list_entries` services, `RATE_LIMIT_AUDIT`, `GATE_ACTIONS` entries, and a thorough test suite covering all ten ACs. The implementation is faithful to the spec: role gating, MFA gate action names, pre-append snapshot semantics for `head_hash`/`bad_seq_numbers`, and the `audit.verify` self-audit row are all correct, and the `verify_chain` refactor preserves existing semantics. The headline issue is that `AuditEntry.details` is typed `dict | None`, so a tampered row whose `details` was rewritten to a non-object JSON value makes the whole list endpoint 500 — exactly the data this feature exists to inspect.

## Major

### 🟠 Tampered `details` of non-object JSON type 500s the list endpoint, `app/schemas/audit.py:19`

**Problem**: `AuditEntry.details` is `dict[str, Any] | None`. The `audit_log.details` column is plain `JSON`, and AC-10's whole premise is that entries are returned "with its stored (corrupted) values" so an auditor can inspect tampering. A tamperer with DB write access can set `details` to any valid JSON — a string, number, list, or `true` — and `AuditEntry.model_validate(row)` in `app/api/audit.py:66` will then raise a `ValidationError`, turning the entire page response into a 500. Any page containing that row is unbrowsable; the auditor can only page around it blindly.

**Why it matters**: The endpoint exists to display possibly-corrupted rows. Verification (`POST /v1/audit/verify`) still works because it never serializes `details`, but the browse side — the primary investigation tool — breaks precisely on the adversarial input it was built to surface. This is a latent crash on attacker-controlled data in a security-audit API.

**Suggested fix**: Widen the schema field to accept any stored JSON (e.g. `details: Any` or a `JsonValue` union covering object/list/scalar/null) so corrupted values pass through verbatim, matching the "returned as stored" contract. Alternatively validate per-row and degrade gracefully, but passthrough is what the spec intends.

## Minor

### 🟡 Test gaps on boundary and auth paths, `tests/test_audit.py`

**Problem**: Coverage of AC-1..AC-10 is otherwise strong, but a few contract edges are untested: (a) no test asserts 401 for unauthenticated calls to either `/v1/audit/*` endpoint; (b) `limit=200` acceptance and the default page size of 50 are never asserted (only `limit=2` and invalid values); (c) the "exactly full final page" edge — where `len(rows) == limit` but no older entries remain, so `next_cursor` is non-null and the next page returns empty — is untested, and it is the one place `next_cursor` semantics could silently regress.

**Why it matters**: These are cheap assertions on a security-sensitive contract; the full-page edge in particular is where an off-by-one in `next_cursor` would hide.

**Suggested fix**: Add a small test creating exactly `limit` rows asserting `next_cursor` behavior on the final page, a `limit=200`/`limit` omitted check, and a 401 case with no session cookie.

### 🟡 `actor` dependency result unused in list endpoint, `app/api/audit.py:51`

**Problem**: `list_entries` declares `actor: User = Depends(require_role("audit.entries_list", AUDITOR))` but never uses `actor`. Harmless (the dependency is what matters), but it reads like forgotten wiring.

**Why it matters**: Cosmetic; a reader may wonder whether the actor should appear in a response field or audit detail.

**Suggested fix**: Either drop the binding (`_=Depends(...)` is not idiomatic either — most FastAPI codebases keep the named param for clarity, so this is arguably fine as-is) or add a comment noting the dependency is load-bearing only.

## Nits

- ⚪ `app/api/audit.py:73` — the endpoint function is named `verify_chain`, identical to `services/audit.verify_chain`. Different module so no real collision, but `run_verify`/`verify` would read cleaner at call sites and in logs.
- ⚪ `app/api/audit.py:36` — `"1000000/minute"` kill-switch value duplicated from `app/api/auth.py:43`; consistent with the existing pattern, but a shared constant would prevent drift if the sentinel ever changes.
- ⚪ `app/schemas/audit.py:20` — `prev_hash: str | None` is nullable in the schema though the column is always populated (genesis is 64 zeros, never NULL); matching the model is fine, just noting the schema is more permissive than reality.

## Strengths

- Spec fidelity is excellent: `GATE_ACTIONS` entries, per-session-token-hash rate limit key with IP fallback, pre-append snapshot semantics for `head_hash`/`bad_seq_numbers`, `audit.verify` self-audit carrying `{valid, checked_count, bad_count}`, and list calls appending nothing are all implemented and tested exactly as specified.
- The `_scan_chain`/`_chain_rows` refactor is clean: `verify_chain` keeps identical semantics (verified against existing tests in `test_api.py`/`test_services.py`), and `verify_summary` gets count + head hash from the same single pass rather than three queries.
- `_as_utc` normalization plus SQLAlchemy's tz-dropping SQLite `DATETIME` bind processor means `occurred_after`/`occurred_before` compare consistently on both SQLite and Postgres — the portability trap the spec called out is handled correctly.
- The test suite is genuinely strong: tamper-by-edit and tamper-by-delete detection, empty-log verify, role denials with audited rows, MFA gate denials under the right action names, per-session rate-limit isolation, and the kill switch are all covered.

## Test coverage

All ten ACs have at least one dedicated test; the tamper and rate-limit scenarios are tested at behavior level, not mock level. Gaps noted above: unauthenticated 401s, `limit` upper bound/default, and the exactly-full final page `next_cursor` edge. No test exercises a tampered `details` value of non-dict JSON type, which is the Major finding.
