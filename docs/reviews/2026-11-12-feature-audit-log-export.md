# Review, feature/maintenance-retention (uncommitted), 2026-11-12

**Reviewed by**: review subagent (fresh model; author on devin)
**Scope**: 11 files, uncommitted working tree vs main (merge-base c5f8910)
**Verdict**: Approve with nits

## Summary

Adds auditor-only `GET /v1/audit/export` streaming CSV or JSONL of filtered `audit_log` rows, pinned to the chain head at start, capped by `EXPORT_MAX_ROWS` via a `COUNT(*)` probe, self-audited through `append_with_retry` in a `finally` path, with CSV formula-injection sanitization and shared rate limiting. The implementation is careful and faithful to spec 0013: the shared `_apply_filters` builder guarantees list/export parity, the `seq <= head_seq` bound plus chain-serialized appends make the snapshot sound, and the audit append correctly survives client disconnect. No blockers or majors; a few minor edge cases and nits.

## Minor

### 🟡 Unbounded snapshot when the log is empty, `app/services/audit.py:406` and `:435`

**Problem**: `export_count` and `export_rows` only apply the `seq <= head_seq` bound `if head_seq is not None`. If `export_head` returns `(None, None)` (empty `audit_log` at capture), both queries run with no upper bound, so a row committed between head capture and the row query would be exported even though AC-5 promises only rows at or below the captured head (recorded as `head_seq: null`).

**Why it matters**: Practically unreachable through the API — an authenticated auditor session implies prior audited logins, so the table is never empty — but the invariant is silently weaker than spec'd, and the service functions are also directly callable.

**Suggested fix**: Apply the bound unconditionally, e.g. treat `head_seq=None` as `AuditLog.seq <= -1` (or `seq < 1`), so an empty-head export deterministically returns zero rows.

### 🟡 Abort test asserts a tautology, `tests/test_audit_export.py:322`

**Problem**: `test_export_audit_recorded_on_abort` asserts `entries[0].details["rows_exported"] >= 0`, which is true for any integer including the field being absent-adjacent wrong values; the `"rows_exported" in details` check on the next line is the only real assertion.

**Why it matters**: AC-7's disconnect guarantee ("`rows_exported` equal to the rows actually sent") is the subtlest part of this feature and is the least verified — a regression that always wrote `0` or the full count would still pass.

**Suggested fix**: Seed a known number of rows, abort after the first chunk, and assert `0 <= rows_exported < total_matching` (or at minimum that the field is an int bounded by the seeded count).

## Nits

- ⚪ `app/api/audit.py:74`, `format` shadows the builtin; `fmt`/`export_format` would read cleaner, though FastAPI query-param naming makes `format` defensible.
- ⚪ `app/services/audit.py:294`, `_apply_filters` has no parameter/return type annotations, inconsistent with the typed signatures around it.
- ⚪ `app/api/audit.py:136`, `rows_sent` increments after `yield` resumes, so a row in flight when the client disconnects is not counted even though its bytes may have been partially sent — `rows_exported` can under-report by at most one. Ambiguous vs AC-7's "rows actually sent"; acceptable as-is.
- ⚪ `tests/test_audit_export.py`, no positive-path test for `occurred_after`/`occurred_before` filtering (only the inverted-range 422); parity is covered structurally by the shared builder, so this is coverage completeness only.
- ⚪ `docs/specs/0013-audit-log-export/verify.md:35`, live disconnect path verified by unit test only — worth a follow-up live check, already self-noted.

## Strengths

- Snapshot design is genuinely sound: chain appends serialize on the unique `prev_hash`, so no row with `seq <= head_seq` can commit after head capture — the bound is a real point-in-time pin, not just a heuristic. The export's own entry always lands above `head_seq` and can never appear in its own file.
- The `finally`-block audit append via `append_with_retry` on a separate session factory is the right shape: own transaction, fork-retry, records partial `rows_exported` on disconnect, and doesn't disturb the streaming request session.
- `_apply_filters` extraction removes duplication rather than copying it — list and export cannot drift.
- `_csv_safe` correctly implements the OWASP set including the `lstrip()` leading-whitespace check, applied uniformly to header and data cells; `details` stays valid compact sorted JSON.
- Test suite is thorough: 16 tests covering all 11 ACs including serializer units, role/MFA denials, truncation, empty results, rate limiting, and the abort path; `verify.md` documents a real 40/40 live run.

## Test coverage

`tests/test_audit_export.py` (16 tests) plus `tests/test_config.py` additions cover every acceptance criterion; all 27 tests pass locally (`uv run pytest tests/test_audit_export.py tests/test_config.py`). Untested/weak spots: the empty-log unbounded edge above (only reachable via direct service call), positive time-range filtering, and the strength of the disconnect assertion noted above. No coverage findings rise to Major.
