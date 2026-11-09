# Review, feature/per-user-sharing, 2026-11-09

**Reviewed by**: fresh review subagent (author on the implementing model)
**Scope**: 24 files, branch vs merge-base `6c29251` (includes uncommitted working tree changes)
**Verdict**: Approve with nits

## Summary

Implements spec 0009 per user document sharing: owner managed read only grants that override clearance on all read paths, plus `GET /v1/shares/mine` and `GET /v1/users/lookup`. The implementation is careful and faithful to the spec: ownership is enforced with the same non revealing 404 convention as edit, every grant/revoke/list/shared read appends audit inside the business transaction, `via_share`/`share_id` are recomputed inside the audit transaction to survive mid request revokes, and write paths correctly ignore shares. The main gaps are a Postgres specific error string match in the concurrent grant race handler (SQLite dev/test gets a 500 instead of the documented 200), and the spec's concurrent grant critical scenario has no test. `uv run pytest tests/test_shares.py` passes (18 tests).

## Blockers

None.

## Major

None.

## Minor

### 🟡 Concurrent grant race handler only works on Postgres, `app/services/shares.py:205`

**Problem**: The `IntegrityError` catch in `grant()` decides whether the violation was the `(document_id, user_id)` unique constraint by substring matching `"uq_document_shares_document_user"` against `str(exc.orig)`. Postgres reports the constraint name (`duplicate key value violates unique constraint "uq_document_shares_document_user"`), but SQLite reports `UNIQUE constraint failed: document_shares.document_id, document_shares.user_id`, which never contains that string, so the check fails and the exception is re-raised as a 500.

**Why it matters**: AGENTS.md requires "SQLite tests must match Postgres behavior", and spec 0009 lists the IntegrityError recheck as a load bearing invariant ("a concurrent grant that loses the insert race catches IntegrityError, re reads the row, and returns it with 200"). On the dev/test database a lost insert race produces a 500 instead of the winner's row. Additionally, even on Postgres there is a residual window: if the winner's transaction has not committed when `_active_share` re-reads, `winner is None` yields a 500 rather than a retry.

**Suggested fix**: Detect the violation portably, e.g. inspect `exc.orig` diagnostics (`sqlite_errorname == "SQLITE_CONSTRAINT_UNIQUE"` / `constraint_name` attributes) or simply treat any `IntegrityError` from the share insert flush as the pair conflict and re-read the row before giving up. Consider a short bounded retry when the winner row is not yet visible.

### 🟡 Spec critical scenario "two concurrent grants" is untested, `tests/test_shares.py`

**Problem**: Spec 0009's critical test scenarios explicitly call for "two concurrent grants for the same pair produce one row and consistent responses (IntegrityError recheck returns 200), verifies AC-4". No test exercises the `IntegrityError` recheck path in `grant()`; all grant tests are sequential.

**Why it matters**: The recheck path is the only code that recovers from a real race, and as noted above it is dialect sensitive. With TEST_SIGNAL=configured, untested branching logic in a security relevant path is a finding.

**Suggested fix**: Add a test that forces the conflict deterministically (e.g. pre-insert the share row via a second session between the existence check and flush, or invoke the service twice concurrently) and asserts a single row plus a 200/201 response.

## Nits

- ⚪ `app/services/shares.py:53`, `_deny` returns detail `"not found"` for every non-403 status, so the 409 eligibility denials (`self_share`, `grantee_disabled`, `grantee_role`) respond with `{"detail": "not found"}`. Status codes are correct; only the message is misleading. Same pattern exists in `app/services/documents.py:139`.
- ⚪ `app/services/shares.py:34-53`, `_deny` duplicates `app/services/documents.py:121-139` almost verbatim; a shared helper (or reuse) would keep the two copies from drifting.
- ⚪ `app/services/shares.py:118-158`, eligibility checks run before the already-active-share lookup, so re-POSTing an active share whose grantee has since been disabled returns 409 `grantee_disabled` rather than the spec's "200 with the existing share unchanged". The spec does not address post grant eligibility drift, so this is arguably correct deny-by-default behavior, but worth a conscious decision.
- ⚪ `app/services/users.py:293` and `app/services/shares.py:333`, `AuditChainFork` from `audit.transact` is not converted to `HTTPException(500)` here (unlike most other services); it still surfaces as a 500 via the unhandled exception path, matching the preexisting `list_users` behavior, but inconsistent with the surrounding style.

## Strengths

- `via_share`/`share_id` are recomputed inside the audit transaction (`_share_audit_details`, `app/services/documents.py:177-191`) rather than trusting the earlier policy read, correctly implementing the spec's same snapshot invariant.
- `list_mine` and `lookup_users` materialize plain values before `audit.transact` with an explicit comment about chain fork rollbacks expiring ORM state — a subtle correctness detail handled well.
- `lookup_users` escapes `%`, `_`, and `\` and uses a parameterized `ilike` with `escape`, with tests proving wildcards are literal.
- Test suite is genuinely strong: 18 tests covering all 15 ACs including admin lifecycle interaction, search non leak, read only enforcement, role gates, and audit detail assertions.

## Test coverage

Well covered: `tests/test_shares.py` exercises every AC including edge cases (regrant preserves `created_at`, noop POST adds no audit row, versionless documents excluded from `/v1/shares/mine`, ordering, literal wildcard lookup, disabled/demoted grantee lifecycle). The only spec mandated scenario without a test is the concurrent grant IntegrityError recheck (noted above).
