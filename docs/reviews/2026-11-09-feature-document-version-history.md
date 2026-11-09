# Review, feature/document-version-history, 2026-11-09

**Reviewed by**: review subagent (fresh-eyes reviewer; author model unknown to reviewer)
**Scope**: 9 files, branch vs main (b197a3a), including uncommitted working-tree changes to `docs/scope/scope.md` and `tests/test_api.py`
**Verdict**: Approve with nits

## Summary

Spec 0007 adds three endpoints — version list, per-version content download, and owner-only restore — plus `VersionMeta`/`VersionListResponse` schemas, `GATE_ACTIONS` entries, service functions in `app/services/documents.py`, and a thorough test suite. The implementation closely follows the spec's check ordering, audit vocabulary, and append-only invariants, reuses the existing `_readable_document`/`_deny`/`audit.transact` machinery cleanly, and keeps routers thin per the layered-monolith convention. No blockers or majors; a few narrow race-condition and coverage nits below. `uv run pytest` (72 tests) and `uv run ruff check` both pass.

## Minor

### 🟡 Restore's in-transaction "re-fetch" does not refresh `current_version_id`, `app/services/documents.py:588-591`

**Problem**: Inside `attempt`, `doc = await _fetch_document(session, doc_id)` runs on the same `AsyncSession` (`db`) that already loaded the `Document` earlier in `restore`. With `expire_on_commit=False` and no intervening commit, SQLAlchemy's identity map returns the same instance and `session.execute(select(...))` does not overwrite already-loaded column attributes. So `doc.current_version_id` compared against `src["id"]` is the value from the pre-transaction fetch, not a fresh read — despite AC-7's "checked inside the transaction against the re-fetched document".

**Why it matters**: A concurrent edit/restore committing between the outer fetch and the transaction could make the source version current without the 409 firing; the request would then append a new version duplicating current content (returns 201 instead of 409). The `(document_id, version_number)` unique constraint still prevents numbering corruption, so impact is limited to a spec-deviation in a rare race.

**Suggested fix**: Re-read the column fresh inside `attempt` — e.g. `await session.refresh(doc, attribute_names=["current_version_id"])` after the fetch, or run the check as a scalar `select(Document.current_version_id)` query — so the comparison sees committed state under READ COMMITTED.

### 🟡 `IntegrityError → 409` conflict path in `restore` is untested, `app/services/documents.py:632-634`

**Problem**: AC-7 requires a 409 on a `(document_id, version_number)` unique conflict from a concurrent edit or restore. The code handles it (`except IntegrityError` → rollback → 409, unaudited, matching `edit`), but no test exercises this branch — the suite covers the already-current 409 but not the unique-violation path.

**Why it matters**: This is new branching/error-handling logic; a regression (e.g. the `except` ordering vs `AuditChainFork`, or the rollback leaving the session usable) would go unnoticed. `edit` has the same untested branch, so this is consistent with existing coverage debt rather than a new sin.

**Suggested fix**: Add a test that forces the conflict — e.g. seed two versions with a hand-computed `max + 1` collision via a second session, or monkeypatch `func.max` — and assert 409 with no audit row.

### 🟡 `list_versions` `is_current` flag uses a pre-transaction snapshot, `app/services/documents.py:419,454`

**Problem**: `current_id = doc.current_version_id` is captured before `audit.transact`, while the version rows are queried inside it. A concurrent edit committing in between yields a list whose `is_current` marks the wrong row.

**Why it matters**: Read-only endpoint, sub-millisecond window, and the response is inherently a snapshot anyway — but re-fetching `current_version_id` inside `attempt` (as `read_meta` does for the doc) would make the flag consistent with the rows returned.

**Suggested fix**: Move the `current_version_id` read inside `attempt` (e.g. a scalar select or `session.refresh`), or accept and document the snapshot semantics.

## Nits

- ⚪ `app/services/documents.py:588`, `_fetch_document(session, doc_id)` inside `attempt` can return `None` if the document was concurrently deleted, then `doc.current_version_id` raises `AttributeError` → 500. Same latent pattern exists in `edit` (line 347); pre-existing, not introduced here.
- ⚪ `app/services/documents.py:494`, `blob_store.load` failures (missing/corrupt blob file) propagate as unaudited 500s; identical to existing `read_content` behavior, so consistent — noted only for completeness.
- ⚪ `app/api/documents.py:118-135`, `get_version_content` duplicates the `Response`/`Content-Disposition`/`Content-Length` boilerplate from `get_document_content`; a small shared helper would remove the copy-paste, but matching the existing style is defensible.

## Strengths

- Faithful spec implementation: denial ordering in `restore` matches AC-7 exactly (owner/404 → read gate → source 404 → source clearance → already-current 409), audit details carry `source_version_number`/`version_number` as specified, and both 409 paths are correctly unaudited.
- Good async discipline: `blob_store.load` already wraps blocking file I/O in `asyncio.to_thread`; `selectinload(DocumentVersion.created_by_user)` avoids an N+1 on `created_by` usernames.
- Test suite is genuinely strong: covers AC-1 through AC-10 including per-version clearance filtering, integrity-mismatch 500s via blob tampering, restore field-copy assertions at the ORM level, role/MFA/401 gates, and audit row contents — well beyond happy-path coverage.
- `_deny`'s new `details` parameter threads `version_number` into denial rows cleanly without disturbing existing callers.

## Test coverage

`TEST_SIGNAL = configured`. The new suite in `tests/test_api.py` (~480 lines, 15 tests) covers every acceptance criterion: list ordering/shape/audit, clearance filtering, read-gate denials, content round-trip, 404/422 paths, restore semantics and field copying, all denial reasons, role/MFA/unauthenticated gates, and blob integrity failures. Gaps: the unique-constraint 409 path (noted above) and the concurrent-restore race are untested — the latter is impractical to test deterministically. Overall coverage is strong.
