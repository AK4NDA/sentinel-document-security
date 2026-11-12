# Review, uncommitted (maintenance & retention r2, spec 0012), 2026-11-12

**Reviewed by**: review subagent (fresh model; author on the implementing model)
**Scope**: 9 files, uncommitted working tree vs `main` (merge base c5f8910)
**Verdict**: Approve with nits

## Summary

Second pass on spec 0012. The first review's Major (blob stage TOCTOU) is substantially closed: `blob_store.store` now refreshes mtime on dedup claims via `_claim_existing`/`os.utime`, and `_cleanup_blobs` re-verifies each doomed file with a fresh `blob_path` reference query plus a fresh `st_mtime` immediately before unlink. The inflated `deleted` count and dead scheduler lock are also fixed, and three targeted regression tests cover the new logic. What remains is a drastically narrowed residual race (stat→unlink gap, microseconds), a session held open across slow filesystem I/O, and a few nits. All 32 maintenance/config tests pass.

## Verification of first-review fixes

- **Major (blob TOCTOU)**: Mitigated, not fully eliminated. `store()` (`app/services/blob_store.py:39`) utime's existing blobs on dedup hits, and `_cleanup_blobs` (`app/services/maintenance.py:152-169`) rechecks reference + mtime per file before unlink. I traced every `DocumentVersion` creation site (`documents.py:219,407,674`): upload/edit call `store()` first (fresh write or utime), and `restore` only copies `blob_path` values already referenced by an existing version row — so no path creates an unreferenced→referenced transition without touching the file. The residual hole is noted below as a Minor.
- **Minor (inflated blob count)**: Fixed. `FileNotFoundError` is caught separately and does not increment `deleted` (`maintenance.py:164-167`); other `OSError`s are logged and skipped.
- **Minor (dead scheduler lock)**: Fixed. `_cleanup_lock` is module scope (`maintenance.py:183`) and acquired inside `run_cleanup` (`:197`), genuinely serializing in-process runs; `scheduler_loop`'s dead lock and unreachable interval recheck are gone.
- **Nits**: CLI now prints stage errors before the summary (`app/cli.py:88-93`).

## Minor

### 🟡 Residual stat→unlink race can still orphan a live blob reference, `app/services/maintenance.py:157-164`

**Problem**: The per-file recheck orders reference SELECT → `path.stat()` → `path.unlink`, each separated by `await asyncio.to_thread` yields. A dedup-hit `store()` whose `os.utime` lands between the stat and the unlink refreshes mtime too late to be seen, then its `document_versions` row commits after the reference SELECT — the unlink removes a file a live row is about to reference. The window is now microseconds (two adjacent thread-pool dispatches) versus the original seconds-scale scan window, and the mtime refresh makes the common interleavings self-correcting, but it is not zero.

**Why it matters**: Same failure mode as the first review's Major — permanent silent data loss on download — just far less probable. AC-8 sanctions idempotent deletes for overlap, but this is not overlap of two cleanups; it's cleanup vs. upload. The first review explicitly suggested documenting the accepted race in the spec's Consequences if it can't be fully closed; the spec text doesn't mention it.

**Suggested fix**: Either (a) shrink further by doing stat+unlink inside a single `asyncio.to_thread` call so the gap is syscall-adjacent, or (b) accept it and add a Consequences line in the spec stating the residual window and why it's tolerated. Full closure would require a lock shared with `blob_store.store`, which is likely overkill for a microsecond race.

### 🟡 Blob stage holds an open transaction/pooled connection across all file I/O, `app/services/maintenance.py:152-170`

**Problem**: The second `session_factory()` session stays open for the entire doomed-file loop. Each `_blob_still_referenced` execute autobegins a transaction that is never committed or rolled back until the `async with` exits — so one pooled connection sits idle-in-transaction while `asyncio.to_thread(path.stat)` / `path.unlink` run for every candidate. With a large orphan set this can be thousands of sequential thread-pool round-trips under a held connection.

**Why it matters**: On Postgres this pins a pool slot (default size 5, shared with API traffic) for the duration; on SQLite tests it's harmless. `_cleanup_lock` serializes in-process runs so at most one such session exists per process, bounding the impact — which is why this is Minor, not Major.

**Suggested fix**: `await session.rollback()` after each `_blob_still_referenced` check (cheap, releases the transaction until the next SELECT re-begins it), or fetch existence checks in short-lived sessions. Alternatively collect still-referenced paths first, then unlink outside the session entirely.

## Nits

- ⚪ `app/services/maintenance.py:183`, module-level `asyncio.Lock` binds to the first event loop that experiences contention (`_get_loop` is only called on the contended path). Safe today — one loop per process, and only the `asyncio.gather` test contends — but a second contended caller on a different loop (e.g., a future test) would raise "bound to a different event loop."
- ⚪ `app/services/blob_store.py:26-32`, `_claim_existing` maps *any* `OSError` to "missing" and falls through to the write path. A dedup hit on an existing-but-unwritable blob now attempts seal+`os.replace` where the old `path.exists()` check returned early; it usually still succeeds (replace needs dir, not file, perms) but the error conflation is imprecise — consider treating `FileNotFoundError` as the only write-path signal.
- ⚪ `app/services/blob_store.py:21`, pre-existing (not introduced here): `_write_atomic` uses a fixed `path.name + ".tmp"` sibling, so two concurrent first-time stores of identical content can interleave writes to the same tmp file and `os.replace` a partially-written blob. Worth a follow-up; the new `_claim_existing` narrows but doesn't eliminate it.
- ⚪ `app/services/maintenance.py:199`, `now` is captured once for all five stages; the blob cutoff uses run-start time, so a slow run collects blobs that crossed min-age mid-run seconds early. Negligible drift; noting for completeness.

## Strengths

- The TOCTOU fix is well-reasoned, not just patched over: the mtime refresh in `store()` is the key insight — it makes dedup-hit re-references self-protecting regardless of cleanup timing, and the per-file recheck covers the committed-reference case. Verified against all three `DocumentVersion` creation sites.
- The three new regression tests are genuinely adversarial: `test_cleanup_skips_blob_referenced_mid_run` injects a committed version row mid-scan via `call_soon_threadsafe` + a blocking `threading.Event`, and `test_cleanup_skips_blob_refreshed_mid_run` simulates the dedup-claim utime — both assert the file survives *and* the count is 0.
- `test_store_dedup_hit_refreshes_mtime` directly locks the `store()` side of the contract.
- Error-path discipline is clean: stage exceptions land in `report.errors` and the audit entry, `AuditChainFork` propagates to CLI exit 1, `CancelledError` correctly bypasses `scheduler_loop`'s `except Exception`, and shutdown cancels+awaits the task before `engine.dispose()`.

## Test coverage

`TEST_SIGNAL = configured`. Coverage is excellent and was extended for the fixes: 32 tests pass (`uv run pytest tests/test_maintenance.py tests/test_config.py`). Every AC still maps to at least one test, config validators are covered including env-var reads, and the lifespan start/cancel/disable paths are tested with a fake loop. Untested residuals: the stat→unlink microsecond window (not practically testable without fault injection inside `to_thread`), and the `FileNotFoundError`-doesn't-count path under truly concurrent unlinks (the code is simple enough that this is acceptable).
