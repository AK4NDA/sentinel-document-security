# Review, uncommitted (maintenance & retention, spec 0012), 2026-11-12

**Reviewed by**: review subagent (fresh model; author on the implementing model)
**Scope**: 11 files, uncommitted working tree vs `main` (merge base c5f8910)
**Verdict**: Changes requested

## Summary

The change adds `app/services/maintenance.py` (`run_cleanup` with five stages plus `scheduler_loop`), a `cleanup` CLI subcommand, lifespan wiring, three `Settings` fields, compose/env passthrough, and a thorough test suite. The delete predicates match the read-path dead definitions in `services/mfa.py` and `services/sessions.py` exactly, dry run performs zero data writes, each stage gets its own session, the audit entry shape matches AC-5, and all 29 new/updated tests pass. The headline issue is a TOCTOU in the blob stage: the referenced-path set is read once, then files are unlinked later, so a concurrent upload that hits the content-addressed dedup path in `blob_store.store` can have its blob deleted after it becomes referenced — live data loss the spec's min-age guard does not cover for existing files.

## Major

### 🟠 Blob stage can delete a file that becomes referenced between the reference SELECT and the unlink, `app/services/maintenance.py:139-149`

**Problem**: `_cleanup_blobs` loads `SELECT DISTINCT blob_path FROM document_versions` in one session, closes it, scans the filesystem in a thread, then unlinks candidates. `blob_store.store` (`app/services/blob_store.py:30-33`) skips the write entirely when the content-addressed `.enc` file already exists — so a re-upload of previously seen content produces a young *database reference* to an *old* file. If a document was deleted (cascading its version rows, orphaning the blob) and someone re-uploads identical content while a cleanup run is between its reference SELECT and its unlink, the new `document_versions` row commits after the SELECT, the file is not in `referenced`, its mtime is far older than `MAINTENANCE_BLOB_MIN_AGE_SECONDS`, and it is unlinked — leaving a live version row pointing at a missing blob.

**Why it matters**: This violates the spec's core invariant "a blob file referenced by any `document_versions.blob_path` is never deleted." The min-age guard only covers the store-to-commit gap for *new* files; dedup hits write nothing, so mtime stays old and the guard does not apply. The window is small (SELECT → scan → unlink, typically sub-second to seconds) and requires a dedup-hit upload concurrent with a run, but the consequence is permanent, silent data loss discovered only on download. The hourly scheduler makes this a recurring exposure, not a one-off.

**Suggested fix**: Narrow or close the race. Options, roughly in order of robustness: (a) in `blob_store.store`, `os.utime`/touch the existing `.enc` on a dedup hit so re-referenced blobs look young again; (b) re-read the distinct `blob_path` set immediately before unlinking (still racy but shrinks the window to per-file); (c) hold the reference check and unlink under a short-lived transaction or a filesystem-level lock shared with `store`. At minimum, document the accepted race in the spec's Consequences so the residual risk is explicit.

## Minor

### 🟡 Blob `deleted` count overstates under concurrent runs, `app/services/maintenance.py:147-150`

**Problem**: `path.unlink(missing_ok=True)` followed by `deleted += 1` counts every candidate as deleted even when the file was already removed by a concurrent cleanup (CLI vs scheduler, or two `run_cleanup` calls). The audit entry's `stages.blobs.deleted` then reports N when fewer files were actually unlinked by this run.

**Why it matters**: AC-8 accepts cross-process overlap relying on idempotent deletes, and both runs append audit entries — so the audit trail can show two runs each "deleting" the same files. Counts are the audit's evidence; inflated numbers weaken it. Row stages don't have this problem because `DELETE` `rowcount` reflects actual removals.

**Suggested fix**: Check existence before unlink (or catch `FileNotFoundError` distinctly from other `OSError`) and only increment when this run actually removed the file. `missing_ok=True` already tolerates the race; it just needs to be reflected in the count.

### 🟡 Scheduler `asyncio.Lock` does not do what AC-8 describes, `app/services/maintenance.py:202-206`

**Problem**: The lock is created inside `scheduler_loop` and wraps only the `run_cleanup` call within a single sequential loop that can never overlap with itself — the `await asyncio.sleep(interval)` is outside the lock and the loop is strictly serial. Meanwhile `run_cleanup` itself takes no lock, so two in-process callers (e.g., a test or a future second task) can still overlap, exactly as `test_cleanup_is_idempotent_and_concurrency_safe` demonstrates via `asyncio.gather`.

**Why it matters**: AC-8 says "an `asyncio.Lock` prevents overlapping in process runs." As written the lock is dead code guarding a non-existent hazard, while the actual in-process overlap path is unguarded (safety there rests on idempotent deletes, which the spec also sanctions). Not a runtime bug — the deletes are idempotent — but the mechanism described in the spec and implied by the code isn't real.

**Suggested fix**: Either move the lock to module scope and acquire it inside `run_cleanup` so it genuinely serializes in-process runs, or drop it and amend AC-8/spec text to say in-process safety comes from idempotent deletes like cross-process safety.

## Nits

- ⚪ `app/cli.py:90-96`, stage errors are printed to stderr *after* "cleanup complete" on stdout; consider printing errors before the summary line or flushing order so operators see failures first.
- ⚪ `app/services/maintenance.py:209-211`, the `interval <= 0` re-check inside the loop is unreachable (the value is checked on entry and settings aren't mutated); harmless defensive code.
- ⚪ `app/services/maintenance.py:152`, blob unlink failures are logged with the full path — paths are content hashes so this is safe per the spec's security model, just noting it was considered.

## Strengths

- Delete predicates verified line-by-line against the read paths: `mfa.py:44-46` (live = unconsumed, unexpired, under `CHALLENGE_MAX_ATTEMPTS`) and `sessions.py:67-68` (dead = revoked or expired) — the cleanup mirrors them exactly, including the `<= now` boundary.
- Blob reference handling is correct on the sequential path: `SELECT DISTINCT blob_path`, posix-relative comparison matching `blob_store.py:34`, `*.enc`/`*.enc.tmp` rglob covering the atomic-write temp suffix, missing `UPLOAD_DIR` treated as empty, and all filesystem work pushed through `asyncio.to_thread` per the async discipline rule.
- Test suite is genuinely strong: boundary tests (exact retention cutoff, exact min age), dry-run zero-write verification, all-stages-fail audit entry, CLI exit codes, lifespan start/cancel/disable, and concurrent `asyncio.gather` idempotency — every AC has at least one locking test. `uv run pytest tests/test_maintenance.py tests/test_config.py` → 29 passed.
- `run_cleanup` keeps stage failures out of the audit append path correctly: `AuditChainFork` propagates to the CLI (exit 1) and is contained by `scheduler_loop`'s `except Exception`, matching AC-5/AC-6.

## Test coverage

`TEST_SIGNAL = configured`. Coverage is excellent — all ten ACs map to tests, including the tricky ones (audit-entry-on-total-failure, dry-run audit shape, scheduler disable, CLI argparse). The one gap relative to findings: no test exercises the blob TOCTOU (understandable — it's a timing race), and no test asserts the `deleted` count excludes already-missing files under concurrency. Neither is easily testable without fault injection; flagging for awareness rather than as a coverage failure.
