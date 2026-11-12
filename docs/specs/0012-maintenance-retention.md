# 0012. Maintenance and retention job

**Date**: 2026-11-12
**Status**: In Progress

## Summary

The system currently keeps dead data forever: spent MFA challenges, expired or revoked sessions, old revoked shares and acknowledged alerts, and encrypted files left behind when documents are deleted. This spec adds one cleanup job that sweeps all of them on an hourly schedule and on demand from the command line, records each run in the audit log, and never touches live data or the audit chain itself.

## Context

Every feature so far writes rows and files but nothing ever removes them. `mfa_challenges` rows past `expires_at` or marked `consumed_at` are filtered at read time in `services/mfa.py` but never deleted. `sessions` rows past `expires_at` or with `revoked_at` set are likewise only filtered in `services/sessions.py`. Document deletes cascade `document_versions` rows but the AES-GCM blob files under `UPLOAD_DIR` stay on disk, and version restores deliberately share `blob_path` values, so blob collection must dedupe references across every `document_versions` row, not just current versions. Revoked `document_shares` and acknowledged `alerts` rows also accumulate with no bound.

There is no scheduler or background task in the app today: `main.py` lifespan only manages the engine, and `pyproject.toml` carries no job dependency. The CLI in `app/cli.py` already offers operator commands (`create-admin`, `seed-demo`), which is the natural home for a manual run. The audit log is append only and hash chained, so its retention is a separate, harder decision that this spec explicitly leaves alone.

Scope feature 13 asks for exactly this: expired challenges and orphaned blobs removed by a defined mechanism, the cleanup itself audited or logged, and no live data ever collected.

## Requirements

**User stories**:
- As an operator, I want expired challenges, dead sessions, old shares, old alerts, and orphaned blobs removed automatically so that the database and upload volume stay bounded without manual work.
- As an operator, I want to run the same cleanup by hand with a dry run option so that I can preview what would be deleted before it happens.
- As an auditor, I want every cleanup run recorded in the audit log with per stage counts so that deletions are part of the tamper evident trail.

**Acceptance criteria** (the contract, each criterion is IDed and independently checkable):
- **AC-1**: A cleanup run deletes every `mfa_challenges` row that is consumed, expired, or at the attempt limit (mirroring the read path's dead definition), and every `sessions` row that is expired or revoked. Unexpired, unconsumed, under limit, unrevoked rows survive.
- **AC-2**: A cleanup run deletes `document_shares` rows whose `revoked_at` is at or beyond the configured retention window and `alerts` rows in state `acknowledged` whose `acknowledged_at` is at or beyond the same window. Open alerts, unrevoked shares, rows inside the window, and acknowledged alerts with NULL `acknowledged_at` survive.
- **AC-3**: A cleanup run deletes blob files under `UPLOAD_DIR` that are not referenced by any `document_versions.blob_path` across all versions and whose age is at or beyond the configured minimum. Referenced files are never deleted, including `.tmp` files orphaned by failed atomic writes once they age past the minimum. The scan matches `*.enc` and `*.enc.tmp` filenames in the two level shard directories; a missing `UPLOAD_DIR` counts as an empty candidate set.
- **AC-4**: No stage ever deletes `audit_log` rows.
- **AC-5**: Each run, scheduled or manual, appends exactly one `maintenance.cleanup` audit entry with `outcome="allowed"`, `target_type="maintenance"`, `target_id=None`, `actor_username="system"` (actor id and role NULL), and `details` shaped as `{"dry_run": bool, "stages": {"<stage>": {"deleted": n}}, "errors": {"<stage>": "<message>"}}`, JSON safe values only. The entry is appended even when individual stages fail, with per stage errors noted in `details`. If the audit append itself fails after the existing fork retries, the failure is logged via structlog and the CLI exits nonzero.
- **AC-6**: Cleanup runs two ways: an asyncio task started in the app lifespan on `MAINTENANCE_INTERVAL_SECONDS` (default 3600, 0 disables the loop) that runs once at startup then sleeps between runs, is cancelled and awaited on shutdown, and contains its own exceptions; and a `python -m app cleanup` CLI command with a `--dry-run` flag that reports the same per stage counts without deleting anything. Exit code is 0 when the run completes even with stage errors, 1 if the run cannot start or the audit append fails.
- **AC-7**: Stages are independent: each stage runs in its own `AsyncSession` and commits separately, and a failure in one stage is logged, recorded in the audit entry, and does not roll back or block the remaining stages.
- **AC-8**: Cleanup is idempotent and safe under overlap: repeated or concurrent runs delete nothing extra, file deletions tolerate already missing files, an `asyncio.Lock` prevents overlapping in process runs (cross process overlap relies on the idempotent deletes), and the audit append uses the existing chain fork retry.
- **AC-9**: No live data is ever collected: sessions not yet expired and not revoked, challenges not yet expired, not consumed, and under the attempt limit, shares not revoked or inside the window, alerts open or inside the window, and blobs younger than the minimum age or referenced by any version row all survive.
- **AC-10**: Retention windows are configurable through `Settings` env vars with the defaults and validators in the Configuration section (`maintenance_interval_seconds` `ge=0`, the two retention settings `gt=0`), all deletes pass an aware `datetime.now(UTC)` so SQLite and Postgres compare identically, and all behavior is verified on the in memory SQLite test database.

## Options considered

### Option 1: In app asyncio scheduler plus CLI command

A `services/maintenance.py` module exposes `run_cleanup`, an asyncio task in the `main.py` lifespan invokes it every `MAINTENANCE_INTERVAL_SECONDS`, and `python -m app cleanup` runs the same function once with an optional `--dry-run`. No new dependencies.

**Pros**:
- Self contained: the demo compose stack runs the scheduler with zero extra wiring, and the CLI matches the existing `create-admin` and `seed-demo` pattern.
- One code path serves scheduled, manual, dry run, and test invocation.

**Cons**:
- An in process loop is less observable than an external scheduler and only runs while the API process is up.
- Overlapping runs across processes rely on idempotent deletes rather than a lock.

### Option 2: CLI command only, scheduled externally

Ship `python -m app cleanup` and let cron or a compose sidecar service reusing the image drive the schedule.

**Pros**:
- No background work inside the API process; scheduling is an ops concern.
- The sidecar can mount the same `upload-data` volume safely since blob paths are content addressed.

**Cons**:
- The demo never shows retention working unless compose gains a second service, and scheduling silently does nothing if ops forgets to wire it.
- Two places to configure (image env plus scheduler) for one job.

### Option 3: Admin API endpoint

An admin only `POST /v1/maintenance/cleanup` endpoint triggers a run on demand.

**Pros**:
- Ops can trigger cleanup from the same authenticated surface as everything else, with the caller recorded as the audit actor.

**Cons**:
- On demand only: nothing cleans up unless someone remembers, which fails the scope goal of bounded growth.
- Adds an authenticated mutation surface, rate limit and gate action entries, for a job that is really infrastructure.

### Option 4: Lazy retention at read time

Delete dead rows opportunistically whenever they are read (expired sessions on validate, old challenges on create).

**Pros**:
- No scheduler, no CLI, no new surface at all.

**Cons**:
- Rows for users who never return are never collected, and blob files have no read path to hang cleanup on, so orphans still accumulate forever.

## Decision

**Chosen option**: Option 1: In app asyncio scheduler plus CLI command

One `run_cleanup` service drives an hourly in process loop (disable with `MAINTENANCE_INTERVAL_SECONDS=0`) and a `python -m app cleanup [--dry-run]` command, giving the demo automatic cleanup and operators a manual, previewable path with no new dependencies or services.

**Implementation skills**: `async-python-patterns` (`.agents/skills/async-python-patterns/`) · `sqlalchemy` (`.agents/skills/sqlalchemy/`) · `structlog-python` (`.agents/skills/structlog-python/`) · `pytest-asyncio-patterns` (`.agents/skills/pytest-asyncio-patterns/`)

## Rationale

Option 1 is the only choice that makes retention actually happen by default: the scheduler runs inside the existing container with no compose changes, while the CLI covers manual runs, dry runs, and tests through the same code path. Option 2 pushes a required behavior into ops configuration that the demo and a fresh deploy would silently lack. Option 3 solves triggering but not scheduling, and buys an authenticated endpoint for what is infrastructure work. Option 4 cannot collect blobs at all and leaves rows for inactive users behind forever.

The audit log stays untouched because it is the product's core tamper evident guarantee; retention there would need chain re anchoring and is a separate decision. Per artifact env settings beat a global window because sessions and challenges die on their own expiry while shares, alerts, and blobs need real age cutoffs. Deleting dead rows as soon as they are dead is safe because every read path already filters them, and the blob minimum age covers the window between `blob_store.store` writing a file and the version row committing.

## Feature design

**Data model sketch**:
No new tables and no migration. The job reads and deletes from existing tables only: `mfa_challenges` (`consumed_at`, `expires_at`), `sessions` (`expires_at`, `revoked_at`), `document_shares` (`revoked_at`), `alerts` (`state`, `acknowledged_at`), `document_versions` (`blob_path`), and the filesystem under `UPLOAD_DIR`. `audit_log` is never deleted from.

**State transitions** (if applicable):
None. Cleanup is a stateless sweep; there is no lifecycle on the job itself beyond run start and finish.

**API surface**:
No HTTP endpoints. The surface is internal and operational:

| Surface | Kind | Key inputs | Key outputs | Auth | Key errors |
|---|---|---|---|---|---|
| `services/maintenance.py::run_cleanup` | async function | `session_factory` (the app `SessionLocal`, injectable for tests), `settings`, `dry_run: bool` | `CleanupReport` (`dry_run`, per stage `deleted` counts, per stage error strings) | n/a (in process) | per stage exceptions captured into the report, never raised past the run |
| `python -m app cleanup` | CLI subcommand | `--dry-run` flag | per stage counts printed; exit code 0 on completed run even with stage errors, 1 if the run cannot start or the audit append fails | operator local | argparse usage errors |
| lifespan scheduler task | asyncio task | `MAINTENANCE_INTERVAL_SECONDS` | periodic `run_cleanup` calls | n/a | logged via structlog, task never crashes the app |

**Value sourcing** (every value each action produces, computes, or displays names where it comes from):
| Action | Value produced / displayed | Source |
|---|---|---|
| run_cleanup | per stage deleted counts | SQL `rowcount` of each stage's DELETE (or the matched row count in dry run), or filesystem unlink count for blobs (candidate count in dry run) |
| run_cleanup | blob candidate set | `rglob` scan of `UPLOAD_DIR` for `*.enc` and `*.enc.tmp` files |
| run_cleanup | referenced blob paths | `SELECT DISTINCT blob_path FROM document_versions` |
| run_cleanup | blob file age | file `st_mtime` compared to `now - MAINTENANCE_BLOB_MIN_AGE_SECONDS` |
| audit entry | outcome and target | fixed values: `outcome="allowed"`, `target_type="maintenance"`, `target_id=None` |
| audit entry | actor | fixed system snapshot: `actor_username="system"`, `actor_id=None`, `actor_role=None` |
| audit entry | details | `CleanupReport` serialized to the JSON shape pinned in AC-5 |
| CLI output | printed counts | the same `CleanupReport` |
| scheduler | run interval | `settings.maintenance_interval_seconds` |

**Key invariants**:
- A blob file referenced by any `document_versions.blob_path` is never deleted, even across document deletes that cascade version rows (restores share paths, so the reference set is the union over all remaining rows).
- `audit_log` rows are never deleted by any stage, preserving chain verifiability.
- Live rows are never collected: the delete predicates are exactly the dead predicates (consumed or expired challenge, expired or revoked session, share revoked beyond window, alert acknowledged beyond window).
- `dry_run` performs zero writes: no row deletes, no file unlinks, and the audit entry records `dry_run: true` with the counts that would have been deleted.
- Each stage commits independently; the audit entry commits in its own transaction after all stages, using `append_with_retry` so `AuditChainFork` retries apply.
- Deletes use portable SQLAlchemy `delete()` statements that run identically on SQLite and Postgres, always comparing against an aware `datetime.now(UTC)`.
- The challenge delete predicate mirrors the read path exactly: `consumed_at IS NOT NULL OR expires_at <= now OR attempts >= CHALLENGE_MAX_ATTEMPTS`.
- Blob candidates are found by `rglob` over `UPLOAD_DIR` matching `*.enc` and `*.enc.tmp` (the atomic write temp suffix), and a file is referenced when `path.relative_to(upload_dir).as_posix()` equals any `document_versions.blob_path`.
- Dry run performs zero writes but still produces counts: row stages report the rows their DELETE would match, the blob stage reports the candidate count.
- Each stage gets its own `AsyncSession` from the injected session factory so a failed stage's rollback cannot poison the others; the audit entry goes through `audit.append_with_retry`, which manages its own sessions.

**Security model**:
No new HTTP surface and no new authenticated roles: the CLI is operator local like `create-admin`, and the scheduler is in process. The audit entry carries counts and stage error strings only, never file contents, secrets, or `MASTER_KEY` material. Blob paths are content hashes and safe to count but are not written to audit details beyond aggregate numbers.

**Configuration required**:
- `MAINTENANCE_INTERVAL_SECONDS`: seconds between scheduled runs, default 3600, validator `ge=0`; 0 disables the lifespan task entirely.
- `MAINTENANCE_SHARE_ALERT_RETENTION_DAYS`: days a revoked share or acknowledged alert is kept before cleanup, default 90, validator `gt=0`.
- `MAINTENANCE_BLOB_MIN_AGE_SECONDS`: minimum file age before an unreferenced blob may be collected, default 3600, validator `gt=0` (0 would expose the store to commit gap races).

Sessions and challenges need no window setting: they are collected the moment they are dead, because every read path already treats them as unusable.

**Critical test scenarios** (each maps to an acceptance criterion in ## Requirements):
- Happy path: seed expired and live rows of every kind plus an orphaned and a referenced blob, run `run_cleanup`, verify only the dead set is gone and one `maintenance.cleanup` audit entry exists, verifies **AC-1**, **AC-2**, **AC-3**, **AC-5**
- Failure case: force one stage to raise (for example a monkeypatched blob scan), verify the other stages still commit, the audit entry records the stage error, and the run reports partial success; separately force `append_with_retry` to exhaust and verify the CLI exits 1, verifies **AC-5**, **AC-7**
- Dry run: run with `dry_run=True`, verify zero rows and files changed while the report and audit entry still show the would be counts, verifies **AC-6**, **AC-9**
- Idempotency: run cleanup twice back to back and concurrently via `asyncio.gather`, verify the second run deletes nothing and no error surfaces, verifies **AC-8**
- Scheduler: boot the app with a tiny `MAINTENANCE_INTERVAL_SECONDS` in tests (or call the loop helper directly), verify runs recur and `0` disables the task, verifies **AC-6**
- Boundary: a session expiring exactly now, a share revoked exactly at the window edge, and a blob exactly at min age follow the specified predicates, verifies **AC-9**, **AC-10**

## Build plan

Ordered as thin end to end slices per the project's Tracer Bullet approach: each task lands a working vertical piece (service logic plus its trigger) before the next artifact type joins.

1. [x] Add the three `Settings` fields (with the validators above) and `services/maintenance.py` with `run_cleanup` covering the dead row stages (`mfa_challenges`, `sessions`) in per stage sessions and commits, a `CleanupReport`, and the `maintenance.cleanup` audit entry via `append_with_retry` with the pinned field values; wire the `python -m app cleanup` CLI subcommand with `--dry-run` and the exit code rules. Satisfies **AC-1**, **AC-4**, **AC-5**, **AC-6**, **AC-7**, **AC-8**, **AC-9**, **AC-10**
2. [x] Add the shares and alerts retention stage using `MAINTENANCE_SHARE_ALERT_RETENTION_DAYS`. Satisfies **AC-2**, **AC-9**, **AC-10**
3. [x] Add the blob collection stage: scan `UPLOAD_DIR`, load the distinct `blob_path` reference set, delete only unreferenced files older than `MAINTENANCE_BLOB_MIN_AGE_SECONDS`, tolerating missing files. Satisfies **AC-3**, **AC-8**, **AC-9**
4. [x] Add the lifespan scheduler task honoring `MAINTENANCE_INTERVAL_SECONDS` (0 disables): create the task before yield, run once at startup then loop with sleep, `task.cancel()` plus `asyncio.gather(..., return_exceptions=True)` on shutdown before `engine.dispose()`, keep the `asyncio.Lock` single flight, log stage failures via structlog without killing the loop, and add compose env passthrough for the new settings. Satisfies **AC-6**, **AC-8**, **AC-10**
5. [x] Full test suite on in memory SQLite covering every critical scenario above, including Postgres portable query shapes. Satisfies all ACs

## Consequences

**Positive**:
- Database tables and the upload volume stay bounded with zero operator effort; the demo stack self cleans.
- Every deletion is part of the hash chained audit trail, strengthening the tamper evidence story rather than bypassing it.
- One `run_cleanup` serves scheduler, CLI, dry run, and tests, so behavior cannot drift between paths.

**Negative / tradeoffs**:
- An in process scheduler only runs while the API is up; a long downtime simply delays cleanup, which is acceptable for retention but worth knowing.
- Cross process overlap (CLI while the scheduler fires) is handled by idempotent deletes rather than a lock, so two runs can race harmlessly but both append audit entries.
- The blob stage re-verifies each candidate (fresh reference query plus fresh mtime) immediately before unlinking, and `blob_store.store` refreshes mtime on dedup claims, so a blob claimed mid run survives. A claim landing inside the final stat-to-unlink syscall gap can still slip through; closing that fully would need a lock shared with `store`, judged not worth the complexity for a sub millisecond window.
- Stage errors are recorded but do not page anyone; a persistently failing stage is visible only in the audit log and logs until alerting covers it.

**Neutral**:
- No schema migration is needed; the feature is purely service, CLI, lifespan, config, and tests.
- `docker-compose.yml` gains env passthrough lines for the three new settings but no new services.
- The audit log grows by exactly one entry per run (hourly by default), a negligible addition.

## Follow-up

- [ ] Audit log retention is deliberately out of scope: deleting chain entries requires re anchoring design and deserves its own spec if ever needed.
- [ ] Consider wiring repeated `maintenance.cleanup` stage failures into the alerts classifier in a later feature, since stage errors currently only surface in logs and the audit entry.
