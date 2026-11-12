# Verify: maintenance and retention · spec 0012 · updated 2026-11-12
_Steps derived from spec 0012 acceptance criteria. `/check verify` runs these; `/test` locks the durable ones._

## Manual

Backend only; all steps are CLI and SQL against the dev database (`uv run python -m app cleanup`, `uv run python -m app cleanup --dry-run`) plus direct row and file inspection. Seed dead and live rows of every kind first (expired and consumed `mfa_challenges`, expired and revoked `sessions`, revoked `document_shares` inside and outside the window, `alerts` open, acknowledged inside and outside the window, acknowledged with NULL `acknowledged_at`, and blob files under `UPLOAD_DIR` referenced, orphaned old, orphaned young, and `.tmp` orphans).

- [x] `uv run python -m app cleanup` → per stage counts print, exit 0; only dead challenges, dead sessions, out of window shares and alerts, and old unreferenced blobs are gone; every live row and young or referenced file survives → AC-1, AC-2, AC-3, AC-9
- [x] `audit_log` gains exactly one `maintenance.cleanup` row per run with `outcome="allowed"`, `target_type="maintenance"`, `target_id` NULL, `actor_username="system"`, `actor_id`/`actor_role` NULL, and `details` shaped `{"dry_run": bool, "stages": {"<stage>": {"deleted": n}}, "errors": {}}`; `audit_log` row count otherwise only grows, never shrinks → AC-4, AC-5
- [x] `uv run python -m app cleanup --dry-run` → same counts printed with "would delete", zero rows and files changed, audit entry records `"dry_run": true` → AC-6
- [x] Boot the app with a small `MAINTENANCE_INTERVAL_SECONDS` → cleanup runs recur and each appends an audit entry; `MAINTENANCE_INTERVAL_SECONDS=0` → no scheduler task → AC-6
- [x] Run cleanup twice back to back → second run reports zero deletions; run two concurrently → combined deletions still correct, both append audit entries → AC-8
- [x] Lower `MAINTENANCE_SHARE_ALERT_RETENTION_DAYS` or `MAINTENANCE_BLOB_MIN_AGE_SECONDS` via env and re-run → the cutoff moves and the newly in scope rows or files are collected → AC-10, value sourcing
- [x] Value sourcing: per stage `deleted` counts equal the DELETE rowcount (or candidate count on dry run, unlink count for blobs); blob candidates come from `rglob` of `UPLOAD_DIR` for `*.enc`/`*.enc.tmp`; referenced set is `SELECT DISTINCT blob_path FROM document_versions`; file age compares `st_mtime` to `now - MAINTENANCE_BLOB_MIN_AGE_SECONDS`; audit actor is the fixed `system` snapshot; CLI prints the same `CleanupReport` → spec value table

## Commands

- [x] `uv run pytest` → all tests pass including `tests/test_maintenance.py` → AC-1 through AC-10
- [x] `uv run ruff check .` and `uv run ruff format --check .` → clean → AC-1 through AC-10

## Acceptance-criteria coverage

- AC-1 … steps 1, 6 · AC-2 … steps 1, 6 · AC-3 … steps 1, 6 · AC-4 … step 2 · AC-5 … step 2 · AC-6 … steps 3, 4 · AC-7 … covered by `test_stage_failure_isolated_and_audited` (per stage sessions and commits) · AC-8 … step 5 · AC-9 … step 1 · AC-10 … steps 1, 6
