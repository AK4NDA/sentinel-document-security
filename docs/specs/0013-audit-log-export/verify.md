# Verify: audit log export (spec 0013)

Run against a live instance (compose demo stack or `uv run uvicorn app.main:app`) with an MFA enrolled auditor session and at least a handful of audit rows present. Each step names the acceptance criterion it proves.

## Steps

- **AC-1, AC-11 (CSV shape)**: as auditor, `GET /v1/audit/export?format=csv` → 200, `Content-Type: text/csv`, `Content-Disposition` attachment named `audit-export-<UTC timestamp>.csv`, first row equals the 13 column list (`seq, id, occurred_at, actor_id, actor_username, actor_role, action, outcome, target_type, target_id, details, prev_hash, hash`), `seq` ascending, every `occurred_at` ends in `Z`.
- **Value sourcing (filters)**: repeat with `actor_username=<known user>` and `action=auth.login` → every exported row matches the filter; an unfiltered export's row count agrees with `GET /v1/audit/entries` totals. Proves filter values come from the query params.
- **AC-2 (JSONL)**: `format=json` → `Content-Type: application/x-ndjson`, `.jsonl` filename, one JSON object per line, `details` a nested object or null; `format=xml` → 422.
- **AC-3 (filter parity)**: `occurred_after` later than `occurred_before` → 422; passing `cursor`/`limit` still returns 200 (not export params, ignored).
- **AC-4 (roles)**: admin and user sessions → 403, and `GET /v1/audit/entries?action=audit.export&outcome=denied` shows the audited denials; an auditor without MFA enrollment → 403 `mfa enrollment required`.
- **AC-5 (snapshot)**: note `head_seq`/`head_hash` on the newest `audit.export` entry; run a second export → the file contains the first export's audit row, never its own, and every `seq` is at or below the recorded `head_seq`.
- **AC-6 (cap)**: set `EXPORT_MAX_ROWS=5`, restart, export → `X-Export-Truncated: true` header, exactly 5 data rows, audit detail `truncated: true` and `rows_exported: 5`.
- **AC-7 (self audit)**: after any export, `GET /v1/audit/entries?action=audit.export` shows one `allowed` row with `target_type="audit_log"` and details covering `filters`, `format`, `rows_exported`, `truncated`, `head_seq`, `head_hash`.
- **AC-8 (CSV injection)**: with an audit row whose `actor_username` begins `=`, the CSV cell starts with a single quote; the `details` cell still parses as JSON.
- **AC-9 (empty)**: `action=no.such.action` → CSV returns headers only, JSONL returns an empty body, audit detail `rows_exported: 0`.
- **AC-10 (rate limit)**: with `RATE_LIMIT_AUDIT=2/minute`, the third export within a minute → 429.

## Results

Run live on 2026-11-12 against `uv run uvicorn app.main:app` with a seeded SQLite database (`data/verify_export.db`) and the demo users, driven by `data/verify_export.py` plus `data/verify_export_cap.py`. Phase A ran with default settings (35 checks); phase B restarted the server with `EXPORT_MAX_ROWS=5 RATE_LIMIT_AUDIT=2/minute` (5 checks).

- **AC-1, AC-11**: PASS. CSV 200, `text/csv; charset=utf-8`, attachment filename `audit-export-20261112T211601Z.csv`, exact 13 column header, `seq` ascending across 45 rows, `occurred_at` values end in `Z`, `details` parses as JSON.
- **Value sourcing**: PASS. `actor_username` filter returned only matching rows, combined `actor_username`+`action`+`outcome` filters ANDed correctly, `cursor`/`limit` query params accepted and ignored.
- **AC-2**: PASS. `format=json` → 200 `application/x-ndjson`, `.jsonl` filename, one object per line, `details` nested object, `occurred_at` ends in `Z`; `format=xml` → 422.
- **AC-3**: PASS. Inverted `occurred_after`/`occurred_before` → 422.
- **AC-4**: PASS. Admin and user sessions → 403, denials audited with `actor_username` of each caller. A newly created unenrolled auditor logged in, export → 403 `mfa enrollment required`, and the denied `audit.export` entry was present.
- **AC-5**: PASS. A second export contained the first export's `audit.export` row (seq 55 inside snapshot), excluded its own row, and every exported `seq` was at or below the recorded `head_seq`.
- **AC-6**: PASS (phase B). `X-Export-Truncated: true`, exactly 5 data rows, audit detail `truncated: true`, `rows_exported: 5`, `head_seq`/`head_hash` recorded.
- **AC-7**: PASS. `audit.export` allowed entry carried `target_type="audit_log"` and details with `filters`, `format`, `rows_exported`, `truncated`, `head_seq`, `head_hash`.
- **AC-8**: PASS. Cells for `actor_username` `'=1+1` and `' =cmd` (leading whitespace) were prefixed with a single quote; the `details` cell still parsed as JSON.
- **AC-9**: PASS. `action=no.such.action` → CSV headers only, JSONL empty body, both 200, audit detail `rows_exported: 0`.
- **AC-10**: PASS (phase B). With `RATE_LIMIT_AUDIT=2/minute`, export status codes were `[200, 429, 429]`.

40/40 live checks passed. Client disconnect mid stream was covered by unit test only (the `finally` append path); not exercised against the live server.
