# 0013. Audit log export

**Date**: 2026-11-12
**Status**: Accepted

## Summary

Auditors can download a filtered slice of the hash chained audit log as a CSV or JSONL file, using the same filters as the entries endpoint. The export is pinned to a single point in the chain, streamed so memory stays flat, capped by a setting, and the export itself is written back into the audit log. Only the auditor role can do it; every other role is denied and that denial is audited.

## Context

Spec 0006 gave auditors a browsable, verifiable view of the audit log inside the app, and its follow up asked for a way to pull a filtered range out as a file for offline evidence. Scope feature 14 picks this up as the last planned hardening item. The in app verify already exposes `head_hash`, so an exported file plus its recorded head hash lets an auditor prove later that the slice they hold matches a known chain state.

The audit log is the system's tamper evidence. Anything that reads it at volume deserves the same care as the log itself: bounded work per request, a record of who pulled what, and output that survives being opened in a spreadsheet without executing formulas. The entries endpoint already solved filtering, role gating, and rate limiting; the export should reuse those decisions rather than grow a parallel path.

## Requirements

**User stories**:
- As an auditor, I want to export a filtered slice of the audit log as a file so that I can analyze or preserve evidence offline.
- As an auditor, I want every export recorded in the audit log so that pulling evidence is itself accountable.
- As a security officer, I want exports denied for non auditor roles and logged, so that bulk log access cannot happen quietly.

**Acceptance criteria** (the contract, each criterion is IDed and independently checkable):
- **AC-1**: `GET /v1/audit/export` with `format=csv` returns a `text/csv` attachment streamed to the client, rows ordered oldest first by `seq`, with every `audit_log` column present: `seq`, `id`, `occurred_at`, `actor_id`, `actor_username`, `actor_role`, `action`, `outcome`, `target_type`, `target_id`, `details`, `prev_hash`, `hash`.
- **AC-2**: `format=json` returns `application/x-ndjson`, one JSON object per line with the same fields, filters, and ordering as the CSV path. Any other `format` value returns 422.
- **AC-3**: The endpoint accepts the same filters as `GET /v1/audit/entries` (`actor_username`, `action`, `outcome`, `target_type`, `target_id`, `occurred_after`, `occurred_before`) with inclusive time bounds matching `list_entries`, and rejects `occurred_after` later than `occurred_before` with 422. It has no `cursor` or `limit` parameters.
- **AC-4**: Only the `auditor` role may export. `admin` and `user` callers receive the standard role denial, the denial is audited, and the MFA enrollment gate applies to the endpoint like every other gated action.
- **AC-5**: The export is pinned to the chain head captured when it starts: only rows with `seq` at or below that head are exported, so entries appended mid export never appear. The export's audit entry records `head_seq` and `head_hash` for that snapshot.
- **AC-6**: Export stops after `EXPORT_MAX_ROWS` matching rows (default 50000). Truncation is decided before streaming starts by a `COUNT(*)` probe over the same filters and snapshot bound: `truncated = count > EXPORT_MAX_ROWS`. On truncation the response carries `X-Export-Truncated: true` and the audit entry records `truncated: true`; the file itself contains only data rows.
- **AC-7**: Every allowed export appends one `audit.export` entry in its own transaction (via `append_with_retry`) with `target_type="audit_log"` and details covering the filters used, `format`, `rows_exported`, `truncated`, `head_seq`, and `head_hash`. If the client disconnects mid stream the append still runs, with `rows_exported` equal to the rows actually sent.
- **AC-8**: CSV cells are sanitized against spreadsheet formula injection: any data cell whose first character, or first non whitespace character, is `=`, `+`, `-`, `@`, tab, or carriage return is prefixed with a single quote before CSV quoting is applied. The `details` column is serialized as a compact sorted JSON string in CSV and as a nested JSON object in JSONL.
- **AC-9**: A filter combination matching zero rows returns 200 with a headers only CSV or an empty JSONL body, and the audit entry records `rows_exported: 0`.
- **AC-10**: The endpoint is rate limited by `RATE_LIMIT_AUDIT` keyed per session like `POST /v1/audit/verify`, and streaming uses bounded memory regardless of result size.
- **AC-11**: The response is a `Content-Disposition` attachment named `audit-export-<UTC timestamp>.<ext>` where the timestamp uses format `%Y%m%dT%H%M%SZ` and `<ext>` is `csv` or `jsonl`. The CSV body starts with a header row naming the AC-1 columns in the listed order.

## Options considered

### Option 1: Single format endpoint, in memory build

One endpoint that materializes the whole filtered result in memory and returns it as a file, in one format only.

**Pros**:
- Simplest possible code; no streaming machinery.

**Cons**:
- Unbounded memory per request even with a row cap, and picking one format forces a second endpoint or a breaking change later.

### Option 2: Dual format streaming export with snapshot pinning (chosen)

One endpoint, `format` selects CSV or JSONL, rows stream from the database in bounded memory, and the export is pinned to the head seq captured at start.

**Pros**:
- Covers both evidence consumers, constant memory, and a provable point in the chain for offline verification.

**Cons**:
- More moving parts: an async generator, two serializers, and truncation detection via a cap plus one probe row.

### Option 3: Async export job with signed download link

Queue the export, write the file to storage, and email or link a download when ready.

**Pros**:
- Handles arbitrarily large exports and survives client disconnects.

**Cons**:
- Needs a job queue, file storage, and expiry handling for a demo scale audit log; heavy infrastructure for a problem the row cap already bounds.

## Decision

**Chosen option**: Option 2: Dual format streaming export with snapshot pinning.

`GET /v1/audit/export` streams CSV or JSONL for the auditor role, reusing the entries filter logic, pinned to the head seq at start, capped by `EXPORT_MAX_ROWS`, with the export itself appended to the chain.

## Rationale

The scope asks for "a filtered slice of the audit log as a file (CSV or JSON)", and both formats are cheap once the row stream exists, so offering both through one `format` parameter avoids a second endpoint later. Streaming matters because the row cap bounds count, not memory per row, and `details` payloads can be large; an async generator keeps memory flat, and a single `COUNT(*)` probe over the same filters decides truncation before the response headers are sent. Pinning to head seq matters because the log is append only evidence: an export that silently includes rows written after it started is not a clean snapshot, and recording `head_seq`/`head_hash` in the export's own audit entry lets an auditor verify the slice against a known chain state later. The async job option solves a scale this system does not have and would add a queue and storage lifecycle for no current benefit.

## Feature design

**Data model sketch**:
No schema change. The export reads `audit_log` rows and writes exactly one new `audit_log` row per allowed export (`action="audit.export"`, `outcome="allowed"`, `target_type="audit_log"`). Snapshot boundary: `head_seq` is `MAX(seq)` at export start; only rows with `seq <= head_seq` matching the filters are streamed. On an empty log `head_seq` and `head_hash` are recorded as null in the audit details. The export's own entry is appended after streaming, so its `seq` is always greater than `head_seq` and it can never appear inside its own export; a concurrent export's entry can appear if it committed before the head capture, which is intended.

**State transitions** (if applicable):
None. Exports are stateless reads plus one audit append.

**API surface**:
| Endpoint | Method | Key inputs | Key outputs | Auth | Key errors |
|---|---|---|---|---|---|
| /v1/audit/export | GET | format: "csv" \| "json" (req), actor_username, action, outcome, target_type, target_id, occurred_after, occurred_before (opt) | streamed file body, Content-Type per format, Content-Disposition attachment, X-Export-Truncated when capped | auditor role, MFA enrolled, rate limited | 401, 403 (role denial audited), 422 (bad format or inverted range), 429 |

**Value sourcing** (every value each action produces, computes, or displays names where it comes from):
| Action | Value produced / displayed | Source |
|---|---|---|
| export rows | seq through hash columns | `audit_log` columns via filtered select, `seq <= head_seq`, ordered `seq` asc |
| head_seq, head_hash | snapshot boundary and chain proof | `MAX(seq)` row's `seq` and `hash` queried once at export start (tail lookup, not a full `verify_summary` scan) |
| rows_exported | count in audit details | number of rows actually streamed |
| truncated | audit detail and response header | `COUNT(*)` probe over the same filters and `seq <= head_seq` bound run before streaming; `truncated = count > EXPORT_MAX_ROWS` |
| rows streamed | file body | filtered select ordered `seq` asc, `LIMIT EXPORT_MAX_ROWS`, executed via `session.stream()` on the request session held open for the stream's duration |
| EXPORT_MAX_ROWS | row cap | new `Settings` field, env `EXPORT_MAX_ROWS`, default 50000, validated positive |
| filename timestamp | Content-Disposition name | server UTC time at response build |
| audit details filters | echoed filter params | the request query params, canonicalized (unset params omitted) |
| format ext | filename extension and Content-Type | `format` param: csv → `text/csv`, json → `application/x-ndjson` |
| head_seq, head_hash on empty log | audit details | null when `audit_log` has no rows at export start |

**Response shapes** (wire format per field, both formats share the same logical row):
| Field | CSV cell | JSONL value |
|---|---|---|
| seq, prev_hash, hash | decimal / hex string | number / string |
| id, actor_id | UUID string, empty cell when null | string / null |
| occurred_at | ISO 8601 UTC with `Z` suffix | same string |
| actor_username, actor_role, action, outcome, target_type, target_id | raw string, empty cell when null | string / null |
| details | compact sorted JSON string (`separators=(",", ":")`, `ensure_ascii=False`), empty cell when null, sanitized per AC-8 | nested JSON object / null |

**Key invariants**:
- Deny by default: only `auditor` reaches the export path; the role check runs through `require_role` with a new `GATE_ACTIONS` entry `audit.export`, so denials are audited like every other gate.
- The export's audit entry is appended via `append_with_retry` in its own transaction, and the append is guaranteed to run even when the client disconnects mid stream: the generator counts rows actually yielded and the append records that partial `rows_exported` with the pre computed `truncated` flag.
- Truncation and the `X-Export-Truncated` header are decided by the `COUNT(*)` probe before the response starts, so headers are never rewritten mid stream.
- The export never mutates `audit_log` except its own appended entry; no stored export files exist anywhere.
- Filter semantics match `list_entries` exactly; the shared where clause builder is reused, not duplicated.
- CSV output is sanitized per AC-8; JSONL output writes the `details` dict as a nested JSON object, not a string.

**Security model**:
Auditor role only, same trust level as the existing entries and verify endpoints, so it reuses `RATE_LIMIT_AUDIT` and the per session key function (the existing `_verify_key` helper is renamed to `_session_key` and shared). The export exposes the same data auditors already browse, at higher volume, which is why the row cap and the audited export entry exist. CSV formula injection is mitigated because audit fields can carry user controlled text (usernames, target ids, details). The alert classifier is deliberately unchanged: `audit.*` actions are excluded from the denied prefix set by design (spec 0010), so export attempts, allowed or denied, raise no alerts; whether export volume or denials should alert is a follow up. No compliance scope beyond the audit trail integrity the project already claims; the exported `prev_hash`/`hash` columns keep offline tamper evidence intact.

**Configuration required**:
- `EXPORT_MAX_ROWS`: maximum rows per export, default 50000, must be a positive integer; bounds work per request.

**Critical test scenarios** (each maps to an acceptance criterion in ## Requirements):
- Happy path: auditor exports a CSV with two filters over seeded entries, verify streamed body parses, row order is `seq` ascending, all columns present, and one `audit.export` entry exists with matching details, verifies **AC-1**, **AC-3**, **AC-7**
- JSON path: same export with `format=json` yields valid JSONL with identical rows, and `format=xml` returns 422, verifies **AC-2**
- Snapshot: append a new audit entry while an export streams (or between head capture and read), verify the late row is absent and `head_seq`/`head_hash` in the audit entry match the pre export tail, verifies **AC-5**
- Cap: configure a tiny `EXPORT_MAX_ROWS`, seed more matches, verify the body stops at the cap, `X-Export-Truncated: true` is present, and `truncated: true` lands in the audit details, verifies **AC-6**
- Disconnect: abort the response mid stream, verify an `audit.export` entry still exists with `rows_exported` below the match count, verifies **AC-7**
- Auth: `admin` and `user` callers get the role denial and an audited denied entry; an auditor without MFA enrollment is gated, verifies **AC-4**
- Injection: seed an actor username starting with `=`, export CSV, verify the cell is quote prefixed and details round trips as JSON, verifies **AC-8**
- Empty and invalid: filter matching nothing returns 200 with headers only / empty body and `rows_exported: 0`; `occurred_after` after `occurred_before` returns 422, verifies **AC-3**, **AC-9**
- Rate limit: exceed `RATE_LIMIT_AUDIT` on the export route and verify 429, verifies **AC-10**

## Build plan

Ordered as thin end to end slices per the project's Tracer Bullet approach: the first task lands a working audited CSV export through every layer before the second format joins.

1. [x] Add the `EXPORT_MAX_ROWS` setting, extract the shared audit filter where clause from `list_entries`, and add `export_entries` in `services/audit.py`: capture `head_seq`/`head_hash` via a tail lookup, run the `COUNT(*)` truncation probe, then stream rows `seq <= head_seq` ordered ascending with `LIMIT EXPORT_MAX_ROWS` via `session.stream()` on the request session. Wire `GET /v1/audit/export` in `api/audit.py` with the `format` param (csv first), the same filter params, `require_role("audit.export", AUDITOR)`, the `GATE_ACTIONS` entry, the `_session_key` rate limit (renamed from `_verify_key`), CSV serialization with AC-8 sanitization and the response shapes table, `Content-Disposition` filename, `X-Export-Truncated` header, and the `audit.export` append via `append_with_retry` guaranteed on generator exit including client disconnect. Satisfies **AC-1**, **AC-3**, **AC-4**, **AC-5**, **AC-6**, **AC-7**, **AC-8**, **AC-10**, **AC-11**
2. [x] Add the `format=json` path: JSONL serializer emitting one object per row (nested `details` object), `application/x-ndjson` content type, `.jsonl` filename extension. Satisfies **AC-2**, **AC-9**
3. [x] Full test suite on in memory SQLite covering every critical scenario above, including Postgres portable query shapes. Satisfies all ACs

## Consequences

**Positive**:
- Auditors get portable evidence that keeps the hash columns needed for offline chain verification, closing the spec 0006 follow up.
- The export is itself chained evidence: who pulled which slice, under which filters, against which head hash, is recorded in the same tamper evident log.
- Streaming plus the row cap bounds memory and per request work without new infrastructure.

**Negative / tradeoffs**:
- A capped export silently drops rows beyond the cap from the file; only the response header and audit entry reveal it, so an auditor who ignores both could mistake a truncated file for complete evidence.
- CSV sanitization prefixes some cells with a quote, so byte level fidelity of those cells differs from the stored values (the JSONL format remains exact).
- Each export costs one `COUNT(*)` plus one filtered scan up to the cap; on a very large log a broad unfiltered export is the most expensive auditor action in the system, bounded only by `EXPORT_MAX_ROWS` and the audit rate limit.
- A slow client holds the request's DB session and connection open for the whole download; the rate limit bounds frequency, not duration. Acceptable at demo scale.

**Neutral**:
- No migration, no new tables, no stored files; the only persistence is the `audit.export` audit row itself.
- `GATE_ACTIONS` gains `audit.export`, matching the existing gate pattern for auditor actions.
- One new settings field (`EXPORT_MAX_ROWS`) with compose passthrough if the demo stack should tune it.

## Follow-up

- [ ] Consider feeding export volume and denied export attempts into the alerts classifier; `audit.*` actions are currently excluded from alerting by design (spec 0010), so bulk log pulls are only visible by reading the log.
