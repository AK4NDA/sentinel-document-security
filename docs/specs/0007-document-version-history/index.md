# 0007. Document version history

**Date**: 2026-11-09
**Status**: In Progress

## Summary

This completes the version history story that spec 0003 started. Today the system already keeps every version a document ever had, but there is no way to look at them: this spec adds a version list, download of an older version's content, and restore of an older version. Restore never rewrites history; it appends a new version that copies the old content, so the chain of custody stays intact. Access is decided per version: each version carries its own classification, and a caller only sees versions at or below their clearance.

## Requirements

**User stories**:
- As a document owner, I want to list every version of my document so that I can see what changed and who changed it.
- As a cleared reader, I want to download an older version's content so that I can inspect or compare history.
- As a document owner, I want to restore an earlier version so that I can roll back a bad edit without losing the versions in between.
- As the system owner, I want every version event audited and every version protected by its own classification so that history cannot be browsed or rewritten around the policy engine.

**Acceptance criteria** (the contract, each criterion is IDed and independently checkable):
- **AC-1**: `GET /v1/documents/{doc_id}/versions` returns 200 for a caller with read access to the document, with entries ordered `version_number` descending. Each entry carries `version_number`, `classification`, `size_bytes`, `mime_type`, `created_by` (username), `created_at`, and `is_current`. The response wraps entries in a `versions` list; there is no pagination.
- **AC-2**: Versions whose `classification` exceeds the caller's clearance are omitted from the list entirely; their existence, classification, and authorship are never revealed.
- **AC-3**: A caller whose clearance is below the current version's classification receives 403 on the list endpoint with an audited denial under action `document.versions_list`. Admin and auditor roles receive 403 on all three new endpoints with audited role denials, and the MFA enrollment gate applies.
- **AC-4**: `GET /v1/documents/{doc_id}/versions/{version_number}/content` returns the decrypted bytes of that version as an `attachment` response with the same `Content-Disposition` filename convention as current content download, but only when the caller can read the document (clearance at least the current version's classification) AND the target version's classification is at most the caller's clearance. `content_sha256` is verified after decryption; a mismatch returns 500 with an audited `integrity_mismatch` denial.
- **AC-5**: Version content requests are denied with 403 and an audited `document.version_download` denial when the target version's classification exceeds the caller's clearance or the document itself is unreadable. An unknown `version_number` returns 404; a missing or unreadable document returns 404 for non owners and 403 for owners per the existing read rule.
- **AC-6**: `POST /v1/documents/{doc_id}/versions/{version_number}/restore` by the document owner creates a new `document_versions` row with `version_number = max + 1`, `classification` equal to the restorer's clearance, `created_by` equal to the restorer, and `content_sha256`, `blob_path`, `size_bytes`, `mime_type`, `key_id`, and `key_version` copied from the source version. `documents.current_version_id` moves to the new version, `documents.updated_at` is bumped, the response is 201 `DocumentMeta`, and exactly one `document.version_restore` audit entry is appended in the same transaction with details carrying the source and new version numbers.
- **AC-7**: Restore checks run in this order: document fetch, then owner or existence 404 (`not_owner_or_missing`, matching `edit`), then the document read gate 403 (`clearance`), then source version lookup 404, then source version clearance 403, then the already current check. Restore returns 409 when the target version is already current (checked inside the transaction against the re-fetched document), 404 when the caller is not the owner or the version does not exist, 403 with an audited denial when the document read gate or the source version's classification fails, and 409 on a `(document_id, version_number)` unique conflict from a concurrent edit or restore. Both 409 paths are unaudited, matching the existing `edit` conflict behavior.
- **AC-8**: All prior versions remain listed and downloadable after a restore, each still governed by its own classification; the restored copy appears as a new highest `version_number` with `is_current` true.
- **AC-9**: Successful list, version download, and restore calls each append exactly one audit entry (`document.versions_list`, `document.version_download`, `document.version_restore`); every denial is audited under the same action name as the attempted operation.
- **AC-10**: Admin, auditor, and unenrolled MFA callers are rejected on all three endpoints before any document logic runs, with the rejections audited under the endpoint's action name via `GATE_ACTIONS` and `require_role`.

## Decision

**Chosen option**: Option 1: Append only history with per version access.

Add three endpoints to the existing documents router: a filtered version list, a per version content download, and a restore that appends a new version copying the source row's content fields. Access is two gated checks: the caller must be able to read the document (clearance at least the current version's classification), and each version is additionally protected by its own classification. Restore is owner only and requires the caller to be able to read the source version.

**Implementation skills**: `fastapi` (`fastapi/fastapi`, `.agents/skills/fastapi/`) · `sqlalchemy` (`TerminalSkills/skills`, `.agents/skills/sqlalchemy/`) · `pytest-asyncio-patterns` (`testland/qa`, `.agents/skills/pytest-asyncio-patterns/`)

## Feature design

**Data model sketch**:
No schema changes and no migration. The existing `document_versions` table supplies every field: `version_number` (unique per document), `classification`, `content_sha256`, `blob_path`, `size_bytes`, `mime_type`, `key_id`, `key_version`, `created_by`, `created_at`. `documents.current_version_id` continues to point at the live version. A restore is a plain insert into `document_versions` plus a pointer move on `documents`, identical in shape to what `edit` already does.

**API surface**:
| Endpoint | Method | Key inputs | Key outputs | Auth | Key errors |
|---|---|---|---|---|---|
| /v1/documents/{doc_id}/versions | GET | doc_id:uuid path | VersionListResponse: versions[] of VersionMeta | officer session + document read | 401, 403, 404 |
| /v1/documents/{doc_id}/versions/{version_number}/content | GET | version_number:int path, positive | attachment bytes, Content-Disposition filename | officer session + document read + version clearance | 401, 403, 404, 500 |
| /v1/documents/{doc_id}/versions/{version_number}/restore | POST | version_number:int path, positive; no body | DocumentMeta, 201 | owner session + can read source version | 401, 403, 404, 409 |

`version_number` path parameters must be positive integers via `Path(ge=1)`; 0, negative, or non integer values return 422. `VersionMeta`: `version_number:int`, `classification:int`, `size_bytes:int`, `mime_type:str`, `created_by:str` (username), `created_at:ISO 8601`, `is_current:bool`. `VersionListResponse`: `versions:VersionMeta[]` ordered `version_number` descending, filtered to versions at or below the caller's clearance.

**Audited action vocabulary** (new `action` values): `document.versions_list`, `document.version_download`, `document.version_restore`. Allowed and denied attempts are both audited; list success is audited like `document.list` today. All three actions use `target_type="document"` and `target_id=<doc_id>`, including the list success row (unlike `document.list`, which has no target, these are per document events). `details` carries `version_number` for download and restore, and `source_version_number` plus `version_number` (the new row) for restore; denial rows carry the same `version_number` where a version was named. Both restore 409 paths are unaudited, matching `edit`. All three routes get `GATE_ACTIONS` entries so the MFA enrollment gate audits under the right name, and `require_role` uses the officer role like the other document routes.

**Denial vocabulary** (status, reason, details keys; consistent with existing `edit`/`read_content` reasons):
| Failure | Status | Reason | Details |
|---|---|---|---|
| document missing or not owner (restore) | 404 | `not_owner_or_missing` | `version_number` when named |
| document missing (list, download) | 404 | `not_found` | none |
| document read gate fails (clearance below current classification) | 403 | `clearance` | none |
| version_number not found | 404 | `not_found` | `version_number` |
| target version classification above caller | 403 | `clearance` | `version_number` |
| blob integrity mismatch on download | 500 | `integrity_mismatch` | `version_number` |
| role denial (admin, auditor) | 403 | `role` | none |
| MFA enrollment required | 403 | `mfa_enrollment_required` | none |

**Value sourcing**:
| Action | Value produced / displayed | Source |
|---|---|---|
| list versions | version_number, classification, size_bytes, mime_type, created_at | `document_versions` columns |
| list versions | created_by username | `users.username` via `created_by` FK |
| list versions | is_current | derived: `version.id == documents.current_version_id` |
| list versions | filtered subset | query: `document_versions.classification <= actor.clearance`, after the document read gate passes |
| version content | plaintext bytes, filename, mime | `blob_store.load(version.blob_path)`, verified against `version.content_sha256`; filename via existing `_download_filename(doc.title, version.mime_type)` (current title; versions do not store titles) |
| restore | new version_number | derived: `max(document_versions.version_number) + 1` inside the transaction |
| restore | content_sha256, blob_path, size_bytes, mime_type, key_id, key_version | copied from the source `document_versions` row |
| restore | classification, created_by | derived: `actor.clearance`, `actor.id` |
| restore | is_current after restore | derived: `documents.current_version_id` set to the new row |

**Key invariants**:
- `document_versions` is append only: no endpoint updates or deletes a version row; restore inserts a new row.
- `documents.current_version_id` always points at a version of the same document (existing spec 0002 invariant, now exercised by restore).
- `version_number` is unique per document; computed as `max + 1` inside the transaction and a unique violation returns 409, same as `edit`.
- Every version event is audited in the same transaction as its mutation; reads of old versions are audited like current content reads.
- A restored version references the same content addressed `blob_path` as its source; no blob bytes are copied or re encrypted, and blob garbage collection remains deferred per spec 0003. Restore copies `blob_path` and `content_sha256` without verifying the blob still decrypts; a missing or corrupt blob propagates into the new current version and is caught by the existing verify at read check on download, not at restore time.
- Classification of any version row equals the clearance of the user who created that row; restore follows the same rule with the restorer as creator.

**Security model**:
Officer (`user`) role only on all three endpoints; admin and auditor get audited 403 through `require_role` and `GATE_ACTIONS`, and the MFA enrollment gate applies. Two layered checks guard version content: the caller must pass the document read rule (clearance at least the current version's classification) and the target version's own classification must be at most the caller's clearance. The version list applies the document read rule then omits versions above the caller's clearance so their existence never leaks; the content endpoint accepts the same tradeoff spec 0003 already made for document reads, where a 403 on an above clearance version reveals that a version exists at that number. Two accepted details: the download filename is built from the current `doc.title` because versions do not store titles, and downloading the current version through the new endpoint audits as `document.version_download` rather than `document.download`. Restore is owner only (404 `not_owner_or_missing` for non owners, matching `edit`) and additionally requires the caller to be able to read the source version under the same two checks. No regulated data scope beyond the existing classified document mission; audit details carry version numbers and roles only, never content or secrets.

**Configuration required**:
- None. No new environment variables, settings, or dependencies.

**Critical test scenarios** (each maps to an acceptance criterion in ## Requirements):
- Happy path: owner uploads, edits twice, lists versions newest first with `is_current` on the latest, downloads version 1 content and verifies the bytes, restores version 1, then lists again seeing four versions with the restored copy current, verifies **AC-1**, **AC-4**, **AC-6**, **AC-8**, **AC-9**
- Failure case: two restores or a restore racing an edit collide on `version_number` and the loser gets 409; restoring the current version gets 409; verifies **AC-7**
- Auth/permission: a Confidential cleared reader lists a document whose v1 was Secret and v3 is Confidential, sees only v2 and v3, gets 403 downloading v1; an unenrolled, admin, or auditor caller gets 403 on all three endpoints; verifies **AC-2**, **AC-3**, **AC-5**, **AC-10**
- Denial audit: every 403 and 404 above lands in `audit_log` under the endpoint's action name; verifies **AC-3**, **AC-5**, **AC-7**, **AC-9**

## Build plan

1. Add `VersionMeta` and `VersionListResponse` to `schemas/documents.py` and a `list_versions` service function with the document read gate, per version clearance filter, `version_number` descending order, `created_by` username resolved via `selectinload` on `created_by_user` (no N+1), the whole read inside `audit.transact` like `list_own`, and `document.versions_list` audit append, satisfies **AC-1**, **AC-2**, **AC-3**, **AC-9**
2. Add the version content endpoint reusing the `read_content` decrypt, hash verify, and audit pattern but resolving the target `version_number` row and enforcing the per version clearance check under action `document.version_download`, satisfies **AC-4**, **AC-5**, **AC-9**
3. Add the restore service function and endpoint: owner and source readability checks, new `document_versions` row copying content fields with `classification = actor.clearance`, pointer move, `updated_at` bump, `document.version_restore` audit in the same transaction, 409 on current version or unique conflict, satisfies **AC-6**, **AC-7**, **AC-8**, **AC-9**
4. Register the three routes in `api/documents.py`, add `GATE_ACTIONS` entries in `api/deps.py`, and write the test suite covering list filtering, per version download, restore semantics, all denials, and audit rows, satisfies **AC-1** through **AC-10**

## Consequences

**Positive**:
- The chain of custody becomes complete: every state a document's content ever held is listable, downloadable, and restorable, and restores are themselves versioned and audited
- Per version classification makes history honest under clearance changes; a demoted owner's old high classified versions stay protected instead of being exposed or hidden incorrectly
- Restore is cheap: one row insert reusing the content addressed blob, no file copy, following the spec 0002 recommendation

**Negative / tradeoffs**:
- Classification on a version tracks its creator's clearance, not the content's intrinsic sensitivity; restoring old content under a higher clearance raises its label, consistent with edit but worth remembering when reasoning about what a classification means
- The version list is unpaginated; fine at expected per document version counts, needs a cursor if documents accumulate thousands of versions
- Restored versions share `blob_path` with their source, so any future blob garbage collection must count references across versions rather than per document

**Neutral**:
- No migration, no new dependencies, no new settings; the endpoints follow the existing thin router, fat service layering
- Audit action vocabulary grows by three names; downstream consumers (alerts, export) should treat `document.version_restore` as a notable event

## Follow-up

- [ ] If per document version counts grow large, add cursor pagination to the version list (currently bounded by realistic edit frequency)
- [ ] When slice 8 (access alerts) lands, consider alerting on restores of versions older than N or on downloads of non current versions
- [ ] If blob garbage collection is ever built, it must dedupe by `blob_path` across all `document_versions` rows since restores share paths
