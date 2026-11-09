# Verify: document version history · spec 0007 · updated 2026-11-09
_Steps derived from spec 0007 acceptance criteria. `/check verify` runs these; `/test` locks the durable ones._

## UI / manual

Backend only; all steps are HTTP against a running dev server (`uv run uvicorn app.main:app`) with an officer session cookie or Bearer token. Officer users need MFA enrolled except where the gate itself is under test.

- [ ] Upload a doc as a SECRET cleared officer, edit twice via `POST /v1/documents/{id}/versions`, then `GET /v1/documents/{id}/versions` → 200, three entries newest first, `is_current` true only on v3, `created_by` is the owner's username → AC-1
- [ ] `GET /v1/documents/{id}/versions/1/content` → 200, body equals the v1 upload bytes, `Content-Disposition` is `attachment` with the `.txt` filename convention → AC-4
- [ ] `POST /v1/documents/{id}/versions/1/restore` as owner → 201 `DocumentMeta`; `GET /v1/documents/{id}/content` returns the v1 bytes; versions list shows 4 entries with v4 `is_current`; v1 to v3 still listed and downloadable → AC-6, AC-8
- [ ] `POST /v1/documents/{id}/versions/{current}/restore` → 409 and no `document.version_restore` row in the audit log → AC-7
- [ ] Restore as a non owner → 404 `not_owner_or_missing`; restore `version_number` 99 → 404 `not_found`; both audited under `document.version_restore` → AC-7, AC-9
- [ ] Officer cleared below the current version's classification → 403 on list, version content, and restore, each audited under its own action name → AC-3, AC-5, AC-7
- [ ] A version classified above the caller (simulate via administration clearance change or direct row update) is absent from the list and returns 403 on content download → AC-2, AC-5
- [ ] Admin, auditor, and MFA unenrolled callers → 403 on all three endpoints before document logic, audited via `GATE_ACTIONS` → AC-10
- [ ] Audit check: exactly one allowed `document.versions_list` / `document.version_download` / `document.version_restore` row per successful call; every denial lands under the attempted action; restore details carry `source_version_number` and `version_number` → AC-9
- [ ] Value sourcing: `created_by` resolves `users.username`; `is_current` derives from `documents.current_version_id`; download filename uses current `doc.title` plus the version's `mime_type`; the restored row copies `content_sha256`, `blob_path`, `size_bytes`, `mime_type`, `key_id`, `key_version` from the source version → spec value table

## Commands

- [ ] `uv run pytest` → all tests pass including the spec 0007 suite in `tests/test_api.py` → AC-1 through AC-10
- [ ] `uv run ruff check .` and `uv run ruff format --check .` → clean → AC-1 through AC-10

## Acceptance-criteria coverage

- AC-1 … steps 1 · AC-2 … step 7 · AC-3 … step 6 · AC-4 … steps 2, 7 · AC-5 … steps 5, 6, 7 · AC-6 … step 3 · AC-7 … steps 4, 5, 6 · AC-8 … step 3 · AC-9 … steps 4, 5, 6, 8 · AC-10 … step 8
