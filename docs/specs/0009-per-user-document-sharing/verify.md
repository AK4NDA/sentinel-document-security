# Verify: per user document sharing · spec 0009 · updated 2026-11-09
_Steps derived from spec 0009 acceptance criteria. `/check verify` runs these; `/test` locks the durable ones._

## API / manual

Backend only; all steps are HTTP against a running dev server (`uv run uvicorn app.main:app`) with session cookies or Bearer tokens. Officer users need MFA enrolled except where the gate itself is under test. Setup: an owner officer at Secret clearance who uploads a Secret document, and a grantee officer at Unclassified clearance.

- [x] Owner `POST /v1/documents/{id}/shares` with `{"user_id": "<grantee uuid>"}` plus extra junk fields → 201 `ShareOut` (`access_level` stays `read`); audit shows one allowed `document.share_grant` row targeting the document with `share_id` and `grantee_id` in details → AC-1
- [x] Grantee `GET /v1/documents/{id}` and `GET /v1/documents/{id}/content` → 200 despite clearance below classification; audit shows allowed `document.read` and `document.download` rows with `details.via_share = true` and `details.share_id` matching the share → AC-2
- [x] Owner `DELETE /v1/documents/{id}/shares/{user_id}` → 204; grantee read, download, and version accesses → 403 and audited; audit shows allowed `document.share_revoke` with `share_id` and `grantee_id` → AC-3
- [x] Regrant after revoke via POST → 200, same share `id`, `created_at` preserved, `revoked_at`/`revoked_by` cleared, `granted_by` updated, new `document.share_grant` row; POST while a share is already active → 200 with the existing row and no new audit entry → AC-4
- [x] Owner `GET /v1/documents/{id}/shares` → every row for the document active and revoked, each `ShareOut` carrying grantee `username`, `granted_by`/`revoked_by` usernames, `access_level`, timestamps; the call audits `document.shares_list` as an endpoint target → AC-5
- [x] A non owner, including one whose clearance meets the document's, gets 404 with audited `not_owner_or_missing` on grant, revoke, and list → AC-8
- [x] Grantee `GET /v1/shares/mine` → `SharedDocumentOut` rows for active shares only, documents above their clearance included, versionless documents excluded, ordered `shared_at` descending then document id; audited `document.list_shared` → AC-6
- [x] Grantee `GET /v1/documents/{id}/versions` lists every version regardless of per version classification, and `GET .../versions/{n}/content` downloads each; `document.versions_list` and `document.version_download` audit rows carry `via_share`/`share_id` under the AC-2 rule → AC-7
- [x] Grant to self → 409 `self_share`; disabled account → 409 `grantee_disabled`; admin or auditor account → 409 `grantee_role`; unknown id → 404 `user_not_found`; each is an audited denial under `document.share_grant` → AC-9
- [x] DELETE on a share that never existed or is already revoked → 404 with audited `share_not_active` → AC-10
- [x] Shared above clearance document stays out of the grantee's `GET /v1/documents/search` results and out of `GET /v1/documents` (own only); it still appears in `/v1/shares/mine` → AC-11
- [x] Admin and auditor callers get 403 role denials on all share endpoints, `/v1/shares/mine`, and `/v1/users/lookup`; an auditor can never hold a share (grant rejects non `user` roles); auditor document denials still log → AC-12
- [x] `GET /v1/users/lookup?username=<prefix>` → active `user` role accounts only, case insensitive prefix, username ascending, `{id, username}` only, default limit 20 capped at 20, prefix under 2 chars → 422, `user.lookup` audited per handled call and not on 429 → AC-13
- [x] Admin patches to grantee clearance, role, and disabled state, and disabling the share owner, leave `document_shares` rows untouched; a disabled grantee's session fails, a demoted auditor grantee is role denied, and grantees of a disabled owner keep read access → AC-14
- [x] Grantee edit, delete, version restore, and onward share attempts → denied by owner/clearance checks and audited; document content unchanged → AC-15
- [x] Value sourcing: `granted_by` equals the session user id resolved to username; `share_id` in audit details equals the `document_shares.id` row; list usernames come from `users` joins on `user_id`/`granted_by`/`revoked_by`; `shared_at` equals `document_shares.created_at`; `/v1/shares/mine` classification comes from `document_versions.classification` via `current_version_id`; lookup matching is `username ILIKE 'prefix%'` case insensitive over active `user` rows; `via_share`/`share_id` are recomputed inside the audit append transaction (revoke between check and append cannot claim a dead share) → spec value table

## Commands

- [x] `uv run pytest` → all tests pass including `tests/test_shares.py` covering AC-1 through AC-15 → all ACs
- [x] `uv run ruff check .` and `uv run ruff format --check .` → clean → all ACs

## Acceptance-criteria coverage

- AC-1 … steps 1 · AC-2 … steps 2, value sourcing · AC-3 … step 3 · AC-4 … step 4 · AC-5 … step 5 · AC-6 … step 7 · AC-7 … step 8 · AC-8 … step 6 · AC-9 … step 9 · AC-10 … step 10 · AC-11 … step 11 · AC-12 … step 12 · AC-13 … step 13 · AC-14 … step 14 · AC-15 … step 15
