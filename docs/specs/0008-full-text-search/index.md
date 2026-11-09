# 0008. Full text search over encrypted document content

**Date**: 2026-11-09
**Status**: Accepted

## Summary

Users will be able to search documents by words in the title, description, and extracted file text. Because file bytes are AES-GCM encrypted, the system extracts text once at upload or edit time, stores that text encrypted on the version row, and matches queries in memory at search time. No plaintext index is ever persisted, so the encryption guarantee is untouched. Results are filtered per document by the caller's clearance before anything is returned, so a search can never reveal that a higher classified document exists.

## Requirements

**User stories**:
- As an officer, I want to search my readable documents by keywords so that I can find a file without remembering its title.
- As an officer, I want search results to only include documents my clearance permits so that the search itself never leaks classified material.
- As an auditor, I want every search recorded in the audit log so that access patterns stay accountable.

**Acceptance criteria** (the contract, each criterion is IDed and independently checkable):
- **AC-1**: `GET /v1/documents/search?q=<terms>` returns documents where every query term appears (case insensitive, tokenized) in the union of the title, description, and extracted text of the current version: one token set per document across all three sources, all query terms required.
- **AC-2**: Results contain only documents the caller can read: role `user` and `clearance >= current_version.classification`, regardless of ownership. A term that exists only inside a higher classified document produces no result and no metadata leak (title, id, or count).
- **AC-3**: Roles `admin` and `auditor` receive 403 on the search endpoint, and the denial is audited.
- **AC-4**: Unauthenticated requests receive 401.
- **AC-5**: Only the current version's extracted text is searched; text from superseded versions never produces a match.
- **AC-6**: Documents whose MIME type is not text extractable (images) still match on title and description but never on content.
- **AC-7**: `q` is required, trimmed, 1 to 200 characters; `limit` defaults to 50 (max 200), `offset` defaults to 0; violations return 422. `q` and indexed text share one tokenization pipeline (casefold, then `\w+` runs); a `q` that yields zero tokens (e.g. `"!!!"`) returns 422.
- **AC-8**: Every executed search appends one `document.search` audit row (outcome `allowed`, `target_type="endpoint"`, `target_id="/v1/documents/search"`, details carry the query truncated to 200 characters and `total` matches) inside the same transaction; role denials are audited by the existing gate, and 422 validation failures produce no audit row.
- **AC-9**: Extracted text is persisted only as AES-GCM ciphertext (same `encryption.seal` format as blobs); no plaintext derivative of file content is stored in the database or on disk.
- **AC-10**: `search_text` stays in sync with the current version: upload and edit populate it for extractable MIME types, restore copies the source version's stored ciphertext and re extracts from the restored blob when the source is NULL, and a failed extraction stores NULL while the upload still succeeds. Extracted text is capped at the first 2 MB of plain text; `text/*` MIME types decode as UTF-8 with `errors="replace"`.
- **AC-11**: Results are ordered by `updated_at` descending with `id` as tiebreak; the response reports `total` matches (the full count before `limit`/`offset`), the returned page (empty when `offset` exceeds `total`), and echoes the validated `limit` and `offset`.
- **AC-12**: A query with no matches returns 200 with an empty `documents` list and `total` 0, not a 404.
- **AC-13**: The endpoint is rate limited by a new `RATE_LIMIT_SEARCH` setting (default `30/minute`, disabled by `RATE_LIMIT_ENABLED=false` like the other limits), wired through env, `.env.example`, and `docker-compose.yml`.

## Decision

**Chosen option**: Option 2: Encrypted extract plus query time scan

Extract text once when a version is written, store it AES-GCM encrypted in a new `document_versions.search_text` column, and evaluate queries by decrypting and token matching in memory over the caller's readable set. No search index table and no plaintext derivative is introduced.

**Implementation skills**: `fastapi` (`fastapi/fastapi`, `.agents/skills/fastapi/`) · `sqlalchemy` (`TerminalSkills/skills`, `.agents/skills/sqlalchemy/`) · `alembic` (`TerminalSkills/skills`, `.agents/skills/alembic/`) · `pydantic` (`pydantic/skills`, `.agents/skills/pydantic/`) · `async-python-patterns` (`wshobson/agents`, `.agents/skills/async-python-patterns/`) · `pytest-asyncio-patterns` (`testland/qa`, `.agents/skills/pytest-asyncio-patterns/`)

## Feature design

**Data model sketch**:
- `document_versions.search_text`: new nullable `LargeBinary` column holding AES-GCM ciphertext (`nonce || ciphertext+tag`, the `encryption.seal` output) of the UTF-8 extracted plain text. NULL means the MIME type is not extractable, extraction produced no text, or extraction failed. One Alembic migration; portable type, works on SQLite and Postgres.

**State transitions**: none (search is read only; `search_text` lifecycle follows the version row it lives on).

**API surface**:
| Endpoint | Method | Key inputs | Key outputs | Auth | Key errors |
|---|---|---|---|---|---|
| /v1/documents/search | GET | `q`: str (req, 1 to 200 after trim, must yield ≥1 token) · `limit`: int (opt, default 50, max 200) · `offset`: int (opt, default 0) | `documents`: list of DocumentMeta · `total`: int · `limit` · `offset` | bearer, role `user`, per doc clearance, `RATE_LIMIT_SEARCH` | 401, 403, 422, 429 |

**Value sourcing** (every value each action produces, computes, or displays names where it comes from):
| Action | Value produced / displayed | Source |
|---|---|---|
| search | matched document list | query `q` matched against `documents.title`, `documents.description`, and decrypted `document_versions.search_text` of the current version |
| search | `total` | count of all matching documents before `limit`/`offset` are applied |
| search | ordering | `documents.updated_at` desc, `documents.id` tiebreak |
| upload / edit / restore | `search_text` value | extracted at write time from the uploaded bytes by `services/text_extract.py` for extractable MIME types, capped at 2 MB of plain text; restore copies the source version's ciphertext, or re extracts from the restored blob when the source is NULL |

**Key invariants**:
- Search never returns a document whose current version classification exceeds the caller's clearance. Candidates are documents with a non NULL `current_version` whose classification is within the caller's clearance, filtered in SQL before any decryption; per document clearance filtering is deliberately not separately audited (one aggregate row per query, matching the `document.list` precedent, so phantom denials cannot leak existence).
- `search_text` ciphertext decrypts only under the current `MASTER_KEY`; it uses the same `encryption.seal` format as blobs and the `key_id`/`key_version` columns already on the row.
- Tokenization is identical everywhere: casefold, then `\w+` runs (unicode aware). Each document contributes one token set built as the union of title, description, and decrypted `search_text`; a document matches when the query's token set is a subset. `text/*` MIME types decode as UTF-8 with `errors="replace"`.
- A `search_text` value that fails to decrypt (corrupt or wrong key) counts as no content match; the document can still match on title and description, a warning is logged, and the request never fails because of it.
- Extraction and decryption of file content run via `asyncio.to_thread`; extraction happens before `audit.transact` opens its transaction so no long CPU work holds a DB transaction open.
- Extracted plain text is capped at the first 2 MB before encryption; truncation is silent and noted in Consequences.

**Security model**:
- Role gate: `require_role("document.search", UserRole.USER)`; admins and auditors are denied and the denial is audited (AC-3, AC-4).
- Per document clearance check against `current_version.classification` before a document can match (AC-2). This matches the existing read rule in `services/documents.py` (`_readable_document`), which is role plus clearance, not ownership.
- The audit row records the query text truncated to 200 characters and `total`; the query itself is user input, stored like other audit details. Auditors see queries and hit counts without gaining document access.
- Rate limited via the shared limiter with `key_func=get_remote_address`, same pattern as the auth routes; `RATE_LIMIT_SEARCH` defaults to `30/minute` because this is the most expensive endpoint in the app.

**Configuration required**:
- `RATE_LIMIT_SEARCH`: per IP request limit for `GET /v1/documents/search` (default `30/minute`); add to `Settings`, `.env.example`, and `docker-compose.yml` alongside the existing `RATE_LIMIT_*` vars.

**Critical test scenarios** (each maps to an acceptance criterion in ## Requirements):
- Happy path: officer uploads a PDF and a text file, searches a term present in both title and extracted text, gets both documents ordered by `updated_at` desc, verifies **AC-1**, **AC-11**.
- Clearance boundary: a Secret document containing the term is invisible to a Confidential cleared officer; the same officer's search returns only permitted documents and `total` counts only those, verifies **AC-2**.
- Auth: auditor and admin receive 403 with an audited denial, anonymous receives 401, verifies **AC-3**, **AC-4**.
- Query edges: `"!!!"` and oversized `q` return 422 with no audit row; `offset` past `total` returns an empty page with the full `total`, verifies **AC-7**, **AC-8**, **AC-11**.
- Version and type edges: editing a document so the term disappears removes it from results; restoring an old version restores its text (re extracting when the source `search_text` is NULL); an image upload matches on title but never content; extraction failure still allows upload, verifies **AC-5**, **AC-6**, **AC-10**.
- Pagination and empty: `limit`/`offset` slice correctly with stable `total`; no matches returns 200 empty, verifies **AC-11**, **AC-12**.
- Rate limit: exceeding `RATE_LIMIT_SEARCH` returns 429, verifies **AC-13**.

## Build plan

1. Add extraction dependencies (`pypdf`, `python-docx`, `openpyxl`, `python-pptx` via `uv add`) and build `app/services/text_extract.py` with per MIME extractors, the 2 MB cap, UTF-8 `errors="replace"` decoding for `text/*`, and a `to_thread` wrapper, satisfies **AC-6**, **AC-9**, **AC-10**
2. Alembic migration adding `document_versions.search_text` (nullable `LargeBinary`), satisfies **AC-9**
3. Wire extraction into upload, edit, and restore in `services/documents.py`: extract before `audit.transact` opens, populate for extractable MIME types, copy ciphertext on restore or re extract when the source is NULL, NULL on failure, satisfies **AC-5**, **AC-9**, **AC-10**
4. Add `rate_limit_search` to `Settings` (default `30/minute`) and wire it through `.env.example` and `docker-compose.yml`, satisfies **AC-13**
5. Search service (`services/search.py`): candidate query filtered by non NULL current version and clearance in SQL, decrypt `search_text` via `to_thread` (undecryptable counts as no content match), union token set match, stable ordering, limit/offset, single `document.search` audit append in the transaction, satisfies **AC-1**, **AC-2**, **AC-8**, **AC-11**, **AC-12**
6. `GET /v1/documents/search` route registered BEFORE `/{doc_id}` in `api/documents.py` (otherwise `search` parses as a UUID and 422s), `SearchResponse` schema, shared `limiter` with `RATE_LIMIT_SEARCH`, `GATE_ACTIONS` entry for `document.search`, satisfies **AC-1**, **AC-3**, **AC-4**, **AC-7**, **AC-13**
7. Test suite covering every critical scenario above plus unit tests for tokenization and each extractor, satisfies all ACs

## Consequences

**Positive**:
- Full text search ships with zero weakening of the encryption model: the only persisted derivative is itself AES-GCM ciphertext under the same master key.
- No new infrastructure: no search engine, no index table, no background jobs; the whole feature is one column, one module, one endpoint.
- The clearance prefilter happens in SQL before any decryption, so excluded documents are never even read from disk.
- The endpoint carries its own rate limit (`RATE_LIMIT_SEARCH`), the first document route to do so, matching its cost profile.

**Negative / tradeoffs**:
- Search is O(readable documents) per query: every candidate's `search_text` is decrypted and tokenized per request. Fine at prototype and small team scale; it will not survive a large corpus.
- PDF and Office parsing adds four dependencies and CPU cost at write time; a malformed file can make extraction slow or fail (handled as NULL, but a zip bomb style Office file is a residual risk mitigated only by the existing 25 MB upload cap and the 2 MB extracted text cap).
- Extracted text is truncated at 2 MB, so terms beyond that point in very large files will not match.
- `limit`/`offset` pagination over a computed match set means deep offsets rescan everything; acceptable here, noted for the scale path.
- Extracted text inherits whatever the file contained, including hidden sheet cells or document metadata text; search can surface content the uploader did not intend to expose within the same clearance domain.

**Neutral**:
- Old versions keep `search_text` NULL unless restored; a restore re extracts when the source has none, keeping the chain of custody intact.
- The `document.search` audit action joins the existing action vocabulary; auditors see queries and hit counts in the log.

## Follow-up

- [ ] If the corpus grows past a few thousand documents, revisit a blind index (HMAC token table) or per clearance tier encrypted indexes; the current scan does not scale.
- [ ] Consider search snippets or ranking (title matches boosted) if users ask for relevance ordering.
- [ ] OCR for image uploads is out of scope; images remain title and description searchable only.
- [ ] Backfill `search_text` for documents uploaded before this feature ships, if any exist in real deployments (dev databases can be reset instead).

## Rationale

Reasoning, options considered, and references: see [rationale.md](rationale.md).
