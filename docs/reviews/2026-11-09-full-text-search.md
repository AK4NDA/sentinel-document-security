# Review, feature/document-version-history (uncommitted: full-text search), 2026-11-09

**Reviewed by**: SWE-2 Flash (author on SWE-2 Flash — same-model fresh-context review; the cross-model independence guarantee is degraded, stated plainly per review policy)
**Scope**: 13 files, uncommitted working-tree changes vs HEAD (search feature only; unrelated review-fix changes in `app/security/passwords.py`, `app/services/{sessions,blob_store,auth,users}.py`, `app/cli.py`, `app/api/{auth,audit}.py` excluded per scope note; `RATE_LIMIT_AUDIT` lines in `.env.example`/`docker-compose.yml` belong to that out-of-scope change)
**Verdict**: Changes requested

## Summary

Spec 0008 is implemented faithfully: extracted text is sealed with the same AES-GCM format as blobs into `document_versions.search_text`, candidates are clearance-filtered in SQL before any decryption, matching is a union-token subset test, and every executed search appends one `document.search` audit row. The test suite is unusually thorough — all 13 ACs have dedicated API tests plus 12 extractor unit tests. The headline issue is a latent crash in the audit-fork retry path: `search()` builds its result page from ORM objects loaded *before* `audit.transact`, and `attempt` calls `to_meta` on them inside the retried unit, so the first `AuditChainFork` rollback expires those objects and the retry deterministically raises instead of completing.

## Major

### 🟠 Audit-fork retry in `search()` crashes on expired ORM objects, `app/services/search.py:85-98`

**Problem**: The candidate `Document` rows (and their `selectinload`ed `current_version`) are queried at `search.py:64-71`, *outside* `audit.transact`. Inside `attempt` (`search.py:95`), `[to_meta(doc) for doc in page]` dereferences `doc.current_version` — a relationship declared `lazy="raise"` (`app/models/document.py:50`). `audit.transact` (`app/services/audit.py:153-162`) retries the whole `op` on `AuditChainFork` after `await db.rollback()`, and rollback expires every instance in the session. On the first retry, `to_meta` touches expired attributes and raises (`InvalidRequestError` from `lazy="raise"`, or `MissingGreenlet` for expired column attributes under asyncio). That exception is not an `AuditChainFork`, so it propagates out of `transact` and becomes a 500.

**Why it matters**: Every other service that uses `audit.transact` is careful here — `read_meta` re-fetches inside `attempt` (`documents.py:253`), `list_own` re-queries rows inside `attempt` (`documents.py:223-231`), `read_content`'s `attempt` touches no ORM state. `search.py` is the only caller that consumes pre-transaction ORM objects inside the retried unit. A chain fork needs only one concurrent audit append racing the search's own append — two simultaneous searches, or a search overlapping any upload/login/write — which is ordinary production traffic, not an exotic edge. When it fires, the endpoint 500s deterministically on retry rather than returning results.

**Suggested fix**: Compute the response before the transaction — `DocumentMeta` is a plain Pydantic object, so build `metas = [to_meta(doc) for doc in page]` before calling `audit.transact` and have `attempt` only append the audit row and return `metas`. Alternatively re-fetch the page documents inside `attempt` the way `read_meta` does. Add a test that forces a fork (e.g., monkeypatch `audit.append` to raise `AuditChainFork` once) to lock the behavior in.

## Minor

### 🟡 `q` is not trimmed despite AC-7 saying "trimmed", `app/api/documents.py:74`

**Problem**: `q: str = Query(min_length=1, max_length=200)` validates the raw string. Leading/trailing whitespace counts toward the 200-character cap and is never stripped, so `" fox "` works (tokenizer absorbs it) but a query padded with spaces can hit `max_length` where the trimmed query would not, and `" " * 200` is a 200-char string that only fails later via the tokenize check.

**Why it matters**: AC-7 specifies "required, trimmed, 1 to 200 characters". Matching still behaves correctly because `tokenize` casefolds and `\w+`-splits, so impact is limited to the length edge and to the raw (untrimmed) `q` stored in audit `details`. Low risk, but it is a spec-contract deviation.

**Suggested fix**: Strip before validating — e.g. a `field_validator`/`BeforeValidator` on a `q` schema field, or `q = q.strip()` at the top of the route before the tokenize check and before it reaches `search()` and the audit details.

### 🟡 Ordering assertion in pagination test is weaker than AC-11 requires, `tests/test_search.py:392-405`

**Problem**: `test_search_pagination_ordering_and_empty` claims to verify `updated_at` desc ordering but only asserts `set(ids) == set(expected)` plus page disjointness; the comment concedes tie order "may vary". Nothing asserts that page 1 contains the newest documents.

**Why it matters**: `TEST_SIGNAL = configured`, and AC-11's ordering guarantee (`updated_at` desc, `id` tiebreak) is the kind of branching/ordering logic the guide says deserves real coverage. A regression that dropped the `ORDER BY` or sorted ascending could still pass this test if timestamps tie or the set happens to match.

**Suggested fix**: Assert the exact ordered id list for the three sequential uploads (timestamps are written per request and almost certainly distinct at microsecond precision), or set `updated_at` explicitly via `session.execute(update(...))` to force a known order, then assert page contents in order.

## Nits

- ⚪ `app/services/search.py:22` and `app/services/text_extract.py:14` use stdlib `logging.getLogger`, but the project configures structlog (`app/core/logging.py`) with a plain `"%(message)s"` format — the `extra={"version_id": ...}` / `extra={"mime_type": ...}` context is silently dropped from log output. Use `structlog.get_logger(__name__)` (or accept that context is lost).
- ⚪ `app/services/text_extract.py:63-71,96-108`: the DOCX extractor reads paragraphs and tables but misses headers, footers, footnotes, and text boxes; the PPTX extractor misses grouped shapes. Terms living only in those parts will never match. Spec is silent, so this is a documented-limitation candidate rather than a defect — worth a line in Consequences.
- ⚪ `app/services/documents.py:591-595`: the restore re-extract path swallows all exceptions (including a missing/corrupt blob from `blob_store.load`) with no logging, unlike `extract_text` which logs extractor failures. A silently-NULL `search_text` on a genuinely broken blob is harder to diagnose later.
- ⚪ `app/services/search.py:74-79`: `_content_tokens` is awaited sequentially per candidate; N docs means N serialized `to_thread` dispatches. `asyncio.gather` over the candidates would parallelize the decrypt+tokenize work at no correctness cost. The spec already accepts O(n) scan cost, so this is optional.

## Strengths

- The security posture is exactly right and well-tested: clearance filtering happens in SQL (`DocumentVersion.classification <= actor.clearance`, `search.py:68`) before any ciphertext is touched, `search_text` is never persisted as plaintext (verified by `test_search_text_stored_encrypted_and_synced`), and undecryptable ciphertext degrades to a metadata-only match with a warning rather than failing the request (`search.py:36-40`, covered by `test_undecryptable_search_text_does_not_fail_search`).
- Spec fidelity is high: union-token subset semantics, `updated_at desc, id` ordering with `total` computed pre-pagination, one aggregate audit row per query with truncated `q`, 422-without-audit on tokenless queries, route registered before `/{doc_id}`, `GATE_ACTIONS` entry for the MFA gate, and `RATE_LIMIT_SEARCH` wired through settings/env/compose exactly like the auth limits.
- Extraction discipline matches the async rules: all parsing and sealing go through `asyncio.to_thread`, extraction runs before `audit.transact` opens its transaction, and the 2 MB cap is enforced both during accumulation (`_join`) and at the byte level (`_cap`). Restore correctly copies ciphertext when present and re-extracts only when the source is NULL.
- The migration is portable (`batch_alter_table` + `sa.LargeBinary`, linear `down_revision` chain verified against all five existing revisions), and `uv.lock` resolves all four new parsing deps.

## Test coverage

Strong. `tests/test_search.py` maps one-to-one onto AC-1 through AC-13, including the subtle ones: no existence/count leak for higher-classified content (AC-2), superseded-version exclusion plus restore round-trip (AC-5/AC-10), corrupt-PDF upload still succeeding with NULL `search_text`, forced-undecryptable ciphertext, audit-row cardinality (exactly one `allowed` row per executed query, none for 422), and the rate limit. `tests/test_text_extract.py` covers every extractor with real generated files, the 2 MB cap, UTF-8 `errors="replace"`, and ciphertext round-tripping through `encryption.open_blob`. Gaps: no test forces an `AuditChainFork` during search (which is exactly where the Major finding lives), and the AC-11 ordering assertion is set-based rather than order-based (flagged above).
