# 0008 rationale: full text search over encrypted content

## Context

File content in this system is AES-GCM ciphertext under a single master key, stored content addressed on disk. The audit and policy model is the product's reason to exist, so any search design that persists a plaintext or deterministically derivable index trades away a core guarantee. At the same time the scope requires real content search: a user must be able to find a document by words inside it, and must never learn that a document above their clearance contains a term.

The corpus is a prototype to small team scale: dozens to low thousands of documents, 25 MB upload cap, single node deployment. There is no search infrastructure, no background job runner, and no object storage. Whatever is chosen must run inside the existing FastAPI monolith on Postgres and SQLite.

The existing read rule is role `user` plus `clearance >= current_version.classification`, enforced per document in `services/documents.py` and not scoped by ownership. Search must reuse that exact rule or it becomes a side channel.

## Options considered

### Option 1: Pure query time scan

On each search, iterate the caller's readable documents, load and decrypt each content blob, extract text in memory, and match. No schema change at all.

**Pros**:
- Zero storage change, zero new persisted state, simplest possible confidentiality story.

**Cons**:
- Re decrypts and re parses every document on every query; PDF parsing is the expensive part and would dominate request latency even at modest corpus sizes.
- Wasted work is proportional to corpus size times query rate, with no way to amortize it.

### Option 2: Encrypted extract plus query time scan

Extract text once at write time (upload, edit, restore), store it AES-GCM encrypted in a `search_text` column on `document_versions`, and at query time decrypt only that smaller text payload for each policy eligible document and match in memory.

**Pros**:
- No index table, no new service, no plaintext derivative anywhere; the confidentiality model is identical to Option 1.
- Extraction cost is paid once per write instead of once per query per document; queries decrypt small text blobs rather than parsing binaries.
- The column rides the existing version lifecycle, so restore and delete semantics come for free.

**Cons**:
- One nullable column and one migration, plus write time CPU for parsing.
- Still O(corpus) decrypt and tokenize per query; the scan itself is the ceiling, not the extraction.

### Option 3: Blind index

At write time, tokenize the extracted text and store HMAC-SHA256 hashes of normalized tokens in a `search_terms` table keyed by document and version. Queries hash their terms and join.

**Pros**:
- Fast indexed lookup, sublinear in corpus size, the standard searchable encryption pattern.

**Cons**:
- Deterministic tokens leak the vocabulary and the term to document association graph to anyone who can read the database, which for a system whose threat model includes a database admin rewriting the audit tail is a real weakening.
- Frequency analysis and known plaintext attacks apply; it is probabilistic encryption done badly if the HMAC key ever shares fate with the master key.
- More schema, more write path complexity, and a second secret to manage.

### Option 4: Plaintext full text index

Extract text at write time into Postgres `tsvector` (or SQLite FTS5) and query the index directly.

**Pros**:
- Fastest queries, native ranking and highlighting, the least code.

**Cons**:
- Stores directly searchable plaintext derivatives of classified content in the database, defeating the encryption at rest guarantee the whole product is built around. Rejected outright.

## Rationale

Option 2 is the only choice that adds real content search without weakening the encryption guarantee or adding infrastructure. Option 1 is simpler but pays PDF parse cost per query forever; Option 2 pays it once per write and makes queries cheap enough for the scale this system targets. Option 3 buys speed this corpus does not need at the price of leaking associations; it stays on the follow up list for when the scan ceiling is actually hit. Option 4 is not a tradeoff, it is a different product.

The in memory match over the prefiltered readable set is deliberate: the clearance filter runs in SQL before any decryption, so excluded documents are never touched, and `total` plus ordering are computed over exactly the set the caller may see. Token set semantics (casefold plus `\w+` runs, all query terms required) were chosen over substring or boolean syntax because they are predictable, unicode safe, and avoid false positives like "cat" matching "concatenate".

