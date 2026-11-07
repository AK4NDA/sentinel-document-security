# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Project scaffold: FastAPI app shell, layered package layout (`app/api`, `app/core`, `app/models`, `app/repositories`, `app/schemas`, `app/security`, `app/services`), settings via `pydantic-settings`, structured logging, Alembic wired to SQLAlchemy async metadata.
- Core data model (spec `0002-data-model`), one Alembic migration creating seven tables:
  - `users` with role, classification clearance, active flag, login lockout counters, and encrypted TOTP fields.
  - `sessions` with hashed token storage, expiry, revocation, and client metadata.
  - `documents` and append only `document_versions` with per document version numbering, classification, content hash, storage path, and reserved key rotation columns.
  - `document_shares` with per user access levels and revocation tracking.
  - `audit_log`, an append only hash chained table storing actor and target as snapshots with no foreign keys so records survive deletes.
  - `alerts` with severity, dedup fingerprint, and acknowledgement fields.
- Model tests covering UUID defaults, uniqueness constraints, classification and outcome check constraints, cascade and restrict delete behavior, ORM level document delete, audit snapshot integrity, index presence, and an Alembic upgrade/downgrade round trip on SQLite.
- Core classified document loop (spec `0003-core-classified-document-loop`):
  - Authentication API under `/v1/auth` (`login`, `logout`, `me`) with opaque session tokens stored as SHA-256 hashes, HttpOnly SameSite cookies, Bearer token support, sliding expiry with a 24 hour absolute cap, revocation, and per request user re-reads so disabled accounts and role or clearance changes take effect immediately.
  - Admin user management under `/v1/users` (create officer and auditor accounts only, 12 character password minimum, audited) and a `python -m app create-admin` CLI bootstrap command with a hidden password prompt.
  - Document endpoints under `/v1/documents` for upload, list, metadata read, decrypted content download, new version, and hard delete, enforcing strict Bell LaPadula (no read up, no write down) and role rules (only the `user` role touches documents; admins manage accounts; auditors authenticate but reach nothing).
  - File uploads validated by size first (25 MB cap with a chunked reader that aborts early) then MIME allowlist, encrypted with AES GCM before storage at content addressed paths under `UPLOAD_DIR`, with classification pinned to the uploader's clearance and optimistic version conflict returning 409.
  - Real audit hash chain: canonical JSON SHA-256 entries with a 64 zero genesis `prev_hash`, a unique constraint on `prev_hash` plus bounded retry so concurrent writers cannot fork the chain, and a `verify_chain` helper that detects tampering. Every allowed and denied attempt after identity is established writes an entry in the same transaction as the business operation.
