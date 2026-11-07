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
