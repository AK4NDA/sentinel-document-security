# Verify: runnable demo packaging · spec 0011 · updated 2026-11-11
_Steps derived from spec 0011 acceptance criteria. `/check verify` runs these; `/test` locks the durable ones._

## API / manual

All steps run against the compose stack (`MASTER_KEY=<key> docker compose up --build -d`) or a local dev server. The walkthrough script drives the live API; seed runs inside the api container.

- [ ] Clean checkout with `MASTER_KEY` set: `docker compose up --build -d` brings up Postgres and the API; the api container runs `alembic upgrade head` on boot; `GET /healthz` and `GET /readyz` return 200 → AC-1
- [ ] `docker compose exec api python -m app seed-demo` creates `demo-admin`, `demo-auditor`, `demo-officer-low`, `demo-officer-mid`, `demo-officer-high`; each completes `POST /v1/auth/login` (returns `mfa_required` plus `pending_token`), `POST /v1/auth/mfa/verify` with a `pyotp` code from the documented secret, then `GET /v1/auth/me` returns the right username → AC-2
- [ ] Credential table in `docs/demo/walkthrough.md` matches `app/demo_constants.py` exactly (usernames, passwords, roles, clearances, TOTP secrets); both the CLI and `scripts/walkthrough.py` import the same module → AC-6
- [ ] Second `seed-demo` run exits 0, prints `exists` for all five, creates no duplicates; a user drifted in role, clearance, or MFA state is repaired back to the constants → AC-3
- [ ] `ENV=prod python -m app seed-demo` exits nonzero with the dev only message and creates nothing → AC-4
- [ ] `uv run python -m scripts.walkthrough` passes all labeled steps: five TOTP logins, admin profile and user list, admin/auditor 403 on documents, Secret docx and Top Secret txt uploads, denied read by officer-low, search non leak for officer-low and hit for officer-mid, Top Secret content download, edit to version two, version list/download/restore, share grant plus grantee read plus revoke plus denied again, disposable doc delete, auditor alert list and acknowledge, audit entries with allowed and denied outcomes, `POST /v1/audit/verify` valid → AC-7, AC-10
- [ ] Walkthrough against a stopped API fails at the `/readyz` poll with a clear timeout message; a mid tour unexpected status stops the run naming the step with expected versus actual; any 429 prints the `RATE_LIMIT_ENABLED=false` hint and exits nonzero → AC-8, AC-9
- [ ] `uv run python -m scripts.walkthrough --base-url http://example.com` exits 2 with the remote warning unless `--allow-remote` is passed → AC-11
- [ ] After a full tour, audit entries include five `user.create` rows with `details.via = "seed-demo"` and actor columns null, plus allowed and denied document actions from the tour, and chain verification reports valid → AC-5, AC-13
- [ ] Value sourcing: walkthrough base URL resolves `--base-url` then `WALKTHROUGH_BASE_URL` then `http://localhost:8000`; readiness polls `GET /readyz`; remote guard parses the URL host against localhost names; TOTP codes come from `pyotp.TOTP(fixed secret).now()`; document ids and the share target user id are captured from live responses; titles carry a per run unique suffix and temp fixtures are removed on exit → spec value table

## Commands

- [ ] `uv run pytest` → all tests pass including `tests/test_demo_seed.py` covering cast creation with full login, idempotent re-run, drift repair, ENV refusal, and audit entries plus chain verify → AC-2 to AC-5
- [ ] `uv run ruff check .` and `uv run ruff format --check .` → clean → all ACs

## Acceptance-criteria coverage

AC-1 compose boot and health; AC-2 cast creation and login; AC-3 idempotency; AC-4 dev guard; AC-5 seed audit entries; AC-6 shared constants; AC-7 full tour; AC-8 fail fast; AC-9 ready poll and 429 hint; AC-10 runtime fixtures and unique titles; AC-11 remote guard; AC-12 `docs/demo/walkthrough.md`; AC-13 post tour audit verify.
