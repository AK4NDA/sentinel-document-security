# 0011. Runnable demo packaging: rationale

## Context

Scope feature 12 calls for making the whole system boot with one Docker command, with seed data covering every role and clearance and a short scripted walkthrough that exercises allow and deny paths. Much of the machinery already exists: `Dockerfile` and `docker-compose.yml` were delivered under spec 0001, `alembic upgrade head` already runs in the container CMD, and `python -m app create-admin` established the management CLI pattern. What is missing is the demo cast itself, a repeatable tour, and proof the whole pipe works from a clean checkout.

The forces shaping the decision: the demo must be self contained (no external services, per the scope note that recommended in app records for alerts for the same reason), the audit log must show the full trail so the walkthrough can only use real API endpoints, and the demo credentials cannot be real secrets yet must be convenient enough that a presenter never fumbles a login.

## Options considered

### Option 1: Manual seed CLI plus host run Python walkthrough (chosen)

`python -m app seed-demo` creates the demo cast on demand, inside the container via `docker compose exec` or locally via `uv run`. `scripts/walkthrough.py` is a Python httpx client run from the host against `localhost:8000`, generating its own upload fixtures and printing a labeled step log. `docs/demo/walkthrough.md` ties it together.

**Pros**:
- Seeding is explicit and idempotent, never a surprise write on container boot.
- httpx is already a dev dependency and `uv run` covers it on the host; Python handles JSON, cookies, TOTP codes (pyotp), and step assertions far better than shell.
- The script imports the same demo constants module as the seed command, so credentials have one source.
- Running from the host needs no image changes (the image is built `--no-dev`, so the script could not run inside the container anyway); `scripts/` stays out of the image.

**Cons**:
- Three commands instead of literally one (compose up, seed, walkthrough); the docs compress this into a copy paste block.
- The script couples to the live API surface and can break on endpoint changes (accepted: loud failure beats silent doc drift).
- Demo users must be MFA enrolled with fixed TOTP secrets rather than password only, because `api/deps.py` gates every non enroll endpoint behind `totp_enabled_at`. This is more seed code but produces a more realistic demo: the walkthrough performs the real login challenge.

### Option 2: Auto seed on container boot

A seed service or entrypoint flag runs seeding automatically on first boot, so `docker compose up` alone yields a demo ready system.

**Pros**:
- Fewer steps for the presenter; truly one command.

**Cons**:
- Adds a boot code path with ordering concerns (must wait for Postgres healthy and migrations done) and a "first boot only" state check inside the container lifecycle.
- Re running compose after a volume wipe silently reseeds; implicit writes are harder to reason about than an explicit command.
- More moving parts for a demo that runs a handful of times.

### Option 3: Bash plus curl walkthrough

The tour as a shell script using curl and jq, runnable anywhere without Python.

**Pros**:
- No interpreter dependency beyond curl.

**Cons**:
- Cookie sessions, JSON assertions, and fixture generation are all markedly more painful in bash; the script would be longer and more fragile for no portability gain, since the demo audience already has the repo (and `uv`) checked out.

### Option 4: Documentation only walkthrough

A markdown page with copy paste curl commands and expected output, no executable script.

**Pros**:
- Simplest possible artifact.

**Cons**:
- The presenter runs every step by hand; nothing verifies the tour still works, and the audit trail claim is unverifiable without manual checking. The engineer chose the script plus doc form in the design conversation.

## Rationale

Option 1 wins because it matches the project's existing conventions (the `python -m app` CLI from spec 0003, uv for running Python, httpx and pyotp already in the dependency set) while keeping every side effect explicit. Auto seeding (Option 2) buys one fewer command at the cost of boot lifecycle complexity that a demo does not justify. Bash (Option 3) trades a real dependency for worse ergonomics on exactly the operations the tour needs most. Docs only (Option 4) was rejected by the engineer in favor of a repeatable script.

One design conversation answer changed during the cross check: the engineer initially picked password only demo users, but `api/deps.py` returns 403 "mfa enrollment required" on every document, share, alert, and audit endpoint for any user without `totp_enabled_at`. The alternatives were a dev only gate bypass setting (new config surface, weakens a security invariant) or enrolling demo users with fixed documented TOTP secrets (more seed code, but the walkthrough then performs the real MFA challenge and the demo looks like production). The enrolled option won; the "no MFA" intent (no enrollment ceremony during the demo) is preserved because the secrets are pre enrolled, not set up live.

The two guards (dev only ENV check on seed, localhost check on the walkthrough) exist because fixed demo credentials are otherwise a credential hygiene violation; bounding them to dev environments and local hosts keeps the convenience without the blast radius. `sources` level references: the reasoning rests on project conventions already in the repo rather than external practice.

## References

**Project sources** (verifiable, in this repo):

- `AGENTS.md` command reference (`uv run`, `python -m app create-admin`, compose up) and the Tracer Bullet build approach
- `docs/specs/0001-stack-architecture/index.md` (compose and Dockerfile decisions this feature verifies)
- `docs/specs/0003-core-classified-document-loop/index.md` (`create-admin` CLI pattern, audit conventions)
- `docs/specs/0004` through `0010` (the API surface the walkthrough exercises)
- `docker-compose.yml`, `Dockerfile`, `app/cli.py`, `pyproject.toml` (httpx and python-docx already dependencies)

**Practices & standards**:

- Idempotent seed/fixture commands (safe to re-run, top up missing state)
- Twelve factor style configuration (credentials and endpoints via env or flags, never hardcoded targets)
- Demo/seed data kept out of production paths via environment guards
