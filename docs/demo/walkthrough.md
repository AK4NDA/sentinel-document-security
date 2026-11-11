# Demo walkthrough

This guide boots the whole system with Docker Compose, seeds a fixed cast of
demo users, and runs a scripted tour across every feature surface: MFA login,
documents across classifications, deny paths, versions, search, sharing,
alerts, and the audit trail.

## What you need

- Docker with Compose
- `uv` on the host for the walkthrough script
- A `MASTER_KEY`: a base64 encoded 32 byte key. Generate one with

  ```bash
  python -c "import base64, secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"
  ```

## Quickstart

```bash
# 1. Boot Postgres and the API (runs migrations on start)
MASTER_KEY=<your key> docker compose up --build -d

# 2. Seed the demo cast (dev only; safe to re-run)
docker compose exec api python -m app seed-demo

# 3. Run the guided tour from the host
uv run python -m scripts.walkthrough
```

The walkthrough prints one labeled line per step and stops at the first
failure. When it finishes, `POST /v1/audit/verify` reports the chain valid and
the log shows both allowed and denied actions from the tour.

## Demo credentials

All accounts are seeded with TOTP already enrolled. The passwords and TOTP
secrets below are fixed and public on purpose: they only work on a local demo
instance. `seed-demo` refuses to run unless `ENV=dev`, and the walkthrough
refuses non localhost targets without `--allow-remote`.

To log in by hand: `POST /v1/auth/login` with the username and password
returns `mfa_required` plus a `pending_token`, then
`POST /v1/auth/mfa/verify` with that token and the current TOTP code (any
authenticator app, or `pyotp.TOTP(<secret>).now()`) returns the session cookie.

| Username | Password | Role | Clearance | TOTP secret |
|---|---|---|---|---|
| `demo-admin` | `DemoAdmin!Passw0rd2026` | admin | Top Secret | `HGX2B3UCVEEIXLSPGU67PJYGTNTOI7W5` |
| `demo-auditor` | `DemoAudit!Passw0rd2026` | auditor | Unclassified | `DHEAXCEYQVYTMD2TMH6VFNUUBVA7KM6G` |
| `demo-officer-low` | `DemoLow!Passw0rd2026` | user | Confidential | `EMOLQZ42KF4Q4ESKNA2PHLGUZA6SGZEF` |
| `demo-officer-mid` | `DemoMid!Passw0rd2026` | user | Secret | `7FYUBYS5CRWCX4726EOHRJGC7HVFQMYK` |
| `demo-officer-high` | `DemoHigh!Passw0rd2026` | user | Top Secret | `HBBDP2RXNGWFC6ZVV22RJEFBCR7CJRMD` |

## What each step demonstrates

1. **Logins**: every persona completes password login plus the TOTP challenge,
   the same flow a real enrolled user follows.
2. **Admin surfaces**: profile read and user list.
3. **Role denial**: admin and auditor get 403 on document routes; auditor gets
   403 on user administration. Deny by default in action.
4. **Uploads**: `demo-officer-mid` uploads a Secret `.docx`,
   `demo-officer-high` uploads Top Secret `.txt` files. Uploads are pinned to
   the writer's clearance.
5. **Denied read**: `demo-officer-low` (Confidential) is denied the Secret
   document, which raises a `denied_access` alert.
6. **Search**: `demo-officer-low`'s search for the document's unique token
   returns nothing; `demo-officer-mid`'s finds it, proving `.docx` text
   extraction feeds the index.
7. **Sensitive read**: `demo-officer-high` downloads the Top Secret content,
   which raises a `sensitive_read` alert.
8. **Versions**: edit creates version two, the version list shows it current,
   version one content downloads, and restore appends version three copying
   version one.
9. **Sharing**: `demo-officer-mid` grants `demo-officer-low` a share; the
   grantee sees it in `shares/mine` and can read the Secret document despite
   lower clearance; after revoke the read is denied again.
10. **Delete**: `demo-officer-high` deletes its disposable document.
11. **Alerts**: `demo-auditor` lists the open alerts and acknowledges the
   `denied_access` one (self acknowledge is denied by design).
12. **Audit**: entries cover allowed and denied actions and
    `POST /v1/audit/verify` reports the hash chain valid.

## Options and repeat runs

- `--base-url URL` or `WALKTHROUGH_BASE_URL` picks the target; the default is
  `http://localhost:8000`.
- Non localhost targets need `--allow-remote`, so demo passwords are never
  sent to an arbitrary host by accident.
- Rate limits are per client IP, so all localhost logins share the auth
  bucket. For repeated demos set `RATE_LIMIT_ENABLED=false` in `.env` (or the
  compose environment) and restart; the walkthrough prints this hint on any
  429.
- `seed-demo` is idempotent: rerun it any time, it reports `created`,
  `repaired`, or `exists` per user and tops up only drifted fields.
- Uploaded demo documents persist between runs; titles carry a per run unique
  suffix so nothing collides.
