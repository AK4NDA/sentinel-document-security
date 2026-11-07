# Rationale, MFA and login protection

## Context

Spec 0003 shipped password only login with opaque sessions, per IP rate limiting, and audit coverage, but deliberately deferred the second factor and lockout policy: the user model already carries `totp_secret_encrypted`, `totp_enabled_at`, `failed_login_attempts`, and `locked_until`, and `pyotp` is already a dependency. The scope row for this feature asks for three things: TOTP enrollment and a login challenge, throttling of repeated failures, and session revocation guarantees. Session revocation on logout already exists, so the real work is the MFA strand plus giving the dormant lockout columns an enforcement policy.

Forces shaping the choices:

- This is a classified document system; credential theft is the highest value attack, so MFA is mandatory for every role, not an opt in extra.
- The product must stay demoable with no external services, so recovery cannot depend on SMS or email; an admin reset is the only recovery channel that fits.
- The audit log is the product's proof; every MFA decision, allowed or denied, must land in it.
- Spec 0003 established the hashed opaque token pattern for sessions; pending login tokens should mirror it rather than invent a second mechanism.
- Existing users must keep working with no forced migration, so unenrolled accounts need a graceful path, not a lockout.

## Options considered

### Pending token storage

- **New `mfa_challenges` table (chosen)**: hashed token, user FK, 5 minute expiry, attempt counter, consumed marker. Clean separation from sessions, revocable, countable. Costs one table and one migration.
- **Reuse `sessions` with an `mfa_verified` flag**: fewer tables but a "session" that cannot call anything until verified muddies the session invariant and complicates every auth check.
- **Stateless signed token**: no table at all, but cannot be revoked, expired server side, or have its verify attempts counted, which the lockout design needs.

### Enrollment secret storage

- **Reuse `totp_secret_encrypted` with NULL `totp_enabled_at` (chosen)**: the columns already exist for exactly this; an abandoned enrollment leaves an encrypted blob that is simply overwritten on retry.
- **Separate pending secret column**: marginally cleaner state separation but adds a column that exists only during a seconds long window.

### TOTP replay protection

- **`totp_last_counter` monotonic guard (chosen)**: one integer column rejects reuse of a code inside its validity window; cheap and closes a real replay hole.
- **No replay protection**: simpler, but a code observed once (shoulder surfing, log leak) works repeatedly for about 90 seconds.

### Login response shape

- **200 with `mfa_required` flag (chosen)**: the challenge is a normal outcome of login, not an error; clients branch on a field.
- **401 style challenge**: treats a normal flow as an error status; workable but misleading semantics.
- **Separate challenge endpoint for everyone**: uniform but adds a round trip for unenrolled users and complicates the common path.

### QR code generation

- **`segno` server side SVG (chosen)**: pure Python, no system dependencies, returns an image plus the otpauth URI so any client can render its own.
- **otpauth URI only**: zero new dependencies but pushes QR rendering to every client and hurts the demo experience.

### Recovery from lost device

- **Admin reset only (chosen)**: `POST /v1/users/{id}/mfa/reset` clears the enrollment, revokes all sessions, deletes pending challenges, audited. Fits the admin surface that already exists and needs no new user facing machinery.
- **Recovery codes**: better UX on device loss but adds generation, hashing, storage, and a second login credential type; deferred as follow up.
- **Both**: most resilient but the largest surface for a slice whose core promise is the challenge itself.

### Lockout policy

- **5 attempts, 15 minute cool down (chosen)**: strict enough to matter against online guessing, forgiving enough not to lock out legitimate users fat fingering codes; failed TOTP and password attempts share one counter.
- **3 tries, 5 minutes**: stricter but punishes honest mistakes during enrollment.
- **10 tries, 30 minutes**: looser; still bounded but gives an attacker a wider window per lockout cycle.

### Session concurrency

- **Multiple sessions allowed (chosen)**: matches how people actually use phones and laptops; revocation stays per session plus the admin reset that kills all of them.
- **Single active session**: a stolen session dies on next login but logs out the user's other devices constantly, which is hostile for a work tool.

## Rationale

The chosen design extends two proven patterns rather than adding new machinery: sessions already solve hashed opaque tokens with sliding expiry, and `mfa_challenges` is the same idea with a five minute life and a single use flag. Reusing the existing TOTP columns keeps the migration to one table plus one column. The enrollment gate on `totp_enabled_at IS NULL` makes the pre MFA state a first class, auditable state instead of a special case, which is what keeps deny by default honest for users mid enrollment. Lockout numbers were picked to bound guessing without punishing honest users, and admin reset was chosen over recovery codes because it reuses the admin surface and keeps the credential types to exactly two (password, TOTP).

## References

None recorded; the design rests on the project's own spec 0003 session and audit patterns plus standard TOTP practice (RFC 6238, 30 second step, ±1 step skew).
