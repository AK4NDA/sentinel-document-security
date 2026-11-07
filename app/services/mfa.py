"""TOTP enrollment, login challenge exchange, and admin reset (spec 0004)."""

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models import MfaChallenge, User
from app.models import Session as UserSession
from app.security import totp
from app.services import audit, lockout, sessions

ENROLL_ACTION = "mfa.enroll"
VERIFY_ACTION = "mfa.verify"
RESET_ACTION = "mfa.reset"
CHALLENGE_MAX_ATTEMPTS = 5

VerifyOutcome = Literal["ok", "invalid", "locked"]


@dataclass
class VerifyResult:
    outcome: VerifyOutcome
    user: User | None = None
    session_token: str | None = None
    retry_after: int = 0


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _challenge_usable(row: MfaChallenge, now: datetime) -> bool:
    return (
        row.consumed_at is None
        and _aware(row.expires_at) > now
        and row.attempts < CHALLENGE_MAX_ATTEMPTS
    )


async def create_challenge(db: AsyncSession, user: User) -> tuple[str, int]:
    """Issue a pending token; deletes the user's prior unconsumed challenges."""
    await db.execute(
        delete(MfaChallenge).where(
            MfaChallenge.user_id == user.id,
            MfaChallenge.consumed_at.is_(None),
        )
    )
    token = secrets.token_urlsafe(32)
    ttl = get_settings().mfa_challenge_ttl_seconds
    now = datetime.now(UTC)
    row = MfaChallenge(
        user_id=user.id,
        token_hash=_hash_token(token),
        created_at=now,
        expires_at=now + timedelta(seconds=ttl),
        attempts=0,
    )
    db.add(row)
    await db.flush()
    return token, ttl


async def start_enrollment(db: AsyncSession, user: User) -> tuple[str, str, str]:
    """Generate and store a fresh pending secret; returns (secret, uri, qr_svg)."""
    snapshot = audit.actor_kwargs(user)
    secret = totp.generate_secret()
    uri = totp.provisioning_uri(user.username, secret)
    qr = totp.qr_svg(uri)

    async def attempt(session: AsyncSession):
        fresh = await session.get(User, user.id)
        assert fresh is not None
        fresh.totp_secret_encrypted = totp.seal_secret(secret)
        fresh.totp_enabled_at = None
        fresh.totp_last_counter = None
        await audit.append(
            session,
            action=ENROLL_ACTION,
            outcome="allowed",
            target_type="user",
            target_id=str(fresh.id),
            details={"stage": "start"},
            **snapshot,
        )

    try:
        await audit.transact(db, attempt)
    except audit.AuditChainFork:
        from fastapi import HTTPException

        raise HTTPException(500) from None
    return secret, uri, qr


async def confirm_enrollment(db: AsyncSession, user: User, code: str) -> bool:
    """Confirm a pending secret with a valid code; audits the outcome."""
    snapshot = audit.actor_kwargs(user)
    user_id = user.id

    async def attempt(session: AsyncSession) -> bool:
        fresh = await session.get(User, user_id)
        assert fresh is not None
        if fresh.totp_secret_encrypted is None or fresh.totp_enabled_at is not None:
            await audit.append(
                session,
                action=ENROLL_ACTION,
                outcome="denied",
                target_type="user",
                target_id=str(fresh.id),
                details={"stage": "confirm", "reason": "not_pending"},
                **snapshot,
            )
            return False
        secret = totp.open_secret(fresh.totp_secret_encrypted)
        step = totp.verify_code(secret, code, fresh.totp_last_counter)
        if step is None:
            lockout.record_failure(fresh)
            await audit.append(
                session,
                action=ENROLL_ACTION,
                outcome="denied",
                target_type="user",
                target_id=str(fresh.id),
                details={"stage": "confirm", "reason": "invalid_code"},
                **snapshot,
            )
            return False
        fresh.totp_enabled_at = datetime.now(UTC)
        fresh.totp_last_counter = step
        lockout.record_success(fresh)
        await audit.append(
            session,
            action=ENROLL_ACTION,
            outcome="allowed",
            target_type="user",
            target_id=str(fresh.id),
            details={"stage": "confirm"},
            **snapshot,
        )
        return True

    try:
        return await audit.transact(db, attempt)
    except audit.AuditChainFork:
        from fastapi import HTTPException

        raise HTTPException(500) from None


async def verify_challenge(
    db: AsyncSession,
    *,
    pending_token: str,
    code: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> VerifyResult:
    """Exchange a pending token plus TOTP code for a real session."""
    now = datetime.now(UTC)
    result = await db.execute(
        select(MfaChallenge).where(MfaChallenge.token_hash == _hash_token(pending_token))
    )
    challenge = result.scalar_one_or_none()
    actor: User | None = None
    if challenge is not None:
        actor = (
            await db.execute(select(User).where(User.id == challenge.user_id))
        ).scalar_one_or_none()
    snapshot = audit.actor_kwargs(actor)

    async def deny(reason: str, status_hint: str = "invalid") -> VerifyResult:
        await audit.append(
            db,
            action=VERIFY_ACTION,
            outcome="denied",
            target_type="user",
            target_id=str(actor.id) if actor else None,
            details={"reason": reason},
            **snapshot,
        )
        await db.commit()
        if status_hint == "locked":
            return VerifyResult(
                outcome="locked",
                retry_after=lockout.retry_after_seconds(actor) if actor else 0,
            )
        return VerifyResult(outcome="invalid")

    if challenge is None or not _challenge_usable(challenge, now):
        if challenge is None:
            reason = "challenge_invalid"
        elif challenge.consumed_at is not None or challenge.attempts >= CHALLENGE_MAX_ATTEMPTS:
            reason = "challenge_consumed"
        elif _aware(challenge.expires_at) <= now:
            reason = "expired_challenge"
        else:
            reason = "challenge_invalid"
        return await deny(reason)

    user = actor
    if user is None or not user.is_active or user.totp_enabled_at is None:
        return await deny("user_unavailable")
    if lockout.is_locked(user, now):
        return await deny("locked", status_hint="locked")

    secret = totp.open_secret(user.totp_secret_encrypted) if user.totp_secret_encrypted else ""
    step = totp.verify_code(secret, code, user.totp_last_counter) if secret else None
    if step is None:
        challenge.attempts += 1
        lockout.record_failure(user)
        if challenge.attempts >= CHALLENGE_MAX_ATTEMPTS:
            challenge.consumed_at = now
        await deny("invalid_code")
        return VerifyResult(outcome="invalid")

    challenge_id = challenge.id
    user_id = user.id

    async def attempt(session: AsyncSession) -> VerifyResult:
        fresh_challenge = await session.get(MfaChallenge, challenge_id)
        fresh_user = await session.get(User, user_id)
        assert fresh_challenge is not None and fresh_user is not None
        fresh_challenge.consumed_at = datetime.now(UTC)
        fresh_user.totp_last_counter = step
        lockout.record_success(fresh_user)
        token, _row = await sessions.create(
            session, fresh_user, ip_address=ip_address, user_agent=user_agent
        )
        await audit.append(
            session,
            action=VERIFY_ACTION,
            outcome="allowed",
            target_type="user",
            target_id=str(fresh_user.id),
            **audit.actor_kwargs(fresh_user),
        )
        return VerifyResult(outcome="ok", user=fresh_user, session_token=token)

    try:
        return await audit.transact(db, attempt)
    except audit.AuditChainFork:
        from fastapi import HTTPException

        raise HTTPException(500) from None


async def reset_mfa(db: AsyncSession, target: User, actor: User) -> None:
    """Admin reset: clear TOTP fields, revoke sessions, delete challenges."""
    snapshot = audit.actor_kwargs(actor)
    target_id = target.id

    async def attempt(session: AsyncSession) -> None:
        target_user = await session.get(User, target_id)
        assert target_user is not None
        target_user.totp_secret_encrypted = None
        target_user.totp_enabled_at = None
        target_user.totp_last_counter = None
        now = datetime.now(UTC)
        for row in (
            await session.execute(
                select(UserSession).where(
                    UserSession.user_id == target_user.id,
                    UserSession.revoked_at.is_(None),
                )
            )
        ).scalars():
            row.revoked_at = now
        await session.execute(delete(MfaChallenge).where(MfaChallenge.user_id == target_user.id))
        await audit.append(
            session,
            action=RESET_ACTION,
            outcome="allowed",
            target_type="user",
            target_id=str(target_user.id),
            **snapshot,
        )

    try:
        await audit.transact(db, attempt)
    except audit.AuditChainFork:
        from fastapi import HTTPException

        raise HTTPException(500) from None
