"""Opaque server side sessions (spec 0001/0002)."""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models import Session as UserSession
from app.models import User

ABSOLUTE_CAP = timedelta(hours=24)
LAST_SEEN_MIN_INTERVAL = timedelta(minutes=1)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _expiry(created_at: datetime, now: datetime) -> datetime:
    idle = now + timedelta(seconds=get_settings().session_ttl_seconds)
    absolute = _aware(created_at) + ABSOLUTE_CAP
    return min(idle, absolute)


async def create(
    db: AsyncSession,
    user: User,
    *,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[str, UserSession]:
    token = secrets.token_urlsafe(32)
    now = datetime.now(UTC)
    row = UserSession(
        user_id=user.id,
        token_hash=_hash_token(token),
        created_at=now,
        last_seen_at=now,
        expires_at=_expiry(now, now),
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(row)
    await db.flush()
    return token, row


async def validate(db: AsyncSession, token: str) -> tuple[UserSession, User] | None:
    """Return (session, user) for a live token, sliding expiry forward."""
    result = await db.execute(
        select(UserSession, User)
        .join(User, User.id == UserSession.user_id)
        .where(UserSession.token_hash == _hash_token(token))
    )
    pair = result.first()
    if pair is None:
        return None
    session_row, user = pair
    now = datetime.now(UTC)
    expires_at = _aware(session_row.expires_at)
    if session_row.revoked_at is not None or expires_at <= now:
        return None
    if not user.is_active:
        return None
    last_seen = _aware(session_row.last_seen_at)
    if now - last_seen >= LAST_SEEN_MIN_INTERVAL:
        session_row.last_seen_at = now
        session_row.expires_at = _expiry(_aware(session_row.created_at), now)
        # Commit so the slide persists even on routes that never write; the
        # throttle keeps this to at most one write per minute per session.
        await db.commit()
    return session_row, user


async def revoke(db: AsyncSession, token: str) -> None:
    result = await db.execute(
        select(UserSession).where(UserSession.token_hash == _hash_token(token))
    )
    row = result.scalar_one_or_none()
    if row is not None and row.revoked_at is None:
        row.revoked_at = datetime.now(UTC)
        await db.flush()
