"""Login, logout, and session lifecycle (spec 0003 AC-2, AC-18; spec 0004)."""

from dataclasses import dataclass

from fastapi import HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import AuthContext
from app.models import User
from app.security import passwords
from app.services import audit, lockout, mfa, sessions

LOGIN_ACTION = "auth.login"
LOGOUT_ACTION = "auth.logout"


@dataclass
class LoginOutcome:
    user: User
    session_token: str | None = None
    pending_token: str | None = None
    challenge_expires_in: int | None = None


def _client_meta(request: Request) -> tuple[str | None, str | None]:
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    return ip, ua


async def _deny_login(
    session: AsyncSession,
    *,
    user: User | None,
    username: str,
    reason: str,
    count_failure: bool = True,
) -> None:
    if user is not None and count_failure:
        lockout.record_failure(user)
    await audit.append(
        session,
        action=LOGIN_ACTION,
        outcome="denied",
        target_type="user",
        target_id=str(user.id) if user else None,
        details={"attempted_username": username, "reason": reason},
        **audit.actor_kwargs(user),
    )


async def login(
    db: AsyncSession,
    *,
    username: str,
    password: str,
    request: Request,
) -> LoginOutcome:
    """Authenticate; returns a session token or an MFA pending token."""
    ip, ua = _client_meta(request)

    async def attempt(session: AsyncSession) -> tuple[str, LoginOutcome | None]:
        result = await session.execute(select(User).where(User.username == username))
        user = result.scalar_one_or_none()
        if user is None:
            await _deny_login(session, user=None, username=username, reason="unknown_user")
            return "unauthorized", None
        if lockout.is_locked(user):
            await _deny_login(
                session, user=user, username=username, reason="locked", count_failure=False
            )
            return "locked", None
        if not user.is_active:
            await _deny_login(session, user=user, username=username, reason="disabled")
            return "unauthorized", None
        if not await passwords.verify_password_async(user.password_hash, password):
            await _deny_login(session, user=user, username=username, reason="bad_password")
            return "unauthorized", None

        if user.totp_enabled_at is not None:
            pending_token, ttl = await mfa.create_challenge(session, user)
            await audit.append(
                session,
                action=LOGIN_ACTION,
                outcome="allowed",
                target_type="user",
                target_id=str(user.id),
                details={"attempted_username": username, "mfa_required": True},
                **audit.actor_kwargs(user),
            )
            return "ok", LoginOutcome(
                user=user, pending_token=pending_token, challenge_expires_in=ttl
            )

        lockout.record_success(user)
        token, _row = await sessions.create(session, user, ip_address=ip, user_agent=ua)
        await audit.append(
            session,
            action=LOGIN_ACTION,
            outcome="allowed",
            target_type="user",
            target_id=str(user.id),
            details={"attempted_username": username},
            **audit.actor_kwargs(user),
        )
        return "ok", LoginOutcome(user=user, session_token=token)

    try:
        status_kind, outcome = await audit.transact(db, attempt)
    except audit.AuditChainFork:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR) from None
    if status_kind == "locked":
        user = (
            await db.execute(select(User).where(User.username == username))
        ).scalar_one_or_none()
        retry = lockout.retry_after_seconds(user) if user else 0
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"reason": "locked", "retry_after_seconds": retry},
        )
    if outcome is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    return outcome


async def logout(db: AsyncSession, auth: AuthContext) -> None:
    await sessions.revoke(db, auth.token)
    await audit.append(
        db,
        action=LOGOUT_ACTION,
        outcome="allowed",
        target_type="session",
        target_id=str(auth.session.id),
        **audit.actor_kwargs(auth.user),
    )
    await db.commit()
