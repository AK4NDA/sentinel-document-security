"""Admin user administration (spec 0003 AC-4, AC-5; spec 0005)."""

import uuid
from datetime import UTC, datetime

from fastapi import HTTPException, status
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import MfaChallenge, User, UserRole
from app.models import Session as UserSession
from app.schemas.users import UserAdminPatch, UserCreate
from app.security import passwords
from app.services import audit

PATCH_ACTION = "user.privilege_update"


async def _append_denial(
    session: AsyncSession,
    action: str,
    snapshot: dict,
    user_id: uuid.UUID,
    reason: str,
    extra: dict | None = None,
) -> None:
    await audit.append(
        session,
        action=action,
        outcome="denied",
        target_type="user",
        target_id=str(user_id),
        details={"reason": reason, **(extra or {})},
        **snapshot,
    )


def _raise_for_kind(kind: str) -> None:
    if kind == "not_found":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    if kind != "ok":
        raise HTTPException(status.HTTP_409_CONFLICT, {"reason": kind})


async def patch_user(
    db: AsyncSession, actor: User, user_id: uuid.UUID, payload: UserAdminPatch
) -> User:
    snapshot = audit.actor_kwargs(actor)
    actor_id = actor.id

    async def attempt(session: AsyncSession) -> tuple[str, User | None]:
        target = await session.get(User, user_id)
        if target is None:
            await _append_denial(session, PATCH_ACTION, snapshot, user_id, "not_found")
            return "not_found", None
        if target.id == actor_id and payload.role is not None and payload.role != UserRole.ADMIN:
            await _append_denial(session, PATCH_ACTION, snapshot, user_id, "self_demotion")
            return "self_demotion", None
        old_role = target.role.value
        old_clearance = int(target.clearance)
        if payload.role is not None:
            target.role = payload.role
        if payload.clearance is not None:
            target.clearance = payload.clearance
        await audit.append(
            session,
            action=PATCH_ACTION,
            outcome="allowed",
            target_type="user",
            target_id=str(user_id),
            details={
                "role": {"old": old_role, "new": target.role.value},
                "clearance": {"old": old_clearance, "new": int(target.clearance)},
            },
            **snapshot,
        )
        return "ok", target

    try:
        kind, target = await audit.transact(db, attempt)
    except audit.AuditChainFork:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR) from None
    _raise_for_kind(kind)
    assert target is not None
    return target


async def set_active(db: AsyncSession, actor: User, user_id: uuid.UUID, *, active: bool) -> None:
    action = "user.enabled" if active else "user.disabled"
    snapshot = audit.actor_kwargs(actor)
    actor_id = actor.id

    async def attempt(session: AsyncSession) -> str:
        target = await session.get(User, user_id)
        if target is None:
            await _append_denial(session, action, snapshot, user_id, "not_found")
            return "not_found"
        if target.is_active == active:
            reason = "already_enabled" if active else "already_disabled"
            await _append_denial(
                session, action, snapshot, user_id, reason, {"is_active": target.is_active}
            )
            return reason
        if not active and target.id == actor_id:
            await _append_denial(session, action, snapshot, user_id, "self_disable")
            return "self_disable"
        old_active = target.is_active
        target.is_active = active
        if not active:
            await session.execute(delete(MfaChallenge).where(MfaChallenge.user_id == user_id))
        await audit.append(
            session,
            action=action,
            outcome="allowed",
            target_type="user",
            target_id=str(user_id),
            details={"is_active": {"old": old_active, "new": active}},
            **snapshot,
        )
        return "ok"

    try:
        kind = await audit.transact(db, attempt)
    except audit.AuditChainFork:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR) from None
    _raise_for_kind(kind)


async def _revoke_all_sessions(session: AsyncSession, user_id: uuid.UUID) -> int:
    now = datetime.now(UTC)
    result = await session.execute(
        update(UserSession)
        .where(
            UserSession.user_id == user_id,
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > now,
        )
        .values(revoked_at=now)
        .execution_options(synchronize_session=False)
    )
    return result.rowcount


async def revoke_sessions(db: AsyncSession, actor: User, user_id: uuid.UUID) -> None:
    action = "session.revoke_all"
    snapshot = audit.actor_kwargs(actor)

    async def attempt(session: AsyncSession) -> str:
        target = await session.get(User, user_id)
        if target is None:
            await _append_denial(session, action, snapshot, user_id, "not_found")
            return "not_found"
        count = await _revoke_all_sessions(session, user_id)
        await audit.append(
            session,
            action=action,
            outcome="allowed",
            target_type="user",
            target_id=str(user_id),
            details={"revoked_count": count},
            **snapshot,
        )
        return "ok"

    try:
        kind = await audit.transact(db, attempt)
    except audit.AuditChainFork:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR) from None
    _raise_for_kind(kind)


async def reset_password(
    db: AsyncSession, actor: User, user_id: uuid.UUID, new_password: str
) -> None:
    action = "user.password_reset"
    snapshot = audit.actor_kwargs(actor)

    async def attempt(session: AsyncSession) -> str:
        target = await session.get(User, user_id)
        if target is None:
            await _append_denial(session, action, snapshot, user_id, "not_found")
            return "not_found"
        password_hash = await passwords.hash_password_async(new_password)
        lockout_cleared = target.failed_login_attempts > 0 or target.locked_until is not None
        target.password_hash = password_hash
        target.failed_login_attempts = 0
        target.locked_until = None
        count = await _revoke_all_sessions(session, user_id)
        await session.execute(delete(MfaChallenge).where(MfaChallenge.user_id == user_id))
        await audit.append(
            session,
            action=action,
            outcome="allowed",
            target_type="user",
            target_id=str(user_id),
            details={"sessions_revoked": count, "lockout_cleared": lockout_cleared},
            **snapshot,
        )
        return "ok"

    try:
        kind = await audit.transact(db, attempt)
    except audit.AuditChainFork:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR) from None
    _raise_for_kind(kind)


async def create_user(db: AsyncSession, payload: UserCreate, actor: User) -> User:
    snapshot = audit.actor_kwargs(actor)

    async def attempt(session: AsyncSession) -> User:
        user = User(
            username=payload.username,
            email=payload.email,
            display_name=payload.display_name,
            password_hash=await passwords.hash_password_async(payload.password),
            role=payload.role,
            clearance=payload.clearance,
            is_active=True,
        )
        session.add(user)
        await session.flush()
        await audit.append(
            session,
            action="user.create",
            outcome="allowed",
            target_type="user",
            target_id=str(user.id),
            **snapshot,
        )
        return user

    try:
        return await audit.transact(db, attempt)
    except IntegrityError as exc:
        await db.rollback()
        raise DuplicateUser() from exc


async def list_users(db: AsyncSession, actor: User) -> list[User]:
    snapshot = audit.actor_kwargs(actor)

    async def attempt(session: AsyncSession):
        rows = (
            (await session.execute(select(User).order_by(User.created_at, User.id))).scalars().all()
        )
        await audit.append(
            session,
            action="user.list",
            outcome="allowed",
            target_type="user",
            **snapshot,
        )
        return list(rows)

    return await audit.transact(db, attempt)


class DuplicateUser(Exception):
    pass
