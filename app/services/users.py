"""Admin user administration (spec 0003 AC-4, AC-5)."""

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import User
from app.schemas.users import UserCreate
from app.security import passwords
from app.services import audit


async def create_user(db: AsyncSession, payload: UserCreate, actor: User) -> User:
    snapshot = audit.actor_kwargs(actor)

    async def attempt(session: AsyncSession) -> User:
        user = User(
            username=payload.username,
            email=payload.email,
            display_name=payload.display_name,
            password_hash=passwords.hash_password(payload.password),
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
