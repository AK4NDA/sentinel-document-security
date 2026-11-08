"""Admin user administration endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core.database import get_db
from app.models import User, UserRole
from app.schemas.users import (
    ResetPasswordRequest,
    UserAdminCreate,
    UserAdminPatch,
    UserListResponse,
    UserProfile,
)
from app.services import mfa as mfa_service
from app.services import users as users_service

router = APIRouter(prefix="/v1/users", tags=["users"])


@router.post("", response_model=UserProfile, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserAdminCreate,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("user.create", UserRole.ADMIN)),
):
    try:
        user = await users_service.create_user(db, body, actor)
    except users_service.DuplicateUser:
        raise HTTPException(status.HTTP_409_CONFLICT, "username or email already exists") from None
    return user


@router.get("", response_model=UserListResponse)
async def list_users(
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("user.list", UserRole.ADMIN)),
):
    rows = await users_service.list_users(db, actor)
    return UserListResponse(users=rows)


@router.patch("/{user_id}", response_model=UserProfile)
async def patch_user(
    user_id: uuid.UUID,
    body: UserAdminPatch,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("user.privilege_update", UserRole.ADMIN)),
):
    return await users_service.patch_user(db, actor, user_id, body)


@router.post("/{user_id}/disable", status_code=status.HTTP_204_NO_CONTENT)
async def disable_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("user.disabled", UserRole.ADMIN)),
):
    await users_service.set_active(db, actor, user_id, active=False)


@router.post("/{user_id}/enable", status_code=status.HTTP_204_NO_CONTENT)
async def enable_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("user.enabled", UserRole.ADMIN)),
):
    await users_service.set_active(db, actor, user_id, active=True)


@router.post("/{user_id}/sessions/revoke", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_user_sessions(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("session.revoke_all", UserRole.ADMIN)),
):
    await users_service.revoke_sessions(db, actor, user_id)


@router.post("/{user_id}/reset-password", status_code=status.HTTP_204_NO_CONTENT)
async def reset_user_password(
    user_id: uuid.UUID,
    body: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("user.password_reset", UserRole.ADMIN)),
):
    await users_service.reset_password(db, actor, user_id, body.new_password)


@router.post("/{user_id}/mfa/reset", status_code=status.HTTP_204_NO_CONTENT)
async def reset_user_mfa(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("mfa.reset", UserRole.ADMIN)),
):
    target = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    await mfa_service.reset_mfa(db, target, actor)
