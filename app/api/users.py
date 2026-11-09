"""Admin user administration endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import limiter
from app.api.deps import require_role
from app.core.config import get_settings
from app.core.database import get_db
from app.models import User, UserRole
from app.schemas.users import (
    ResetPasswordRequest,
    UserAdminCreate,
    UserAdminPatch,
    UserListResponse,
    UserLookupResponse,
    UserProfile,
)
from app.services import mfa as mfa_service
from app.services import users as users_service

router = APIRouter(prefix="/v1/users", tags=["users"])


def _lookup_limit():
    settings = get_settings()
    return settings.rate_limit_user_lookup if settings.rate_limit_enabled else "1000000/minute"


@router.get("/lookup", response_model=UserLookupResponse)
@limiter.limit(_lookup_limit)
async def lookup_users(
    request: Request,
    username: str = Query(min_length=2, max_length=64),
    limit: int = Query(default=20, ge=1, le=20),
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("user.lookup", UserRole.USER)),
):
    rows = await users_service.lookup_users(
        db, actor, prefix=username, limit=limit, path=request.url.path
    )
    return UserLookupResponse(users=rows)


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
