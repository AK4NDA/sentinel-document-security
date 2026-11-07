"""Admin user administration endpoints."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core.database import get_db
from app.models import User, UserRole
from app.schemas.users import UserAdminCreate, UserListResponse, UserProfile
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
