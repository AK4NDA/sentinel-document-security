"""Authentication endpoints: login, logout, me."""

from fastapi import APIRouter, Depends, Request, Response, status
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentAuth, CurrentUser
from app.core.config import get_settings
from app.core.database import get_db
from app.models import User
from app.schemas.auth import LoginRequest, UserProfile
from app.services import auth as auth_service

router = APIRouter(prefix="/v1/auth", tags=["auth"])
limiter = Limiter(key_func=get_remote_address)


def _set_session_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        settings.session_cookie_name,
        token,
        path="/",
        httponly=True,
        samesite="lax",
        secure=settings.env == "prod",
    )


@router.post("/login", response_model=UserProfile)
@limiter.limit(
    lambda: (
        get_settings().rate_limit_auth if get_settings().rate_limit_enabled else "1000000/minute"
    )
)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    user, token = await auth_service.login(
        db,
        username=body.username,
        password=body.password,
        request=request,
    )
    _set_session_cookie(response, token)
    return user


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    auth: CurrentAuth,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    await auth_service.logout(db, auth)
    response.delete_cookie(get_settings().session_cookie_name, path="/")


@router.get("/me", response_model=UserProfile)
async def me(user: CurrentUser) -> User:
    return user
