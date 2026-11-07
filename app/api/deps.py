"""Request authentication and role gate dependencies."""

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.models import User, UserRole
from app.models.session import Session as UserSession
from app.services import audit, sessions


@dataclass
class AuthContext:
    user: User
    token: str
    session: UserSession


def extract_token(request: Request) -> str | None:
    settings = get_settings()
    cookie = request.cookies.get(settings.session_cookie_name)
    if cookie:
        return cookie
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() == "bearer" and token:
        return token
    return None


async def get_auth(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AuthContext:
    token = extract_token(request)
    if token is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
    result = await sessions.validate(db, token)
    if result is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid session")
    session_row, user = result
    return AuthContext(user=user, token=token, session=session_row)


async def current_user(auth: Annotated[AuthContext, Depends(get_auth)]) -> User:
    return auth.user


CurrentUser = Annotated[User, Depends(current_user)]
CurrentAuth = Annotated[AuthContext, Depends(get_auth)]


def require_role(action: str, *roles: UserRole):
    """Dependency factory: authenticated user whose role is in `roles`.

    Role denials are audited; the operation itself audits its own outcome.
    """

    async def dependency(
        auth: CurrentAuth,
        db: Annotated[AsyncSession, Depends(get_db)],
    ) -> User:
        if auth.user.role not in roles:
            await audit.record_denial(
                db,
                action=action,
                actor=auth.user,
                reason="role",
                target_type="user",
                target_id=str(auth.user.id),
            )
            raise HTTPException(status.HTTP_403_FORBIDDEN, "forbidden")
        return auth.user

    return dependency
