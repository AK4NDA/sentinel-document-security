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


ENROLLMENT_EXEMPT_PATHS = frozenset(
    {
        "/v1/auth/mfa/enroll/start",
        "/v1/auth/mfa/enroll/confirm",
        "/v1/auth/me",
        "/v1/auth/logout",
    }
)

# Audit action each protected route would use; the enrollment gate denial is
# recorded under it so the row reads like any other authorization denial.
GATE_ACTIONS: dict[tuple[str, str], str] = {
    ("POST", "/v1/documents"): "document.upload",
    ("GET", "/v1/documents"): "document.list",
    ("GET", "/v1/documents/search"): "document.search",
    ("GET", "/v1/documents/{doc_id}"): "document.read",
    ("GET", "/v1/documents/{doc_id}/content"): "document.download",
    ("POST", "/v1/documents/{doc_id}/versions"): "document.edit",
    ("GET", "/v1/documents/{doc_id}/versions"): "document.versions_list",
    ("GET", "/v1/documents/{doc_id}/versions/{version_number}/content"): (
        "document.version_download"
    ),
    ("POST", "/v1/documents/{doc_id}/versions/{version_number}/restore"): (
        "document.version_restore"
    ),
    ("DELETE", "/v1/documents/{doc_id}"): "document.delete",
    ("POST", "/v1/users"): "user.create",
    ("GET", "/v1/users"): "user.list",
    ("PATCH", "/v1/users/{user_id}"): "user.privilege_update",
    ("POST", "/v1/users/{user_id}/disable"): "user.disabled",
    ("POST", "/v1/users/{user_id}/enable"): "user.enabled",
    ("POST", "/v1/users/{user_id}/sessions/revoke"): "session.revoke_all",
    ("POST", "/v1/users/{user_id}/reset-password"): "user.password_reset",
    ("POST", "/v1/users/{user_id}/mfa/reset"): "mfa.reset",
    ("GET", "/v1/audit/entries"): "audit.entries_list",
    ("POST", "/v1/audit/verify"): "audit.verify",
}


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
    if user.totp_enabled_at is None and request.url.path not in ENROLLMENT_EXEMPT_PATHS:
        route = request.scope.get("route")
        action = GATE_ACTIONS.get(
            (request.method, getattr(route, "path", "")), "mfa.enrollment_gate"
        )
        await audit.record_denial(
            db,
            action=action,
            reason="mfa_enrollment_required",
            actor=user,
            target_type="endpoint",
            target_id=request.url.path,
        )
        raise HTTPException(status.HTTP_403_FORBIDDEN, "mfa enrollment required")
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
