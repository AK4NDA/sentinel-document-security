"""Authentication endpoints: login, MFA challenge and enrollment, logout, me."""

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentAuth, CurrentUser
from app.core.config import get_settings
from app.core.database import get_db
from app.models import User
from app.schemas.auth import (
    LoginRequest,
    MfaEnrollConfirmRequest,
    MfaEnrollStartResponse,
    MfaRequiredResponse,
    MfaVerifyRequest,
    UserProfile,
)
from app.services import audit
from app.services import auth as auth_service
from app.services import mfa as mfa_service


async def _deny_already_enrolled(db: AsyncSession, user: User) -> None:
    await audit.record_denial(
        db,
        action="mfa.enroll",
        reason="already_enrolled",
        actor=user,
        target_type="user",
        target_id=str(user.id),
    )
    raise HTTPException(status.HTTP_403_FORBIDDEN, "mfa already enrolled")


router = APIRouter(prefix="/v1/auth", tags=["auth"])


def _auth_limit():
    settings = get_settings()
    return settings.rate_limit_auth if settings.rate_limit_enabled else "1000000/minute"


def _default_limit():
    settings = get_settings()
    return settings.rate_limit_default if settings.rate_limit_enabled else "1000000/minute"


limiter = Limiter(key_func=get_remote_address, default_limits=[_default_limit])


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


@router.post("/login")
@limiter.limit(_auth_limit)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    outcome = await auth_service.login(
        db,
        username=body.username,
        password=body.password,
        request=request,
    )
    if outcome.session_token is not None:
        _set_session_cookie(response, outcome.session_token)
        return UserProfile.model_validate(outcome.user)
    return MfaRequiredResponse(
        pending_token=outcome.pending_token or "",
        expires_in=outcome.challenge_expires_in or 0,
    )


@router.post("/mfa/verify")
@limiter.limit(_auth_limit)
async def mfa_verify(
    body: MfaVerifyRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    result = await mfa_service.verify_challenge(
        db,
        pending_token=body.pending_token,
        code=body.code,
        ip_address=ip,
        user_agent=ua,
    )
    if result.outcome == "locked":
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"reason": "locked", "retry_after_seconds": result.retry_after},
        )
    if result.outcome != "ok" or result.session_token is None or result.user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    _set_session_cookie(response, result.session_token)
    return UserProfile.model_validate(result.user)


@router.post("/mfa/enroll/start", response_model=MfaEnrollStartResponse)
@limiter.limit(_auth_limit)
async def mfa_enroll_start(
    request: Request,
    auth: CurrentAuth,
    db: AsyncSession = Depends(get_db),
):
    if auth.user.totp_enabled_at is not None:
        await _deny_already_enrolled(db, auth.user)
    _secret, uri, qr = await mfa_service.start_enrollment(db, auth.user)
    return MfaEnrollStartResponse(secret=_secret, otpauth_uri=uri, qr_svg=qr)


@router.post("/mfa/enroll/confirm", response_model=UserProfile)
@limiter.limit(_auth_limit)
async def mfa_enroll_confirm(
    body: MfaEnrollConfirmRequest,
    request: Request,
    auth: CurrentAuth,
    db: AsyncSession = Depends(get_db),
):
    if auth.user.totp_enabled_at is not None:
        await _deny_already_enrolled(db, auth.user)
    ok = await mfa_service.confirm_enrollment(db, auth.user, body.code)
    if not ok:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid code")
    await db.refresh(auth.user)
    return auth.user


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
