"""Share discovery endpoints (officer role only)."""

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core.database import get_db
from app.models import User, UserRole
from app.schemas.shares import SharedDocumentListResponse
from app.services import shares as shares_service

router = APIRouter(prefix="/v1/shares", tags=["shares"])

OFFICER = UserRole.USER


@router.get("/mine", response_model=SharedDocumentListResponse)
async def list_my_shares(
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("document.list_shared", OFFICER)),
):
    documents = await shares_service.list_mine(db, actor, path=request.url.path)
    return SharedDocumentListResponse(documents=documents)
