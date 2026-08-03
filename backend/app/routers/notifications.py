
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import enforce_csrf, get_current_user
from app.models import User
from app.pagination import PageParams, to_paginated_response
from app.schemas import NotificationOut, UnreadCountOut
from app.services import NotificationService

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("", response_model=dict)
async def list_notifications(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
    is_read: bool | None = Query(default=None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Возвращает уведомления текущего пользователя."""
    items, total = await NotificationService(db).list(current_user.id, page, size, is_read)
    return to_paginated_response(items, total, PageParams(page=page, size=size)).model_dump()


@router.get("/unread-count", response_model=UnreadCountOut)
async def unread_count(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UnreadCountOut:
    """Возвращает количество непрочитанных уведомлений."""
    count = await NotificationService(db).unread_count(current_user.id)
    return UnreadCountOut(count=count)


@router.patch("/{notification_id}/read", response_model=NotificationOut)
async def mark_read(
    notification_id: int,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> NotificationOut:
    """Помечает уведомление как прочитанное."""
    item = await NotificationService(db).mark_read(notification_id, current_user.id)
    return NotificationOut(
        id=item.id,
        type=item.type.value,
        comment_id=item.comment_id,
        is_read=item.is_read,
        created_at=item.created_at,
        context=None,
    )


@router.patch("/read-all", status_code=status.HTTP_204_NO_CONTENT)
async def mark_all_read(
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Помечает все уведомления пользователя как прочитанные."""
    await NotificationService(db).mark_all_read(current_user.id)
