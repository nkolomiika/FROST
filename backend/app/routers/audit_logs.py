from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import Text, and_, cast, func, not_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import require_admin
from app.models import AuditLog, User
from app.pagination import PageParams, to_paginated_response
from app.schemas import AuditLogOut

router = APIRouter(prefix="/audit-logs", tags=["audit"])


@router.get("", response_model=dict)
async def list_audit_logs(
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    user_id: int | None = None,
    username: str | None = None,
    action: str | None = None,
    entity_type: str | None = None,
    entity_id: int | None = None,
    ip_address: str | None = None,
    query: str | None = None,
    created_from: str | None = None,
    created_to: str | None = None,
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Возвращает журнал действий с фильтрацией."""
    stmt = select(AuditLog, User.username).outerjoin(User, User.id == AuditLog.user_id)
    conditions = [
        # Скрываем LOGIN-события, инициированные refresh-токеном: они шумные
        # и не отражают реальной активности пользователя.
        not_(and_(AuditLog.action == "LOGIN", AuditLog.details["source"].as_string() == "refresh"))
    ]
    if user_id:
        conditions.append(AuditLog.user_id == user_id)
    if username:
        conditions.append(User.username.ilike(f"%{username.strip()}%"))
    if action:
        conditions.append(AuditLog.action.ilike(f"%{action.strip()}%"))
    if entity_type:
        conditions.append(AuditLog.entity_type.ilike(f"%{entity_type.strip()}%"))
    if entity_id:
        conditions.append(AuditLog.entity_id == entity_id)
    if ip_address:
        conditions.append(AuditLog.ip_address.ilike(f"%{ip_address.strip()}%"))
    if query is not None and query.strip():
        query_value = f"%{query.strip()}%"
        # Поиск по «всему сразу»: action / entity_type / username / ip / detail-JSON.
        # cast(details, Text) — Postgres приводит jsonb к строке, на маленьких объёмах
        # это приемлемо. Если станет узко — добавить GIN-индекс на details.
        conditions.append(
            or_(
                AuditLog.action.ilike(query_value),
                AuditLog.entity_type.ilike(query_value),
                AuditLog.ip_address.ilike(query_value),
                User.username.ilike(query_value),
                cast(AuditLog.details, Text).ilike(query_value),
            )
        )
    if created_from:
        try:
            conditions.append(AuditLog.created_at >= datetime.fromisoformat(created_from.replace("Z", "+00:00")))
        except ValueError:
            pass
    if created_to:
        try:
            conditions.append(AuditLog.created_at <= datetime.fromisoformat(created_to.replace("Z", "+00:00")))
        except ValueError:
            pass
    stmt = stmt.where(and_(*conditions))
    total = await db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = (
        await db.execute(stmt.order_by(AuditLog.created_at.desc()).offset((page - 1) * size).limit(size))
    ).all()
    total_count = total if isinstance(total, int) else 0
    payload = [
        AuditLogOut.model_validate(
            {
                "id": item.id,
                "user_id": item.user_id,
                "username": joined_username,
                "action": item.action,
                "entity_type": item.entity_type,
                "entity_id": item.entity_id,
                "details": item.details,
                "ip_address": item.ip_address,
                "created_at": item.created_at,
            }
        )
        for item, joined_username in rows
    ]
    return to_paginated_response(payload, total_count, PageParams(page=page, size=size)).model_dump()
