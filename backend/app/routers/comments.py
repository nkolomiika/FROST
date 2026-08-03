
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import enforce_csrf, get_current_user, require_project_access
from app.models import User
from app.pagination import PageParams, to_paginated_response
from app.schemas import CommentCreate, CommentOut, CommentUpdate
from app.services import CommentService

router = APIRouter(tags=["comments"])


@router.get("/projects/{project_id}/vulnerabilities/{vuln_id}/comments", response_model=dict)
async def list_comments(
    project_id: int,
    vuln_id: int,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Возвращает комментарии уязвимости."""
    items, total = await CommentService(db).list(vuln_id, page, size)
    return to_paginated_response(items, total, PageParams(page=page, size=size)).model_dump()


@router.post("/projects/{project_id}/vulnerabilities/{vuln_id}/comments", response_model=CommentOut, status_code=status.HTTP_201_CREATED)
async def create_comment(
    project_id: int,
    vuln_id: int,
    payload: CommentCreate,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> CommentOut:
    """Создаёт комментарий и обрабатывает упоминания."""
    return await CommentService(db).create(project_id, vuln_id, payload.content, current_user)


@router.put("/projects/{project_id}/vulnerabilities/{vuln_id}/comments/{comment_id}", response_model=CommentOut)
async def update_comment(
    project_id: int,
    vuln_id: int,
    comment_id: int,
    payload: CommentUpdate,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> CommentOut:
    """Редактирует комментарий."""
    return await CommentService(db).update(project_id, vuln_id, comment_id, payload.content, current_user)


@router.delete("/projects/{project_id}/vulnerabilities/{vuln_id}/comments/{comment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_comment(
    project_id: int,
    vuln_id: int,
    comment_id: int,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Удаляет комментарий."""
    await CommentService(db).delete(project_id, vuln_id, comment_id, current_user)
