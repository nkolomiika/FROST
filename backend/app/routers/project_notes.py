
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import enforce_csrf, get_current_user, require_project_access
from app.models import User
from app.pagination import PageParams, to_paginated_response
from app.schemas import (
    ProjectNoteCommentCreate,
    ProjectNoteCommentOut,
    ProjectNoteCommentUpdate,
    ProjectNoteCreate,
    ProjectNoteMove,
    ProjectNoteOut,
    ProjectNoteReorder,
    ProjectNoteUpdate,
)
from app.services import ProjectNoteService

router = APIRouter(tags=["project-notes"])


@router.get("/projects/{project_id}/notes", response_model=list[ProjectNoteOut])
async def list_project_notes(
    project_id: int,
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> list[ProjectNoteOut]:
    items = await ProjectNoteService(db).list_notes(project_id)
    return [ProjectNoteOut.model_validate(item) for item in items]


@router.get("/projects/{project_id}/notes-activity", response_model=list[dict])
async def list_project_notes_activity(
    project_id: int,
    limit: int = Query(30, ge=1, le=200),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Журнал действий с заметками проекта (CREATE/UPDATE/DELETE)
    с никнеймами авторов. Видим всем, у кого есть доступ к проекту,
    в отличие от глобального /audit-logs (только для админов)."""
    items = await ProjectNoteService(db).list_activity(project_id, limit=limit)
    return items


@router.post("/projects/{project_id}/notes", response_model=ProjectNoteOut, status_code=status.HTTP_201_CREATED)
async def create_project_note(
    project_id: int,
    payload: ProjectNoteCreate,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> ProjectNoteOut:
    note = await ProjectNoteService(db).create_note(project_id, payload.model_dump(), current_user.id)
    return ProjectNoteOut.model_validate(note)


@router.get("/projects/{project_id}/notes/{note_id}", response_model=ProjectNoteOut)
async def get_project_note(
    project_id: int,
    note_id: int,
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> ProjectNoteOut:
    note = await ProjectNoteService(db).get_note(project_id, note_id)
    return ProjectNoteOut.model_validate(note)


@router.put("/projects/{project_id}/notes/{note_id}", response_model=ProjectNoteOut)
async def update_project_note(
    project_id: int,
    note_id: int,
    payload: ProjectNoteUpdate,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> ProjectNoteOut:
    note = await ProjectNoteService(db).update_note(project_id, note_id, payload.model_dump(exclude_unset=True), current_user.id)
    return ProjectNoteOut.model_validate(note)


@router.patch("/projects/{project_id}/notes/{note_id}/move", response_model=ProjectNoteOut)
async def move_project_note(
    project_id: int,
    note_id: int,
    payload: ProjectNoteMove,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> ProjectNoteOut:
    note = await ProjectNoteService(db).move_note(project_id, note_id, payload.parent_id, current_user.id)
    return ProjectNoteOut.model_validate(note)


@router.patch("/projects/{project_id}/notes/reorder", response_model=list[ProjectNoteOut])
async def reorder_project_notes(
    project_id: int,
    payload: ProjectNoteReorder,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> list[ProjectNoteOut]:
    notes = await ProjectNoteService(db).reorder_notes(
        project_id=project_id,
        parent_id=payload.parent_id,
        items=[item.model_dump() for item in payload.items],
        actor_id=current_user.id,
    )
    return [ProjectNoteOut.model_validate(item) for item in notes]


@router.delete("/projects/{project_id}/notes/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project_note(
    project_id: int,
    note_id: int,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> None:
    await ProjectNoteService(db).delete_note(project_id, note_id, current_user.id)


@router.get("/projects/{project_id}/notes/{note_id}/comments", response_model=dict)
async def list_note_comments(
    project_id: int,
    note_id: int,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> dict:
    items, total = await ProjectNoteService(db).list_comments(project_id, note_id, page, size)
    return to_paginated_response(items, total, PageParams(page=page, size=size)).model_dump()


@router.post(
    "/projects/{project_id}/notes/{note_id}/comments",
    response_model=ProjectNoteCommentOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_note_comment(
    project_id: int,
    note_id: int,
    payload: ProjectNoteCommentCreate,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> ProjectNoteCommentOut:
    return await ProjectNoteService(db).create_comment(project_id, note_id, payload.content, current_user)


@router.put("/projects/{project_id}/notes/{note_id}/comments/{comment_id}", response_model=ProjectNoteCommentOut)
async def update_note_comment(
    project_id: int,
    note_id: int,
    comment_id: int,
    payload: ProjectNoteCommentUpdate,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> ProjectNoteCommentOut:
    return await ProjectNoteService(db).update_comment(project_id, note_id, comment_id, payload.content, current_user)


@router.delete("/projects/{project_id}/notes/{note_id}/comments/{comment_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_note_comment(
    project_id: int,
    note_id: int,
    comment_id: int,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> None:
    await ProjectNoteService(db).delete_comment(project_id, note_id, comment_id, current_user)
