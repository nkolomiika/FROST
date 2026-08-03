
from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import enforce_csrf, get_client_ip, get_current_user, require_admin, require_project_access
from app.models import User
from app.pagination import PageParams, to_paginated_response
from app.schemas import (
    ProjectCreate,
    ProjectFolderCreate,
    ProjectFolderMove,
    ProjectFolderOut,
    ProjectMemberCreate,
    ProjectMemberOut,
    ProjectOut,
    ProjectUpdate,
)
from app.services import ProjectService

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("", response_model=dict)
async def list_projects(
    page: int = Query(1, ge=1),
    # Лимит до 1000 — нужен для select-всех в UI (например, диалог токенов API),
    # где админу удобно один раз подтянуть весь каталог проектов и фильтровать локально.
    size: int = Query(20, ge=1, le=1000),
    status_filter: str | None = Query(None, alias="status"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Возвращает список проектов с учётом прав доступа."""
    items, total = await ProjectService(db).list_projects(current_user, page, size, status_filter)
    return to_paginated_response([ProjectOut.model_validate(it) for it in items], total, PageParams(page=page, size=size)).model_dump()


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
async def create_project(
    payload: ProjectCreate,
    request: Request,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ProjectOut:
    """Создаёт проект."""
    project = await ProjectService(db).create_project(payload.model_dump(), admin.id, get_client_ip(request))
    return ProjectOut.model_validate(project)


@router.get("/folders", response_model=list[ProjectFolderOut])
async def list_project_folders(
    _: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[ProjectFolderOut]:
    """Возвращает дерево папок проектов (плоским списком)."""
    items = await ProjectService(db).list_folders()
    return [ProjectFolderOut.model_validate(folder) for folder in items]


@router.post("/folders", response_model=ProjectFolderOut, status_code=status.HTTP_201_CREATED)
async def create_project_folder(
    payload: ProjectFolderCreate,
    request: Request,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ProjectFolderOut:
    """Создаёт папку проекта (в т.ч. вложенную)."""
    folder = await ProjectService(db).create_folder(payload.name, payload.parent_id, admin.id, get_client_ip(request))
    return ProjectFolderOut.model_validate(folder)


@router.patch("/folders/{folder_id}/move", response_model=ProjectFolderOut)
async def move_project_folder(
    folder_id: int,
    payload: ProjectFolderMove,
    request: Request,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ProjectFolderOut:
    """Перемещает папку проекта в другой раздел дерева."""
    folder = await ProjectService(db).move_folder(folder_id, payload.parent_id, admin.id, get_client_ip(request))
    return ProjectFolderOut.model_validate(folder)


@router.delete("/folders/{folder_id}", status_code=status.HTTP_200_OK)
async def delete_project_folder(
    folder_id: int,
    request: Request,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Каскадно удаляет папку проекта со всеми подпапками и проектами."""
    return await ProjectService(db).delete_folder(folder_id, admin.id, get_client_ip(request))


# Объявлен до "/{project_id}", иначе FastAPI попытается разобрать "stats" как id.
@router.get("/stats", response_model=list[dict])
async def list_project_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Счётчики (хосты/уязвимости) по каждому доступному проекту — одним запросом."""
    return await ProjectService(db).list_project_stats(current_user)


@router.get("/{project_id}", response_model=ProjectOut)
async def get_project(
    project_id: int,
    _project = Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> ProjectOut:
    """Возвращает проект по ID."""
    project = await ProjectService(db).get_project(project_id)
    return ProjectOut.model_validate(project)


@router.put("/{project_id}", response_model=ProjectOut)
async def update_project(
    project_id: int,
    payload: ProjectUpdate,
    request: Request,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ProjectOut:
    """Обновляет карточку проекта: название, описание, сроки.

    Доступно админу, лиду проекта или его создателю (удаление — только админу).
    """
    service = ProjectService(db)
    await service.ensure_can_edit_project(project_id, current_user)
    project = await service.update_project(project_id, payload.model_dump(exclude_unset=True), current_user.id, get_client_ip(request))
    return ProjectOut.model_validate(project)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: int,
    request: Request,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Удаляет проект."""
    await ProjectService(db).delete_project(project_id, admin.id, get_client_ip(request))


@router.get("/{project_id}/members", response_model=list[ProjectMemberOut])
async def list_members(
    project_id: int,
    _project = Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> list[ProjectMemberOut]:
    """Возвращает участников проекта."""
    items = await ProjectService(db).list_members(project_id)
    return [ProjectMemberOut.model_validate(row) for row in items]


@router.post("/{project_id}/members", status_code=status.HTTP_201_CREATED)
async def add_member(
    project_id: int,
    payload: ProjectMemberCreate,
    request: Request,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Добавляет участника в проект (админ, лид проекта или его создатель)."""
    service = ProjectService(db)
    await service.ensure_can_manage_members(project_id, current_user)
    return await service.add_member(project_id, payload.user_id, current_user.id, get_client_ip(request))


@router.delete("/{project_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    project_id: int,
    user_id: int,
    request: Request,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Удаляет участника из проекта (админ, лид проекта или его создатель)."""
    service = ProjectService(db)
    await service.ensure_can_manage_members(project_id, current_user)
    await service.remove_member(project_id, user_id, current_user.id, get_client_ip(request))


@router.get("/{project_id}/activity", response_model=list[dict])
async def list_project_activity(
    project_id: int,
    limit: int = Query(50, ge=1, le=200),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Активность проекта — доступна всем участникам проекта."""
    return await ProjectService(db).list_project_activity(project_id, limit)


