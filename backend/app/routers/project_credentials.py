
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import enforce_csrf, get_current_user, require_project_access
from app.models import User
from app.schemas import (
    ProjectCredentialCreate,
    ProjectCredentialOut,
    ProjectCredentialUpdate,
)
from app.services import ProjectCredentialService

router = APIRouter(tags=["project-credentials"])


@router.get("/projects/{project_id}/credentials", response_model=list[ProjectCredentialOut])
async def list_project_credentials(
    project_id: int,
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> list[ProjectCredentialOut]:
    items = await ProjectCredentialService(db).list_credentials(project_id)
    return [ProjectCredentialOut.model_validate(item) for item in items]


@router.post(
    "/projects/{project_id}/credentials",
    response_model=ProjectCredentialOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_project_credential(
    project_id: int,
    payload: ProjectCredentialCreate,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> ProjectCredentialOut:
    item = await ProjectCredentialService(db).create_credential(project_id, payload.model_dump(), current_user.id)
    return ProjectCredentialOut.model_validate(item)


@router.put("/projects/{project_id}/credentials/{credential_id}", response_model=ProjectCredentialOut)
async def update_project_credential(
    project_id: int,
    credential_id: int,
    payload: ProjectCredentialUpdate,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> ProjectCredentialOut:
    item = await ProjectCredentialService(db).update_credential(
        project_id, credential_id, payload.model_dump(exclude_unset=True), current_user.id
    )
    return ProjectCredentialOut.model_validate(item)


@router.delete(
    "/projects/{project_id}/credentials/{credential_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_project_credential(
    project_id: int,
    credential_id: int,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> None:
    await ProjectCredentialService(db).delete_credential(project_id, credential_id, current_user.id)
