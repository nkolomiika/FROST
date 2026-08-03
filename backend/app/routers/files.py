
from fastapi import APIRouter, Depends, File as UploadApiFile, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import enforce_csrf, get_current_user, require_project_access
from app.models import User
from app.schemas import FileOut
from app.services import FileService

router = APIRouter(tags=["files"])


@router.get("/projects/{project_id}/vulnerabilities/{vuln_id}/files", response_model=list[FileOut])
async def list_files(
    project_id: int,
    vuln_id: int,
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> list[FileOut]:
    """Возвращает список файлов уязвимости."""
    items = await FileService(db).list(project_id, vuln_id)
    return [FileOut.model_validate(item) for item in items]


@router.post("/projects/{project_id}/vulnerabilities/{vuln_id}/files", response_model=FileOut, status_code=201)
async def upload_file(
    project_id: int,
    vuln_id: int,
    file: UploadFile = UploadApiFile(...),
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> FileOut:
    """Загружает файл доказательной базы."""
    item = await FileService(db).upload(project_id, vuln_id, file, current_user.id)
    return FileOut.model_validate(item)


@router.get("/files/{file_id}/download")
async def download_file(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """Отдаёт бинарный контент файла."""
    meta, content = await FileService(db).download(file_id, current_user)
    disposition = "inline" if meta.content_type.startswith("image/") else "attachment"
    headers = {"Content-Disposition": f'{disposition}; filename="{meta.original_name}"'}
    return StreamingResponse(iter([content]), media_type=meta.content_type, headers=headers)


@router.delete("/projects/{project_id}/vulnerabilities/{vuln_id}/files/{file_id}", status_code=204)
async def delete_file(
    project_id: int,
    vuln_id: int,
    file_id: int,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Удаляет файл уязвимости."""
    await FileService(db).delete(project_id, vuln_id, file_id, current_user.id)
