
from fastapi import APIRouter, Depends, File as UploadApiFile, UploadFile
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import enforce_csrf, get_current_user, require_project_access
from app.exceptions import ValidationError
from app.models import User
from app.schemas import ImportResult, OpenApiImportResult
from app.services import ImportService

router = APIRouter(tags=["import"])


@router.post("/projects/{project_id}/import", response_model=ImportResult)
async def import_project_data(
    project_id: int,
    file: UploadFile = UploadApiFile(...),
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> ImportResult:
    """Импортирует JSON-структуру активов в проект."""
    payload = await file.read()
    return await ImportService(db).import_json(project_id, payload, current_user.id)


@router.post("/projects/{project_id}/hosts/{host_id}/import-openapi", response_model=OpenApiImportResult)
async def import_openapi_file(
    project_id: int,
    host_id: int,
    file: UploadFile = UploadApiFile(...),
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> OpenApiImportResult:
    """Импортирует OpenAPI/Swagger JSON/YAML в endpoint-структуру конкретного хоста."""
    if not file.filename:
        raise ValidationError("Нужно выбрать Swagger/OpenAPI файл")
    payload = await file.read()
    return await ImportService(db).import_openapi(project_id, host_id, payload, current_user.id)


@router.get("/projects/{project_id}/hosts/{host_id}/export-openapi")
async def export_openapi_file(
    project_id: int,
    host_id: int,
    current_user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """Экспортирует эндпоинты хоста в OpenAPI 3.0 JSON."""
    _ = current_user
    document = await ImportService(db).export_openapi(project_id, host_id)
    filename = f"openapi-{host_id}.json"
    return JSONResponse(
        content=document,
        headers={"Content-Disposition": f"attachment; filename=\"{filename}\""},
    )
