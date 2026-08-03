import asyncio
import re
from uuid import uuid4

from fastapi import APIRouter, Depends, File as UploadApiFile, UploadFile
from fastapi.responses import Response

from app.dependencies import enforce_csrf, get_current_user, require_project_access
from app.exceptions import NotFoundError, ValidationError
from app.models import User
from app.storage.minio_client import MinioStorage

router = APIRouter(tags=["images"])

# Разрешённые типы картинок для markdown-редакторов (описания, шаги, заметки).
_ALLOWED_EXT: dict[str, str] = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "image/webp": ".webp",
}
_MAX_BYTES = 10 * 1024 * 1024
_IMAGE_NAME_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.(?:png|jpg|gif|webp)$")


@router.post("/projects/{project_id}/images", status_code=201)
async def upload_project_image(
    project_id: int,
    file: UploadFile = UploadApiFile(...),
    _: None = Depends(enforce_csrf),
    _user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
) -> dict:
    """Загружает картинку проекта и возвращает URL для вставки в markdown."""
    ext = _ALLOWED_EXT.get((file.content_type or "").lower())
    if not ext:
        raise ValidationError("Поддерживаются только изображения PNG, JPEG, GIF или WEBP")
    content = await file.read()
    if not content:
        raise ValidationError("Пустой файл")
    if len(content) > _MAX_BYTES:
        raise ValidationError("Изображение больше 10 МБ")

    storage = MinioStorage()
    storage.ensure_bucket()
    image_name = f"{uuid4()}{ext}"
    key = f"images/{project_id}/{image_name}"
    await asyncio.to_thread(storage.upload_bytes_with_key, key, content, file.content_type or "application/octet-stream")
    return {"url": f"/api/v1/projects/{project_id}/images/{image_name}/download"}


@router.get("/projects/{project_id}/images/{image_name}/download")
async def download_project_image(
    project_id: int,
    image_name: str,
    _user: User = Depends(get_current_user),
    _project=Depends(require_project_access),
) -> Response:
    """Отдаёт картинку проекта (доступ — только участникам проекта)."""
    if not _IMAGE_NAME_RE.match(image_name):
        raise NotFoundError("Изображение не найдено")
    key = f"images/{project_id}/{image_name}"
    storage = MinioStorage()
    try:
        content, content_type = await asyncio.to_thread(storage.download_with_content_type, key)
    except Exception as exc:
        raise NotFoundError("Изображение не найдено") from exc
    return Response(content=content, media_type=content_type, headers={"Cache-Control": "private, max-age=86400"})
