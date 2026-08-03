from urllib.parse import quote

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import enforce_csrf, get_current_user, require_project_access
from app.models import Project, User
from app.services import ReportService

router = APIRouter(tags=["reports"])

DOCX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def _safe_filename(name: str) -> str:
    """Возвращает имя файла с разрешёнными ASCII-символами для Content-Disposition."""
    cleaned = "".join(ch for ch in (name or "").strip() if ch.isalnum() or ch in ("-", "_"))
    return cleaned or "report"


def _content_disposition(project_name: str, suffix: str) -> str:
    base = _safe_filename(project_name)
    filename_ascii = f"{base}_{suffix}.docx"
    filename_utf8 = f"{(project_name or 'report').strip()}_{suffix}.docx"
    return f'attachment; filename="{filename_ascii}"; filename*=UTF-8\'\'{quote(filename_utf8)}'


async def _stream_word_report(
    *, project_id: int, project: Project, db: AsyncSession, kind: str
) -> StreamingResponse:
    content = await ReportService(db).generate(project_id, kind)  # type: ignore[arg-type]
    headers = {"Content-Disposition": _content_disposition(project.name, kind)}
    return StreamingResponse(iter([content]), media_type=DOCX_MEDIA_TYPE, headers=headers)


@router.post("/projects/{project_id}/reports/szi")
async def generate_szi_report(
    project_id: int,
    _: None = Depends(enforce_csrf),
    _user: User = Depends(get_current_user),
    project: Project = Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """Генерирует Word-отчёт «СЗИ» (для сертификации) по шаблону."""
    return await _stream_word_report(project_id=project_id, project=project, db=db, kind="szi")


@router.post("/projects/{project_id}/reports/pp")
async def generate_pp_report(
    project_id: int,
    _: None = Depends(enforce_csrf),
    _user: User = Depends(get_current_user),
    project: Project = Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """Генерирует Word-отчёт «ПП» (внутренняя приёмка) по шаблону."""
    return await _stream_word_report(project_id=project_id, project=project, db=db, kind="pp")
