from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from starlette.requests import Request

from app.dependencies import enforce_csrf, require_project_access
from app.exceptions import ForbiddenError
from app.models import UserRole


def _request(method: str) -> Request:
    scope = {
        "type": "http",
        "method": method,
        "path": "/",
        "headers": [],
        "query_string": b"",
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
        "scheme": "http",
    }
    return Request(scope)


@pytest.mark.asyncio
async def test_enforce_csrf_skips_get_requests() -> None:
    await enforce_csrf(_request("GET"), origin=None)


@pytest.mark.asyncio
async def test_enforce_csrf_requires_origin_on_post_tc_auth_005() -> None:
    with pytest.raises(ForbiddenError, match="Отсутствует заголовок Origin"):
        await enforce_csrf(_request("POST"), origin=None)


@pytest.mark.asyncio
async def test_enforce_csrf_rejects_unknown_origin_tc_sec_005() -> None:
    with pytest.raises(ForbiddenError, match="Недопустимый Origin"):
        await enforce_csrf(_request("PATCH"), origin="http://evil.local")


@pytest.mark.asyncio
async def test_enforce_csrf_accepts_allowed_origin() -> None:
    await enforce_csrf(_request("DELETE"), origin="http://localhost:3000")


@pytest.mark.asyncio
async def test_require_project_access_admin_without_membership() -> None:
    """Админ открывает любой проект, даже не будучи его участником.

    Членство не проверяется вовсе: `db.scalar` возвращает проект первым вызовом
    и больше не вызывается — до запроса ProjectMember дело не доходит.
    """
    project = SimpleNamespace(id=7, name="Project without the admin")
    db = AsyncMock()
    db.scalar = AsyncMock(return_value=project)
    admin = SimpleNamespace(id=1, role=UserRole.ADMIN)

    result = await require_project_access(project_id=7, db=db, current_user=admin)

    assert result is project
    assert db.scalar.await_count == 1  # только выборка проекта, без ProjectMember


@pytest.mark.asyncio
async def test_require_project_access_rejects_non_member_pentester() -> None:
    """Не-админ без членства получает 403 — это и есть правило доступа."""
    project = SimpleNamespace(id=7, name="Someone else's project")
    db = AsyncMock()
    # 1-й scalar — проект, 2-й — поиск членства (его нет).
    db.scalar = AsyncMock(side_effect=[project, None])
    user = SimpleNamespace(id=2, role=UserRole.PENTESTER)

    with pytest.raises(ForbiddenError, match="Нет доступа к проекту"):
        await require_project_access(project_id=7, db=db, current_user=user)
