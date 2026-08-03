from types import SimpleNamespace
from itertools import count as _id_count

_ids = _id_count(1)

import pytest
from app.enums import NotificationType, ProjectRole, ProjectStatus
from app.exceptions import ForbiddenError
from app.models import Notification, UserRole
from app.services import ProjectService
from unittest.mock import AsyncMock, MagicMock


def _make_scalars_result(items: list[object]) -> MagicMock:
    result = MagicMock()
    result.all.return_value = items
    return result


@pytest.mark.asyncio
async def test_list_projects_applies_status_filter_for_admin() -> None:
    db = AsyncMock()
    project_item = SimpleNamespace(id=next(_ids), name="Project A")
    db.scalar = AsyncMock(return_value=1)
    db.scalars = AsyncMock(return_value=_make_scalars_result([project_item]))
    service = ProjectService(db)
    current_user = SimpleNamespace(id=next(_ids), role=UserRole.ADMIN)

    items, total = await service.list_projects(current_user=current_user, page=1, size=20, status="active")

    assert items == [project_item]
    assert total == 1
    statement = db.scalars.await_args.args[0]
    sql = str(statement)
    assert "projects.status" in sql
    assert "project_members" not in sql


@pytest.mark.asyncio
async def test_list_projects_ignores_membership_for_admin() -> None:
    """Админ видит все проекты, даже те, в которых он не участник.

    Правило: участие ограничивает выдачу только не-админам. Запрос админа не
    джойнит project_members вообще, поэтому его членство ни на что не влияет.
    """
    db = AsyncMock()
    project_item = SimpleNamespace(id=next(_ids), name="Project without the admin")
    db.scalar = AsyncMock(return_value=1)
    db.scalars = AsyncMock(return_value=_make_scalars_result([project_item]))
    service = ProjectService(db)
    admin = SimpleNamespace(id=next(_ids), role=UserRole.ADMIN)

    items, total = await service.list_projects(current_user=admin, page=1, size=20, status=None)

    assert items == [project_item]
    assert total == 1
    sql = str(db.scalars.await_args.args[0])
    assert "project_members" not in sql


@pytest.mark.asyncio
async def test_list_projects_limits_to_membership_for_pentester() -> None:
    db = AsyncMock()
    project_item = SimpleNamespace(id=next(_ids), name="Project B")
    db.scalar = AsyncMock(return_value=1)
    db.scalars = AsyncMock(return_value=_make_scalars_result([project_item]))
    service = ProjectService(db)
    current_user = SimpleNamespace(id=next(_ids), role=UserRole.PENTESTER)

    items, total = await service.list_projects(current_user=current_user, page=2, size=10, status=None)

    assert items == [project_item]
    assert total == 1
    statement = db.scalars.await_args.args[0]
    sql = str(statement)
    assert "JOIN project_members" in sql
    assert "project_members.user_id" in sql


@pytest.mark.asyncio
async def test_delete_project_removes_entity_and_writes_audit() -> None:
    db = AsyncMock()
    service = ProjectService(db)
    project_id = next(_ids)
    actor_id = next(_ids)
    project = SimpleNamespace(id=project_id)
    service.get_project = AsyncMock(return_value=project)  # type: ignore[method-assign]
    service.audit.log = AsyncMock()  # type: ignore[method-assign]

    await service.delete_project(project_id=project_id, actor_id=actor_id, ip_address="127.0.0.1")

    db.delete.assert_awaited_once_with(project)
    db.commit.assert_awaited_once()
    service.audit.log.assert_awaited_once_with(
        "DELETE",
        user_id=actor_id,
        entity_type="project",
        entity_id=project_id,
        ip_address="127.0.0.1",
    )


@pytest.mark.asyncio
async def test_update_project_freezes_timeline_on_first_non_active_status() -> None:
    db = AsyncMock()
    # Смена статуса рассылает уведомления участникам — здесь их нет.
    db.scalars = AsyncMock(return_value=_make_scalars_result([]))
    service = ProjectService(db)
    project_id = next(_ids)
    actor_id = next(_ids)
    project = SimpleNamespace(
        id=project_id,
        start_date=None,
        end_date=None,
        folder="",
        status=ProjectStatus.ACTIVE,
        timeline_frozen_at=None,
    )
    service.get_project = AsyncMock(return_value=project)  # type: ignore[method-assign]
    service.audit.log = AsyncMock()  # type: ignore[method-assign]

    updated = await service.update_project(
        project_id=project_id,
        payload={"status": ProjectStatus.HANDOVER_TO_DEVELOPMENT},
        actor_id=actor_id,
        ip_address="127.0.0.1",
    )

    assert updated.status == ProjectStatus.HANDOVER_TO_DEVELOPMENT
    assert updated.timeline_frozen_at is not None
    db.commit.assert_awaited()


@pytest.mark.asyncio
async def test_update_project_keeps_existing_frozen_timestamp_for_non_active_transitions() -> None:
    db = AsyncMock()
    # Смена статуса рассылает уведомления участникам — здесь их нет.
    db.scalars = AsyncMock(return_value=_make_scalars_result([]))
    service = ProjectService(db)
    project_id = next(_ids)
    actor_id = next(_ids)
    frozen_at = object()
    project = SimpleNamespace(
        id=project_id,
        start_date=None,
        end_date=None,
        folder="",
        status=ProjectStatus.HANDOVER_TO_DEVELOPMENT,
        timeline_frozen_at=frozen_at,
    )
    service.get_project = AsyncMock(return_value=project)  # type: ignore[method-assign]
    service.audit.log = AsyncMock()  # type: ignore[method-assign]

    updated = await service.update_project(
        project_id=project_id,
        payload={"status": ProjectStatus.VULNERABILITY_RECHECK},
        actor_id=actor_id,
        ip_address="127.0.0.1",
    )

    assert updated.status == ProjectStatus.VULNERABILITY_RECHECK
    assert updated.timeline_frozen_at is frozen_at


@pytest.mark.asyncio
async def test_update_project_unfreezes_timeline_when_reactivated() -> None:
    db = AsyncMock()
    # Смена статуса рассылает уведомления участникам — здесь их нет.
    db.scalars = AsyncMock(return_value=_make_scalars_result([]))
    service = ProjectService(db)
    project_id = next(_ids)
    actor_id = next(_ids)
    project = SimpleNamespace(
        id=project_id,
        start_date=None,
        end_date=None,
        folder="",
        status=ProjectStatus.VULNERABILITY_RECHECK,
        timeline_frozen_at=object(),
    )
    service.get_project = AsyncMock(return_value=project)  # type: ignore[method-assign]
    service.audit.log = AsyncMock()  # type: ignore[method-assign]

    updated = await service.update_project(
        project_id=project_id,
        payload={"status": ProjectStatus.ACTIVE},
        actor_id=actor_id,
        ip_address="127.0.0.1",
    )

    assert updated.status == ProjectStatus.ACTIVE
    assert updated.timeline_frozen_at is None


# ---- кто может править карточку проекта (название/описание/сроки) ----
# Правило: админ, создатель проекта или лид-участник. Лид — глобальная роль,
# поэтому одного лидерства мало: нужно ещё состоять в проекте.


def _edit_service(project, membership):
    """ProjectService с подменёнными get_project и поиском членства."""
    db = AsyncMock()
    db.scalar = AsyncMock(return_value=membership)
    service = ProjectService(db)
    service.get_project = AsyncMock(return_value=project)  # type: ignore[method-assign]
    return service


@pytest.mark.asyncio
async def test_ensure_can_edit_project_allows_admin_non_member() -> None:
    project = SimpleNamespace(id=1, created_by=999)
    service = _edit_service(project, membership=None)
    admin = SimpleNamespace(id=1, role=UserRole.ADMIN, project_role=ProjectRole.PENTESTER)

    assert await service.ensure_can_edit_project(1, admin) is project


@pytest.mark.asyncio
async def test_ensure_can_edit_project_allows_creator() -> None:
    project = SimpleNamespace(id=1, created_by=42)
    service = _edit_service(project, membership=None)
    creator = SimpleNamespace(id=42, role=UserRole.PENTESTER, project_role=ProjectRole.PENTESTER)

    assert await service.ensure_can_edit_project(1, creator) is project


@pytest.mark.asyncio
async def test_ensure_can_edit_project_allows_lead_member() -> None:
    project = SimpleNamespace(id=1, created_by=999)
    service = _edit_service(project, membership=SimpleNamespace(id=7))
    lead = SimpleNamespace(id=42, role=UserRole.PENTESTER, project_role=ProjectRole.LEAD)

    assert await service.ensure_can_edit_project(1, lead) is project


@pytest.mark.asyncio
async def test_ensure_can_edit_project_rejects_lead_without_membership() -> None:
    """Лид не из проекта править его не может — роль глобальная, доступ — нет."""
    project = SimpleNamespace(id=1, created_by=999)
    service = _edit_service(project, membership=None)
    outsider_lead = SimpleNamespace(id=42, role=UserRole.PENTESTER, project_role=ProjectRole.LEAD)

    with pytest.raises(ForbiddenError, match="Изменять проект"):
        await service.ensure_can_edit_project(1, outsider_lead)


@pytest.mark.asyncio
async def test_ensure_can_edit_project_rejects_plain_member() -> None:
    project = SimpleNamespace(id=1, created_by=999)
    service = _edit_service(project, membership=SimpleNamespace(id=7))
    member = SimpleNamespace(id=42, role=UserRole.PENTESTER, project_role=ProjectRole.PENTESTER)

    with pytest.raises(ForbiddenError, match="Изменять проект"):
        await service.ensure_can_edit_project(1, member)


# ---- уведомления по проекту ----
# Только два повода: тебя добавили в проект и у проекта сменился статус.


@pytest.mark.asyncio
async def test_add_member_notifies_the_added_user(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.services.ws_manager", SimpleNamespace(notify_user=AsyncMock()))
    db = AsyncMock()
    added = SimpleNamespace(id=42, username="bob", project_role=ProjectRole.PENTESTER)
    # 1-й scalar — пользователь, 2-й — проверка, что он ещё не участник.
    db.scalar = AsyncMock(side_effect=[added, None])
    service = ProjectService(db)
    service.get_project = AsyncMock(return_value=SimpleNamespace(id=1))  # type: ignore[method-assign]
    service.audit.log = AsyncMock()  # type: ignore[method-assign]

    await service.add_member(project_id=1, user_id=42, actor_id=1, ip_address="127.0.0.1")

    notifications = [c.args[0] for c in db.add.call_args_list if isinstance(c.args[0], Notification)]
    assert len(notifications) == 1
    assert notifications[0].user_id == 42
    assert notifications[0].type == NotificationType.PROJECT_MEMBER_ADDED
    assert notifications[0].project_id == 1


@pytest.mark.asyncio
async def test_add_member_does_not_notify_yourself(monkeypatch: pytest.MonkeyPatch) -> None:
    """Добавил себя — уведомлять некого."""
    monkeypatch.setattr("app.services.ws_manager", SimpleNamespace(notify_user=AsyncMock()))
    db = AsyncMock()
    me = SimpleNamespace(id=1, username="admin", project_role=ProjectRole.LEAD)
    db.scalar = AsyncMock(side_effect=[me, None])
    service = ProjectService(db)
    service.get_project = AsyncMock(return_value=SimpleNamespace(id=1))  # type: ignore[method-assign]
    service.audit.log = AsyncMock()  # type: ignore[method-assign]

    await service.add_member(project_id=1, user_id=1, actor_id=1, ip_address="127.0.0.1")

    assert not [c.args[0] for c in db.add.call_args_list if isinstance(c.args[0], Notification)]


@pytest.mark.asyncio
async def test_project_status_change_notifies_members_except_actor(monkeypatch: pytest.MonkeyPatch) -> None:
    ws = SimpleNamespace(broadcast=AsyncMock(), broadcast_projects_index=AsyncMock(), notify_user=AsyncMock())
    monkeypatch.setattr("app.services.ws_manager", ws)
    db = AsyncMock()
    # Участники: сам инициатор (1) и ещё двое.
    db.scalars = AsyncMock(return_value=_make_scalars_result([1, 2, 3]))
    service = ProjectService(db)
    project = SimpleNamespace(
        id=1, start_date=None, end_date=None, folder="", status=ProjectStatus.ACTIVE, timeline_frozen_at=None
    )
    service.get_project = AsyncMock(return_value=project)  # type: ignore[method-assign]
    service.audit.log = AsyncMock()  # type: ignore[method-assign]

    await service.update_project(project_id=1, payload={"status": ProjectStatus.FREEZE}, actor_id=1, ip_address="127.0.0.1")

    notifications = [c.args[0] for c in db.add.call_args_list if isinstance(c.args[0], Notification)]
    assert sorted(n.user_id for n in notifications) == [2, 3]  # инициатор себя не уведомляет
    assert {n.type for n in notifications} == {NotificationType.PROJECT_STATUS_CHANGED}
    assert {n.status for n in notifications} == {"freeze"}


@pytest.mark.asyncio
async def test_project_update_without_status_change_notifies_nobody(monkeypatch: pytest.MonkeyPatch) -> None:
    """Переименование — не повод для уведомления."""
    ws = SimpleNamespace(broadcast=AsyncMock(), broadcast_projects_index=AsyncMock(), notify_user=AsyncMock())
    monkeypatch.setattr("app.services.ws_manager", ws)
    db = AsyncMock()
    db.scalars = AsyncMock(return_value=_make_scalars_result([1, 2, 3]))
    service = ProjectService(db)
    project = SimpleNamespace(
        id=1, start_date=None, end_date=None, folder="", status=ProjectStatus.ACTIVE, timeline_frozen_at=None, name="old"
    )
    service.get_project = AsyncMock(return_value=project)  # type: ignore[method-assign]
    service.audit.log = AsyncMock()  # type: ignore[method-assign]

    await service.update_project(project_id=1, payload={"name": "new"}, actor_id=1, ip_address="127.0.0.1")

    assert not [c.args[0] for c in db.add.call_args_list if isinstance(c.args[0], Notification)]
