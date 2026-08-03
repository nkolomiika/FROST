from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from itertools import count as _id_count

_ids = _id_count(1)

import pytest

from app.enums import NotificationType, UserRole
from app.exceptions import ForbiddenError
from app.models import Comment, CommentMention, Notification
from app.services import CommentService


@pytest.mark.asyncio
async def test_admin_cannot_update_foreign_comment() -> None:
    comment = SimpleNamespace(id=next(_ids), vulnerability_id=next(_ids), user_id=next(_ids))
    actor = SimpleNamespace(id=next(_ids), role=UserRole.ADMIN)
    db = MagicMock()
    db.scalar = AsyncMock(return_value=comment)
    service = CommentService(db)
    service._ensure_vuln = AsyncMock()

    with pytest.raises(ForbiddenError, match="только свой комментарий"):
        await service.update(next(_ids), comment.vulnerability_id, comment.id, "updated", actor)


@pytest.mark.asyncio
async def test_admin_cannot_delete_foreign_comment() -> None:
    comment = SimpleNamespace(id=next(_ids), vulnerability_id=next(_ids), user_id=next(_ids))
    actor = SimpleNamespace(id=next(_ids), role=UserRole.ADMIN)
    db = MagicMock()
    db.scalar = AsyncMock(return_value=comment)
    service = CommentService(db)
    service._ensure_vuln = AsyncMock()

    with pytest.raises(ForbiddenError, match="только свой комментарий"):
        await service.delete(next(_ids), comment.vulnerability_id, comment.id, actor)


@pytest.mark.asyncio
async def test_update_comment_mentions_do_not_create_notifications(monkeypatch: pytest.MonkeyPatch) -> None:
    project_id = next(_ids)
    vuln_id = next(_ids)
    comment = SimpleNamespace(
        id=next(_ids),
        vulnerability_id=vuln_id,
        user_id=next(_ids),
        content="old",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    actor = SimpleNamespace(id=comment.user_id, role=UserRole.PENTESTER, username="author", avatar_url=None)
    mentioned_user = SimpleNamespace(id=next(_ids), username="target")
    db = MagicMock()
    db.scalar = AsyncMock(return_value=comment)
    db.execute = AsyncMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    ws_manager = SimpleNamespace(broadcast=AsyncMock(), notify_user=AsyncMock())
    monkeypatch.setattr("app.services.ws_manager", ws_manager)

    service = CommentService(db)
    service._ensure_vuln = AsyncMock()
    service._extract_mentions = AsyncMock(return_value=[mentioned_user])
    service.audit.log = AsyncMock()

    result = await service.update(project_id, vuln_id, comment.id, "updated @target", actor)

    added_models = [call.args[0] for call in db.add.call_args_list]
    assert any(isinstance(model, CommentMention) for model in added_models)
    assert not any(isinstance(model, Notification) for model in added_models)
    ws_manager.notify_user.assert_not_awaited()
    ws_manager.broadcast.assert_awaited_once()
    assert result.mentions[0].username == "target"


# ---- поводы для уведомлений ----
# Уведомляем только по четырём поводам, и никогда — самого инициатора.


def _comment_service(db: AsyncMock, mentioned: list[SimpleNamespace]) -> CommentService:
    """CommentService поверх мок-сессии; flush проставляет PK, как настоящий."""

    def stamp(*_args: object, **_kwargs: object) -> None:
        now = datetime.now(timezone.utc)
        for call in db.add.call_args_list:
            obj = call.args[0]
            if isinstance(obj, Comment) and obj.id is None:
                obj.id, obj.created_at, obj.updated_at = 1, now, now

    db.flush = AsyncMock(side_effect=stamp)
    service = CommentService(db)
    # title/host_id попадают в websocket-пейлоад уведомления.
    service._ensure_vuln = AsyncMock(return_value=SimpleNamespace(id=1, project_id=1, title="SQLi"))  # type: ignore[method-assign]
    service._extract_mentions = AsyncMock(return_value=mentioned)  # type: ignore[method-assign]
    service.audit.log = AsyncMock()  # type: ignore[method-assign]
    return service


@pytest.mark.asyncio
async def test_self_mention_creates_no_notification(monkeypatch: pytest.MonkeyPatch) -> None:
    """Упомянул себя — уведомления быть не должно: он сам это и написал."""
    monkeypatch.setattr("app.services.ws_manager", SimpleNamespace(broadcast=AsyncMock(), notify_user=AsyncMock()))
    actor = SimpleNamespace(id=7, username="alice", avatar_url=None)
    db = AsyncMock()
    service = _comment_service(db, [actor])

    await service.create(project_id=1, vuln_id=1, content="@alice проверь", actor=actor)

    added = [c.args[0] for c in db.add.call_args_list]
    assert not [x for x in added if isinstance(x, Notification)]
    # Само упоминание при этом сохраняется — подсветка в тексте нужна.
    assert [x for x in added if isinstance(x, CommentMention)]


@pytest.mark.asyncio
async def test_mention_of_someone_else_creates_notification(monkeypatch: pytest.MonkeyPatch) -> None:
    ws = SimpleNamespace(broadcast=AsyncMock(), notify_user=AsyncMock())
    monkeypatch.setattr("app.services.ws_manager", ws)
    actor = SimpleNamespace(id=7, username="alice", avatar_url=None)
    other = SimpleNamespace(id=9, username="bob", avatar_url=None)
    db = AsyncMock()
    service = _comment_service(db, [other])

    await service.create(project_id=1, vuln_id=1, content="@bob посмотри", actor=actor)

    notifications = [c.args[0] for c in db.add.call_args_list if isinstance(c.args[0], Notification)]
    assert len(notifications) == 1
    assert notifications[0].user_id == other.id
    assert notifications[0].type == NotificationType.MENTION
    assert notifications[0].actor_id == actor.id
    ws.notify_user.assert_awaited_once()
