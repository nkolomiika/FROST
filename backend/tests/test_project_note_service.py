from types import SimpleNamespace
from itertools import count as _id_count

_ids = _id_count(1)
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.exceptions import ValidationError
from app.services import ProjectNoteService


def _make_scalars_result(items: list[object]) -> MagicMock:
    result = MagicMock()
    result.all.return_value = items
    return result


@pytest.mark.asyncio
async def test_move_note_blocks_descendant_cycle() -> None:
    service = ProjectNoteService(AsyncMock())
    project_id = next(_ids)
    note_id = next(_ids)
    child_id = next(_ids)

    parent_chain = [note_id, None]

    async def scalar_side_effect(statement):  # noqa: ANN001
        sql = str(statement)
        if "project_notes.id =" in sql and "project_notes.project_id" in sql and "project_notes.title" in sql:
            return SimpleNamespace(id=note_id, project_id=project_id, parent_id=None, title="Page")
        if "SELECT project_notes.parent_id" in sql:
            return parent_chain.pop(0)
        return None

    service.db.scalar = AsyncMock(side_effect=scalar_side_effect)  # type: ignore[method-assign]

    with pytest.raises(ValidationError, match="дочернюю"):
        await service.move_note(project_id, note_id, child_id, actor_id=next(_ids))


@pytest.mark.asyncio
async def test_reorder_requires_full_sibling_set() -> None:
    db = AsyncMock()
    service = ProjectNoteService(db)
    project_id = next(_ids)
    actor_id = next(_ids)
    parent_id = next(_ids)
    sibling_a = SimpleNamespace(id=next(_ids), project_id=project_id, parent_id=parent_id, sort_order=1)
    sibling_b = SimpleNamespace(id=next(_ids), project_id=project_id, parent_id=parent_id, sort_order=2)
    db.scalars = AsyncMock(return_value=_make_scalars_result([sibling_a, sibling_b]))
    service._ensure_parent = AsyncMock(return_value=SimpleNamespace(id=parent_id))

    with pytest.raises(ValidationError, match="полный набор sibling"):
        await service.reorder_notes(
            project_id=project_id,
            parent_id=parent_id,
            items=[{"id": sibling_a.id, "sort_order": 1}],
            actor_id=actor_id,
        )

