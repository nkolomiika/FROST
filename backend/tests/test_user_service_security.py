from types import SimpleNamespace
from itertools import count as _id_count

_ids = _id_count(1)

import pytest
from unittest.mock import AsyncMock

from app.enums import UserRole
from app.exceptions import ForbiddenError, ValidationError
from app.services import UserService


@pytest.mark.asyncio
async def test_admin_cannot_change_other_user_email() -> None:
    db = AsyncMock()
    service = UserService(db)
    user = SimpleNamespace(id=next(_ids), username="alice", email="alice@example.com")
    service.get_user = AsyncMock(return_value=user)  # type: ignore[method-assign]

    with pytest.raises(ValidationError, match="can't change a user's email"):
        await service.update_user(user.id, {"email": "new@example.com"}, actor_id=next(_ids))


def test_avatar_download_forbidden_for_other_non_admin_users() -> None:
    requester = SimpleNamespace(id=next(_ids), role=UserRole.PENTESTER)
    target_user_id = next(_ids)

    with pytest.raises(ForbiddenError, match="чужого аватара"):
        UserService.ensure_can_view_avatar(requester, target_user_id)
