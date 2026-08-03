from itertools import count as _id_count
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.models import ProjectCredential
from app.security import decrypt_secret, encrypt_secret
from app.services import ProjectCredentialService

_ids = _id_count(1)


def _service_with_captured_add() -> tuple[ProjectCredentialService, list]:
    """Сервис с mock-БД, где db.add собирает добавленные объекты."""
    db = AsyncMock()
    added: list = []
    db.add = MagicMock(side_effect=added.append)
    service = ProjectCredentialService(db)
    return service, added


@pytest.mark.asyncio
async def test_create_credential_encrypts_password_and_excludes_it_from_audit() -> None:
    service, added = _service_with_captured_add()
    service._ensure_project = AsyncMock(return_value=SimpleNamespace(id=1))  # type: ignore[method-assign]
    service.audit.log = AsyncMock()  # type: ignore[method-assign]

    result = await service.create_credential(
        project_id=1,
        payload={"username": "dbuser", "password": "s3cr3t-pw"},
        actor_id=next(_ids),
    )

    credential = next(obj for obj in added if isinstance(obj, ProjectCredential))
    # В БД лежит только шифртекст, а не сам пароль.
    assert credential.password_encrypted != "s3cr3t-pw"
    assert decrypt_secret(credential.password_encrypted) == "s3cr3t-pw"
    # Выдача содержит расшифрованный пароль и username.
    assert result["password"] == "s3cr3t-pw"
    assert result["username"] == "dbuser"
    # Пароль никогда не попадает в журнал аудита.
    _, kwargs = service.audit.log.call_args
    assert "s3cr3t-pw" not in str(kwargs.get("details"))


@pytest.mark.asyncio
async def test_update_credential_keeps_password_when_blank() -> None:
    service, _added = _service_with_captured_add()
    service.audit.log = AsyncMock()  # type: ignore[method-assign]
    existing = ProjectCredential(
        id=7,
        project_id=1,
        username="root",
        password_encrypted=encrypt_secret("keep-me"),
        created_by=next(_ids),
    )
    service._get_credential = AsyncMock(return_value=existing)  # type: ignore[method-assign]

    # Присылаем только username — пустой password означает «не менять».
    await service.update_credential(project_id=1, credential_id=7, payload={"username": "admin"}, actor_id=next(_ids))

    assert existing.username == "admin"
    assert decrypt_secret(existing.password_encrypted) == "keep-me"


@pytest.mark.asyncio
async def test_serialize_round_trips_password() -> None:
    credential = ProjectCredential(
        id=3,
        project_id=1,
        username="dbuser",
        password_encrypted=encrypt_secret("p@ss"),
        created_by=1,
    )
    serialized = ProjectCredentialService._serialize(credential)
    assert serialized["password"] == "p@ss"
    assert serialized["username"] == "dbuser"
