"""Scanner: обратный резолв IP → PTR-имя → ферма хостов (делегирование ферме IP)."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.exceptions import ValidationError
from app.farm.ips import IpFarmService
from app.farm.reverse import ReverseFarmService
from app.schemas import IpFarmResult


def _mock_db() -> MagicMock:
    db = MagicMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.scalars = AsyncMock(return_value=MagicMock(all=lambda: []))
    return db


def _service(monkeypatch: pytest.MonkeyPatch, db: MagicMock) -> ReverseFarmService:
    svc = ReverseFarmService(db)
    svc.audit.log = AsyncMock()
    monkeypatch.setattr("app.farm.reverse.ws_manager.broadcast", AsyncMock())
    return svc


@pytest.mark.asyncio
async def test_delegates_to_ip_farm_with_resolve_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    """Явные IP уходят в ферму IP с resolve_hosts=True; сводка мапится из её результата."""
    svc = _service(monkeypatch, _mock_db())
    ip_stub = AsyncMock(return_value=IpFarmResult(hostnames_found=2, hosts_promoted=1))
    monkeypatch.setattr(IpFarmService, "probe_and_import", ip_stub)

    result = await svc.probe_and_import(101, "1.2.3.4\n5.6.7.8", actor_id=7)

    ip_stub.assert_awaited_once()
    # bound-вызов IpFarmService(db).probe_and_import(...): self не передаётся под моком.
    assert ip_stub.await_args.args[1] == "1.2.3.4\n5.6.7.8"
    assert ip_stub.await_args.kwargs.get("resolve_hosts") is True
    assert result.ips_scanned == 2
    assert result.hostnames_found == 2
    assert result.hosts_discovered == 1


@pytest.mark.asyncio
async def test_empty_input_defaults_to_project_ips(monkeypatch: pytest.MonkeyPatch) -> None:
    """Пустой ввод → берём все IP-адреса проекта (origin='ip')."""
    svc = _service(monkeypatch, _mock_db())
    svc._project_ips = AsyncMock(return_value=["9.9.9.9"])
    ip_stub = AsyncMock(return_value=IpFarmResult())
    monkeypatch.setattr(IpFarmService, "probe_and_import", ip_stub)

    result = await svc.probe_and_import(101, "", actor_id=7)

    assert ip_stub.await_args.args[1] == "9.9.9.9"
    assert result.ips_scanned == 1


@pytest.mark.asyncio
async def test_no_ips_returns_empty_without_calling_ip_farm(monkeypatch: pytest.MonkeyPatch) -> None:
    svc = _service(monkeypatch, _mock_db())
    svc._project_ips = AsyncMock(return_value=[])
    ip_stub = AsyncMock(return_value=IpFarmResult())
    monkeypatch.setattr(IpFarmService, "probe_and_import", ip_stub)

    result = await svc.probe_and_import(101, "", actor_id=7)

    ip_stub.assert_not_awaited()
    assert result.ips_scanned == 0


@pytest.mark.asyncio
async def test_create_job_without_ips_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    svc = _service(monkeypatch, _mock_db())
    svc._project_ips = AsyncMock(return_value=[])

    with pytest.raises(ValidationError):
        await svc.create_job(101, "", actor_id=7)
