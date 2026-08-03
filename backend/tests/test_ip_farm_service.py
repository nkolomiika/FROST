import socket
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.cloudflare import is_cloudflare_ip
from app.enums import HostStatus
from app.farm import HostFarmService, IpFarmService, ProbeResult, ResolvedHost
from app.farm.resolver import ResolvedName, ReverseResult, merge_names, reverse_resolve
from app.schemas import HostFarmResult, IpFarmResult

# --------------------------------------------------------------------- parse


def test_parse_accepts_ips_with_and_without_ports() -> None:
    raw = "1.2.3.4\n1.2.3.4:8443\nhttps://5.6.7.8:443\n[2001:db8::1]:8443"
    targets, errors = IpFarmService.parse_ip_targets(raw)

    assert set(targets) == {"1.2.3.4", "5.6.7.8", "2001:db8::1"}
    assert targets["1.2.3.4"].explicit_ports == {8443: "https"}
    assert targets["5.6.7.8"].explicit_ports == {443: "https"}
    assert targets["2001:db8::1"].explicit_ports == {8443: "https"}
    assert all(t.is_ip for t in targets.values())
    assert errors == []


def test_parse_rejects_hostnames_with_a_hint() -> None:
    targets, errors = IpFarmService.parse_ip_targets("1.2.3.4\nexample.com")

    assert set(targets) == {"1.2.3.4"}
    assert any("example.com: не IP-адрес" in e for e in errors)


# ---------------------------------------------------------------- cloudflare


@pytest.mark.parametrize(
    ("addr", "expected"),
    [
        ("104.16.0.1", True),  # 104.16.0.0/13
        ("172.64.1.1", True),  # 172.64.0.0/13
        ("2606:4700::1", True),  # 2606:4700::/32
        ("93.184.216.34", False),
        ("8.8.8.8", False),
        ("не-адрес", False),
        ("", False),
        (None, False),
    ],
)
def test_is_cloudflare_ip(addr: str | None, expected: bool) -> None:
    assert is_cloudflare_ip(addr) is expected


# ------------------------------------------------------------------- reverse


def _addrinfo(addr: str) -> list[tuple]:
    family = socket.AF_INET6 if ":" in addr else socket.AF_INET
    return [(family, socket.SOCK_STREAM, 6, "", (addr, 0))]


def _patch_dns(
    monkeypatch: pytest.MonkeyPatch,
    *,
    ptr: dict[str, tuple[str, list[str]]] | None = None,
    forward: dict[str, str] | None = None,
) -> None:
    """Подменяет PTR и прямой резолв. Отсутствующее имя/адрес → ошибка резолвера."""
    ptr = ptr or {}
    forward = forward or {}

    def fake_gethostbyaddr(ip: str) -> tuple[str, list[str], list[str]]:
        if ip not in ptr:
            raise socket.herror(1, "Unknown host")
        primary, aliases = ptr[ip]
        return primary, aliases, [ip]

    def fake_getaddrinfo(host: str, *_args, **_kwargs) -> list[tuple]:
        if host not in forward:
            raise socket.gaierror(-2, "Name or service not known")
        return _addrinfo(forward[host])

    monkeypatch.setattr(socket, "gethostbyaddr", fake_gethostbyaddr)
    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


@pytest.mark.asyncio
async def test_reverse_confirms_matching_forward(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_dns(
        monkeypatch,
        ptr={"1.2.3.4": ("api.acme.com", [])},
        forward={"api.acme.com": "1.2.3.4"},
    )
    result = await reverse_resolve(["1.2.3.4"], [])

    (name,) = result["1.2.3.4"].names
    assert (name.hostname, name.source, name.confirmed) == ("api.acme.com", "ptr", True)


@pytest.mark.asyncio
async def test_reverse_keeps_unconfirmed_ptr_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """PTR-имя, чей A смотрит в другой адрес, не выбрасываем — помечаем."""
    _patch_dns(
        monkeypatch,
        ptr={"1.2.3.4": ("stale.acme.com", [])},
        forward={"stale.acme.com": "9.9.9.9"},
    )
    result = await reverse_resolve(["1.2.3.4"], [])

    (name,) = result["1.2.3.4"].names
    assert name.hostname == "stale.acme.com"
    assert name.confirmed is False


@pytest.mark.asyncio
async def test_reverse_survives_missing_ptr(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_dns(monkeypatch, ptr={}, forward={})
    result = await reverse_resolve(["1.2.3.4"], [])

    assert result["1.2.3.4"].names == []


@pytest.mark.asyncio
async def test_reverse_adds_project_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    """Имя известного хоста, резолвящееся в этот IP, попадает в колонку."""
    _patch_dns(monkeypatch, ptr={}, forward={"cdn.acme.com": "1.2.3.4"})
    result = await reverse_resolve(["1.2.3.4"], ["cdn.acme.com", "other.acme.com"])

    (name,) = result["1.2.3.4"].names
    assert (name.hostname, name.source, name.confirmed) == ("cdn.acme.com", "project", True)


@pytest.mark.asyncio
async def test_reverse_merges_ptr_and_project_into_one_name(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_dns(
        monkeypatch,
        ptr={"1.2.3.4": ("api.acme.com", [])},
        forward={"api.acme.com": "1.2.3.4"},
    )
    result = await reverse_resolve(["1.2.3.4"], ["api.acme.com"])

    (name,) = result["1.2.3.4"].names  # одна запись, не две
    assert (name.source, name.confirmed) == ("ptr", True)


@pytest.mark.asyncio
async def test_reverse_returns_several_names_for_one_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    """Один IP → несколько имён: строка в UI остаётся одна, имён в ячейке больше."""
    _patch_dns(
        monkeypatch,
        ptr={"1.2.3.4": ("api.acme.com", ["www.acme.com"])},
        forward={"api.acme.com": "1.2.3.4", "www.acme.com": "1.2.3.4"},
    )
    result = await reverse_resolve(["1.2.3.4"], [])

    assert [n.hostname for n in result["1.2.3.4"].names] == ["api.acme.com", "www.acme.com"]
    assert all(n.confirmed for n in result["1.2.3.4"].names)


@pytest.mark.asyncio
async def test_reverse_disabled_does_no_lookups(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args, **_kwargs):
        raise AssertionError("резолв не должен вызываться при выключенном флаге")

    monkeypatch.setattr(socket, "gethostbyaddr", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr("app.farm.resolver.settings.farm_reverse_dns_enabled", False)

    result = await reverse_resolve(["1.2.3.4"], ["acme.com"])
    assert result["1.2.3.4"].names == []


def test_merge_names_prefers_ptr_and_ors_confirmation() -> None:
    merged = merge_names(
        [
            ResolvedName("a.com", "project", confirmed=True),
            ResolvedName("a.com", "ptr", confirmed=False),
            ResolvedName("b.com", "ptr", confirmed=False),
        ]
    )
    assert [(n.hostname, n.source, n.confirmed) for n in merged] == [
        ("a.com", "ptr", True),  # подтверждённые выше
        ("b.com", "ptr", False),
    ]


# ------------------------------------------------------------------- persist


def _mock_db() -> MagicMock:
    db = MagicMock()
    db.scalar = AsyncMock(return_value=None)
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    # create_job снимает адреса со скрытия через db.execute(delete(ProjectHiddenIp)).
    db.execute = AsyncMock(return_value=MagicMock())
    return db


def _service(monkeypatch: pytest.MonkeyPatch, db: MagicMock) -> IpFarmService:
    svc = IpFarmService(db)
    svc.audit.log = AsyncMock()
    monkeypatch.setattr("app.farm.ips.ws_manager.broadcast", AsyncMock())
    return svc


@pytest.mark.asyncio
async def test_persist_creates_ip_only_host(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _mock_db()
    svc = _service(monkeypatch, db)

    targets, _ = IpFarmService.parse_ip_targets("104.16.0.1:443")
    resolved = {"104.16.0.1": ResolvedHost(ip="104.16.0.1", ips=["104.16.0.1"])}
    reverse = {"104.16.0.1": ReverseResult("104.16.0.1", [ResolvedName("cf.acme.com", "ptr", True)])}
    probes = [ProbeResult("104.16.0.1", 443, "https", inferred=False, responded=True, http_status=200)]

    result = await svc._persist_ips(101, targets, resolved, reverse, probes, actor_id=7)

    created_hosts = [o for o in db.add.call_args_list if getattr(o.args[0], "origin", None) == "ip"]
    assert len(created_hosts) == 1
    assert created_hosts[0].args[0].hostname is None
    assert result.ips_created == 1
    assert result.ips_online == 1
    assert result.hostnames_found == 1
    assert result.ips[0].is_cloudflare is True
    assert result.ips[0].hostnames[0].hostname == "cf.acme.com"
    assert result.ips[0].attached_to_existing_host is False
    svc.audit.log.assert_awaited_once()


@pytest.mark.asyncio
async def test_persist_keeps_ip_measurement_off_domain_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """Даже когда подтверждённое PTR-имя совпадает с доменным хостом, ферма IP
    создаёт СВОЙ origin=ip хост и не подшивается к доменному — иначе пробив по IP
    затирал бы порты, снятые пробивом по домену (тот самый баг)."""
    db = _mock_db()
    svc = _service(monkeypatch, db)
    # attach ищет только origin=ip хост; его нет → None → создаём свой.
    db.scalar = AsyncMock(return_value=None)

    targets, _ = IpFarmService.parse_ip_targets("1.2.3.4:443")
    resolved = {"1.2.3.4": ResolvedHost(ip="1.2.3.4", ips=["1.2.3.4"])}
    reverse = {"1.2.3.4": ReverseResult("1.2.3.4", [ResolvedName("api.acme.com", "ptr", True)])}
    probes = [ProbeResult("1.2.3.4", 443, "https", inferred=False, responded=True, http_status=200)]

    result = await svc._persist_ips(101, targets, resolved, reverse, probes, actor_id=7)

    # создан свой origin=ip хост, а не подшито к доменному
    assert [c for c in db.add.call_args_list if getattr(c.args[0], "origin", None) == "ip"]
    assert result.ips[0].attached_to_existing_host is False
    # запрос привязки фильтрует именно origin=ip — доменные не матчатся
    attach_query = str(db.scalar.await_args_list[0].args[0]).replace("\n", " ")
    assert "hosts.origin" in attach_query
    # имя из PTR всё равно попадает в колонку Hostname — оно из hostnames-JSON,
    # а не из привязки портов
    assert result.ips[0].hostnames[0].hostname == "api.acme.com"


@pytest.mark.asyncio
async def test_persist_reuses_existing_ip_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """Повторный скан того же адреса переиспользует origin=ip хост, не плодя дубли,
    и обновляет статус ЕГО (не доменного) свежим пробивом."""
    db = _mock_db()
    svc = _service(monkeypatch, db)
    ip_row = MagicMock(ip_address="1.2.3.4", is_primary=True, is_cloudflare=False)
    ip_host = MagicMock(id=9, origin="ip", hostname=None, status=HostStatus.DOWN, ip_addresses=[ip_row])
    # 1-й scalar — attach находит origin=ip хост; 2-й — порт-лукап (нет → создастся).
    db.scalar = AsyncMock(side_effect=[ip_host, None])

    targets, _ = IpFarmService.parse_ip_targets("1.2.3.4:443")
    resolved = {"1.2.3.4": ResolvedHost(ip="1.2.3.4", ips=["1.2.3.4"])}
    reverse = {"1.2.3.4": ReverseResult("1.2.3.4", [])}
    probes = [ProbeResult("1.2.3.4", 443, "https", inferred=False, responded=True, http_status=200)]

    result = await svc._persist_ips(101, targets, resolved, reverse, probes, actor_id=7)

    assert result.ips[0].attached_to_existing_host is True
    assert result.ips[0].host_id == 9
    assert not [c for c in db.add.call_args_list if getattr(c.args[0], "origin", None) == "ip"]
    assert result.ips_updated == 1 and result.ips_created == 0
    assert ip_host.status is HostStatus.UP  # свой хост обновлён свежим пробивом


@pytest.mark.asyncio
async def test_persist_commits_per_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _mock_db()
    svc = _service(monkeypatch, db)

    targets, _ = IpFarmService.parse_ip_targets("1.2.3.4\n5.6.7.8")
    resolved = {
        "1.2.3.4": ResolvedHost(ip="1.2.3.4", ips=["1.2.3.4"]),
        "5.6.7.8": ResolvedHost(ip="5.6.7.8", ips=["5.6.7.8"]),
    }
    reverse = {ip: ReverseResult(ip) for ip in targets}

    result = await svc._persist_ips(101, targets, resolved, reverse, [], actor_id=7)

    assert db.commit.await_count == 2
    assert result.ips_offline == 2  # ни один порт не ответил


@pytest.mark.asyncio
async def test_persist_blocked_internal_ip_is_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _mock_db()
    svc = _service(monkeypatch, db)

    targets, _ = IpFarmService.parse_ip_targets("10.0.0.5")
    resolved = {"10.0.0.5": ResolvedHost(ip="10.0.0.5", ips=["10.0.0.5"], blocked=True, error="internal")}
    reverse = {"10.0.0.5": ReverseResult("10.0.0.5")}

    result = await svc._persist_ips(101, targets, resolved, reverse, [], actor_id=7)

    assert result.ips_online == 0 and result.ips_offline == 0
    assert result.ports_created == 0


# ------------------------------------------------ IP → host promotion (chain)


def _promotion_service(monkeypatch: pytest.MonkeyPatch, names: list[ResolvedName]) -> tuple:
    """IpFarmService со всеми сетевыми/БД-фазами замоканными, кроме продвижения."""
    db = _mock_db()
    db.scalars = AsyncMock(return_value=MagicMock(all=lambda: []))  # _load_project_hostnames
    svc = IpFarmService(db)
    svc._resolve_dns = AsyncMock(return_value={"1.2.3.4": ResolvedHost(ip="1.2.3.4", ips=["1.2.3.4"])})
    svc._probe_all = AsyncMock(return_value=[])
    svc._persist_ips = AsyncMock(return_value=IpFarmResult())
    monkeypatch.setattr("app.farm.ips.detect_services", AsyncMock(return_value={}))
    monkeypatch.setattr(
        "app.farm.ips.reverse_resolve",
        AsyncMock(return_value={"1.2.3.4": ReverseResult("1.2.3.4", names)}),
    )
    host_stub = AsyncMock(return_value=HostFarmResult(hosts_created=1))
    monkeypatch.setattr(HostFarmService, "probe_and_import", host_stub)
    return svc, host_stub


@pytest.mark.asyncio
async def test_confirmed_ptr_name_is_promoted_through_host_farm(monkeypatch: pytest.MonkeyPatch) -> None:
    """IP → подтверждённое PTR-имя → ферма хостов ищет его порты/сервисы → Host."""
    svc, host_stub = _promotion_service(
        monkeypatch,
        [ResolvedName("api.acme.com", "ptr", confirmed=True), ResolvedName("bad.acme.com", "ptr", confirmed=False)],
    )
    result = await svc.probe_and_import(101, "1.2.3.4", actor_id=7)

    host_stub.assert_awaited_once()
    # только подтверждённое имя ушло в ферму хостов (неподтверждённое — вектор спуфинга)
    assert host_stub.await_args.args[2] == "api.acme.com"
    # рекурсию обрываем: ферма хостов не должна продвигать адреса обратно в ферму IP
    assert host_stub.await_args.kwargs.get("resolve_ips") is False
    assert result.hosts_promoted == 1


@pytest.mark.asyncio
async def test_no_confirmed_names_no_promotion(monkeypatch: pytest.MonkeyPatch) -> None:
    svc, host_stub = _promotion_service(monkeypatch, [ResolvedName("bad.acme.com", "ptr", confirmed=False)])
    result = await svc.probe_and_import(101, "1.2.3.4", actor_id=7)

    host_stub.assert_not_awaited()
    assert result.hosts_promoted == 0


@pytest.mark.asyncio
async def test_promotion_can_be_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    svc, host_stub = _promotion_service(monkeypatch, [ResolvedName("api.acme.com", "ptr", confirmed=True)])
    monkeypatch.setattr("app.farm.ips.settings.farm_ip_resolve_hosts_enabled", False)
    await svc.probe_and_import(101, "1.2.3.4", actor_id=7)

    host_stub.assert_not_awaited()


@pytest.mark.asyncio
async def test_promotion_skipped_when_resolve_hosts_false(monkeypatch: pytest.MonkeyPatch) -> None:
    """resolve_hosts=False (обычное «Add IPs») не продвигает PTR-имя в ферму хостов —
    кросс-рекон делается только явным запуском Reverse-DNS сканера."""
    svc, host_stub = _promotion_service(monkeypatch, [ResolvedName("api.acme.com", "ptr", confirmed=True)])
    await svc.probe_and_import(101, "1.2.3.4", actor_id=7, resolve_hosts=False)

    host_stub.assert_not_awaited()


@pytest.mark.asyncio
async def test_skip_targets_are_not_probed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Уже добавленный адрес исключается из резолва/пробива и считается пропущенным."""
    svc, _ = _promotion_service(monkeypatch, [])
    # переопределяем резолв, чтобы поймать, какие адреса реально ушли в фазу резолва
    svc._resolve_dns = AsyncMock(return_value={"5.6.7.8": ResolvedHost(ip="5.6.7.8", ips=["5.6.7.8"])})
    result = await svc.probe_and_import(101, "1.2.3.4\n5.6.7.8", actor_id=7, skip_targets=["1.2.3.4"])

    assert result.ips_skipped == 1
    assert svc._resolve_dns.await_args.args[0] == ["5.6.7.8"]


@pytest.mark.asyncio
async def test_create_job_all_existing_finishes_immediately(monkeypatch: pytest.MonkeyPatch) -> None:
    """Все адреса уже добавлены → задача сразу done, пробинг не запускается."""
    from app.enums import ReconJobStatus

    db = _mock_db()
    db.refresh = AsyncMock()
    db.scalars = AsyncMock(return_value=MagicMock(all=lambda: ["1.2.3.4", "5.6.7.8"]))
    svc = IpFarmService(db)

    job = await svc.create_job(101, "1.2.3.4\n5.6.7.8", actor_id=7)

    assert job.status == ReconJobStatus.DONE
    assert job.targets_total == 0
    assert job.result["ips_skipped"] == 2
