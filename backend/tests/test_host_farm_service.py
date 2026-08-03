import socket
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from app.enums import PortState
from app.farm import TOP_WEB_PORTS, HostFarmService, IpFarmService, ProbeResult, ResolvedHost
from app.farm.resolver import order_addrs
from app.schemas import HostFarmResult, IpFarmResult

# --------------------------------------------------------------------- parse


def test_parse_worked_example() -> None:
    raw = "https://example.com\nwww.example.com\nhttp://example.com\nwww.example.com"
    targets, errors = HostFarmService.parse_targets(raw)
    assert set(targets) == {"example.com", "www.example.com"}
    # both schemes collapse onto one host as explicit 80/443
    assert targets["example.com"].explicit_ports == {80: "http", 443: "https"}
    assert targets["example.com"].has_explicit is True
    # scheme-less host has no explicit ports → gets the curated set at probe time
    assert targets["www.example.com"].has_explicit is False
    assert targets["www.example.com"].explicit_ports == {}
    assert errors == []


def test_parse_strips_and_dedups() -> None:
    raw = "https://user:pass@example.com:8443/admin?x=1#frag\nexample.com:8443"
    targets, errors = HostFarmService.parse_targets(raw)
    assert set(targets) == {"example.com"}
    assert targets["example.com"].explicit_ports == {8443: "https"}
    assert errors == []


def test_parse_scheme_conflict_https_wins() -> None:
    targets, _ = HostFarmService.parse_targets("http://a.com:8080\nhttps://a.com:8080")
    assert targets["a.com"].explicit_ports == {8080: "https"}


def test_parse_ip_ipv6_and_idn() -> None:
    t_ipv6, _ = HostFarmService.parse_targets("[2001:db8::1]:8443")
    assert t_ipv6["2001:db8::1"].is_ip is True
    assert t_ipv6["2001:db8::1"].explicit_ports == {8443: "https"}

    t_ip, _ = HostFarmService.parse_targets("10.0.0.5")
    assert t_ip["10.0.0.5"].is_ip is True
    assert t_ip["10.0.0.5"].has_explicit is False

    t_idn, _ = HostFarmService.parse_targets("пример.рф")
    (name,) = t_idn
    assert name.startswith("xn--")


def test_parse_rejects_invalid() -> None:
    raw = "*.evil.com\nftp://x.com\nbad_host.com\nhttp://\n# a comment\n\n"
    targets, errors = HostFarmService.parse_targets(raw)
    assert targets == {}
    assert len(errors) == 4


def test_candidates_explicit_vs_inferred() -> None:
    svc = HostFarmService(MagicMock())
    targets, _ = HostFarmService.parse_targets("https://a.com\nb.com")
    explicit = svc._candidates_for(targets["a.com"])
    assert [(c.port, c.scheme, c.inferred) for c in explicit] == [(443, "https", False)]
    inferred = svc._candidates_for(targets["b.com"])
    assert all(c.inferred for c in inferred)
    assert {c.port for c in inferred} == set(TOP_WEB_PORTS)


# --------------------------------------------------------------------- probe


@pytest.mark.asyncio
async def test_probe_captures_status_without_following_redirect() -> None:
    responses = {
        ("example.com", 443, "https"): 200,
        ("example.com", 80, "http"): 301,
        ("www.example.com", 443, "https"): 200,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        # httpx normalizes a scheme's default port (80/443) to None on the URL.
        port = request.url.port or (443 if request.url.scheme == "https" else 80)
        key = (request.url.host, port, request.url.scheme)
        if key in responses:
            return httpx.Response(responses[key])
        raise httpx.ConnectError("connection refused")

    svc = HostFarmService(MagicMock())
    targets, _ = HostFarmService.parse_targets("https://example.com\nhttp://example.com\nwww.example.com")
    resolved = {
        "example.com": ResolvedHost(ip="93.184.216.34"),
        "www.example.com": ResolvedHost(ip="93.184.216.34"),
    }
    probes = await svc._probe_all(targets, resolved, transport=httpx.MockTransport(handler))
    by = {(p.hostname, p.port): p for p in probes}

    # 301 is captured, not followed
    assert by[("example.com", 80)].responded and by[("example.com", 80)].http_status == 301
    assert by[("example.com", 443)].http_status == 200
    assert by[("www.example.com", 443)].responded and by[("www.example.com", 443)].http_status == 200
    # a curated port with no mapping → ConnectError → not responded, no status
    dead = [p for p in probes if p.hostname == "www.example.com" and not p.responded]
    assert dead and all(p.http_status is None and p.inferred for p in dead)


# ------------------------------------------------------------------- persist


def _mock_db() -> MagicMock:
    db = MagicMock()
    db.scalar = AsyncMock(return_value=None)  # nothing pre-exists
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    db.execute = AsyncMock()  # для bulk-DELETE сервисов в _replace_services
    return db


@pytest.mark.asyncio
async def test_persist_creates_hosts_and_classifies_ports(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _mock_db()
    svc = HostFarmService(db)
    svc.audit.log = AsyncMock()
    monkeypatch.setattr("app.farm.hosts.ws_manager.broadcast", AsyncMock())

    targets, _ = HostFarmService.parse_targets("https://example.com\nwww.example.com")
    resolved = {"example.com": ResolvedHost(ip="1.1.1.1"), "www.example.com": ResolvedHost(ip="2.2.2.2")}
    probes = [
        ProbeResult("example.com", 443, "https", inferred=False, responded=True, http_status=200),
        ProbeResult("www.example.com", 443, "https", inferred=True, responded=True, http_status=200),
        ProbeResult("www.example.com", 80, "http", inferred=True, responded=False, http_status=None),
    ]
    result = await svc._persist(101, targets, resolved, probes, actor_id=7)

    assert result.hosts_created == 2
    assert result.hosts_online == 2
    # example:443 + www:443 created; www:80 inferred+dead → skipped
    assert result.ports_created == 2
    # persist commits per host (progressive), then one audit log at the end
    assert db.commit.await_count == 2
    svc.audit.log.assert_awaited_once()


@pytest.mark.asyncio
async def test_persist_offline_and_explicit_filtered(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _mock_db()
    svc = HostFarmService(db)
    svc.audit.log = AsyncMock()
    monkeypatch.setattr("app.farm.hosts.ws_manager.broadcast", AsyncMock())

    targets, _ = HostFarmService.parse_targets("https://dead.example")  # explicit 443
    resolved = {"dead.example": ResolvedHost(ip="1.2.3.4")}
    probes = [ProbeResult("dead.example", 443, "https", inferred=False, responded=False, http_status=None)]
    result = await svc._persist(101, targets, resolved, probes, actor_id=7)

    assert result.hosts_offline == 1
    assert result.hosts_online == 0
    # explicit port is recorded even when it didn't respond (as FILTERED)
    assert result.ports_created == 1
    assert result.hosts[0].status == "down"
    assert result.hosts[0].ports[0].state == "filtered"
    assert result.hosts[0].ports[0].http_status is None


@pytest.mark.asyncio
async def test_persist_blocked_internal_target(monkeypatch: pytest.MonkeyPatch) -> None:
    db = _mock_db()
    svc = HostFarmService(db)
    svc.audit.log = AsyncMock()
    monkeypatch.setattr("app.farm.hosts.ws_manager.broadcast", AsyncMock())

    targets, _ = HostFarmService.parse_targets("intranet.corp")
    resolved = {"intranet.corp": ResolvedHost(ip="10.0.0.5", blocked=True, error="internal")}
    result = await svc._persist(101, targets, resolved, [], actor_id=7)

    assert result.hosts[0].status == "unknown"  # not probed, not offline
    assert result.ports_created == 0
    assert result.hosts_online == 0 and result.hosts_offline == 0


# ------------------------------------------------------------------- resolve


def _info(family: int, addr: str) -> tuple:
    return (family, socket.SOCK_STREAM, 6, "", (addr, 0))


def test_order_addrs_ipv4_first_and_dedups() -> None:
    infos = [
        _info(socket.AF_INET6, "2606:4700::1"),
        _info(socket.AF_INET, "1.1.1.1"),
        _info(socket.AF_INET, "1.0.0.1"),
        _info(socket.AF_INET, "1.1.1.1"),  # дубль от разных socktype
    ]
    assert order_addrs(infos) == ["1.1.1.1", "1.0.0.1", "2606:4700::1"]
    assert order_addrs([]) == []


@pytest.mark.asyncio
async def test_ensure_ips_stores_every_resolved_address() -> None:
    """За одним именем обычно несколько A/AAAA — раньше писался только первый."""
    db = _mock_db()
    svc = HostFarmService(db)
    host = MagicMock()
    host.id = 1
    host.ip_addresses = []
    host.ip_address = None

    added: list = []
    db.add = MagicMock(side_effect=lambda row: added.append(row))

    primary = await svc._ensure_ips(host, ["1.1.1.1", "1.0.0.1", "2606:4700::1"])

    assert [row.ip_address for row in added] == ["1.1.1.1", "1.0.0.1", "2606:4700::1"]
    assert [row.is_primary for row in added] == [True, False, False]
    assert host.ip_address == "1.1.1.1"
    assert primary is added[0]
    # 2606:4700::/32 — сеть Cloudflare → True; для остальных сигнала CF нет и
    # cf_responded не передан → None (unknown), а не «нет CF».
    assert [row.is_cloudflare for row in added] == [None, None, True]


@pytest.mark.asyncio
async def test_ensure_ips_reuses_existing_rows() -> None:
    db = _mock_db()
    svc = HostFarmService(db)
    existing = MagicMock(ip_address="104.16.0.1", is_primary=True, is_cloudflare=False)
    host = MagicMock(id=1, ip_addresses=[existing], ip_address="104.16.0.1")
    db.add = MagicMock()

    primary = await svc._ensure_ips(host, ["104.16.0.1"])

    assert primary is existing
    db.add.assert_not_called()
    # признак пересчитывается даже на переиспользованной строке
    assert existing.is_cloudflare is True


@pytest.mark.asyncio
async def test_ensure_ips_cloudflare_tri_state() -> None:
    """is_cloudflare трёхзначен: None — сигнала нет (хост ещё пробится),
    False — ответил без CF, True — CF (по заголовкам/детекту или CIDR)."""

    async def cf_of(ip: str, *, hint: bool, responded: bool):
        db = _mock_db()
        svc = HostFarmService(db)
        added: list = []
        db.add = MagicMock(side_effect=lambda row: added.append(row))
        host = MagicMock(id=1, ip_addresses=[], ip_address=None)
        await svc._ensure_ips(host, [ip], cloudflare_hint=hint, cf_responded=responded)
        return added[0].is_cloudflare

    assert await cf_of("8.8.8.8", hint=False, responded=False) is None   # unknown (пробится)
    assert await cf_of("8.8.8.8", hint=False, responded=True) is False   # ответил, CF нет
    assert await cf_of("8.8.8.8", hint=True, responded=True) is True     # CF по сигналу пробива
    assert await cf_of("104.16.0.1", hint=False, responded=False) is True  # CF по CIDR


# --------------------------------------------------------- service detection


def _mock_ip_row(id_: int = 1):
    row = MagicMock()
    row.id = id_
    row.is_primary = True
    row.is_cloudflare = False
    row.ip_address = "1.1.1.1"
    return row


@pytest.mark.asyncio
async def test_upsert_port_writes_detected_services(monkeypatch: pytest.MonkeyPatch) -> None:
    """techs → Service-строки на порту (whatweb-стек в карточку хоста)."""
    from app.farm.fingerprint import Tech
    from app.models import Service

    db = _mock_db()
    svc = HostFarmService(db)
    host = MagicMock(id=1)
    ip_row = _mock_ip_row()
    p = ProbeResult("acme.com", 443, "https", inferred=False, responded=True, http_status=200)

    created = await svc._upsert_port(host, ip_row, p, PortState.OPEN, [Tech("nginx", "1.25.3"), Tech("PHP", "8.2")])

    assert created is True
    services = [c.args[0] for c in db.add.call_args_list if isinstance(c.args[0], Service)]
    assert [(s.name, s.version) for s in services] == [("nginx", "1.25.3"), ("PHP", "8.2")]
    db.execute.assert_awaited()  # старые сервисы порта вычищаются перед записью


@pytest.mark.asyncio
async def test_upsert_port_none_techs_leaves_services_untouched() -> None:
    """techs=None (детект не запускался) — сервисы не трогаем: ни DELETE, ни ADD."""
    from app.models import Service

    db = _mock_db()
    svc = HostFarmService(db)
    p = ProbeResult("acme.com", 443, "https", inferred=False, responded=True, http_status=200)

    await svc._upsert_port(MagicMock(id=1), _mock_ip_row(), p, PortState.OPEN, None)

    assert not [c for c in db.add.call_args_list if isinstance(c.args[0], Service)]
    db.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_upsert_port_empty_techs_clears_services() -> None:
    """techs=[] (детект прошёл, пусто) — чистим сервисы, порт станет unknown."""
    from app.models import Service

    db = _mock_db()
    svc = HostFarmService(db)
    p = ProbeResult("acme.com", 443, "https", inferred=False, responded=True, http_status=200)

    await svc._upsert_port(MagicMock(id=1), _mock_ip_row(), p, PortState.OPEN, [])

    db.execute.assert_awaited()  # DELETE выполнен
    assert not [c for c in db.add.call_args_list if isinstance(c.args[0], Service)]


@pytest.mark.asyncio
async def test_persist_flags_cloudflare_from_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    """claude.com за CF, но его адрес вне CIDR-списка → CF ставится по детекту."""
    from app.farm.fingerprint import Tech
    from app.models import HostIpAddress

    db = _mock_db()
    svc = HostFarmService(db)
    svc.audit.log = AsyncMock()
    monkeypatch.setattr("app.farm.hosts.ws_manager.broadcast", AsyncMock())

    targets, _ = HostFarmService.parse_targets("https://claude.com")
    resolved = {"claude.com": ResolvedHost(ip="93.184.216.34", ips=["93.184.216.34"])}  # НЕ CF-диапазон
    probes = [ProbeResult("claude.com", 443, "https", inferred=False, responded=True, http_status=200)]
    techs = {("claude.com", 443): [Tech("Cloudflare"), Tech("HSTS")]}

    await svc._persist(101, targets, resolved, probes, actor_id=7, techs_by_port=techs)

    ip_rows = [c.args[0] for c in db.add.call_args_list if isinstance(c.args[0], HostIpAddress)]
    assert ip_rows and ip_rows[0].is_cloudflare is True  # CIDR промахнулся — спас детект


# ---------------------------------------------- skip existing / IP promotion


def _import_service(monkeypatch: pytest.MonkeyPatch, resolved: dict) -> tuple:
    """HostFarmService со всеми сетевыми/БД-фазами замоканными, кроме продвижения
    адресов в ферму IP. Возвращает (svc, ip_stub)."""
    db = _mock_db()
    svc = HostFarmService(db)
    svc._resolve_dns = AsyncMock(return_value=resolved)
    svc._probe_all = AsyncMock(return_value=[])
    svc._persist = AsyncMock(return_value=HostFarmResult())
    monkeypatch.setattr("app.farm.hosts.detect_services", AsyncMock(return_value={}))
    ip_stub = AsyncMock(return_value=IpFarmResult(ips_created=1))
    monkeypatch.setattr(IpFarmService, "probe_and_import", ip_stub)
    return svc, ip_stub


@pytest.mark.asyncio
async def test_resolved_domain_ip_is_probed_by_ip_farm(monkeypatch: pytest.MonkeyPatch) -> None:
    """Адрес, в который разрезолвился домен, отдельно пробивается фермой IP
    (голым запросом к IP) — статусы портов домена и адреса не переиспользуются."""
    svc, ip_stub = _import_service(
        monkeypatch, {"example.com": ResolvedHost(ip="1.2.3.4", ips=["1.2.3.4"])}
    )
    result = await svc.probe_and_import(101, "example.com", actor_id=7)

    ip_stub.assert_awaited_once()
    # bound-вызов IpFarmService(db).probe_and_import(project_id, raw, actor_id): под
    # моком self не передаётся, поэтому raw с адресами — второй позиционный аргумент.
    assert ip_stub.await_args.args[1] == "1.2.3.4"
    # рекурсию обрываем: ферма IP не должна продвигать имена обратно в ферму хостов
    assert ip_stub.await_args.kwargs.get("resolve_hosts") is False
    assert result.ips_promoted == 1


@pytest.mark.asyncio
async def test_ip_literal_in_host_import_is_not_promoted(monkeypatch: pytest.MonkeyPatch) -> None:
    """IP-литерал из списка хостов уже пробит как есть — второй пробив не нужен."""
    svc, ip_stub = _import_service(
        monkeypatch, {"1.2.3.4": ResolvedHost(ip="1.2.3.4", ips=["1.2.3.4"])}
    )
    await svc.probe_and_import(101, "1.2.3.4", actor_id=7)

    ip_stub.assert_not_awaited()


@pytest.mark.asyncio
async def test_blocked_internal_ip_is_not_promoted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Внутренний адрес (SSRF-gate) не уходит в ферму IP."""
    svc, ip_stub = _import_service(
        monkeypatch,
        {"intranet.local": ResolvedHost(ip="10.0.0.5", ips=["10.0.0.5"], blocked=True)},
    )
    await svc.probe_and_import(101, "intranet.local", actor_id=7)

    ip_stub.assert_not_awaited()


@pytest.mark.asyncio
async def test_promotion_can_be_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    svc, ip_stub = _import_service(
        monkeypatch, {"example.com": ResolvedHost(ip="1.2.3.4", ips=["1.2.3.4"])}
    )
    monkeypatch.setattr("app.farm.hosts.settings.farm_host_resolve_ips_enabled", False)
    await svc.probe_and_import(101, "example.com", actor_id=7)

    ip_stub.assert_not_awaited()


@pytest.mark.asyncio
async def test_skip_targets_are_not_probed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Уже добавленные цели исключаются из резолва/пробива и считаются пропущенными."""
    svc, _ = _import_service(
        monkeypatch, {"b.com": ResolvedHost(ip="2.2.2.2", ips=["2.2.2.2"])}
    )
    result = await svc.probe_and_import(101, "a.com\nb.com", actor_id=7, skip_targets=["a.com"])

    assert result.hosts_skipped == 1
    # только не-пропущенная цель резолвится и передаётся в _persist
    assert svc._resolve_dns.await_args.args[0] == ["b.com"]
    assert set(svc._persist.await_args.args[1]) == {"b.com"}


# ------------------------------------------------ create_job: nothing-to-probe


@pytest.mark.asyncio
async def test_create_job_all_existing_finishes_immediately(monkeypatch: pytest.MonkeyPatch) -> None:
    """Все хосты уже добавлены → задача сразу done (воркер не будим, пробинг не идёт)."""
    from app.enums import ReconJobStatus

    db = _mock_db()
    db.refresh = AsyncMock()
    db.scalars = AsyncMock(return_value=MagicMock(all=lambda: ["a.com", "b.com"]))  # обе существуют
    svc = HostFarmService(db)

    job = await svc.create_job(101, "a.com\nb.com", actor_id=7)

    assert job.status == ReconJobStatus.DONE
    assert job.targets_total == 0
    assert job.result["hosts_skipped"] == 2
    # заготовок не заводим — обе цели существуют
    assert not [c for c in db.add.call_args_list if getattr(c.args[0], "hostname", "x") in ("a.com", "b.com")]


@pytest.mark.asyncio
async def test_create_job_with_new_targets_stays_pending(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.enums import ReconJobStatus

    db = _mock_db()
    db.refresh = AsyncMock()
    db.scalars = AsyncMock(return_value=MagicMock(all=lambda: ["a.com"]))  # только a.com существует
    svc = HostFarmService(db)

    job = await svc.create_job(101, "a.com\nb.com", actor_id=7)

    assert job.status == ReconJobStatus.PENDING
    assert job.targets_total == 1
    assert job.result is None
