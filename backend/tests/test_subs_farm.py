"""Scanner: раскрытие поддоменов — чистые парсеры и сборка коллектора."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.farm.subs import (
    SubdomainFarmService,
    in_scope,
    parse_crtsh,
    parse_roots,
    parse_subfinder,
)

# --------------------------------------------------------------------- parse


def test_parse_roots_dedups_and_drops_ip_and_comments() -> None:
    raw = "Example.com\n# comment\nexample.com\n10.0.0.1\napi.example.com, www.example.com\nbadword"
    assert parse_roots(raw) == ["example.com", "api.example.com", "www.example.com"]


def test_in_scope() -> None:
    assert in_scope("api.example.com", "example.com") is True
    assert in_scope("example.com", "example.com") is True
    assert in_scope("evil.com", "example.com") is False
    assert in_scope("notexample.com", "example.com") is False  # без точки-границы


def test_parse_crtsh_extracts_names_splits_and_strips_wildcards() -> None:
    raw = (
        '[{"name_value":"*.api.example.com\\nwww.example.com","common_name":"example.com"},'
        '{"name_value":"mail.example.com"},'
        '{"name_value":"out.of.scope.evil.com"}]'
    )
    got = parse_crtsh(raw, "example.com")
    assert got == {"api.example.com", "www.example.com", "example.com", "mail.example.com"}


def test_parse_crtsh_handles_garbage() -> None:
    assert parse_crtsh("", "example.com") == set()
    assert parse_crtsh("not json", "example.com") == set()
    assert parse_crtsh('{"not":"a list"}', "example.com") == set()


def test_parse_subfinder_filters_scope_and_ip() -> None:
    text = "api.example.com\nWWW.Example.com\n10.0.0.1\nevil.com\n\n"
    assert parse_subfinder(text, "example.com") == {"api.example.com", "www.example.com"}


# ------------------------------------------------------------------- collect


@pytest.mark.asyncio
async def test_collect_merges_sources_and_dedups() -> None:
    async def collector(roots: list[str]):
        return {
            "example.com": ({"a.example.com", "b.example.com"}, ["crt.sh"], []),
            "acme.com": ({"a.example.com", "x.acme.com"}, ["subfinder"], ["acme.com: boom"]),
        }

    svc = SubdomainFarmService(MagicMock())
    subs, used, errors = await svc._collect(["example.com", "acme.com"], collector)

    assert subs == {"a.example.com", "b.example.com", "x.acme.com"}  # дедуп across roots
    assert set(used) == {"crt.sh", "subfinder"}
    assert errors == ["acme.com: boom"]


@pytest.mark.asyncio
async def test_probe_and_import_runs_only_new_via_host_farm(monkeypatch: pytest.MonkeyPatch) -> None:
    """Найдено 3 поддомена, один уже есть в проекте → ферме хостов уходят только 2 новых."""
    from app.farm import subs as subs_mod
    from app.schemas import HostFarmResult

    async def collector(roots: list[str]):
        return {"example.com": ({"a.example.com", "b.example.com", "old.example.com"}, ["crt.sh"], [])}

    svc = SubdomainFarmService(MagicMock())
    svc.audit.log = AsyncMock()
    monkeypatch.setattr("app.farm.subs.ws_manager.broadcast", AsyncMock())
    # В проекте уже есть old.example.com.
    svc._project_hostnames = AsyncMock(return_value={"old.example.com"})

    passed: dict = {}

    class FakeHostFarm:
        def __init__(self, db):
            pass

        async def probe_and_import(self, project_id, raw, actor_id, **kwargs):
            passed["raw"] = raw
            return HostFarmResult(hosts_created=2, hosts_online=1, hosts_offline=1)

    monkeypatch.setattr(subs_mod, "HostFarmService", FakeHostFarm)

    result = await svc.probe_and_import(1, "example.com", 7, collector=collector)

    assert sorted(passed["raw"].split("\n")) == ["a.example.com", "b.example.com"]
    assert result.subdomains_found == 3
    assert result.subdomains_new == 2
    assert result.hosts_created == 2
    assert result.hosts_online == 1
