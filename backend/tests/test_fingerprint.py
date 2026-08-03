import pytest

from app.farm.core import ProbeResult
from app.farm.fingerprint import (
    Tech,
    detect_services,
    has_cloudflare,
    parse_httpx_jsonl,
    parse_whatweb_json,
    url_for,
)
from app.farm.resolver import ResolvedHost

# ------------------------------------------------------------------- httpx

# Реальный формат httpx-pd v1.10 -json (claude.com за Cloudflare).
HTTPX_JSONL = (
    '{"input":"https://claude.com:443/","url":"https://claude.com:443/","webserver":"cloudflare",'
    '"tech":["Cloudflare","Cloudflare Bot Management","HSTS","HTTP/3"],"cdn_name":null}\n'
    '{"input":"https://api.acme.com:443/","url":"https://api.acme.com:443/","webserver":"nginx",'
    '"tech":["Nginx:1.25.3","PHP:8.2.1","WordPress"]}'
)


def test_parse_httpx_extracts_stack_with_versions() -> None:
    parsed = parse_httpx_jsonl(HTTPX_JSONL)
    acme = {t.name: t.version for t in parsed["https://api.acme.com:443/"]}
    assert acme["Nginx"] == "1.25.3"
    assert acme["PHP"] == "8.2.1"
    assert acme["WordPress"] is None


def test_parse_httpx_flags_cloudflare_from_tech() -> None:
    parsed = parse_httpx_jsonl(HTTPX_JSONL)
    cf = parsed["https://claude.com:443/"]
    assert [t.name for t in cf] == ["Cloudflare", "Cloudflare Bot Management", "HSTS", "HTTP/3"]
    assert has_cloudflare(cf) is True
    # у api.acme.com Cloudflare нет
    assert has_cloudflare(parsed["https://api.acme.com:443/"]) is False


def test_parse_httpx_adds_cdn_name_as_tech() -> None:
    # tech без Cloudflare, но cdn_name говорит cloudflare → добавляем как технологию
    line = '{"input":"https://x/","tech":["Nginx"],"cdn_name":"cloudflare"}'
    techs = parse_httpx_jsonl(line)["https://x/"]
    assert has_cloudflare(techs) is True


def test_parse_httpx_skips_garbage_lines() -> None:
    assert parse_httpx_jsonl("") == {}
    assert parse_httpx_jsonl("not json\n{bad}") == {}


# ------------------------------------------------------------------- whatweb


def test_parse_whatweb_drops_meta_and_keeps_stack() -> None:
    raw = '[{"plugins":{"Country":{"string":["ZZ"]},"HTTPServer":{"string":["nginx/1.25.3"]},"PHP":{"version":["8.2"]}}}]'
    techs = {t.name for t in parse_whatweb_json(raw)}
    assert "nginx" in techs and "PHP" in techs
    assert "Country" not in techs


# ------------------------------------------------------------------- helpers


def test_url_for_wraps_ipv6() -> None:
    assert url_for(ProbeResult("2001:db8::1", 8443, "https", False, True, 200)) == "https://[2001:db8::1]:8443/"
    assert url_for(ProbeResult("acme.com", 443, "https", False, True, 200)) == "https://acme.com:443/"


# ------------------------------------------------------------------- detect


@pytest.mark.asyncio
async def test_detect_services_maps_engine_output_to_ports() -> None:
    async def fake(urls: list[str]) -> dict[str, list[Tech]]:
        # движок нормализовал URL (убрал слэш) — матчинг по _url_key всё равно сойдётся
        return {"https://acme.com:443": [Tech("Cloudflare"), Tech("Nginx", "1.25.3")]}

    probes = [
        ProbeResult("acme.com", 443, "https", False, True, 200),
        ProbeResult("acme.com", 80, "http", True, False, None),  # не ответил → не детектим
    ]
    result = await detect_services(probes, detector=fake)

    assert [t.name for t in result[("acme.com", 443)]] == ["Cloudflare", "Nginx"]
    assert has_cloudflare(result[("acme.com", 443)]) is True


@pytest.mark.asyncio
async def test_detect_services_empty_when_nothing_responded() -> None:
    async def boom(urls: list[str]) -> dict[str, list[Tech]]:
        raise AssertionError("не должно вызываться")

    probes = [ProbeResult("acme.com", 80, "http", True, False, None)]
    assert await detect_services(probes, detector=boom) == {}


@pytest.mark.asyncio
async def test_detect_services_regate_drops_rebound_host() -> None:
    """Хост, который к моменту детекта резолвится во внутренний адрес, из выхода
    наружу исключается (anti-rebind)."""
    seen_urls: list[str] = []

    async def fake(urls: list[str]) -> dict[str, list[Tech]]:
        seen_urls.extend(urls)
        return {u: [Tech("Nginx")] for u in urls}

    async def resolver(hosts: list[str]) -> dict[str, ResolvedHost]:
        return {
            "ext.com": ResolvedHost(ip="8.8.8.8", ips=["8.8.8.8"]),
            "rebind.com": ResolvedHost(ip="10.0.0.1", ips=["10.0.0.1"], blocked=True),
        }

    probes = [
        ProbeResult("ext.com", 443, "https", False, True, 200),
        ProbeResult("rebind.com", 443, "https", False, True, 200),
    ]
    result = await detect_services(probes, detector=fake, resolver=resolver)

    assert seen_urls == ["https://ext.com:443/"]  # rebind.com не ушёл в бинарь
    assert ("ext.com", 443) in result
    assert ("rebind.com", 443) not in result
