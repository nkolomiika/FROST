"""CF по заголовкам ответа пробива — независимо от внешнего движка детекта."""

import httpx

from app.farm.core import _cf_from_headers


def test_cf_from_server_header() -> None:
    assert _cf_from_headers(httpx.Headers({"server": "cloudflare"})) is True
    assert _cf_from_headers(httpx.Headers({"Server": "Cloudflare"})) is True  # регистр не важен


def test_cf_from_cf_ray_header() -> None:
    # BYOIP вроде claude.com: server может быть иным, но cf-ray выдаёт CF-edge.
    assert _cf_from_headers(httpx.Headers({"cf-ray": "a1dce7b1-VNO"})) is True
    assert _cf_from_headers(httpx.Headers({"cf-cache-status": "DYNAMIC"})) is True


def test_no_cf_headers() -> None:
    assert _cf_from_headers(httpx.Headers({"server": "nginx"})) is False
    assert _cf_from_headers(httpx.Headers({})) is False
