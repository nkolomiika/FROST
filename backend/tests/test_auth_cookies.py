from fastapi import Response

from app.routers.auth import _clear_auth_cookies, _set_auth_cookies


def test_set_auth_cookies_contains_security_flags_tc_auth_001() -> None:
    response = Response()

    _set_auth_cookies(response, "access-value", "refresh-value")

    set_cookie_headers = response.headers.getlist("set-cookie")
    access_cookie = next(item for item in set_cookie_headers if item.startswith("access_token="))
    refresh_cookie = next(item for item in set_cookie_headers if item.startswith("refresh_token="))

    assert "HttpOnly" in access_cookie
    assert "Path=/" in access_cookie
    assert "SameSite=strict" in access_cookie

    assert "HttpOnly" in refresh_cookie
    assert "Path=/api/v1/auth/refresh" in refresh_cookie
    assert "SameSite=strict" in refresh_cookie


def test_clear_auth_cookies_sets_zero_max_age_tc_auth_008() -> None:
    response = Response()

    _clear_auth_cookies(response)

    set_cookie_headers = response.headers.getlist("set-cookie")
    access_cookie = next(item for item in set_cookie_headers if item.startswith("access_token="))
    refresh_cookie = next(item for item in set_cookie_headers if item.startswith("refresh_token="))

    assert "Max-Age=0" in access_cookie
    assert "Max-Age=0" in refresh_cookie
