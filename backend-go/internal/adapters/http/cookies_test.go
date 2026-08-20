package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Порт backend/tests/test_auth_cookies.py — флаги безопасности auth-cookie и
// их очистка (Max-Age=0). set/clear живут в CookieConfig.

func cookieByName(cs []*http.Cookie, name string) *http.Cookie {
	for _, c := range cs {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// test_set_auth_cookies_contains_security_flags.
func TestSetAuthCookiesContainsSecurityFlags(t *testing.T) {
	cfg := CookieConfig{Secure: true, SameSite: http.SameSiteStrictMode, AccessMaxAge: 1800, RefreshMaxAge: 2592000}
	rec := httptest.NewRecorder()
	cfg.setAuthCookies(rec, "acc", "ref")
	cs := rec.Result().Cookies()

	access := cookieByName(cs, accessCookie)
	if access == nil {
		t.Fatal("access_token cookie missing")
	}
	if !access.HttpOnly || !access.Secure || access.SameSite != http.SameSiteStrictMode {
		t.Errorf("access flags = HttpOnly:%v Secure:%v SameSite:%v", access.HttpOnly, access.Secure, access.SameSite)
	}
	if access.Path != "/" || access.MaxAge != 1800 || access.Value != "acc" {
		t.Errorf("access = path:%q maxage:%d value:%q", access.Path, access.MaxAge, access.Value)
	}
	refresh := cookieByName(cs, refreshCookie)
	if refresh == nil {
		t.Fatal("refresh_token cookie missing")
	}
	if !refresh.HttpOnly || !refresh.Secure || refresh.Path != refreshPath || refresh.MaxAge != 2592000 {
		t.Errorf("refresh = HttpOnly:%v Secure:%v path:%q maxage:%d", refresh.HttpOnly, refresh.Secure, refresh.Path, refresh.MaxAge)
	}
}

// test_clear_auth_cookies_sets_zero_max_age: удаление → Max-Age=0 в заголовке.
func TestClearAuthCookiesSetsZeroMaxAge(t *testing.T) {
	cfg := CookieConfig{Secure: true, SameSite: http.SameSiteStrictMode}
	rec := httptest.NewRecorder()
	cfg.clearAuthCookies(rec)
	for _, c := range rec.Result().Cookies() {
		// net/http кодирует MaxAge<0 как "Max-Age=0" и обнуляет значение.
		if c.MaxAge > 0 || c.Value != "" {
			t.Errorf("cookie %q not cleared: maxage=%d value=%q", c.Name, c.MaxAge, c.Value)
		}
	}
	if cookieByName(rec.Result().Cookies(), accessCookie) == nil || cookieByName(rec.Result().Cookies(), refreshCookie) == nil {
		t.Fatal("clear must still emit both cookies for deletion")
	}
}
