package http

import (
	"net/http"
	"strings"
)

// CookieConfig — параметры auth-cookie (зеркало cookie_* и TTL из config.py).
type CookieConfig struct {
	Secure        bool
	SameSite      http.SameSite
	AccessMaxAge  int // сек (jwt_access_token_expire_minutes*60)
	RefreshMaxAge int // сек (jwt_refresh_token_expire_days*86400)
	TwoFAMaxAge   int // сек (TWO_FA_PENDING_TTL_MINUTES*60)
}

// ParseSameSite переводит строку конфига в http.SameSite (strict по умолчанию).
func ParseSameSite(s string) http.SameSite {
	switch strings.ToLower(s) {
	case "lax":
		return http.SameSiteLaxMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteStrictMode
	}
}

const (
	accessCookie  = "access_token"
	refreshCookie = "refresh_token"
	twoFACookie   = "twofa_token"
	refreshPath   = "/api/v1/auth/refresh"
	twoFAPath     = "/api/v1/auth"
)

func (c CookieConfig) set(w http.ResponseWriter, name, value, path string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   c.Secure,
		SameSite: c.SameSite,
	})
}

// setAuthCookies ставит access+refresh cookie после успешного логина.
func (c CookieConfig) setAuthCookies(w http.ResponseWriter, access, refresh string) {
	c.set(w, accessCookie, access, "/", c.AccessMaxAge)
	c.set(w, refreshCookie, refresh, refreshPath, c.RefreshMaxAge)
}

// clearAuthCookies удаляет access+refresh cookie (MaxAge<0 → Max-Age=0 у Python).
func (c CookieConfig) clearAuthCookies(w http.ResponseWriter) {
	c.set(w, accessCookie, "", "/", -1)
	c.set(w, refreshCookie, "", refreshPath, -1)
}

// set2FACookie ставит промежуточную cookie второго шага логина.
func (c CookieConfig) set2FACookie(w http.ResponseWriter, pending string) {
	c.set(w, twoFACookie, pending, twoFAPath, c.TwoFAMaxAge)
}

// clear2FACookie убирает промежуточную 2FA-cookie.
func (c CookieConfig) clear2FACookie(w http.ResponseWriter) {
	c.set(w, twoFACookie, "", twoFAPath, -1)
}

// cookieValue возвращает значение cookie или "" если её нет.
func cookieValue(r *http.Request, name string) string {
	ck, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return ck.Value
}
