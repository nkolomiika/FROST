package http

import (
	"net"
	"net/http"

	"github.com/nkolomiika/frost/internal/apperr"
)

var mutatingMethods = map[string]bool{
	http.MethodPost:   true,
	http.MethodPut:    true,
	http.MethodPatch:  true,
	http.MethodDelete: true,
}

// enforceCSRF — middleware проверки Origin для мутирующих методов (порт
// dependencies.enforce_csrf). GET/HEAD/OPTIONS пропускаются.
func enforceCSRF(allowed []string) func(http.Handler) http.Handler {
	set := make(map[string]bool, len(allowed))
	for _, o := range allowed {
		set[o] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if mutatingMethods[r.Method] {
				origin := r.Header.Get("Origin")
				if origin == "" {
					writeError(w, apperr.Forbidden("Отсутствует заголовок Origin"))
					return
				}
				if !set[origin] {
					writeError(w, apperr.Forbidden("Недопустимый Origin"))
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientIP возвращает IP клиента (host из RemoteAddr; RealIP-middleware уже
// подставил forwarded-адрес, если он есть).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
