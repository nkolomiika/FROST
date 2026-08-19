package http

import (
	"context"
	"net/http"

	"github.com/nkolomiika/frost/internal/app/auth"
)

type ctxKey int

const userCtxKey ctxKey = iota

// requireAuth — middleware, извлекающий пользователя из access-cookie и кладущий
// его в контекст (порт dependencies.get_current_user).
func requireAuth(svc *auth.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, err := svc.AuthenticateAccessToken(r.Context(), cookieValue(r, accessCookie))
			if err != nil {
				writeError(w, err)
				return
			}
			ctx := context.WithValue(r.Context(), userCtxKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// userFromContext достаёт аутентифицированного пользователя (после requireAuth).
func userFromContext(ctx context.Context) *auth.User {
	u, _ := ctx.Value(userCtxKey).(*auth.User)
	return u
}
