package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nkolomiika/frost/internal/app/auth"
)

// Гейт админ-доступа к workspace-интеграциям: IntegrationsHandler монтирует роуты
// под requireAdmin — проверяем сам гейт (тот же, что защищает /workspace/integrations):
// ADMIN проходит, PENTESTER и аноним получают 403.
func TestRequireAdmin_IntegrationsGate(t *testing.T) {
	cases := []struct {
		name    string
		user    *auth.User
		reached bool
		code    int
	}{
		{"admin passes", &auth.User{ID: 1, Role: "ADMIN"}, true, http.StatusOK},
		{"pentester blocked", &auth.User{ID: 2, Role: "PENTESTER"}, false, http.StatusForbidden},
		{"anonymous blocked", nil, false, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var reached bool
			mw := requireAdmin(okHandler(&reached))
			req := httptest.NewRequest(http.MethodGet, "/api/v1/workspace/integrations", nil)
			if tc.user != nil {
				req = req.WithContext(context.WithValue(req.Context(), userCtxKey, tc.user))
			}
			rec := httptest.NewRecorder()
			mw.ServeHTTP(rec, req)
			if reached != tc.reached || rec.Code != tc.code {
				t.Fatalf("reached=%v code=%d, want reached=%v code=%d", reached, rec.Code, tc.reached, tc.code)
			}
		})
	}
}
