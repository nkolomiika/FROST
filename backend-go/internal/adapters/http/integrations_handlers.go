package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/nkolomiika/frost/internal/app/auth"
	"github.com/nkolomiika/frost/internal/app/integrations"
)

// IntegrationsHandler обслуживает workspace-level API-ключи внешних сервисов
// (/api/v1/workspace/integrations), admin-only. Секреты наружу не отдаются — только
// факт «configured».
type IntegrationsHandler struct {
	svc         *integrations.Service
	auth        *auth.Service
	csrfOrigins []string
}

// NewIntegrationsHandler собирает обработчик интеграций.
func NewIntegrationsHandler(svc *integrations.Service, authSvc *auth.Service, csrfOrigins []string) *IntegrationsHandler {
	return &IntegrationsHandler{svc: svc, auth: authSvc, csrfOrigins: csrfOrigins}
}

// Register монтирует роуты интеграций под requireAuth+requireAdmin (+CSRF на PUT).
func (h *IntegrationsHandler) Register(r chi.Router) {
	r.Route("/api/v1/workspace/integrations", func(ar chi.Router) {
		ar.Use(enforceCSRF(h.csrfOrigins))
		ar.Use(requireAuth(h.auth))
		ar.Use(requireAdmin)
		ar.Get("/", h.list)
		ar.Put("/", h.put)
	})
}

// integrationItem — элемент ответа (без секрета).
type integrationItem struct {
	KeyName    string  `json:"key_name"`
	Configured bool    `json:"configured"`
	UpdatedAt  *string `json:"updated_at"`
}

func itemResp(it integrations.Item) integrationItem {
	var ua *string
	if it.UpdatedAt != nil {
		s := it.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
		ua = &s
	}
	return integrationItem{KeyName: it.KeyName, Configured: it.Configured, UpdatedAt: ua}
}

func (h *IntegrationsHandler) list(w http.ResponseWriter, r *http.Request) {
	items, err := h.svc.List(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]integrationItem, 0, len(items))
	for _, it := range items {
		out = append(out, itemResp(it))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *IntegrationsHandler) put(w http.ResponseWriter, r *http.Request) {
	var req struct {
		KeyName string `json:"key_name"`
		Value   string `json:"value"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	it, err := h.svc.Set(r.Context(), req.KeyName, req.Value, actorFrom(r).ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, itemResp(it))
}
