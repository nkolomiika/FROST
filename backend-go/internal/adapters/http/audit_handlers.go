package http

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/nkolomiika/frost/internal/app/audit"
	"github.com/nkolomiika/frost/internal/app/auth"
)

// AuditHandler обслуживает /api/v1/audit-logs (admin-only).
type AuditHandler struct {
	svc  *audit.Service
	auth *auth.Service
}

// NewAuditHandler собирает обработчик журнала.
func NewAuditHandler(svc *audit.Service, authSvc *auth.Service) *AuditHandler {
	return &AuditHandler{svc: svc, auth: authSvc}
}

// Register монтирует роут журнала под requireAuth+requireAdmin.
func (h *AuditHandler) Register(r chi.Router) {
	r.Route("/api/v1/audit-logs", func(ar chi.Router) {
		ar.Use(requireAuth(h.auth))
		ar.Use(requireAdmin)
		ar.Get("/", h.list)
	})
}

func (h *AuditHandler) list(w http.ResponseWriter, r *http.Request) {
	page := intQuery(r, "page", 1, 1, 1_000_000)
	size := intQuery(r, "size", 50, 1, 200)
	q := r.URL.Query()

	f := audit.Filters{
		Username:    strings.TrimSpace(q.Get("username")),
		Action:      strings.TrimSpace(q.Get("action")),
		EntityType:  strings.TrimSpace(q.Get("entity_type")),
		IPAddress:   strings.TrimSpace(q.Get("ip_address")),
		Query:       strings.TrimSpace(q.Get("query")),
		CreatedFrom: parseISOTime(q.Get("created_from")),
		CreatedTo:   parseISOTime(q.Get("created_to")),
		Offset:      int32((page - 1) * size),
		Limit:       int32(size),
	}
	if v := parseInt32(q.Get("user_id")); v != nil {
		f.UserID = v
	}
	if v := parseInt32(q.Get("entity_id")); v != nil {
		f.EntityID = v
	}

	items, total, err := h.svc.List(r.Context(), f)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, paginated(items, total, page, size))
}

// parseISOTime разбирает ISO8601 (Z→+00:00); при ошибке фильтр пропускается (nil).
func parseISOTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	s = strings.Replace(s, "Z", "+00:00", 1)
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05-07:00", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

func parseInt32(s string) *int32 {
	if s == "" {
		return nil
	}
	v, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return nil
	}
	x := int32(v)
	return &x
}
