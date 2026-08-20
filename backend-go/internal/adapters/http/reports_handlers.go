package http

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/nkolomiika/frost/internal/app/auth"
	"github.com/nkolomiika/frost/internal/app/projects"
	"github.com/nkolomiika/frost/internal/app/report"
)

const docxMime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

// ReportsHandler обслуживает /api/v1/projects/{id}/reports/{szi,pp}.
type ReportsHandler struct {
	svc         *report.Service
	authz       *projects.Service
	auth        *auth.Service
	csrfOrigins []string
}

// NewReportsHandler собирает обработчик отчётов.
func NewReportsHandler(svc *report.Service, authz *projects.Service, authSvc *auth.Service, csrfOrigins []string) *ReportsHandler {
	return &ReportsHandler{svc: svc, authz: authz, auth: authSvc, csrfOrigins: csrfOrigins}
}

// Register монтирует роуты под requireAuth + CSRF + project-access.
func (h *ReportsHandler) Register(r chi.Router) {
	r.Route("/api/v1/projects/{project_id}/reports", func(ar chi.Router) {
		ar.Use(enforceCSRF(h.csrfOrigins))
		ar.Use(requireAuth(h.auth))
		pa := requireProjectAccessFor(h.authz)
		ar.With(pa).Post("/szi", h.generate(report.KindSZI))
		ar.With(pa).Post("/pp", h.generate(report.KindPP))
	})
}

func (h *ReportsHandler) generate(kind report.Kind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pid, err := pathInt32(r, "project_id")
		if err != nil {
			writeError(w, err)
			return
		}
		content, projectName, err := h.svc.Generate(r.Context(), pid, kind)
		if err != nil {
			writeError(w, err)
			return
		}
		w.Header().Set("Content-Type", docxMime)
		w.Header().Set("Content-Disposition", contentDisposition(projectName, string(kind)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}
}

// contentDisposition строит заголовок с ASCII-fallback и RFC 5987 UTF-8 именем.
func contentDisposition(projectName, suffix string) string {
	ascii := safeASCIIFilename(projectName)
	if ascii == "" {
		ascii = "report"
	}
	utf8name := fmt.Sprintf("%s_%s.docx", projectName, suffix)
	asciiName := fmt.Sprintf("%s_%s.docx", ascii, suffix)
	return fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`, asciiName, url.PathEscape(utf8name))
}

func safeASCIIFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('_')
		}
	}
	return strings.Trim(b.String(), "_-")
}
