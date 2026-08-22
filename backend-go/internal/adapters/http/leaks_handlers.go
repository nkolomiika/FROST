package http

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/nkolomiika/frost/internal/app/auth"
	"github.com/nkolomiika/frost/internal/app/leaks"
	"github.com/nkolomiika/frost/internal/app/projects"
	"github.com/nkolomiika/frost/internal/app/recon"
	"github.com/nkolomiika/frost/internal/apperr"
)

// LeaksHandler обслуживает ЕДИНОЕ хранилище утечек проекта (/leaks/*): запуск
// сканеров (пока github), отчёт по всем источникам, импорт выбранного и очистку.
// Проектный скоуп и гейтинг — как у recon-роутов (CSRF + auth + project-access).
// Запуск/статус скана делегируется recon.Service (job на обычной дорожке), а
// чтение/импорт/очистка — leaks.Service.
type LeaksHandler struct {
	recon       *recon.Service
	leaks       *leaks.Service
	authz       *projects.Service
	auth        *auth.Service
	csrfOrigins []string
	maxRawBytes int
}

// NewLeaksHandler собирает обработчик утечек.
func NewLeaksHandler(reconSvc *recon.Service, leaksSvc *leaks.Service, authz *projects.Service, authSvc *auth.Service, csrfOrigins []string, maxRawBytes int) *LeaksHandler {
	if maxRawBytes <= 0 {
		maxRawBytes = 262144
	}
	return &LeaksHandler{recon: reconSvc, leaks: leaksSvc, authz: authz, auth: authSvc, csrfOrigins: csrfOrigins, maxRawBytes: maxRawBytes}
}

// Register монтирует роуты утечек (project-scoped).
func (h *LeaksHandler) Register(r chi.Router) {
	pa := requireProjectAccessFor(h.authz)
	const base = "/api/v1/projects/{project_id}"
	r.Group(func(ar chi.Router) {
		ar.Use(enforceCSRF(h.csrfOrigins))
		ar.Use(requireAuth(h.auth))

		// сканеры (пока github; место под /leaks/scan/linkedin, /leaks/scan/breach и т.п.)
		ar.With(pa).Post(base+"/leaks/scan/github", h.startGithubScan)
		ar.With(pa).Get(base+"/leaks/scan/{job_id}", h.getScan)

		// единый отчёт/импорт/очистка (все источники)
		ar.With(pa).Get(base+"/leaks", h.listLeaks)
		ar.With(pa).Post(base+"/leaks/import", h.importLeaks)
		ar.With(pa).Delete(base+"/leaks", h.clearLeaks)
	})
}

// startGithubScan ставит github secret-scan (202). Валидирует github-URL в сервисе.
func (h *LeaksHandler) startGithubScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if len(req.URL) > h.maxRawBytes {
		writeError(w, apperr.Validation("URL слишком длинный"))
		return
	}
	pid := projectFromContext(r.Context()).ID
	actor := actorFrom(r).ID
	view, err := h.recon.CreateJob(r.Context(), recon.KindGithubScan, pid, actor, strings.TrimSpace(req.URL))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, jobResponse(view))
}

// getScan отдаёт статус/результат скана по job_id.
func (h *LeaksHandler) getScan(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	jobID, err := pathInt32(r, "job_id")
	if err != nil {
		writeError(w, err)
		return
	}
	view, err := h.recon.GetJob(r.Context(), recon.KindGithubScan, pid, jobID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, jobResponse(view))
}

// leakFilterFromQuery разбирает ?source= и ?job_id= (пусто → nil).
func leakFilterFromQuery(r *http.Request) (leaks.Filter, error) {
	var f leaks.Filter
	if src := strings.TrimSpace(r.URL.Query().Get("source")); src != "" {
		f.Source = &src
	}
	jobID, err := optionalJobID(r)
	if err != nil {
		return leaks.Filter{}, err
	}
	f.JobID = jobID
	return f, nil
}

// listLeaks отдаёт единый отчёт утечек (все источники) с фильтрами source/job_id.
func (h *LeaksHandler) listLeaks(w http.ResponseWriter, r *http.Request) {
	f, err := leakFilterFromQuery(r)
	if err != nil {
		writeError(w, err)
		return
	}
	pid := projectFromContext(r.Context()).ID
	rep, err := h.leaks.Report(r.Context(), pid, f)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// importLeaks создаёт записи проекта (project_notes) из выбранных утечек.
func (h *LeaksHandler) importLeaks(w http.ResponseWriter, r *http.Request) {
	var req bulkIDsRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	ids, err := dedupIDs(req.IDs)
	if err != nil {
		writeError(w, err)
		return
	}
	pid := projectFromContext(r.Context()).ID
	actor := actorFrom(r).ID
	res, err := h.leaks.Import(r.Context(), pid, actor, ids)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// clearLeaks чистит утечки проекта (с фильтрами source/job_id). Отдаёт {"cleared":n}.
func (h *LeaksHandler) clearLeaks(w http.ResponseWriter, r *http.Request) {
	f, err := leakFilterFromQuery(r)
	if err != nil {
		writeError(w, err)
		return
	}
	pid := projectFromContext(r.Context()).ID
	n, err := h.leaks.Clear(r.Context(), pid, f)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"cleared": n})
}
