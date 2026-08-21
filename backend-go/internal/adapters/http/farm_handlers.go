package http

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/nkolomiika/frost/internal/adapters/http/apiv1"
	"github.com/nkolomiika/frost/internal/app/auth"
	"github.com/nkolomiika/frost/internal/app/projects"
	"github.com/nkolomiika/frost/internal/app/recon"
	"github.com/nkolomiika/frost/internal/apperr"
)

// ReconHandler обслуживает рекон-ферму (host/ip/js-farm), scanner (subdomains/
// port-scan/reverse) и синхронные js-files (список + zip-архив). POST ставят
// фоновую задачу (202) и опрашиваются по job_id; фильтр по kind (404 при чужом).
type ReconHandler struct {
	svc         *recon.Service
	authz       *projects.Service
	auth        *auth.Service
	csrfOrigins []string
	maxRawBytes int
}

// NewReconHandler собирает обработчик рекона.
func NewReconHandler(svc *recon.Service, authz *projects.Service, authSvc *auth.Service, csrfOrigins []string, maxRawBytes int) *ReconHandler {
	if maxRawBytes <= 0 {
		maxRawBytes = 262144
	}
	return &ReconHandler{svc: svc, authz: authz, auth: authSvc, csrfOrigins: csrfOrigins, maxRawBytes: maxRawBytes}
}

// Register монтирует роуты рекона (плоские chi-роуты, не generated ServerInterface).
func (h *ReconHandler) Register(r chi.Router) {
	pa := requireProjectAccessFor(h.authz)
	const base = "/api/v1/projects/{project_id}"
	r.Group(func(ar chi.Router) {
		ar.Use(enforceCSRF(h.csrfOrigins))
		ar.Use(requireAuth(h.auth))

		// farm
		ar.With(pa).Post(base+"/host-farm", h.startHostFarm)
		ar.With(pa).Get(base+"/host-farm/jobs/{job_id}", h.getHostFarmJob)
		ar.With(pa).Post(base+"/ip-farm", h.startIPFarm)
		ar.With(pa).Get(base+"/ip-farm/jobs/{job_id}", h.getIPFarmJob)
		ar.With(pa).Post(base+"/js-farm", h.startJSFarm)
		ar.With(pa).Get(base+"/js-farm/jobs/{job_id}", h.getJSFarmJob)

		// scanner
		ar.With(pa).Post(base+"/scanner/subdomains", h.startSubdomainScan)
		ar.With(pa).Get(base+"/scanner/subdomains/jobs/{job_id}", h.getSubdomainJob)
		ar.With(pa).Post(base+"/scanner/port-scan", h.startPortScan)
		ar.With(pa).Get(base+"/scanner/port-scan/jobs/{job_id}", h.getPortScanJob)
		ar.With(pa).Post(base+"/scanner/reverse", h.startReverseScan)
		ar.With(pa).Get(base+"/scanner/reverse/jobs/{job_id}", h.getReverseJob)

		// js-files (синхронные)
		ar.With(pa).Get(base+"/js-files", h.listJSFiles)
		ar.With(pa).Get(base+"/js-files/archive", h.downloadJSArchive)
		ar.With(pa).Delete(base+"/js-files/hosts/{host_id}", h.deleteJSForHost)

		// конфигурация фермы (пер-проектная)
		ar.With(pa).Get(base+"/recon/farm-config", h.getFarmConfig)
		ar.With(pa).Put(base+"/recon/farm-config", h.putFarmConfig)
	})
}

// ─────────────────────────── farm-config ───────────────────────────

func (h *ReconHandler) getFarmConfig(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	cfg, err := h.svc.GetFarmConfig(r.Context(), pid)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (h *ReconHandler) putFarmConfig(w http.ResponseWriter, r *http.Request) {
	var cfg recon.FarmConfig
	if err := decodeJSON(r, &cfg); err != nil {
		writeError(w, err)
		return
	}
	pid := projectFromContext(r.Context()).ID
	saved, err := h.svc.SaveFarmConfig(r.Context(), pid, cfg)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

// ─────────────────────────── общие помощники ───────────────────────────

func (h *ReconHandler) start(w http.ResponseWriter, r *http.Request, kind, raw string) {
	if len(raw) > h.maxRawBytes {
		writeError(w, apperr.Validation("Список слишком большой"))
		return
	}
	pid := projectFromContext(r.Context()).ID
	actor := actorFrom(r).ID
	view, err := h.svc.CreateJob(r.Context(), kind, pid, actor, raw)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, jobResponse(view))
}

func (h *ReconHandler) get(w http.ResponseWriter, r *http.Request, kind string) {
	pid := projectFromContext(r.Context()).ID
	jobID, err := pathInt32(r, "job_id")
	if err != nil {
		writeError(w, err)
		return
	}
	view, err := h.svc.GetJob(r.Context(), kind, pid, jobID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, jobResponse(view))
}

func derefRaw(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// ─────────────────────────── farm ───────────────────────────

func (h *ReconHandler) startHostFarm(w http.ResponseWriter, r *http.Request) {
	var req apiv1.HostFarmRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	h.start(w, r, recon.KindHosts, req.Raw)
}

func (h *ReconHandler) getHostFarmJob(w http.ResponseWriter, r *http.Request) {
	h.get(w, r, recon.KindHosts)
}

func (h *ReconHandler) startIPFarm(w http.ResponseWriter, r *http.Request) {
	var req apiv1.IpFarmRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	h.start(w, r, recon.KindIPs, req.Raw)
}

func (h *ReconHandler) getIPFarmJob(w http.ResponseWriter, r *http.Request) {
	h.get(w, r, recon.KindIPs)
}

func (h *ReconHandler) startJSFarm(w http.ResponseWriter, r *http.Request) {
	var req apiv1.JsFarmRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	h.start(w, r, recon.KindJS, derefRaw(req.Raw))
}

func (h *ReconHandler) getJSFarmJob(w http.ResponseWriter, r *http.Request) {
	h.get(w, r, recon.KindJS)
}

// ─────────────────────────── js-files ───────────────────────────

func (h *ReconHandler) listJSFiles(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	files, err := h.svc.ListJsFiles(r.Context(), pid)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, jsFileResponses(files))
}

func (h *ReconHandler) deleteJSForHost(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	hostID, err := pathInt32(r, "host_id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.svc.DeleteJSForHost(r.Context(), pid, hostID); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ReconHandler) downloadJSArchive(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	var hostID *int32
	if raw := r.URL.Query().Get("host_id"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, apperr.Validation("Некорректный host_id"))
			return
		}
		id := int32(v)
		hostID = &id
	}
	name, blob, err := h.svc.BuildArchive(r.Context(), pid, hostID)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(blob)
}
