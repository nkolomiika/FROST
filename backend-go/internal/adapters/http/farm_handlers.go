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
		ar.With(pa).Post(base+"/js-files/bulk-delete", h.bulkDeleteJSFiles)
		ar.With(pa).Delete(base+"/js-files/hosts/{host_id}", h.deleteJSForHost)

		// конфигурация фермы (пер-проектная)
		ar.With(pa).Get(base+"/recon/farm-config", h.getFarmConfig)
		ar.With(pa).Put(base+"/recon/farm-config", h.putFarmConfig)

		// полный прогон фермы (один клик — весь стек)
		ar.With(pa).Post(base+"/recon/farm/run", h.startFarmRun)
		ar.With(pa).Get(base+"/recon/farm/run/{job_id}", h.getFarmRun)
		ar.With(pa).Get(base+"/recon/farm/runs", h.getFarmRuns)
		ar.With(pa).Delete(base+"/recon/farm/run/{job_id}", h.deleteFarmRun)

		// отмена прогона фермы (весь прогон / один шаг / все активные)
		ar.With(pa).Post(base+"/recon/farm/run/cancel-all", h.cancelAllFarmRuns)
		ar.With(pa).Post(base+"/recon/farm/run/{job_id}/cancel", h.cancelFarmRun)
		ar.With(pa).Post(base+"/recon/farm/run/{job_id}/steps/{step_id}/cancel", h.cancelFarmStep)

		// отчёт стейджинга прогона (ревью → импорт выбранного → очистка карантина)
		ar.With(pa).Get(base+"/recon/farm/report", h.getFarmReport)
		ar.With(pa).Post(base+"/recon/farm/report/import", h.importFarmReport)
		ar.With(pa).Delete(base+"/recon/farm/report", h.deleteFarmReport)
	})
}

// requireLeadOrAdmin — гейт lead/admin (создатель проекта тоже проходит) поверх
// уже проверенного доступа к проекту. Возвращает false и пишет 403, если нельзя.
func (h *ReconHandler) requireLeadOrAdmin(w http.ResponseWriter, r *http.Request) bool {
	pid := projectFromContext(r.Context()).ID
	if _, err := h.authz.EnsureCanEditProject(r.Context(), pid, actorFrom(r)); err != nil {
		writeError(w, err)
		return false
	}
	return true
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
	// Правка конфига фермы — только лидам/админам (фронт гейтит на canEditProject).
	if !h.requireLeadOrAdmin(w, r) {
		return
	}
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

// ─────────────────────────── полный прогон фермы ───────────────────────────

func (h *ReconHandler) startFarmRun(w http.ResponseWriter, r *http.Request) {
	// Запуск полного прогона — только лидам/админам.
	if !h.requireLeadOrAdmin(w, r) {
		return
	}
	var req struct {
		UseDefaults bool     `json:"use_defaults"`
		Domains     []string `json:"domains"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	pid := projectFromContext(r.Context()).ID
	actor := actorFrom(r).ID
	view, err := h.svc.StartFarmRun(r.Context(), pid, actor, req.UseDefaults, req.Domains)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, farmRunResp(view))
}

func (h *ReconHandler) getFarmRun(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	jobID, err := pathInt32(r, "job_id")
	if err != nil {
		writeError(w, err)
		return
	}
	view, err := h.svc.GetFarmRun(r.Context(), pid, jobID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, farmRunResp(view))
}

// cancelFarmRun отменяет ВЕСЬ прогон (все его процессы). Только лид/админ.
func (h *ReconHandler) cancelFarmRun(w http.ResponseWriter, r *http.Request) {
	if !h.requireLeadOrAdmin(w, r) {
		return
	}
	pid := projectFromContext(r.Context()).ID
	jobID, err := pathInt32(r, "job_id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.svc.CancelFarmRun(r.Context(), pid, jobID); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// cancelFarmStep отменяет ОДИН выполняющийся шаг прогона по его id. Только лид/админ.
func (h *ReconHandler) cancelFarmStep(w http.ResponseWriter, r *http.Request) {
	if !h.requireLeadOrAdmin(w, r) {
		return
	}
	pid := projectFromContext(r.Context()).ID
	jobID, err := pathInt32(r, "job_id")
	if err != nil {
		writeError(w, err)
		return
	}
	stepID, err := pathInt32(r, "step_id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.svc.CancelFarmStep(r.Context(), pid, jobID, stepID); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// cancelAllFarmRuns отменяет ВСЕ активные (pending|running) прогоны проекта.
// Возвращает {"cancelled": <count>}. Только лид/админ.
func (h *ReconHandler) cancelAllFarmRuns(w http.ResponseWriter, r *http.Request) {
	if !h.requireLeadOrAdmin(w, r) {
		return
	}
	pid := projectFromContext(r.Context()).ID
	n, err := h.svc.CancelAllFarmRuns(r.Context(), pid)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]int64{"cancelled": n})
}

// ─────────────────────────── отчёт стейджинга прогона ───────────────────────────

// optionalJobID разбирает необязательный ?job_id=. Пусто → nil (последний прогон).
func optionalJobID(r *http.Request) (*int32, error) {
	raw := r.URL.Query().Get("job_id")
	if raw == "" {
		return nil, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return nil, apperr.Validation("Некорректный job_id")
	}
	id := int32(v)
	return &id, nil
}

// getFarmReport отдаёт отчёт стейджинга прогона (по ?job_id= либо последнего).
// Прогонов нет → пустой отчёт (200). Только лид/админ.
// getFarmRuns — история прогонов фермы проекта (логи сканов). Lead/admin.
func (h *ReconHandler) getFarmRuns(w http.ResponseWriter, r *http.Request) {
	if !h.requireLeadOrAdmin(w, r) {
		return
	}
	pid := projectFromContext(r.Context()).ID
	runs, err := h.svc.ListFarmRuns(r.Context(), pid)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, farmRunListResponse(runs))
}

// deleteFarmRun — удалить прогон из истории сканов (+ его staging). Lead/admin.
func (h *ReconHandler) deleteFarmRun(w http.ResponseWriter, r *http.Request) {
	if !h.requireLeadOrAdmin(w, r) {
		return
	}
	pid := projectFromContext(r.Context()).ID
	jobID, err := pathInt32(r, "job_id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.svc.DeleteFarmRun(r.Context(), pid, jobID); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ReconHandler) getFarmReport(w http.ResponseWriter, r *http.Request) {
	if !h.requireLeadOrAdmin(w, r) {
		return
	}
	jobID, err := optionalJobID(r)
	if err != nil {
		writeError(w, err)
		return
	}
	pid := projectFromContext(r.Context()).ID
	rep, err := h.svc.FarmReport(r.Context(), pid, jobID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// importFarmReport создаёт реальные объекты проекта из выбранных staged-строк
// (хосты/эндпоинты/JS — что передано) и помечает их imported. Возвращает
// {"imported_hosts","imported_endpoints","imported_js"}. Только лид/админ.
func (h *ReconHandler) importFarmReport(w http.ResponseWriter, r *http.Request) {
	if !h.requireLeadOrAdmin(w, r) {
		return
	}
	var req struct {
		HostIDs     []int32 `json:"host_ids"`
		EndpointIDs []int32 `json:"endpoint_ids"`
		JsIDs       []int32 `json:"js_ids"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	pid := projectFromContext(r.Context()).ID
	actor := actorFrom(r).ID
	res, err := h.svc.ImportStagedReport(r.Context(), pid, actor, req.HostIDs, req.EndpointIDs, req.JsIDs)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// deleteFarmReport чистит staged-строки прогона (по ?job_id= либо последнего).
// Возвращает {"cleared":n}. Только лид/админ.
func (h *ReconHandler) deleteFarmReport(w http.ResponseWriter, r *http.Request) {
	if !h.requireLeadOrAdmin(w, r) {
		return
	}
	jobID, err := optionalJobID(r)
	if err != nil {
		writeError(w, err)
		return
	}
	pid := projectFromContext(r.Context()).ID
	n, err := h.svc.ClearStagedReport(r.Context(), pid, jobID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"cleared": n})
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

// bulkDeleteJSFiles удаляет JS-находки проекта по списку id (POST
// .../js-files/bulk-delete, тело {"ids":[…]}). Отдаёт {"deleted":N}. Скоуп проекта
// в SQL — чужие id не удаляются.
func (h *ReconHandler) bulkDeleteJSFiles(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
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
	deleted, err := h.svc.DeleteJSFilesBulk(r.Context(), pid, ids)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"deleted": deleted})
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
