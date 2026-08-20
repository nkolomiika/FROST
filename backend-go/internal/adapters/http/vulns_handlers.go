package http

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/nkolomiika/frost/internal/adapters/http/apiv1"
	"github.com/nkolomiika/frost/internal/app/auth"
	"github.com/nkolomiika/frost/internal/app/projects"
	"github.com/nkolomiika/frost/internal/app/vulns"
	"github.com/nkolomiika/frost/internal/apperr"
)

// uploadMaxMemory — сколько байт multipart-формы держим в памяти (порт запаса под 50 МБ).
const uploadMaxMemory = 64 << 20

// VulnsHandler обслуживает контекст уязвимостей: сами уязвимости, активы,
// комментарии(+упоминания) и файлы. Проверку доступа к проекту переиспользует у
// projects.Service (authz); аутентификацию — у auth.Service.
type VulnsHandler struct {
	svc         *vulns.Service
	authz       *projects.Service
	auth        *auth.Service
	csrfOrigins []string
}

// NewVulnsHandler собирает обработчик.
func NewVulnsHandler(svc *vulns.Service, authz *projects.Service, authSvc *auth.Service, csrfOrigins []string) *VulnsHandler {
	return &VulnsHandler{svc: svc, authz: authz, auth: authSvc, csrfOrigins: csrfOrigins}
}

// vulnActor строит vulns.Actor из аутентифицированного пользователя.
func vulnActor(r *http.Request) vulns.Actor {
	a := actorFrom(r)
	return vulns.Actor{ID: a.ID, Username: a.Username, Role: a.Role}
}

// Register монтирует роуты в общей группе под enforceCSRF + requireAuth. Роуты под
// проектом дополнительно проходят requireProjectAccess (pa); download файла имеет
// собственную проверку членства (без project_id) и потому идёт без pa.
func (h *VulnsHandler) Register(r chi.Router) {
	pa := requireProjectAccessFor(h.authz)
	r.Group(func(gr chi.Router) {
		gr.Use(enforceCSRF(h.csrfOrigins))
		gr.Use(requireAuth(h.auth))

		const base = "/api/v1/projects/{project_id}"

		// vulnerabilities
		gr.With(pa).Get(base+"/vulnerabilities", h.listVulns)
		gr.With(pa).Get(base+"/hosts/{host_id}/vulnerabilities", h.listHostVulns)
		gr.With(pa).Post(base+"/vulnerabilities", h.createVuln)
		gr.With(pa).Get(base+"/vulnerabilities/{vuln_id}", h.getVuln)
		gr.With(pa).Put(base+"/vulnerabilities/{vuln_id}", h.updateVuln)
		gr.With(pa).Patch(base+"/vulnerabilities/{vuln_id}/status", h.patchStatus)
		gr.With(pa).Delete(base+"/vulnerabilities/{vuln_id}", h.deleteVuln)

		// assets
		gr.With(pa).Get(base+"/vulnerabilities/{vuln_id}/assets", h.listAssets)
		gr.With(pa).Post(base+"/vulnerabilities/{vuln_id}/assets", h.addAsset)
		gr.With(pa).Delete(base+"/vulnerabilities/{vuln_id}/assets/{asset_link_id}", h.deleteAsset)

		// comments
		gr.With(pa).Get(base+"/vulnerabilities/{vuln_id}/comments", h.listComments)
		gr.With(pa).Post(base+"/vulnerabilities/{vuln_id}/comments", h.createComment)
		gr.With(pa).Put(base+"/vulnerabilities/{vuln_id}/comments/{comment_id}", h.updateComment)
		gr.With(pa).Delete(base+"/vulnerabilities/{vuln_id}/comments/{comment_id}", h.deleteComment)

		// files
		gr.With(pa).Get(base+"/vulnerabilities/{vuln_id}/files", h.listFiles)
		gr.With(pa).Post(base+"/vulnerabilities/{vuln_id}/files", h.uploadFile)
		gr.With(pa).Delete(base+"/vulnerabilities/{vuln_id}/files/{file_id}", h.deleteFile)

		// download — своя проверка членства (без project_id)
		gr.Get("/api/v1/files/{file_id}/download", h.downloadFile)
	})
}

// ─────────────────────────── vulnerabilities ───────────────────────────

func (h *VulnsHandler) listVulns(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	page := intQuery(r, "page", 1, 1, 1_000_000)
	size := intQuery(r, "size", 20, 1, 200)
	items, total, err := h.svc.ListVulns(r.Context(), pid, page, size,
		r.URL.Query().Get("severity"), r.URL.Query().Get("status"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, paginated(vulnsOut(items), total, page, size))
}

func (h *VulnsHandler) listHostVulns(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	hid, err := pathInt32(r, "host_id")
	if err != nil {
		writeError(w, err)
		return
	}
	page := intQuery(r, "page", 1, 1, 1_000_000)
	size := intQuery(r, "size", 20, 1, 200)
	items, total, err := h.svc.ListHostVulns(r.Context(), pid, hid, page, size,
		r.URL.Query().Get("severity"), r.URL.Query().Get("status"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, paginated(vulnsOut(items), total, page, size))
}

func vulnsOut(items []vulns.Vuln) []apiv1.VulnerabilityOut {
	out := make([]apiv1.VulnerabilityOut, 0, len(items))
	for i := range items {
		out = append(out, vulnOut(&items[i]))
	}
	return out
}

func (h *VulnsHandler) createVuln(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.VulnerabilityCreate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	vuln, err := h.svc.CreateVuln(r.Context(), pid, buildCreatePayload(req), vulnActor(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, vulnOut(vuln))
}

func (h *VulnsHandler) getVuln(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	vid, err := pathInt32(r, "vuln_id")
	if err != nil {
		writeError(w, err)
		return
	}
	detail, err := h.svc.GetVulnDetail(r.Context(), pid, vid)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, vulnDetailOut(detail))
}

func (h *VulnsHandler) updateVuln(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	vid, err := pathInt32(r, "vuln_id")
	if err != nil {
		writeError(w, err)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, apperr.Validation("Некорректное тело запроса"))
		return
	}
	payload, err := buildUpdatePayload(body)
	if err != nil {
		writeError(w, err)
		return
	}
	vuln, err := h.svc.UpdateVuln(r.Context(), pid, vid, payload, vulnActor(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, vulnOut(vuln))
}

func (h *VulnsHandler) patchStatus(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	vid, err := pathInt32(r, "vuln_id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.VulnerabilityStatusPatch
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	statusDB := strings.ToUpper(string(req.Status))
	vuln, err := h.svc.PatchStatus(r.Context(), pid, vid, statusDB, vulnActor(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, vulnOut(vuln))
}

func (h *VulnsHandler) deleteVuln(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	vid, err := pathInt32(r, "vuln_id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.svc.DeleteVuln(r.Context(), pid, vid, vulnActor(r)); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─────────────────────────── assets ───────────────────────────

func (h *VulnsHandler) listAssets(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	vid, err := pathInt32(r, "vuln_id")
	if err != nil {
		writeError(w, err)
		return
	}
	items, err := h.svc.ListAssets(r.Context(), pid, vid)
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]apiv1.VulnerabilityAssetOut, 0, len(items))
	for _, a := range items {
		out = append(out, vulnAssetOut(a))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *VulnsHandler) addAsset(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	vid, err := pathInt32(r, "vuln_id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.VulnerabilityAssetCreate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	link, err := h.svc.AddAsset(r.Context(), pid, vid, strings.ToUpper(string(req.AssetType)), int32(req.AssetId), vulnActor(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, vulnAssetOut(*link))
}

func (h *VulnsHandler) deleteAsset(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	vid, err := pathInt32(r, "vuln_id")
	if err != nil {
		writeError(w, err)
		return
	}
	lid, err := pathInt32(r, "asset_link_id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.svc.DeleteAsset(r.Context(), pid, vid, lid, vulnActor(r)); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─────────────────────────── comments ───────────────────────────

func (h *VulnsHandler) listComments(w http.ResponseWriter, r *http.Request) {
	vid, err := pathInt32(r, "vuln_id")
	if err != nil {
		writeError(w, err)
		return
	}
	page := intQuery(r, "page", 1, 1, 1_000_000)
	size := intQuery(r, "size", 50, 1, 200)
	items, total, err := h.svc.ListComments(r.Context(), vid, page, size)
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]apiv1.CommentOut, 0, len(items))
	for i := range items {
		out = append(out, vulnCommentOut(&items[i]))
	}
	writeJSON(w, http.StatusOK, paginated(out, total, page, size))
}

func (h *VulnsHandler) createComment(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	vid, err := pathInt32(r, "vuln_id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.CommentCreate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	comment, err := h.svc.CreateComment(r.Context(), pid, vid, req.Content, vulnActor(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, vulnCommentOut(comment))
}

func (h *VulnsHandler) updateComment(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	vid, err := pathInt32(r, "vuln_id")
	if err != nil {
		writeError(w, err)
		return
	}
	cid, err := pathInt32(r, "comment_id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.CommentUpdate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	comment, err := h.svc.UpdateComment(r.Context(), pid, vid, cid, req.Content, vulnActor(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, vulnCommentOut(comment))
}

func (h *VulnsHandler) deleteComment(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	vid, err := pathInt32(r, "vuln_id")
	if err != nil {
		writeError(w, err)
		return
	}
	cid, err := pathInt32(r, "comment_id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.svc.DeleteComment(r.Context(), pid, vid, cid, vulnActor(r)); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─────────────────────────── files ───────────────────────────

func (h *VulnsHandler) listFiles(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	vid, err := pathInt32(r, "vuln_id")
	if err != nil {
		writeError(w, err)
		return
	}
	items, err := h.svc.ListFiles(r.Context(), pid, vid)
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]apiv1.FileOut, 0, len(items))
	for _, f := range items {
		out = append(out, vulnFileOut(f))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *VulnsHandler) uploadFile(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	vid, err := pathInt32(r, "vuln_id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := r.ParseMultipartForm(uploadMaxMemory); err != nil {
		writeError(w, apperr.Validation("Некорректная загрузка файла"))
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, apperr.Validation("Файл не передан"))
		return
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(file)
	if err != nil {
		writeError(w, apperr.Validation("Некорректная загрузка файла"))
		return
	}
	filename := ""
	if header != nil {
		filename = header.Filename
	}
	meta, err := h.svc.UploadFile(r.Context(), pid, vid, filename, data, vulnActor(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, vulnFileOut(*meta))
}

func (h *VulnsHandler) deleteFile(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	vid, err := pathInt32(r, "vuln_id")
	if err != nil {
		writeError(w, err)
		return
	}
	fid, err := pathInt32(r, "file_id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.svc.DeleteFile(r.Context(), pid, vid, fid, vulnActor(r)); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *VulnsHandler) downloadFile(w http.ResponseWriter, r *http.Request) {
	fid, err := pathInt32(r, "file_id")
	if err != nil {
		writeError(w, err)
		return
	}
	meta, data, err := h.svc.Download(r.Context(), fid, vulnActor(r))
	if err != nil {
		writeError(w, err)
		return
	}
	disposition := "attachment"
	if strings.HasPrefix(meta.ContentType, "image/") {
		disposition = "inline"
	}
	w.Header().Set("Content-Type", meta.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("%s; filename=%q", disposition, meta.OriginalName))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
