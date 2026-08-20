package http

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/nkolomiika/frost/internal/adapters/http/apiv1"
	"github.com/nkolomiika/frost/internal/app/agenttokens"
	"github.com/nkolomiika/frost/internal/app/inventory"
	"github.com/nkolomiika/frost/internal/app/projects"
	"github.com/nkolomiika/frost/internal/app/vulns"
	"github.com/nkolomiika/frost/internal/apperr"
)

// AgentV2Handler обслуживает /api/v2 — агентский API с Bearer-аутентификацией и
// scopes. Делегирует в сервисы projects/inventory/vulns; авторство пишет на
// создателя токена (context.created_by).
type AgentV2Handler struct {
	tokens    *agenttokens.Service
	projects  *projects.Service
	inventory *inventory.Service
	vulns     *vulns.Service
}

// NewAgentV2Handler собирает v2-обработчик.
func NewAgentV2Handler(tokens *agenttokens.Service, proj *projects.Service, inv *inventory.Service, v *vulns.Service) *AgentV2Handler {
	return &AgentV2Handler{tokens: tokens, projects: proj, inventory: inv, vulns: v}
}

const agentCtxKey ctxKey = 100

// Register монтирует /api/v2 под Bearer-аутентификацией (без CSRF — не cookie-сессия).
func (h *AgentV2Handler) Register(r chi.Router) {
	r.Route("/api/v2", func(ar chi.Router) {
		ar.Use(h.bearer)
		ar.Get("/projects", h.listProjects)
		ar.Get("/projects/{project_id}", h.getProject)
		ar.Get("/projects/{project_id}/hosts", h.listHosts)
		ar.Get("/projects/{project_id}/hosts/{host_id}", h.getHost)
		ar.Get("/projects/{project_id}/hosts/{host_id}/vulnerabilities", h.listHostVulns)
		ar.Get("/projects/{project_id}/hosts/{host_id}/vulnerabilities/{vulnerability_id}", h.getHostVuln)
		ar.Get("/projects/{project_id}/notes", h.listNotes)
		ar.Post("/projects/{project_id}/notes", h.createNote)
		ar.Get("/projects/{project_id}/notes/{note_id}", h.getNote)
		ar.Put("/projects/{project_id}/notes/{note_id}", h.updateNote)
		ar.Post("/projects/{project_id}/vulnerabilities", h.createVuln)
		ar.Put("/projects/{project_id}/vulnerabilities/{vuln_id}", h.updateVuln)
	})
}

func (h *AgentV2Handler) bearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		if !strings.HasPrefix(authz, "Bearer ") {
			writeError(w, apperr.Unauthorized("Требуется Bearer token"))
			return
		}
		raw := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
		ac, err := h.tokens.Authenticate(r.Context(), raw)
		if err != nil {
			writeError(w, err)
			return
		}
		ctx := context.WithValue(r.Context(), agentCtxKey, ac)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func agentFromContext(ctx context.Context) *agenttokens.AgentContext {
	ac, _ := ctx.Value(agentCtxKey).(*agenttokens.AgentContext)
	return ac
}

func agentActor(ac *agenttokens.AgentContext) vulns.Actor {
	role := "PENTESTER"
	if ac.CreatorIsAdmin {
		role = "ADMIN"
	}
	return vulns.Actor{ID: ac.CreatedBy, Role: role}
}

// guard проверяет scope и доступ к проекту (существование → 403, как в Python v2).
func (h *AgentV2Handler) guard(w http.ResponseWriter, r *http.Request, scope string) (*agenttokens.AgentContext, int32, bool) {
	ac := agentFromContext(r.Context())
	if err := h.tokens.RequireScope(ac, scope); err != nil {
		writeError(w, err)
		return nil, 0, false
	}
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return nil, 0, false
	}
	if _, err := h.projects.GetProject(r.Context(), pid); err != nil {
		writeError(w, apperr.Forbidden("Проект не найден или недоступен"))
		return nil, 0, false
	}
	if err := h.tokens.AuthorizeProject(ac, pid); err != nil {
		writeError(w, err)
		return nil, 0, false
	}
	return ac, pid, true
}

func (h *AgentV2Handler) allowedProjectIDs(ctx context.Context, ac *agenttokens.AgentContext) ([]int32, error) {
	if ac.AllProjects {
		if ac.CreatorIsAdmin {
			return h.projects.AllProjectIDs(ctx)
		}
		out := make([]int32, 0, len(ac.CreatorProjectIDs))
		for id := range ac.CreatorProjectIDs {
			out = append(out, id)
		}
		return out, nil
	}
	out := make([]int32, 0, len(ac.ProjectIDs))
	for id := range ac.ProjectIDs {
		if ac.CreatorIsAdmin || ac.CreatorProjectIDs[id] {
			out = append(out, id)
		}
	}
	return out, nil
}

func (h *AgentV2Handler) listProjects(w http.ResponseWriter, r *http.Request) {
	ac := agentFromContext(r.Context())
	if err := h.tokens.RequireScope(ac, "projects:read"); err != nil {
		writeError(w, err)
		return
	}
	ids, err := h.allowedProjectIDs(r.Context(), ac)
	if err != nil {
		writeError(w, err)
		return
	}
	list, err := h.projects.ProjectsByIDs(r.Context(), ids)
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]apiv1.ProjectOut, 0, len(list))
	for i := range list {
		out = append(out, projectOut(&list[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *AgentV2Handler) getProject(w http.ResponseWriter, r *http.Request) {
	_, pid, ok := h.guard(w, r, "projects:read")
	if !ok {
		return
	}
	proj, err := h.projects.GetProject(r.Context(), pid)
	if err != nil {
		writeError(w, apperr.Forbidden("Проект не найден или недоступен"))
		return
	}
	writeJSON(w, http.StatusOK, projectOut(proj))
}

func (h *AgentV2Handler) listHosts(w http.ResponseWriter, r *http.Request) {
	_, pid, ok := h.guard(w, r, "assets:read")
	if !ok {
		return
	}
	page := intQuery(r, "page", 1, 1, 1_000_000)
	size := intQuery(r, "size", 100, 1, 200)
	hosts, total, err := h.inventory.ListHosts(r.Context(), pid, page, size, "", "host")
	if err != nil {
		writeError(w, err)
		return
	}
	items := make([]map[string]any, 0, len(hosts))
	for i := range hosts {
		items = append(items, hostListItem(&hosts[i]))
	}
	writeJSON(w, http.StatusOK, paginated(items, total, page, size))
}

func (h *AgentV2Handler) getHost(w http.ResponseWriter, r *http.Request) {
	_, pid, ok := h.guard(w, r, "assets:read")
	if !ok {
		return
	}
	hid, err := pathInt32(r, "host_id")
	if err != nil {
		writeError(w, err)
		return
	}
	host, err := h.inventory.GetHost(r.Context(), pid, hid)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, hostDetail(host))
}

func (h *AgentV2Handler) listHostVulns(w http.ResponseWriter, r *http.Request) {
	_, pid, ok := h.guard(w, r, "vulns:read")
	if !ok {
		return
	}
	hid, err := pathInt32(r, "host_id")
	if err != nil {
		writeError(w, err)
		return
	}
	if _, err := h.inventory.GetHost(r.Context(), pid, hid); err != nil {
		writeError(w, err)
		return
	}
	page := intQuery(r, "page", 1, 1, 1_000_000)
	size := intQuery(r, "size", 100, 1, 200)
	list, total, err := h.vulns.ListHostVulns(r.Context(), pid, hid, page, size, "", "")
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]apiv1.VulnerabilityOut, 0, len(list))
	for i := range list {
		out = append(out, vulnOut(&list[i]))
	}
	writeJSON(w, http.StatusOK, paginated(out, total, page, size))
}

func (h *AgentV2Handler) getHostVuln(w http.ResponseWriter, r *http.Request) {
	_, pid, ok := h.guard(w, r, "vulns:read")
	if !ok {
		return
	}
	hid, err := pathInt32(r, "host_id")
	if err != nil {
		writeError(w, err)
		return
	}
	if _, err := h.inventory.GetHost(r.Context(), pid, hid); err != nil {
		writeError(w, apperr.NotFound("Хост не принадлежит указанному проекту"))
		return
	}
	vid, err := pathInt32(r, "vulnerability_id")
	if err != nil {
		writeError(w, err)
		return
	}
	detail, err := h.vulns.GetVulnDetail(r.Context(), pid, vid)
	if err != nil {
		writeError(w, err)
		return
	}
	if !vulnHasHostLink(detail, hid) {
		writeError(w, apperr.NotFound("Уязвимость не найдена на указанном хосте"))
		return
	}
	writeJSON(w, http.StatusOK, vulnOut(detail.Vuln))
}

func (h *AgentV2Handler) listNotes(w http.ResponseWriter, r *http.Request) {
	_, pid, ok := h.guard(w, r, "notes:read")
	if !ok {
		return
	}
	notes, err := h.projects.ListNotes(r.Context(), pid)
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]apiv1.ProjectNoteOut, 0, len(notes))
	for i := range notes {
		out = append(out, noteOut(&notes[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *AgentV2Handler) getNote(w http.ResponseWriter, r *http.Request) {
	_, pid, ok := h.guard(w, r, "notes:read")
	if !ok {
		return
	}
	nid, err := pathInt32(r, "note_id")
	if err != nil {
		writeError(w, err)
		return
	}
	note, err := h.projects.GetNote(r.Context(), pid, nid)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, noteOut(note))
}

func (h *AgentV2Handler) createNote(w http.ResponseWriter, r *http.Request) {
	ac, pid, ok := h.guard(w, r, "notes:write")
	if !ok {
		return
	}
	var req apiv1.ProjectNoteCreate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	var parentID *int32
	if req.ParentId != nil {
		v := int32(*req.ParentId)
		parentID = &v
	}
	note, err := h.projects.CreateNote(r.Context(), pid, req.Title, parentID, req.Content, ac.CreatedBy)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, noteOut(note))
}

func (h *AgentV2Handler) updateNote(w http.ResponseWriter, r *http.Request) {
	ac, pid, ok := h.guard(w, r, "notes:write")
	if !ok {
		return
	}
	nid, err := pathInt32(r, "note_id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.ProjectNoteUpdate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	note, err := h.projects.UpdateNote(r.Context(), pid, nid, req.Title, req.Content, ac.CreatedBy)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, noteOut(note))
}

func (h *AgentV2Handler) createVuln(w http.ResponseWriter, r *http.Request) {
	ac, pid, ok := h.guard(w, r, "vulns:write")
	if !ok {
		return
	}
	var req apiv1.VulnerabilityCreate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	vuln, err := h.vulns.CreateVuln(r.Context(), pid, buildCreatePayload(req), agentActor(ac))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, vulnOut(vuln))
}

func (h *AgentV2Handler) updateVuln(w http.ResponseWriter, r *http.Request) {
	ac, pid, ok := h.guard(w, r, "vulns:write")
	if !ok {
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
	vuln, err := h.vulns.UpdateVuln(r.Context(), pid, vid, payload, agentActor(ac))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, vulnOut(vuln))
}

// vulnHasHostLink — есть ли у уязвимости HOST-привязка к hostID.
func vulnHasHostLink(detail *vulns.VulnDetail, hostID int32) bool {
	for _, a := range detail.Assets {
		if strings.EqualFold(a.AssetType, "HOST") && a.AssetID == hostID {
			return true
		}
	}
	return false
}
