package http

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/nkolomiika/frost/internal/adapters/http/apiv1"
	"github.com/nkolomiika/frost/internal/app/auth"
	"github.com/nkolomiika/frost/internal/app/projects"
)

// ProjectsHandler обслуживает контекст /api/v1/projects (проекты, папки, участники,
// заметки+комментарии, креды, hidden-ips, статистика, активность).
type ProjectsHandler struct {
	svc         *projects.Service
	auth        *auth.Service
	csrfOrigins []string
}

// NewProjectsHandler собирает обработчик.
func NewProjectsHandler(svc *projects.Service, authSvc *auth.Service, csrfOrigins []string) *ProjectsHandler {
	return &ProjectsHandler{svc: svc, auth: authSvc, csrfOrigins: csrfOrigins}
}

// Register монтирует роуты под enforceCSRF + requireAuth. Литеральные сегменты
// (folders/stats) регистрируются вместе с wildcard — chi отдаёт приоритет статике.
func (h *ProjectsHandler) Register(r chi.Router) {
	pa := h.requireProjectAccess
	r.Route("/api/v1/projects", func(ar chi.Router) {
		ar.Use(enforceCSRF(h.csrfOrigins))
		ar.Use(requireAuth(h.auth))

		// literal segments
		ar.Get("/", h.listProjects)
		ar.With(requireAdmin).Post("/", h.createProject)
		ar.Get("/folders", h.listFolders)
		ar.With(requireAdmin).Post("/folders", h.createFolder)
		ar.With(requireAdmin).Patch("/folders/{folder_id}/move", h.moveFolder)
		ar.With(requireAdmin).Delete("/folders/{folder_id}", h.deleteFolder)
		ar.Get("/stats", h.listStats)

		// project card
		ar.With(pa).Get("/{project_id}", h.getProject)
		ar.Put("/{project_id}", h.updateProject)
		ar.With(requireAdmin).Delete("/{project_id}", h.deleteProject)

		// members
		ar.With(pa).Get("/{project_id}/members", h.listMembers)
		ar.Post("/{project_id}/members", h.addMember)
		ar.Delete("/{project_id}/members/{user_id}", h.removeMember)

		// activity
		ar.With(pa).Get("/{project_id}/activity", h.listActivity)
		ar.With(pa).Get("/{project_id}/notes-activity", h.listNotesActivity)

		// notes
		ar.With(pa).Get("/{project_id}/notes", h.listNotes)
		ar.With(pa).Post("/{project_id}/notes", h.createNote)
		ar.With(pa).Patch("/{project_id}/notes/reorder", h.reorderNotes)
		ar.With(pa).Get("/{project_id}/notes/{note_id}", h.getNote)
		ar.With(pa).Put("/{project_id}/notes/{note_id}", h.updateNote)
		ar.With(pa).Patch("/{project_id}/notes/{note_id}/move", h.moveNote)
		ar.With(pa).Delete("/{project_id}/notes/{note_id}", h.deleteNote)

		// note comments
		ar.With(pa).Get("/{project_id}/notes/{note_id}/comments", h.listNoteComments)
		ar.With(pa).Post("/{project_id}/notes/{note_id}/comments", h.createNoteComment)
		ar.With(pa).Put("/{project_id}/notes/{note_id}/comments/{comment_id}", h.updateNoteComment)
		ar.With(pa).Delete("/{project_id}/notes/{note_id}/comments/{comment_id}", h.deleteNoteComment)

		// credentials
		ar.With(pa).Get("/{project_id}/credentials", h.listCredentials)
		ar.With(pa).Post("/{project_id}/credentials", h.createCredential)
		ar.With(pa).Put("/{project_id}/credentials/{credential_id}", h.updateCredential)
		ar.With(pa).Delete("/{project_id}/credentials/{credential_id}", h.deleteCredential)

		// hidden ips
		ar.With(pa).Get("/{project_id}/hidden-ips", h.listHiddenIPs)
		ar.With(pa).Post("/{project_id}/hidden-ips", h.hideIP)
		ar.With(pa).Delete("/{project_id}/hidden-ips/{ip_address}", h.unhideIP)
	})
}

// ─────────────────────────── projects ───────────────────────────

func (h *ProjectsHandler) listProjects(w http.ResponseWriter, r *http.Request) {
	page := intQuery(r, "page", 1, 1, 1_000_000)
	size := intQuery(r, "size", 20, 1, 1000)
	statusFilter := strings.TrimSpace(r.URL.Query().Get("status"))
	items, total, err := h.svc.ListProjects(r.Context(), actorFrom(r), page, size, statusFilter)
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]apiv1.ProjectOut, 0, len(items))
	for i := range items {
		out = append(out, projectOut(&items[i]))
	}
	writeJSON(w, http.StatusOK, paginated(out, total, page, size))
}

func (h *ProjectsHandler) createProject(w http.ResponseWriter, r *http.Request) {
	var req apiv1.ProjectCreate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	actor := actorFrom(r)
	in := projects.NewProject{
		Name:        req.Name,
		Description: req.Description,
		StartDate:   fromAPIDate(req.StartDate),
		EndDate:     fromAPIDate(req.EndDate),
	}
	if req.Folder != nil {
		in.Folder = *req.Folder
	}
	project, err := h.svc.CreateProject(r.Context(), in, actor.ID, clientIP(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, projectOut(project))
}

func (h *ProjectsHandler) getProject(w http.ResponseWriter, r *http.Request) {
	// Проект уже загружен requireProjectAccess.
	writeJSON(w, http.StatusOK, projectOut(projectFromContext(r.Context())))
}

func (h *ProjectsHandler) updateProject(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.ProjectUpdate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	actor := actorFrom(r)
	if _, err := h.svc.EnsureCanEditProject(r.Context(), pid, actor); err != nil {
		writeError(w, err)
		return
	}
	in := projects.UpdateInput{
		Name:        req.Name,
		Folder:      req.Folder,
		Description: req.Description,
		StartDate:   fromAPIDate(req.StartDate),
		EndDate:     fromAPIDate(req.EndDate),
	}
	if req.Status != nil {
		up := strings.ToUpper(string(*req.Status))
		in.Status = &up
	}
	project, err := h.svc.UpdateProject(r.Context(), pid, in, actor.ID, clientIP(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, projectOut(project))
}

func (h *ProjectsHandler) deleteProject(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.svc.DeleteProject(r.Context(), pid, actorFrom(r).ID, clientIP(r)); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ProjectsHandler) listStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.svc.ProjectStats(r.Context(), actorFrom(r))
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(stats))
	for _, s := range stats {
		out = append(out, map[string]any{
			"project_id":     s.ProjectID,
			"status":         strings.ToLower(s.Status),
			"hosts_count":    s.HostsCount,
			"total_findings": s.TotalFindings,
			"open_findings":  s.OpenFindings,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// ─────────────────────────── members ───────────────────────────

func (h *ProjectsHandler) listMembers(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	members, err := h.svc.ListMembers(r.Context(), pid)
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]apiv1.ProjectMemberOut, 0, len(members))
	for _, m := range members {
		pr := apiv1.ProjectRole(strings.ToLower(m.ProjectRole))
		out = append(out, apiv1.ProjectMemberOut{
			UserId:      int(m.UserID),
			Username:    m.Username,
			Email:       openapi_types.Email(m.Email),
			Role:        apiv1.UserRole(strings.ToLower(m.Role)),
			ProjectRole: &pr,
			AddedAt:     m.AddedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *ProjectsHandler) addMember(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.ProjectMemberCreate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	actor := actorFrom(r)
	if _, err := h.svc.EnsureCanManageMembers(r.Context(), pid, actor); err != nil {
		writeError(w, err)
		return
	}
	res, err := h.svc.AddMember(r.Context(), pid, int32(req.UserId), actor.ID, clientIP(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"user_id":      res.UserID,
		"username":     res.Username,
		"project_role": strings.ToLower(res.ProjectRole),
		"added_at":     res.AddedAt,
	})
}

func (h *ProjectsHandler) removeMember(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	uid, err := pathInt32(r, "user_id")
	if err != nil {
		writeError(w, err)
		return
	}
	actor := actorFrom(r)
	if _, err := h.svc.EnsureCanManageMembers(r.Context(), pid, actor); err != nil {
		writeError(w, err)
		return
	}
	if err := h.svc.RemoveMember(r.Context(), pid, uid, actor.ID, clientIP(r)); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─────────────────────────── folders ───────────────────────────

func (h *ProjectsHandler) listFolders(w http.ResponseWriter, r *http.Request) {
	folders, err := h.svc.ListFolders(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]apiv1.ProjectFolderOut, 0, len(folders))
	for i := range folders {
		out = append(out, folderOut(&folders[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *ProjectsHandler) createFolder(w http.ResponseWriter, r *http.Request) {
	var req apiv1.ProjectFolderCreate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	folder, err := h.svc.CreateFolder(r.Context(), req.Name, intPtr32(req.ParentId), actorFrom(r).ID, clientIP(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, folderOut(folder))
}

func (h *ProjectsHandler) moveFolder(w http.ResponseWriter, r *http.Request) {
	fid, err := pathInt32(r, "folder_id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.ProjectFolderMove
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	folder, err := h.svc.MoveFolder(r.Context(), fid, intPtr32(req.ParentId), actorFrom(r).ID, clientIP(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, folderOut(folder))
}

func (h *ProjectsHandler) deleteFolder(w http.ResponseWriter, r *http.Request) {
	fid, err := pathInt32(r, "folder_id")
	if err != nil {
		writeError(w, err)
		return
	}
	summary, err := h.svc.DeleteFolder(r.Context(), fid, actorFrom(r).ID, clientIP(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path":             summary.Path,
		"deleted_folders":  summary.DeletedFolders,
		"deleted_projects": summary.DeletedProjects,
	})
}

// ─────────────────────────── notes ───────────────────────────

func (h *ProjectsHandler) listNotes(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	notes, err := h.svc.ListNotes(r.Context(), pid)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, notesOut(notes))
}

func (h *ProjectsHandler) createNote(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.ProjectNoteCreate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	note, err := h.svc.CreateNote(r.Context(), pid, req.Title, intPtr32(req.ParentId), req.Content, actorFrom(r).ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, noteOut(note))
}

func (h *ProjectsHandler) getNote(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	nid, err := pathInt32(r, "note_id")
	if err != nil {
		writeError(w, err)
		return
	}
	note, err := h.svc.GetNote(r.Context(), pid, nid)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, noteOut(note))
}

func (h *ProjectsHandler) updateNote(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
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
	note, err := h.svc.UpdateNote(r.Context(), pid, nid, req.Title, req.Content, actorFrom(r).ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, noteOut(note))
}

func (h *ProjectsHandler) moveNote(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	nid, err := pathInt32(r, "note_id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.ProjectNoteMove
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	note, err := h.svc.MoveNote(r.Context(), pid, nid, intPtr32(req.ParentId), actorFrom(r).ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, noteOut(note))
}

func (h *ProjectsHandler) reorderNotes(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.ProjectNoteReorder
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	items := []projects.ReorderItem{}
	if req.Items != nil {
		for _, it := range *req.Items {
			items = append(items, projects.ReorderItem{ID: int32(it.Id), SortOrder: int32(it.SortOrder)})
		}
	}
	notes, err := h.svc.ReorderNotes(r.Context(), pid, intPtr32(req.ParentId), items, actorFrom(r).ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, notesOut(notes))
}

func (h *ProjectsHandler) deleteNote(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	nid, err := pathInt32(r, "note_id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.svc.DeleteNote(r.Context(), pid, nid, actorFrom(r).ID); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─────────────────────────── note comments ───────────────────────────

func (h *ProjectsHandler) listNoteComments(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	nid, err := pathInt32(r, "note_id")
	if err != nil {
		writeError(w, err)
		return
	}
	page := intQuery(r, "page", 1, 1, 1_000_000)
	size := intQuery(r, "size", 50, 1, 200)
	items, total, err := h.svc.ListNoteComments(r.Context(), pid, nid, page, size)
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]apiv1.ProjectNoteCommentOut, 0, len(items))
	for i := range items {
		out = append(out, noteCommentOut(&items[i]))
	}
	writeJSON(w, http.StatusOK, paginated(out, total, page, size))
}

func (h *ProjectsHandler) createNoteComment(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	nid, err := pathInt32(r, "note_id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.ProjectNoteCommentCreate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	comment, err := h.svc.CreateNoteComment(r.Context(), pid, nid, req.Content, actorFrom(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, noteCommentOut(comment))
}

func (h *ProjectsHandler) updateNoteComment(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	nid, err := pathInt32(r, "note_id")
	if err != nil {
		writeError(w, err)
		return
	}
	cid, err := pathInt32(r, "comment_id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.ProjectNoteCommentUpdate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	comment, err := h.svc.UpdateNoteComment(r.Context(), pid, nid, cid, req.Content, actorFrom(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, noteCommentOut(comment))
}

func (h *ProjectsHandler) deleteNoteComment(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	nid, err := pathInt32(r, "note_id")
	if err != nil {
		writeError(w, err)
		return
	}
	cid, err := pathInt32(r, "comment_id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.svc.DeleteNoteComment(r.Context(), pid, nid, cid, actorFrom(r)); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─────────────────────────── credentials ───────────────────────────

func (h *ProjectsHandler) listCredentials(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	creds, err := h.svc.ListCredentials(r.Context(), pid)
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]apiv1.ProjectCredentialOut, 0, len(creds))
	for i := range creds {
		out = append(out, credentialOut(&creds[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *ProjectsHandler) createCredential(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.ProjectCredentialCreate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	cred, err := h.svc.CreateCredential(r.Context(), pid, req.Username, req.Host, req.Password, actorFrom(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, credentialOut(cred))
}

func (h *ProjectsHandler) updateCredential(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	cid, err := pathInt32(r, "credential_id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.ProjectCredentialUpdate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	cred, err := h.svc.UpdateCredential(r.Context(), pid, cid, req.Username, req.Host, req.Password, actorFrom(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, credentialOut(cred))
}

func (h *ProjectsHandler) deleteCredential(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	cid, err := pathInt32(r, "credential_id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.svc.DeleteCredential(r.Context(), pid, cid, actorFrom(r)); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─────────────────────────── hidden ips ───────────────────────────

func (h *ProjectsHandler) listHiddenIPs(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	ips, err := h.svc.ListHiddenIPs(r.Context(), pid)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ips)
}

func (h *ProjectsHandler) hideIP(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.HiddenIpCreate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if err := h.svc.HideIP(r.Context(), pid, req.IpAddress, actorFrom(r).ID); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ProjectsHandler) unhideIP(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	ip := chi.URLParam(r, "ip_address")
	if err := h.svc.UnhideIP(r.Context(), pid, ip, actorFrom(r).ID); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─────────────────────────── activity ───────────────────────────

func (h *ProjectsHandler) listActivity(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	limit := intQuery(r, "limit", 50, 1, 200)
	items, err := h.svc.ListProjectActivity(r.Context(), pid, limit)
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(items))
	for i := range items {
		it := &items[i]
		out = append(out, map[string]any{
			"id":          it.ID,
			"action":      it.Action,
			"entity_type": it.EntityType,
			"entity_id":   it.EntityID,
			"user_id":     it.UserID,
			"username":    it.Username,
			"title":       it.Title,
			"severity":    it.Severity,
			"url":         it.URL,
			"details":     rawOrNil(it.Details),
			"created_at":  isoTime(it.CreatedAt),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *ProjectsHandler) listNotesActivity(w http.ResponseWriter, r *http.Request) {
	pid, err := pathInt32(r, "project_id")
	if err != nil {
		writeError(w, err)
		return
	}
	limit := intQuery(r, "limit", 30, 1, 200)
	items, err := h.svc.ListNotesActivity(r.Context(), pid, limit)
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		out = append(out, map[string]any{
			"id":         it.ID,
			"action":     it.Action,
			"note_id":    it.NoteID,
			"note_title": it.NoteTitle,
			"user_id":    it.UserID,
			"username":   it.Username,
			"created_at": isoTime(it.CreatedAt),
		})
	}
	writeJSON(w, http.StatusOK, out)
}
