package http

import (
	"context"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/nkolomiika/frost/internal/app/projects"
	"github.com/nkolomiika/frost/internal/apperr"
)

// projectCtxKey — ключ проекта, загруженного requireProjectAccess.
const projectCtxKey ctxKey = iota + 1

// actorFrom строит projects.Actor из аутентифицированного пользователя.
func actorFrom(r *http.Request) projects.Actor {
	u := userFromContext(r.Context())
	if u == nil {
		return projects.Actor{}
	}
	return projects.Actor{ID: u.ID, Username: u.Username, Role: u.Role, ProjectRole: u.ProjectRole}
}

// pathInt32 читает целочисленный path-параметр.
func pathInt32(r *http.Request, name string) (int32, error) {
	v, err := strconv.Atoi(chi.URLParam(r, name))
	if err != nil {
		return 0, apperr.Validation("Некорректный " + name)
	}
	return int32(v), nil
}

// requireProjectAccess — middleware (после requireAuth): грузит проект по
// {project_id}, отсутствие → 403 (не 404), админ проходит, иначе нужно членство.
// Загруженный проект кладётся в контекст (projectCtxKey).
func (h *ProjectsHandler) requireProjectAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pid, err := pathInt32(r, "project_id")
		if err != nil {
			writeError(w, err)
			return
		}
		project, err := h.svc.AuthorizeAccess(r.Context(), pid, actorFrom(r))
		if err != nil {
			writeError(w, err)
			return
		}
		ctx := context.WithValue(r.Context(), projectCtxKey, project)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// projectFromContext достаёт проект, загруженный requireProjectAccess.
func projectFromContext(ctx context.Context) *projects.Project {
	p, _ := ctx.Value(projectCtxKey).(*projects.Project)
	return p
}
