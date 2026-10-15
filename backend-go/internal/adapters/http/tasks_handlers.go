package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/nkolomiika/frost/internal/app/auth"
	"github.com/nkolomiika/frost/internal/app/tasks"
)

// TasksHandler обслуживает /api/v1/tasks (cookie-auth) — задачи из Jira (проект
// STS), только чтение. Список с поиском/фильтром и карточка по ключу.
type TasksHandler struct {
	svc         *tasks.Service
	auth        *auth.Service
	csrfOrigins []string
}

// NewTasksHandler собирает обработчик задач.
func NewTasksHandler(svc *tasks.Service, authSvc *auth.Service, csrfOrigins []string) *TasksHandler {
	return &TasksHandler{svc: svc, auth: authSvc, csrfOrigins: csrfOrigins}
}

// Register монтирует read-only роуты под requireAuth (CSRF не нужен — только GET).
func (h *TasksHandler) Register(r chi.Router) {
	r.Route("/api/v1/tasks", func(ar chi.Router) {
		ar.Use(requireAuth(h.auth))
		ar.Get("/", h.list)
		ar.Get("/{key}", h.get)
	})
}

// taskOut — строка списка задач.
type taskOut struct {
	Key            string  `json:"key"`
	Summary        string  `json:"summary"`
	Status         string  `json:"status"`
	StatusCategory string  `json:"status_category"`
	IssueType      string  `json:"issue_type"`
	Priority       *string `json:"priority"`
	Assignee       *string `json:"assignee"`
	Updated        string  `json:"updated"`
	Created        string  `json:"created"`
}

// taskDetailOut — полная карточка задачи.
type taskDetailOut struct {
	Key            string   `json:"key"`
	Summary        string   `json:"summary"`
	Status         string   `json:"status"`
	StatusCategory string   `json:"status_category"`
	IssueType      string   `json:"issue_type"`
	Priority       *string  `json:"priority"`
	Assignee       *string  `json:"assignee"`
	Reporter       *string  `json:"reporter"`
	Created        string   `json:"created"`
	Updated        string   `json:"updated"`
	Description    string   `json:"description"`
	Labels         []string `json:"labels"`
	URL            string   `json:"url"`
}

func taskRow(t tasks.Task) taskOut {
	return taskOut{
		Key:            t.Key,
		Summary:        t.Summary,
		Status:         t.Status,
		StatusCategory: t.StatusCategory,
		IssueType:      t.IssueType,
		Priority:       ptrIfNonEmpty(t.Priority),
		Assignee:       ptrIfNonEmpty(t.Assignee),
		Updated:        t.Updated,
		Created:        t.Created,
	}
}

func taskDetail(d tasks.TaskDetail) taskDetailOut {
	labels := d.Labels
	if labels == nil {
		labels = []string{}
	}
	return taskDetailOut{
		Key:            d.Key,
		Summary:        d.Summary,
		Status:         d.Status,
		StatusCategory: d.StatusCategory,
		IssueType:      d.IssueType,
		Priority:       ptrIfNonEmpty(d.Priority),
		Assignee:       ptrIfNonEmpty(d.Assignee),
		Reporter:       ptrIfNonEmpty(d.Reporter),
		Created:        d.Created,
		Updated:        d.Updated,
		Description:    d.Description,
		Labels:         labels,
		URL:            d.URL,
	}
}

func (h *TasksHandler) list(w http.ResponseWriter, r *http.Request) {
	page := intQuery(r, "page", 1, 1, 1_000_000)
	size := intQuery(r, "size", 20, 1, 200)
	items, total, err := h.svc.List(r.Context(), tasks.ListParams{
		Query:    r.URL.Query().Get("query"),
		Category: r.URL.Query().Get("category"),
		Page:     page,
		Size:     size,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	rows := make([]taskOut, 0, len(items))
	for _, t := range items {
		rows = append(rows, taskRow(t))
	}
	writeJSON(w, http.StatusOK, paginated(rows, total, page, size))
}

func (h *TasksHandler) get(w http.ResponseWriter, r *http.Request) {
	d, err := h.svc.Get(r.Context(), chi.URLParam(r, "key"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, taskDetail(*d))
}
