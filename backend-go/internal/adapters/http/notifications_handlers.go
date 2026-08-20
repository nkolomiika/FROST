package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/nkolomiika/frost/internal/adapters/http/apiv1"
	"github.com/nkolomiika/frost/internal/app/auth"
	"github.com/nkolomiika/frost/internal/app/notifications"
	"github.com/nkolomiika/frost/internal/apperr"
)

// NotificationsHandler обслуживает /api/v1/notifications (cookie-auth).
type NotificationsHandler struct {
	svc         *notifications.Service
	auth        *auth.Service
	csrfOrigins []string
}

// NewNotificationsHandler собирает обработчик уведомлений.
func NewNotificationsHandler(svc *notifications.Service, authSvc *auth.Service, csrfOrigins []string) *NotificationsHandler {
	return &NotificationsHandler{svc: svc, auth: authSvc, csrfOrigins: csrfOrigins}
}

// Register монтирует роуты под requireAuth (+CSRF на PATCH).
func (h *NotificationsHandler) Register(r chi.Router) {
	r.Route("/api/v1/notifications", func(ar chi.Router) {
		ar.Use(enforceCSRF(h.csrfOrigins))
		ar.Use(requireAuth(h.auth))
		ar.Get("/", h.list)
		ar.Get("/unread-count", h.unreadCount)
		ar.Patch("/read-all", h.markAllRead)
		ar.Patch("/{notification_id}/read", h.markRead)
	})
}

func notifContextOut(c *notifications.Context) *apiv1.NotificationContext {
	if c == nil {
		return nil
	}
	return &apiv1.NotificationContext{
		VulnerabilityId:    int32ToIntPtr(c.VulnerabilityID),
		VulnerabilityTitle: c.VulnerabilityTitle,
		ProjectId:          int32ToIntPtr(c.ProjectID),
		ProjectName:        c.ProjectName,
		NoteId:             int32ToIntPtr(c.NoteID),
		NoteTitle:          c.NoteTitle,
		HostId:             int32ToIntPtr(c.HostID),
		CommenterUsername:  c.CommenterUsername,
		Status:             c.Status,
	}
}

func notifOut(n notifications.Notification, ctx *notifications.Context) apiv1.NotificationOut {
	return apiv1.NotificationOut{
		Id:            int(n.ID),
		Type:          notifications.APIType(n.Type),
		IsRead:        n.IsRead,
		CommentId:     int32ToIntPtr(n.CommentID),
		NoteCommentId: int32ToIntPtr(n.NoteCommentID),
		CreatedAt:     n.CreatedAt,
		Context:       notifContextOut(ctx),
	}
}

func (h *NotificationsHandler) list(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	page := intQuery(r, "page", 1, 1, 1_000_000)
	size := intQuery(r, "size", 20, 1, 200)
	var isRead *bool
	switch r.URL.Query().Get("is_read") {
	case "true":
		v := true
		isRead = &v
	case "false":
		v := false
		isRead = &v
	}
	views, total, err := h.svc.List(r.Context(), user.ID, isRead, page, size)
	if err != nil {
		writeError(w, err)
		return
	}
	items := make([]apiv1.NotificationOut, 0, len(views))
	for _, v := range views {
		items = append(items, notifOut(v.N, v.Ctx))
	}
	writeJSON(w, http.StatusOK, paginated(items, total, page, size))
}

func (h *NotificationsHandler) unreadCount(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	count, err := h.svc.UnreadCount(r.Context(), user.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiv1.UnreadCountOut{Count: int(count)})
}

func (h *NotificationsHandler) markRead(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	id, err := pathInt32(r, "notification_id")
	if err != nil {
		writeError(w, apperr.Validation("Некорректный notification_id"))
		return
	}
	n, err := h.svc.MarkRead(r.Context(), id, user.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, notifOut(*n, nil)) // context всегда null на /read
}

func (h *NotificationsHandler) markAllRead(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	if err := h.svc.MarkAllRead(r.Context(), user.ID); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
