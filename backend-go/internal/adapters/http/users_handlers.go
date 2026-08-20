package http

import (
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/nkolomiika/frost/internal/adapters/http/apiv1"
	"github.com/nkolomiika/frost/internal/app/auth"
	"github.com/nkolomiika/frost/internal/app/users"
	"github.com/nkolomiika/frost/internal/apperr"
)

// UsersHandler обслуживает контекст /api/v1/users (профиль, список, приглашения,
// смена пароля/2FA, аватары, реактивация). Сессии здесь не выдаются.
type UsersHandler struct {
	svc         *users.Service
	auth        *auth.Service
	csrfOrigins []string
}

// NewUsersHandler собирает обработчик users.
func NewUsersHandler(svc *users.Service, authSvc *auth.Service, csrfOrigins []string) *UsersHandler {
	return &UsersHandler{svc: svc, auth: authSvc, csrfOrigins: csrfOrigins}
}

// Register монтирует роуты под enforceCSRF + requireAuth. Литеральные сегменты
// (/me/*, /invitations*) регистрируются вместе с wildcard {user_id} — chi отдаёт
// приоритет статике.
func (h *UsersHandler) Register(r chi.Router) {
	r.Route("/api/v1/users", func(ar chi.Router) {
		ar.Use(enforceCSRF(h.csrfOrigins))
		ar.Use(requireAuth(h.auth))

		// self
		ar.Get("/me", h.me)
		ar.Get("/me/profile", h.myProfile)
		ar.Patch("/me", h.updateMyProfile)
		ar.Patch("/me/password", h.changeMyPassword)
		ar.Post("/me/2fa/setup", h.setupMy2FA)
		ar.Post("/me/2fa/confirm", h.confirmMy2FA)
		ar.Post("/me/2fa/disable", h.disableMy2FA)
		ar.Post("/me/avatar", h.uploadMyAvatar)

		// invitations (admin)
		ar.With(requireAdmin).Post("/invitations", h.createInvitation)
		ar.With(requireAdmin).Get("/invitations", h.listInvitations)
		ar.With(requireAdmin).Post("/invitations/{invitation_id}/resend", h.resendInvitation)
		ar.With(requireAdmin).Delete("/invitations/{invitation_id}", h.revokeInvitation)

		// list (admin)
		ar.With(requireAdmin).Get("/", h.listUsers)

		// by id
		ar.With(requireAdmin).Get("/{user_id}", h.getUser)
		ar.Get("/{user_id}/avatar", h.getUserAvatar)
		ar.With(requireAdmin).Put("/{user_id}", h.updateUser)
		ar.With(requireAdmin).Delete("/{user_id}", h.deleteUser)
		ar.With(requireAdmin).Post("/{user_id}/reactivate", h.reactivateUser)
		ar.With(requireAdmin).Patch("/{user_id}/password", h.resetPassword)
		ar.With(requireAdmin).Post("/{user_id}/2fa/reset", h.reset2FA)
	})
}

// ─────────────────────────── self ───────────────────────────

func (h *UsersHandler) me(w http.ResponseWriter, r *http.Request) {
	user, err := h.svc.GetUser(r.Context(), userFromContext(r.Context()).ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, userOut(user))
}

func (h *UsersHandler) myProfile(w http.ResponseWriter, r *http.Request) {
	h.me(w, r)
}

func (h *UsersHandler) updateMyProfile(w http.ResponseWriter, r *http.Request) {
	var req apiv1.UserProfileUpdate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	user, err := h.svc.UpdateOwnProfile(r.Context(), userFromContext(r.Context()).ID, users.ProfileUpdate{
		Username: req.Username,
		Email:    emailToPtr(req.Email),
		FullName: req.FullName,
	}, clientIP(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, userOut(user))
}

func (h *UsersHandler) changeMyPassword(w http.ResponseWriter, r *http.Request) {
	var req apiv1.OwnPasswordChangeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	user, err := h.svc.ChangeOwnPassword(r.Context(), userFromContext(r.Context()).ID, req.CurrentPassword, req.NewPassword, clientIP(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, userOut(user))
}

func (h *UsersHandler) setupMy2FA(w http.ResponseWriter, r *http.Request) {
	setup, err := h.svc.Setup2FA(r.Context(), userFromContext(r.Context()).ID, clientIP(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiv1.TwoFASetupResponse{
		Secret:       setup.Secret,
		OtpauthUri:   setup.OtpauthURI,
		QrPngDataUrl: setup.QR,
	})
}

func (h *UsersHandler) confirmMy2FA(w http.ResponseWriter, r *http.Request) {
	var req apiv1.TwoFAConfirmRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	user, err := h.svc.Confirm2FA(r.Context(), userFromContext(r.Context()).ID, req.Code, clientIP(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, userOut(user))
}

func (h *UsersHandler) disableMy2FA(w http.ResponseWriter, r *http.Request) {
	var req apiv1.TwoFADisableRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	user, err := h.svc.Disable2FA(r.Context(), userFromContext(r.Context()).ID, req.Password, clientIP(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, userOut(user))
}

func (h *UsersHandler) uploadMyAvatar(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, apperr.Validation("Некорректная multipart-форма"))
		return
	}
	file, header, err := r.FormFile("avatar")
	if err != nil {
		writeError(w, apperr.Validation("avatar: файл обязателен"))
		return
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		writeError(w, apperr.Validation("Не удалось прочитать файл"))
		return
	}
	user, err := h.svc.UploadAvatar(r.Context(), userFromContext(r.Context()).ID, users.AvatarUpload{
		Filename: header.Filename,
		Data:     data,
	}, clientIP(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, userOut(user))
}

// ─────────────────────────── list / by id ───────────────────────────

func (h *UsersHandler) listUsers(w http.ResponseWriter, r *http.Request) {
	page := intQuery(r, "page", 1, 1, 1_000_000)
	size := intQuery(r, "size", 20, 1, 200)
	items, total, err := h.svc.ListUsers(r.Context(), page, size)
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]apiv1.UserOut, 0, len(items))
	for i := range items {
		out = append(out, userOut(&items[i]))
	}
	writeJSON(w, http.StatusOK, paginated(out, total, page, size))
}

func (h *UsersHandler) getUser(w http.ResponseWriter, r *http.Request) {
	uid, err := pathInt32(r, "user_id")
	if err != nil {
		writeError(w, err)
		return
	}
	user, err := h.svc.GetUser(r.Context(), uid)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, userOut(user))
}

func (h *UsersHandler) getUserAvatar(w http.ResponseWriter, r *http.Request) {
	uid, err := pathInt32(r, "user_id")
	if err != nil {
		writeError(w, err)
		return
	}
	requester := userFromContext(r.Context())
	if err := h.svc.EnsureCanViewAvatar(requester.Role, requester.ID, uid); err != nil {
		writeError(w, err)
		return
	}
	user, data, err := h.svc.DownloadAvatar(r.Context(), uid)
	if err != nil {
		writeError(w, err)
		return
	}
	ct := user.AvatarContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (h *UsersHandler) updateUser(w http.ResponseWriter, r *http.Request) {
	uid, err := pathInt32(r, "user_id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.UserUpdate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	user, err := h.svc.UpdateUser(r.Context(), uid, users.AdminUpdate{
		Username:    req.Username,
		Email:       emailToPtr(req.Email),
		FullName:    req.FullName,
		Role:        roleToUpperPtr(req.Role),
		ProjectRole: projectRoleToUpperPtr(req.ProjectRole),
		IsActive:    req.IsActive,
	}, userFromContext(r.Context()).ID, clientIP(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, userOut(user))
}

func (h *UsersHandler) deleteUser(w http.ResponseWriter, r *http.Request) {
	uid, err := pathInt32(r, "user_id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.svc.DeleteUser(r.Context(), uid, userFromContext(r.Context()).ID, clientIP(r)); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *UsersHandler) reactivateUser(w http.ResponseWriter, r *http.Request) {
	uid, err := pathInt32(r, "user_id")
	if err != nil {
		writeError(w, err)
		return
	}
	email, err := h.svc.RequestReactivation(r.Context(), uid, userFromContext(r.Context()).ID, clientIP(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiv1.ReactivationRequestOut{
		EmailSentTo:    openapi_types.Email(email),
		MailPreviewUrl: ptrIfNonEmpty(h.svc.MailPreviewURL()),
	})
}

func (h *UsersHandler) resetPassword(w http.ResponseWriter, r *http.Request) {
	uid, err := pathInt32(r, "user_id")
	if err != nil {
		writeError(w, err)
		return
	}
	user, err := h.svc.ResetPassword(r.Context(), uid, userFromContext(r.Context()).ID, clientIP(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiv1.PasswordResetOut{
		EmailSentTo:    openapi_types.Email(user.Email),
		MailPreviewUrl: ptrIfNonEmpty(h.svc.MailPreviewURL()),
	})
}

func (h *UsersHandler) reset2FA(w http.ResponseWriter, r *http.Request) {
	uid, err := pathInt32(r, "user_id")
	if err != nil {
		writeError(w, err)
		return
	}
	user, err := h.svc.AdminReset2FA(r.Context(), uid, userFromContext(r.Context()).ID, clientIP(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, userOut(user))
}

// ─────────────────────────── invitations ───────────────────────────

func (h *UsersHandler) createInvitation(w http.ResponseWriter, r *http.Request) {
	var req apiv1.InvitationCreate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	inv, err := h.svc.CreateInvitation(r.Context(), users.InvitationInput{
		Email:       string(req.Email),
		FullName:    strOrEmpty(req.FullName),
		Role:        roleToUpper(req.Role),
		ProjectRole: projectRoleToUpper(req.ProjectRole),
	}, userFromContext(r.Context()).ID, clientIP(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, invitationSentOut(inv, h.svc.MailPreviewURL()))
}

func (h *UsersHandler) listInvitations(w http.ResponseWriter, r *http.Request) {
	items, err := h.svc.ListInvitations(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]apiv1.InvitationOut, 0, len(items))
	for i := range items {
		out = append(out, invitationOut(&items[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *UsersHandler) resendInvitation(w http.ResponseWriter, r *http.Request) {
	iid, err := pathInt32(r, "invitation_id")
	if err != nil {
		writeError(w, err)
		return
	}
	inv, err := h.svc.ResendInvitation(r.Context(), iid, userFromContext(r.Context()).ID, clientIP(r))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, invitationSentOut(inv, h.svc.MailPreviewURL()))
}

func (h *UsersHandler) revokeInvitation(w http.ResponseWriter, r *http.Request) {
	iid, err := pathInt32(r, "invitation_id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.svc.RevokeInvitation(r.Context(), iid, userFromContext(r.Context()).ID, clientIP(r)); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func invitationSentOut(inv *users.Invitation, previewURL string) apiv1.InvitationSentOut {
	return apiv1.InvitationSentOut{
		Invitation:     invitationOut(inv),
		EmailSentTo:    openapi_types.Email(inv.Email),
		MailPreviewUrl: ptrIfNonEmpty(previewURL),
	}
}
