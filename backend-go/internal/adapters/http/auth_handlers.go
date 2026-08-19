package http

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/nkolomiika/frost/internal/adapters/http/apiv1"
	"github.com/nkolomiika/frost/internal/app/auth"
	"github.com/nkolomiika/frost/internal/apperr"
)

// AuthHandler обслуживает /api/v1/auth/* поверх use-case-слоя auth.
type AuthHandler struct {
	svc         *auth.Service
	cookies     CookieConfig
	csrfOrigins []string
}

// NewAuthHandler собирает обработчик auth.
func NewAuthHandler(svc *auth.Service, cookies CookieConfig, csrfOrigins []string) *AuthHandler {
	return &AuthHandler{svc: svc, cookies: cookies, csrfOrigins: csrfOrigins}
}

// Register монтирует auth-роуты (те же пути/методы, что в openapi-v1).
func (h *AuthHandler) Register(r chi.Router) {
	r.Route("/api/v1/auth", func(ar chi.Router) {
		ar.Use(enforceCSRF(h.csrfOrigins))
		ar.Post("/login", h.login)
		ar.Post("/2fa/verify", h.verify2FA)
		ar.Get("/invitations/{token}", h.invitationInfo)
		ar.Get("/invitations/{token}/username-available", h.invitationUsernameAvailable)
		ar.Post("/invitations/{token}/accept", h.acceptInvitation)
		ar.Post("/password-reset/request", h.requestPasswordReset)
		ar.Get("/password-reset/{token}", h.passwordResetInfo)
		ar.Post("/password-reset/{token}", h.confirmPasswordReset)
		ar.Get("/reactivate/{token}", h.reactivationInfo)
		ar.Post("/reactivate/{token}", h.completeReactivation)
		ar.Post("/refresh", h.refresh)
		ar.With(requireAuth(h.svc)).Post("/logout", h.logout)
	})
}

func mapRole(dbRole string) apiv1.UserRole {
	return apiv1.UserRole(strings.ToLower(dbRole))
}

// sessionResponse собирает LoginResponse для успешного входа.
func sessionResponse(u *auth.User) apiv1.LoginResponse {
	id := int(u.ID)
	role := mapRole(u.Role)
	return apiv1.LoginResponse{Id: &id, Username: &u.Username, Role: &role}
}

func (h *AuthHandler) login(w http.ResponseWriter, r *http.Request) {
	var req apiv1.LoginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	out, err := h.svc.Login(r.Context(), req.Username, req.Password, clientIP(r))
	if err != nil {
		writeError(w, err)
		return
	}
	if out.Requires2FA {
		h.cookies.set2FACookie(w, out.PendingToken)
		writeJSON(w, http.StatusOK, apiv1.LoginResponse{Requires2fa: ptr(true)})
		return
	}
	h.cookies.setAuthCookies(w, out.AccessToken, out.RefreshToken)
	writeJSON(w, http.StatusOK, sessionResponse(out.User))
}

func (h *AuthHandler) verify2FA(w http.ResponseWriter, r *http.Request) {
	var req apiv1.TwoFAVerifyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	pair, user, err := h.svc.Verify2FA(r.Context(), cookieValue(r, twoFACookie), req.Code, clientIP(r))
	if err != nil {
		writeError(w, err)
		return
	}
	h.cookies.setAuthCookies(w, pair.Access, pair.Refresh)
	h.cookies.clear2FACookie(w)
	writeJSON(w, http.StatusOK, sessionResponse(user))
}

func (h *AuthHandler) invitationInfo(w http.ResponseWriter, r *http.Request) {
	info, err := h.svc.GetInvitationInfo(r.Context(), chi.URLParam(r, "token"))
	if err != nil {
		writeError(w, err)
		return
	}
	out := apiv1.InvitationInfoOut{Valid: info.Valid, Reason: ptrIfNonEmpty(info.Reason), FullName: ptrIfNonEmpty(info.FullName)}
	if info.Email != "" {
		email := openapi_types.Email(info.Email)
		out.Email = &email
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *AuthHandler) invitationUsernameAvailable(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if len(username) < 3 || len(username) > 100 {
		writeError(w, apperr.Validation("username: длина от 3 до 100 символов"))
		return
	}
	available, err := h.svc.CheckInvitationUsernameAvailable(r.Context(), chi.URLParam(r, "token"), username)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiv1.UsernameAvailabilityOut{Available: available})
}

func (h *AuthHandler) acceptInvitation(w http.ResponseWriter, r *http.Request) {
	var req apiv1.InvitationAcceptRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	user, err := h.svc.AcceptInvitation(r.Context(), chi.URLParam(r, "token"), req.Username, req.Password, clientIP(r))
	if err != nil {
		writeError(w, err)
		return
	}
	pair, err := h.svc.IssueSessionForUser(r.Context(), user.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	h.cookies.setAuthCookies(w, pair.Access, pair.Refresh)
	writeJSON(w, http.StatusCreated, sessionResponse(user))
}

func (h *AuthHandler) requestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req apiv1.PasswordResetRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if err := h.svc.RequestPasswordReset(r.Context(), string(req.Email), clientIP(r)); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiv1.PasswordResetRequestOut{Ok: ptr(true), MailPreviewUrl: ptrIfNonEmpty(h.svc.MailPreviewURL())})
}

func (h *AuthHandler) passwordResetInfo(w http.ResponseWriter, r *http.Request) {
	info, err := h.svc.GetPasswordResetInfo(r.Context(), chi.URLParam(r, "token"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiv1.PasswordResetInfoOut{Valid: info.Valid, Reason: ptrIfNonEmpty(info.Reason), Username: ptrIfNonEmpty(info.Username)})
}

func (h *AuthHandler) confirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req apiv1.PasswordResetConfirmRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if err := h.svc.ConfirmPasswordReset(r.Context(), chi.URLParam(r, "token"), req.Password, clientIP(r)); err != nil {
		writeError(w, err)
		return
	}
	h.cookies.clearAuthCookies(w)
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) reactivationInfo(w http.ResponseWriter, r *http.Request) {
	info, err := h.svc.GetReactivationInfo(r.Context(), chi.URLParam(r, "token"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, apiv1.ReactivationInfoOut{Valid: info.Valid, Reason: ptrIfNonEmpty(info.Reason), Username: ptrIfNonEmpty(info.Username)})
}

func (h *AuthHandler) completeReactivation(w http.ResponseWriter, r *http.Request) {
	user, err := h.svc.CompleteReactivation(r.Context(), chi.URLParam(r, "token"), clientIP(r))
	if err != nil {
		writeError(w, err)
		return
	}
	pair, err := h.svc.IssueSessionForUser(r.Context(), user.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	h.cookies.setAuthCookies(w, pair.Access, pair.Refresh)
	writeJSON(w, http.StatusOK, sessionResponse(user))
}

func (h *AuthHandler) refresh(w http.ResponseWriter, r *http.Request) {
	pair, err := h.svc.Refresh(r.Context(), cookieValue(r, refreshCookie), clientIP(r))
	if err != nil {
		writeError(w, err)
		return
	}
	h.cookies.setAuthCookies(w, pair.Access, pair.Refresh)
	writeJSON(w, http.StatusOK, apiv1.RefreshResponse{Ok: ptr(true)})
}

func (h *AuthHandler) logout(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	if err := h.svc.Logout(r.Context(), user.ID, clientIP(r)); err != nil {
		writeError(w, err)
		return
	}
	h.cookies.clearAuthCookies(w)
	w.WriteHeader(http.StatusNoContent)
}
