package http

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/nkolomiika/frost/internal/adapters/http/apiv1"
	"github.com/nkolomiika/frost/internal/app/agenttokens"
	"github.com/nkolomiika/frost/internal/app/auth"
	"github.com/nkolomiika/frost/internal/apperr"
)

// AgentTokenHandler обслуживает /api/v1/agent-tokens (cookie-auth пользователя).
type AgentTokenHandler struct {
	svc         *agenttokens.Service
	auth        *auth.Service
	csrfOrigins []string
}

// NewAgentTokenHandler собирает обработчик.
func NewAgentTokenHandler(svc *agenttokens.Service, authSvc *auth.Service, csrfOrigins []string) *AgentTokenHandler {
	return &AgentTokenHandler{svc: svc, auth: authSvc, csrfOrigins: csrfOrigins}
}

// Register монтирует роуты под requireAuth (+CSRF на мутациях).
func (h *AgentTokenHandler) Register(r chi.Router) {
	r.Route("/api/v1/agent-tokens", func(ar chi.Router) {
		ar.Use(enforceCSRF(h.csrfOrigins))
		ar.Use(requireAuth(h.auth))
		ar.Get("/", h.list)
		ar.Post("/", h.create)
		ar.Delete("/{token_id}", h.revoke)
	})
}

func tokenOut(t *agenttokens.Token) apiv1.AgentTokenOut {
	scopes := append([]string(nil), t.Scopes...)
	pids := make([]int, 0, len(t.ProjectIDs))
	for _, p := range t.ProjectIDs {
		pids = append(pids, int(p))
	}
	return apiv1.AgentTokenOut{
		Id:          int(t.ID),
		Name:        t.Name,
		TokenPrefix: t.TokenPrefix,
		Scopes:      &scopes,
		AllProjects: t.AllProjects,
		CreatedBy:   int(t.CreatedBy),
		ProjectIds:  &pids,
		ExpiresAt:   t.ExpiresAt,
		RevokedAt:   t.RevokedAt,
		LastUsedAt:  t.LastUsedAt,
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
	}
}

func (h *AgentTokenHandler) list(w http.ResponseWriter, r *http.Request) {
	actor := userFromContext(r.Context())
	tokens, err := h.svc.ListTokens(r.Context(), actor.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]apiv1.AgentTokenOut, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, tokenOut(t))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *AgentTokenHandler) create(w http.ResponseWriter, r *http.Request) {
	actor := userFromContext(r.Context())
	var req apiv1.AgentTokenCreate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	in := agenttokens.CreateInput{Name: req.Name, ExpiresAt: req.ExpiresAt}
	if req.Scopes != nil {
		in.Scopes = *req.Scopes
	}
	if req.AllProjects != nil {
		in.AllProjects = *req.AllProjects
	}
	if req.ProjectIds != nil {
		for _, p := range *req.ProjectIds {
			in.ProjectIDs = append(in.ProjectIDs, int32(p))
		}
	}
	token, raw, err := h.svc.CreateToken(r.Context(), actor.ID, actor.Role == "ADMIN", in)
	if err != nil {
		writeError(w, err)
		return
	}
	out := tokenOut(token)
	writeJSON(w, http.StatusCreated, apiv1.AgentTokenCreateResponse{
		Id: out.Id, Name: out.Name, TokenPrefix: out.TokenPrefix, Scopes: out.Scopes,
		AllProjects: out.AllProjects, CreatedBy: out.CreatedBy, ProjectIds: out.ProjectIds,
		ExpiresAt: out.ExpiresAt, RevokedAt: out.RevokedAt, LastUsedAt: out.LastUsedAt,
		CreatedAt: out.CreatedAt, UpdatedAt: out.UpdatedAt, Token: raw,
	})
}

func (h *AgentTokenHandler) revoke(w http.ResponseWriter, r *http.Request) {
	actor := userFromContext(r.Context())
	id, err := strconv.Atoi(chi.URLParam(r, "token_id"))
	if err != nil {
		writeError(w, apperr.Validation("Некорректный token_id"))
		return
	}
	if err := h.svc.RevokeToken(r.Context(), int32(id), actor.ID, actor.Role == "ADMIN"); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
