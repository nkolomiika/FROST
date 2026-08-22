// Package agenttokens — управление agent API токенами (v1 CRUD).
// Bearer-проверка v2 живёт в отдельном слое, но переиспользует этот Store.
package agenttokens

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/nkolomiika/frost/internal/adapters/security"
	"github.com/nkolomiika/frost/internal/apperr"
)

// AllowedScopes — полный набор разрешённых scope (порт ALLOWED_SCOPES).
var AllowedScopes = []string{"projects:read", "assets:read", "vulns:read", "vulns:write", "notes:read", "notes:write", "leaks:read"}

// DefaultScopes — scope по умолчанию, когда запрос не указал ни одного.
var DefaultScopes = []string{"projects:read", "assets:read", "vulns:read", "notes:read"}

// Token — agent API токен в терминах домена.
type Token struct {
	ID          int32
	Name        string
	TokenPrefix string
	Scopes      []string
	AllProjects bool
	CreatedBy   int32
	ExpiresAt   *time.Time
	RevokedAt   *time.Time
	LastUsedAt  *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
	ProjectIDs  []int32
}

// CreateInput — данные запроса на создание токена.
type CreateInput struct {
	Name        string
	Scopes      []string
	AllProjects bool
	ProjectIDs  []int32
	ExpiresAt   *time.Time
}

// CreateParams — параметры вставки строки токена (для Store).
type CreateParams struct {
	Name        string
	TokenHash   string
	TokenPrefix string
	ScopesJSON  []byte
	AllProjects bool
	CreatedBy   int32
	ExpiresAt   *time.Time
}

// Store — порт хранилища токенов.
type Store interface {
	Create(ctx context.Context, p CreateParams) (*Token, error)
	InsertGrant(ctx context.Context, tokenID, projectID int32) error
	ListGrants(ctx context.Context, tokenID int32) ([]int32, error)
	ListByCreator(ctx context.Context, creatorID int32) ([]*Token, error)
	GetByID(ctx context.Context, id int32) (*Token, error)
	Delete(ctx context.Context, id int32) error
	MemberProjectIDs(ctx context.Context, userID int32) ([]int32, error)
	InsertAudit(ctx context.Context, action string, userID *int32, entityType string, entityID *int32) error

	// Для bearer-аутентификации /api/v2.
	GetByHash(ctx context.Context, tokenHash string) (*Token, error)
	TouchLastUsed(ctx context.Context, id int32, t time.Time) error
	CreatorIsAdmin(ctx context.Context, userID int32) (bool, error)
}

// AgentContext — контекст аутентифицированного agent-токена (порт get_agent_token_context).
type AgentContext struct {
	TokenID           int32
	CreatedBy         int32
	Scopes            map[string]bool
	AllProjects       bool
	ProjectIDs        map[int32]bool
	CreatorIsAdmin    bool
	CreatorProjectIDs map[int32]bool
}

// Service — use-cases управления токенами.
type Service struct {
	store Store
	now   func() time.Time
}

// NewService собирает сервис.
func NewService(store Store, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{store: store, now: now}
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func dedupeInts(in []int32) []int32 {
	seen := map[int32]bool{}
	out := make([]int32, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// CreateToken создаёт токен: валидирует scope/срок/права создателя, пишет строку
// и гранты, возвращает токен и «сырой» секрет (показывается один раз).
func (s *Service) CreateToken(ctx context.Context, actorID int32, actorIsAdmin bool, in CreateInput) (*Token, string, error) {
	requested := dedupeStrings(in.Scopes)
	var unknown []string
	for _, sc := range requested {
		if !contains(AllowedScopes, sc) {
			unknown = append(unknown, sc)
		}
	}
	if len(unknown) > 0 {
		return nil, "", apperr.Validation("Неизвестные scope: " + join(unknown))
	}
	if len(requested) == 0 {
		requested = append([]string(nil), DefaultScopes...)
	}

	if in.ExpiresAt != nil && !in.ExpiresAt.After(s.now().UTC()) {
		return nil, "", apperr.Validation("Срок действия токена уже истёк")
	}

	projectIDs := dedupeInts(in.ProjectIDs)
	if !in.AllProjects && !actorIsAdmin {
		memberOf, err := s.store.MemberProjectIDs(ctx, actorID)
		if err != nil {
			return nil, "", err
		}
		var forbidden []string
		for _, pid := range projectIDs {
			if !containsInt(memberOf, pid) {
				forbidden = append(forbidden, itoa(pid))
			}
		}
		if len(forbidden) > 0 {
			return nil, "", apperr.Forbidden("Нет доступа к проектам: " + join(forbidden) + " — токен не может превышать ваши права")
		}
	}

	raw := "frost_" + security.GenerateURLSafeToken(32)
	scopesJSON, _ := json.Marshal(requested)
	token, err := s.store.Create(ctx, CreateParams{
		Name:        in.Name,
		TokenHash:   security.HashTokenSHA256(raw),
		TokenPrefix: raw[:14],
		ScopesJSON:  scopesJSON,
		AllProjects: in.AllProjects,
		CreatedBy:   actorID,
		ExpiresAt:   in.ExpiresAt,
	})
	if err != nil {
		return nil, "", err
	}
	if !in.AllProjects {
		for _, pid := range projectIDs {
			if err := s.store.InsertGrant(ctx, token.ID, pid); err != nil {
				return nil, "", err
			}
		}
		token.ProjectIDs = projectIDs
	}
	_ = s.store.InsertAudit(ctx, "CREATE", &actorID, "agent_api_token", &token.ID)
	return token, raw, nil
}

// ListTokens возвращает токены, созданные пользователем (только свои).
func (s *Service) ListTokens(ctx context.Context, actorID int32) ([]*Token, error) {
	return s.store.ListByCreator(ctx, actorID)
}

// RevokeToken удаляет токен (свой — любому, чужой — только админу).
func (s *Service) RevokeToken(ctx context.Context, tokenID, actorID int32, actorIsAdmin bool) error {
	token, err := s.store.GetByID(ctx, tokenID)
	if err != nil {
		return apperr.NotFound("Agent API token не найден")
	}
	if !actorIsAdmin && token.CreatedBy != actorID {
		return apperr.Forbidden("Можно удалять только свои токены")
	}
	if err := s.store.Delete(ctx, tokenID); err != nil {
		return err
	}
	_ = s.store.InsertAudit(ctx, "DELETE", &actorID, "agent_api_token", &tokenID)
	return nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func containsInt(xs []int32, x int32) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func join(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}

func itoa(v int32) string { return strconv.Itoa(int(v)) }

// Authenticate проверяет Bearer-токен и собирает AgentContext (порт get_agent_token_context).
func (s *Service) Authenticate(ctx context.Context, rawToken string) (*AgentContext, error) {
	if rawToken == "" {
		return nil, apperr.Unauthorized("Требуется Bearer token")
	}
	token, err := s.store.GetByHash(ctx, security.HashTokenSHA256(rawToken))
	if err != nil || token == nil || token.RevokedAt != nil {
		return nil, apperr.Unauthorized("Agent API token недействителен")
	}
	if token.ExpiresAt != nil && !token.ExpiresAt.After(s.now().UTC()) {
		return nil, apperr.Unauthorized("Agent API token истёк")
	}
	grants, err := s.store.ListGrants(ctx, token.ID)
	if err != nil {
		return nil, err
	}
	_ = s.store.TouchLastUsed(ctx, token.ID, s.now().UTC())

	creatorIsAdmin, err := s.store.CreatorIsAdmin(ctx, token.CreatedBy)
	if err != nil {
		return nil, err
	}
	creatorProjects := map[int32]bool{}
	if !creatorIsAdmin {
		ids, err := s.store.MemberProjectIDs(ctx, token.CreatedBy)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			creatorProjects[id] = true
		}
	}
	scopes := map[string]bool{}
	for _, sc := range token.Scopes {
		scopes[sc] = true
	}
	projectIDs := map[int32]bool{}
	for _, id := range grants {
		projectIDs[id] = true
	}
	return &AgentContext{
		TokenID: token.ID, CreatedBy: token.CreatedBy, Scopes: scopes,
		AllProjects: token.AllProjects, ProjectIDs: projectIDs,
		CreatorIsAdmin: creatorIsAdmin, CreatorProjectIDs: creatorProjects,
	}, nil
}

// RequireScope проверяет наличие scope (порт require_agent_scope).
func (s *Service) RequireScope(ac *AgentContext, scope string) error {
	if ac == nil || !ac.Scopes[scope] {
		return apperr.Forbidden("Недостаточно прав agent token: требуется " + scope)
	}
	return nil
}

// AuthorizeProject — доступ токена к проекту: грант токена ∩ права создателя
// (порт require_agent_project_access; существование проекта проверяет вызывающий).
func (s *Service) AuthorizeProject(ac *AgentContext, projectID int32) error {
	if ac == nil {
		return apperr.Forbidden("Agent token не имеет доступа к проекту")
	}
	if !ac.AllProjects && !ac.ProjectIDs[projectID] {
		return apperr.Forbidden("Agent token не имеет доступа к проекту")
	}
	if !ac.CreatorIsAdmin && !ac.CreatorProjectIDs[projectID] {
		return apperr.Forbidden("Agent token не имеет доступа к проекту")
	}
	return nil
}

// AllowedProjectID сообщает, виден ли проект токену (для inline-фильтра GET /projects).
func (s *Service) AllowedProjectID(ac *AgentContext, projectID int32) bool {
	return s.AuthorizeProject(ac, projectID) == nil
}
