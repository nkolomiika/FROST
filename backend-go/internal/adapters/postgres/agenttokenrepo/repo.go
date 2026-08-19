// Package agenttokenrepo — хранилище agent API токенов поверх sqlc.
package agenttokenrepo

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nkolomiika/frost/internal/adapters/postgres/pgconv"
	"github.com/nkolomiika/frost/internal/adapters/postgres/sqlc"
	"github.com/nkolomiika/frost/internal/app/agenttokens"
)

// Repo реализует agenttokens.Store.
type Repo struct{ q *sqlc.Queries }

// New создаёт репозиторий поверх пула.
func New(pool *pgxpool.Pool) *Repo { return &Repo{q: sqlc.New(pool)} }

var _ agenttokens.Store = (*Repo)(nil)

func mapToken(t sqlc.AgentApiToken) *agenttokens.Token {
	var scopes []string
	if len(t.Scopes) > 0 {
		_ = json.Unmarshal(t.Scopes, &scopes)
	}
	return &agenttokens.Token{
		ID:          t.ID,
		Name:        t.Name,
		TokenPrefix: t.TokenPrefix,
		Scopes:      scopes,
		AllProjects: t.AllProjects,
		CreatedBy:   t.CreatedBy,
		ExpiresAt:   pgconv.TsValPtr(t.ExpiresAt),
		RevokedAt:   pgconv.TsValPtr(t.RevokedAt),
		LastUsedAt:  pgconv.TsValPtr(t.LastUsedAt),
		CreatedAt:   pgconv.TsVal(t.CreatedAt),
		UpdatedAt:   pgconv.TsVal(t.UpdatedAt),
	}
}

func (r *Repo) Create(ctx context.Context, p agenttokens.CreateParams) (*agenttokens.Token, error) {
	row, err := r.q.CreateAgentToken(ctx, sqlc.CreateAgentTokenParams{
		Name:        p.Name,
		TokenHash:   p.TokenHash,
		TokenPrefix: p.TokenPrefix,
		Scopes:      p.ScopesJSON,
		AllProjects: p.AllProjects,
		CreatedBy:   p.CreatedBy,
		ExpiresAt:   pgconv.TsPtr(p.ExpiresAt),
	})
	if err != nil {
		return nil, err
	}
	return mapToken(row), nil
}

func (r *Repo) InsertGrant(ctx context.Context, tokenID, projectID int32) error {
	return r.q.InsertAgentTokenGrant(ctx, sqlc.InsertAgentTokenGrantParams{TokenID: tokenID, ProjectID: projectID})
}

func (r *Repo) ListGrants(ctx context.Context, tokenID int32) ([]int32, error) {
	return r.q.ListAgentTokenGrants(ctx, tokenID)
}

func (r *Repo) ListByCreator(ctx context.Context, creatorID int32) ([]*agenttokens.Token, error) {
	rows, err := r.q.ListAgentTokensByCreator(ctx, creatorID)
	if err != nil {
		return nil, err
	}
	out := make([]*agenttokens.Token, 0, len(rows))
	for _, row := range rows {
		t := mapToken(row)
		grants, err := r.q.ListAgentTokenGrants(ctx, t.ID)
		if err != nil {
			return nil, err
		}
		t.ProjectIDs = grants
		out = append(out, t)
	}
	return out, nil
}

func (r *Repo) GetByID(ctx context.Context, id int32) (*agenttokens.Token, error) {
	row, err := r.q.GetAgentTokenByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return mapToken(row), nil
}

func (r *Repo) Delete(ctx context.Context, id int32) error {
	return r.q.DeleteAgentToken(ctx, id)
}

func (r *Repo) MemberProjectIDs(ctx context.Context, userID int32) ([]int32, error) {
	return r.q.ListMemberProjectIDs(ctx, userID)
}

func (r *Repo) InsertAudit(ctx context.Context, action string, userID *int32, entityType string, entityID *int32) error {
	return r.q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		UserID:     pgconv.Int4(userID),
		Action:     action,
		EntityType: pgconv.Text(entityType),
		EntityID:   pgconv.Int4(entityID),
	})
}
