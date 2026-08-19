// Package auditrepo — чтение журнала действий поверх sqlc (порт audit.Store).
package auditrepo

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nkolomiika/frost/internal/adapters/postgres/pgconv"
	"github.com/nkolomiika/frost/internal/adapters/postgres/sqlc"
	"github.com/nkolomiika/frost/internal/app/audit"
)

// Repo реализует audit.Store.
type Repo struct{ q *sqlc.Queries }

// New создаёт репозиторий поверх пула.
func New(pool *pgxpool.Pool) *Repo { return &Repo{q: sqlc.New(pool)} }

var _ audit.Store = (*Repo)(nil)

func (r *Repo) ListAuditLogs(ctx context.Context, f audit.Filters) ([]audit.Item, error) {
	rows, err := r.q.ListAuditLogs(ctx, sqlc.ListAuditLogsParams{
		UserID:      pgconv.Int4(f.UserID),
		Username:    pgconv.Text(f.Username),
		Action:      pgconv.Text(f.Action),
		EntityType:  pgconv.Text(f.EntityType),
		EntityID:    pgconv.Int4(f.EntityID),
		IpAddress:   pgconv.Text(f.IPAddress),
		Q:           pgconv.Text(f.Query),
		CreatedFrom: pgconv.TsPtr(f.CreatedFrom),
		CreatedTo:   pgconv.TsPtr(f.CreatedTo),
		Offset:      f.Offset,
		Lim:         f.Limit,
	})
	if err != nil {
		return nil, err
	}
	items := make([]audit.Item, 0, len(rows))
	for _, row := range rows {
		var details []byte
		if len(row.Details) > 0 {
			details = row.Details
		}
		items = append(items, audit.Item{
			ID:         row.ID,
			UserID:     pgconv.Int4Val(row.UserID),
			Username:   pgconv.TextValPtr(row.Username),
			Action:     row.Action,
			EntityType: pgconv.TextValPtr(row.EntityType),
			EntityID:   pgconv.Int4Val(row.EntityID),
			Details:    details,
			IPAddress:  pgconv.TextValPtr(row.IpAddress),
			CreatedAt:  pgconv.TsVal(row.CreatedAt),
		})
	}
	return items, nil
}

func (r *Repo) CountAuditLogs(ctx context.Context, f audit.Filters) (int64, error) {
	return r.q.CountAuditLogs(ctx, sqlc.CountAuditLogsParams{
		UserID:      pgconv.Int4(f.UserID),
		Username:    pgconv.Text(f.Username),
		Action:      pgconv.Text(f.Action),
		EntityType:  pgconv.Text(f.EntityType),
		EntityID:    pgconv.Int4(f.EntityID),
		IpAddress:   pgconv.Text(f.IPAddress),
		Q:           pgconv.Text(f.Query),
		CreatedFrom: pgconv.TsPtr(f.CreatedFrom),
		CreatedTo:   pgconv.TsPtr(f.CreatedTo),
	})
}
