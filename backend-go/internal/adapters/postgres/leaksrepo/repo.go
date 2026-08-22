// Package leaksrepo — реализация порта leaks.Store поверх sqlc + pgxpool. Вставка
// пачки утечек — в транзакции; импорт создаёт project_notes (лёгкий персист).
package leaksrepo

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nkolomiika/frost/internal/adapters/postgres/pgconv"
	"github.com/nkolomiika/frost/internal/adapters/postgres/sqlc"
	"github.com/nkolomiika/frost/internal/app/leaks"
)

// Repo реализует leaks.Store.
type Repo struct {
	pool *pgxpool.Pool
	q    *sqlc.Queries
}

// New создаёт репозиторий поверх пула соединений.
func New(pool *pgxpool.Pool) *Repo { return &Repo{pool: pool, q: sqlc.New(pool)} }

var _ leaks.Store = (*Repo)(nil)

func (r *Repo) tx(ctx context.Context, fn func(q *sqlc.Queries) error) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(r.q.WithTx(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// InsertLeaks вставляет находки утечек (по строке на находку) в транзакции.
func (r *Repo) InsertLeaks(ctx context.Context, rows []leaks.LeakInput) error {
	if len(rows) == 0 {
		return nil
	}
	return r.tx(ctx, func(q *sqlc.Queries) error {
		for _, l := range rows {
			if err := q.InsertLeak(ctx, sqlc.InsertLeakParams{
				ProjectID: l.ProjectID,
				JobID:     pgconv.Int4(l.JobID),
				Source:    l.Source,
				Kind:      l.Kind,
				Subject:   pgconv.TextPtr(l.Subject),
				Value:     pgconv.TextPtr(l.Value),
				Detail:    l.Detail,
				Verified:  l.Verified,
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

// ListLeaks — утечки проекта с необязательными фильтрами source/job_id.
func (r *Repo) ListLeaks(ctx context.Context, projectID int32, f leaks.Filter) ([]leaks.Leak, error) {
	rows, err := r.q.ListLeaks(ctx, sqlc.ListLeaksParams{
		ProjectID: projectID,
		Source:    pgconv.TextPtr(f.Source),
		JobID:     pgconv.Int4(f.JobID),
	})
	if err != nil {
		return nil, err
	}
	return mapLeaks(rows), nil
}

// ListLeaksByIDs — выбранные утечки проекта по id.
func (r *Repo) ListLeaksByIDs(ctx context.Context, projectID int32, ids []int32) ([]leaks.Leak, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := r.q.ListLeaksByIDs(ctx, sqlc.ListLeaksByIDsParams{ProjectID: projectID, Ids: ids})
	if err != nil {
		return nil, err
	}
	return mapLeaks(rows), nil
}

// MarkImported помечает выбранные утечки импортированными.
func (r *Repo) MarkImported(ctx context.Context, projectID int32, ids []int32) error {
	if len(ids) == 0 {
		return nil
	}
	return r.q.MarkLeaksImported(ctx, sqlc.MarkLeaksImportedParams{ProjectID: projectID, Ids: ids})
}

// ClearLeaks удаляет утечки проекта (с фильтрами); число удалённых.
func (r *Repo) ClearLeaks(ctx context.Context, projectID int32, f leaks.Filter) (int64, error) {
	return r.q.ClearLeaks(ctx, sqlc.ClearLeaksParams{
		ProjectID: projectID,
		Source:    pgconv.TextPtr(f.Source),
		JobID:     pgconv.Int4(f.JobID),
	})
}

// ImportLeakNote создаёт страницу-заметку проекта из утечки (лёгкий персист импорта).
func (r *Repo) ImportLeakNote(ctx context.Context, projectID int32, title, content string, createdBy int32) error {
	return r.q.InsertLeakNote(ctx, sqlc.InsertLeakNoteParams{
		ProjectID: projectID,
		Title:     title,
		Content:   pgtype.Text{String: content, Valid: true},
		CreatedBy: createdBy,
	})
}

func mapLeaks(rows []sqlc.ReconLeak) []leaks.Leak {
	out := make([]leaks.Leak, 0, len(rows))
	for _, row := range rows {
		out = append(out, leaks.Leak{
			ID:       row.ID,
			Source:   row.Source,
			Kind:     row.Kind,
			Subject:  pgconv.TextValPtr(row.Subject),
			Value:    pgconv.TextValPtr(row.Value),
			Detail:   detailOrNull(row.Detail),
			Verified: row.Verified,
			Imported: row.Imported,
		})
	}
	return out
}

// detailOrNull отдаёт JSON detail либо литерал null (провод: detail всегда валидный JSON).
func detailOrNull(b []byte) []byte {
	if len(b) == 0 {
		return []byte("null")
	}
	return b
}
