// Package mailerrepo — хранилище mail-outbox для воркера поверх sqlc.
package mailerrepo

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nkolomiika/frost/internal/adapters/postgres/pgconv"
	"github.com/nkolomiika/frost/internal/adapters/postgres/sqlc"
	"github.com/nkolomiika/frost/internal/app/mailer"
)

// Repo реализует mailer.Store.
type Repo struct{ q *sqlc.Queries }

// New создаёт репозиторий поверх пула.
func New(pool *pgxpool.Pool) *Repo { return &Repo{q: sqlc.New(pool)} }

var _ mailer.Store = (*Repo)(nil)

func (r *Repo) ClaimPending(ctx context.Context, limit, maxAttempts int32) ([]int32, error) {
	rows, err := r.q.ClaimPendingMailJobs(ctx, sqlc.ClaimPendingMailJobsParams{MaxAttempts: maxAttempts, Lim: limit})
	if err != nil {
		return nil, err
	}
	ids := make([]int32, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	return ids, nil
}

func (r *Repo) MarkProcessing(ctx context.Context, id int32) (*mailer.Job, error) {
	row, err := r.q.MarkMailJobProcessing(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil // уже sent / отсутствует
	}
	if err != nil {
		return nil, err
	}
	return &mailer.Job{
		ID:             row.ID,
		RecipientEmail: row.RecipientEmail,
		Subject:        row.Subject,
		Template:       row.Template,
		Payload:        row.Payload,
		Attempts:       row.Attempts,
	}, nil
}

func (r *Repo) MarkSent(ctx context.Context, id int32) error {
	return r.q.MarkMailJobSent(ctx, id)
}

func (r *Repo) MarkPending(ctx context.Context, id int32, errMsg string) error {
	return r.q.MarkMailJobPending(ctx, sqlc.MarkMailJobPendingParams{ID: id, LastError: pgconv.Text(errMsg)})
}

func (r *Repo) MarkFailed(ctx context.Context, id int32, errMsg string) error {
	return r.q.MarkMailJobFailed(ctx, sqlc.MarkMailJobFailedParams{ID: id, LastError: pgconv.Text(errMsg)})
}
