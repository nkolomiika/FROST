// Package integrationsrepo — реализация порта integrations.Store поверх sqlc +
// pgxpool. Значения хранятся зашифрованными (BYTEA), метаданные — без значений.
package integrationsrepo

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nkolomiika/frost/internal/adapters/postgres/pgconv"
	"github.com/nkolomiika/frost/internal/adapters/postgres/sqlc"
	"github.com/nkolomiika/frost/internal/app/integrations"
)

// Repo реализует integrations.Store.
type Repo struct {
	q *sqlc.Queries
}

// New создаёт репозиторий поверх пула соединений.
func New(pool *pgxpool.Pool) *Repo { return &Repo{q: sqlc.New(pool)} }

var _ integrations.Store = (*Repo)(nil)

// GetEncrypted возвращает зашифрованное значение ключа (ErrNoRows — нет строки).
func (r *Repo) GetEncrypted(ctx context.Context, keyName string) ([]byte, error) {
	row, err := r.q.GetIntegration(ctx, keyName)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, integrations.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	return row.ValueEncrypted, nil
}

// ListMeta — метаданные всех заданных ключей (без значений).
func (r *Repo) ListMeta(ctx context.Context) ([]integrations.StoredMeta, error) {
	rows, err := r.q.ListIntegrations(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]integrations.StoredMeta, 0, len(rows))
	for _, row := range rows {
		out = append(out, integrations.StoredMeta{KeyName: row.KeyName, UpdatedAt: pgconv.TsVal(row.UpdatedAt)})
	}
	return out, nil
}

// Upsert вставляет/обновляет зашифрованное значение ключа.
func (r *Repo) Upsert(ctx context.Context, keyName string, valueEncrypted []byte, updatedBy *int32) error {
	var by pgtype.Int4
	if updatedBy != nil {
		by = pgtype.Int4{Int32: *updatedBy, Valid: true}
	}
	return r.q.UpsertIntegration(ctx, sqlc.UpsertIntegrationParams{
		KeyName:        keyName,
		ValueEncrypted: valueEncrypted,
		UpdatedBy:      by,
	})
}

// Delete удаляет ключ.
func (r *Repo) Delete(ctx context.Context, keyName string) error {
	return r.q.DeleteIntegration(ctx, keyName)
}
