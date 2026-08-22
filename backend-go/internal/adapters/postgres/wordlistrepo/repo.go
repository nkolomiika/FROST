// Package wordlistrepo — реализация порта wordlists.Store поверх sqlc + pgxpool.
// Хранит только МЕТАДАННЫЕ словарей (recon_wordlists); байты файла — в MinIO.
package wordlistrepo

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nkolomiika/frost/internal/adapters/postgres/pgconv"
	"github.com/nkolomiika/frost/internal/adapters/postgres/sqlc"
	"github.com/nkolomiika/frost/internal/app/wordlists"
)

// Repo реализует wordlists.Store.
type Repo struct {
	q *sqlc.Queries
}

// New создаёт репозиторий поверх пула соединений.
func New(pool *pgxpool.Pool) *Repo { return &Repo{q: sqlc.New(pool)} }

var _ wordlists.Store = (*Repo)(nil)

func int8Ptr(p *int64) pgtype.Int8 {
	if p == nil {
		return pgtype.Int8{}
	}
	return pgtype.Int8{Int64: *p, Valid: true}
}

func int8ValPtr(v pgtype.Int8) *int64 {
	if !v.Valid {
		return nil
	}
	n := v.Int64
	return &n
}

func rowToWordlist(m sqlc.ReconWordlist) wordlists.Wordlist {
	return wordlists.Wordlist{
		ID:         m.ID,
		Name:       m.Name,
		ObjectKey:  m.ObjectKey,
		SizeBytes:  int8ValPtr(m.SizeBytes),
		Lines:      pgconv.Int4Val(m.Lines),
		UploadedBy: pgconv.Int4Val(m.UploadedBy),
		CreatedAt:  pgconv.TsVal(m.CreatedAt),
	}
}

// Insert вставляет строку метаданных словаря.
func (r *Repo) Insert(ctx context.Context, in wordlists.NewWordlist) (wordlists.Wordlist, error) {
	m, err := r.q.InsertWordlist(ctx, sqlc.InsertWordlistParams{
		Name:       in.Name,
		ObjectKey:  in.ObjectKey,
		SizeBytes:  int8Ptr(in.SizeBytes),
		Lines:      pgconv.Int4(in.Lines),
		UploadedBy: pgconv.Int4(in.UploadedBy),
	})
	if err != nil {
		return wordlists.Wordlist{}, err
	}
	return rowToWordlist(m), nil
}

// List — все кастомные словари (новые сверху).
func (r *Repo) List(ctx context.Context) ([]wordlists.Wordlist, error) {
	rows, err := r.q.ListWordlists(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]wordlists.Wordlist, 0, len(rows))
	for _, m := range rows {
		out = append(out, rowToWordlist(m))
	}
	return out, nil
}

// Get — один словарь по id (ErrNoRows при отсутствии).
func (r *Repo) Get(ctx context.Context, id int32) (wordlists.Wordlist, error) {
	m, err := r.q.GetWordlist(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return wordlists.Wordlist{}, wordlists.ErrNoRows
	}
	if err != nil {
		return wordlists.Wordlist{}, err
	}
	return rowToWordlist(m), nil
}

// Delete удаляет строку по id; число удалённых.
func (r *Repo) Delete(ctx context.Context, id int32) (int64, error) {
	return r.q.DeleteWordlist(ctx, id)
}
