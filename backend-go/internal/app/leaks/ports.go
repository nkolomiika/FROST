package leaks

import "context"

// Store — порт хранилища утечек (реализует leaksrepo поверх sqlc + pgxpool).
type Store interface {
	// InsertLeaks вставляет находки утечек (по строке на находку). Пустой вход — no-op.
	InsertLeaks(ctx context.Context, rows []LeakInput) error
	// ListLeaks — утечки проекта с необязательными фильтрами source/job_id.
	ListLeaks(ctx context.Context, projectID int32, f Filter) ([]Leak, error)
	// ListLeaksByIDs — выбранные утечки проекта по id (для импорта). Скоуп проекта обязателен.
	ListLeaksByIDs(ctx context.Context, projectID int32, ids []int32) ([]Leak, error)
	// MarkImported помечает выбранные утечки импортированными (идемпотентно).
	MarkImported(ctx context.Context, projectID int32, ids []int32) error
	// ClearLeaks удаляет утечки проекта (с фильтрами source/job_id); число удалённых.
	ClearLeaks(ctx context.Context, projectID int32, f Filter) (int64, error)
	// ImportLeakNote создаёт лёгкий персист импорта — страницу-заметку проекта на утечку.
	ImportLeakNote(ctx context.Context, projectID int32, title, content string, createdBy int32) error
}
