// Package audit — просмотр журнала действий (роутер audit_logs.py, admin-only).
// Запись в журнал делают сами контексты через свои Store; здесь только чтение.
package audit

import (
	"context"
	"encoding/json"
	"time"
)

// Filters — параметры фильтрации списка (все опциональны).
type Filters struct {
	UserID      *int32
	Username    string
	Action      string
	EntityType  string
	EntityID    *int32
	IPAddress   string
	Query       string
	CreatedFrom *time.Time
	CreatedTo   *time.Time
	Offset      int32
	Limit       int32
}

// Item — строка журнала с присоединённым именем пользователя.
type Item struct {
	ID         int32           `json:"id"`
	UserID     *int32          `json:"user_id"`
	Username   *string         `json:"username"`
	Action     string          `json:"action"`
	EntityType *string         `json:"entity_type"`
	EntityID   *int32          `json:"entity_id"`
	Details    json.RawMessage `json:"details"`
	IPAddress  *string         `json:"ip_address"`
	CreatedAt  time.Time       `json:"created_at"`
}

// Store — порт чтения журнала (реализуется auditrepo поверх sqlc).
type Store interface {
	ListAuditLogs(ctx context.Context, f Filters) ([]Item, error)
	CountAuditLogs(ctx context.Context, f Filters) (int64, error)
}

// Service — use-case списка журнала.
type Service struct{ store Store }

// NewService собирает сервис аудита.
func NewService(store Store) *Service { return &Service{store: store} }

// List возвращает страницу журнала и общее число записей под фильтр.
func (s *Service) List(ctx context.Context, f Filters) ([]Item, int64, error) {
	total, err := s.store.CountAuditLogs(ctx, f)
	if err != nil {
		return nil, 0, err
	}
	items, err := s.store.ListAuditLogs(ctx, f)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}
