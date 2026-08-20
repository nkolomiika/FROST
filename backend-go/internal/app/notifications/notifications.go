// Package notifications — читающая сторона уведомлений (порт NotificationService +
// routers/notifications.py). Запись строк notifications делают контексты projects/vulns.
package notifications

import (
	"context"
	"strings"
	"time"

	"github.com/nkolomiika/frost/internal/apperr"
)

// Notification — строка notifications в доменных терминах. Type — БД-регистр (UPPERCASE).
type Notification struct {
	ID              int32
	Type            string
	CommentID       *int32
	NoteCommentID   *int32
	ProjectID       *int32
	VulnerabilityID *int32
	ActorID         *int32
	Status          *string
	IsRead          bool
	CreatedAt       time.Time
}

// Context — резолвнутый контекст уведомления (соответствует apiv1.NotificationContext).
type Context struct {
	VulnerabilityID    *int32
	VulnerabilityTitle *string
	ProjectID          *int32
	ProjectName        *string
	NoteID             *int32
	NoteTitle          *string
	HostID             *int32
	CommenterUsername  *string
	Status             *string
}

// View — уведомление с резолвнутым контекстом (для списка).
type View struct {
	N   Notification
	Ctx *Context
}

// Store — порт чтения/резолва уведомлений.
type Store interface {
	List(ctx context.Context, userID int32, isRead *bool, offset, limit int32) ([]Notification, error)
	Count(ctx context.Context, userID int32, isRead *bool) (int64, error)
	CountUnread(ctx context.Context, userID int32) (int64, error)
	MarkRead(ctx context.Context, id, userID int32) (*Notification, error) // nil,ErrNoRows если чужое/нет
	MarkAllRead(ctx context.Context, userID int32) error
	ResolveContext(ctx context.Context, n Notification) (*Context, error)
}

// ErrNoRows — уведомление не найдено (репозиторий).
var ErrNoRows = errNoRows{}

type errNoRows struct{}

func (errNoRows) Error() string { return "no rows" }

// APIType переводит БД-регистр типа (UPPERCASE) в API-значение (lowercase).
func APIType(dbType string) string { return strings.ToLower(dbType) }

// Service — use-cases уведомлений.
type Service struct{ store Store }

// NewService собирает сервис.
func NewService(store Store) *Service { return &Service{store: store} }

// List возвращает страницу уведомлений с резолвнутым контекстом и общее число.
func (s *Service) List(ctx context.Context, userID int32, isRead *bool, page, size int) ([]View, int64, error) {
	total, err := s.store.Count(ctx, userID, isRead)
	if err != nil {
		return nil, 0, err
	}
	rows, err := s.store.List(ctx, userID, isRead, int32((page-1)*size), int32(size))
	if err != nil {
		return nil, 0, err
	}
	views := make([]View, 0, len(rows))
	for _, n := range rows {
		c, err := s.store.ResolveContext(ctx, n)
		if err != nil {
			return nil, 0, err
		}
		views = append(views, View{N: n, Ctx: c})
	}
	return views, total, nil
}

// UnreadCount возвращает число непрочитанных.
func (s *Service) UnreadCount(ctx context.Context, userID int32) (int64, error) {
	return s.store.CountUnread(ctx, userID)
}

// MarkRead помечает одно уведомление прочитанным (404 при чужом/несуществующем).
// Контекст не резолвится (как в Python — /read всегда возвращает context=null).
func (s *Service) MarkRead(ctx context.Context, id, userID int32) (*Notification, error) {
	n, err := s.store.MarkRead(ctx, id, userID)
	if err == ErrNoRows {
		return nil, apperr.NotFound("Уведомление не найдено")
	}
	if err != nil {
		return nil, err
	}
	return n, nil
}

// MarkAllRead помечает все уведомления пользователя прочитанными.
func (s *Service) MarkAllRead(ctx context.Context, userID int32) error {
	return s.store.MarkAllRead(ctx, userID)
}
