// Package notificationsrepo — чтение и резолв уведомлений поверх sqlc.
package notificationsrepo

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nkolomiika/frost/internal/adapters/postgres/pgconv"
	"github.com/nkolomiika/frost/internal/adapters/postgres/sqlc"
	"github.com/nkolomiika/frost/internal/app/notifications"
)

// Repo реализует notifications.Store.
type Repo struct{ q *sqlc.Queries }

// New создаёт репозиторий поверх пула.
func New(pool *pgxpool.Pool) *Repo { return &Repo{q: sqlc.New(pool)} }

var _ notifications.Store = (*Repo)(nil)

func boolp(p *bool) pgtype.Bool {
	if p == nil {
		return pgtype.Bool{}
	}
	return pgtype.Bool{Bool: *p, Valid: true}
}

func mapNotification(n sqlc.Notification) notifications.Notification {
	return notifications.Notification{
		ID:              n.ID,
		Type:            string(n.Type),
		CommentID:       pgconv.Int4Val(n.CommentID),
		NoteCommentID:   pgconv.Int4Val(n.NoteCommentID),
		ProjectID:       pgconv.Int4Val(n.ProjectID),
		VulnerabilityID: pgconv.Int4Val(n.VulnerabilityID),
		ActorID:         pgconv.Int4Val(n.ActorID),
		Status:          pgconv.TextValPtr(n.Status),
		IsRead:          n.IsRead,
		CreatedAt:       pgconv.TsVal(n.CreatedAt),
	}
}

func (r *Repo) List(ctx context.Context, userID int32, isRead *bool, offset, limit int32) ([]notifications.Notification, error) {
	rows, err := r.q.ListNotifications(ctx, sqlc.ListNotificationsParams{UserID: userID, IsRead: boolp(isRead), Offset: offset, Lim: limit})
	if err != nil {
		return nil, err
	}
	out := make([]notifications.Notification, 0, len(rows))
	for _, n := range rows {
		out = append(out, mapNotification(n))
	}
	return out, nil
}

func (r *Repo) Count(ctx context.Context, userID int32, isRead *bool) (int64, error) {
	return r.q.CountNotifications(ctx, sqlc.CountNotificationsParams{UserID: userID, IsRead: boolp(isRead)})
}

func (r *Repo) CountUnread(ctx context.Context, userID int32) (int64, error) {
	return r.q.CountUnreadNotifications(ctx, userID)
}

func (r *Repo) MarkRead(ctx context.Context, id, userID int32) (*notifications.Notification, error) {
	row, err := r.q.MarkNotificationRead(ctx, sqlc.MarkNotificationReadParams{ID: id, UserID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notifications.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	n := mapNotification(row)
	return &n, nil
}

func (r *Repo) MarkAllRead(ctx context.Context, userID int32) error {
	return r.q.MarkAllNotificationsRead(ctx, userID)
}

// ResolveContext резолвит контекст по одной из трёх взаимоисключающих веток.
// Удалённые связанные сущности (ErrNoRows) → контекст без соответствующих полей.
func (r *Repo) ResolveContext(ctx context.Context, n notifications.Notification) (*notifications.Context, error) {
	switch {
	case n.CommentID != nil:
		row, err := r.q.GetCommentNotificationContext(ctx, *n.CommentID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		c := &notifications.Context{
			VulnerabilityID:    &row.VulnerabilityID,
			VulnerabilityTitle: &row.Title,
			ProjectID:          &row.ProjectID,
			CommenterUsername:  &row.Username,
		}
		if host, err := r.q.GetCommentHostID(ctx, *n.CommentID); err == nil {
			h := host
			c.HostID = &h
		}
		return c, nil

	case n.NoteCommentID != nil:
		row, err := r.q.GetNoteCommentNotificationContext(ctx, *n.NoteCommentID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return &notifications.Context{
			NoteID:            &row.NoteID,
			NoteTitle:         &row.NoteTitle,
			ProjectID:         &row.ProjectID,
			CommenterUsername: &row.Username,
		}, nil

	default:
		if n.ProjectID == nil && n.VulnerabilityID == nil {
			return nil, nil
		}
		c := &notifications.Context{Status: n.Status}
		if n.ActorID != nil {
			if uname, err := r.q.GetUsernameByID(ctx, *n.ActorID); err == nil {
				c.CommenterUsername = &uname
			}
		}
		projectID := n.ProjectID
		if n.VulnerabilityID != nil {
			if vp, err := r.q.GetVulnTitleAndProject(ctx, *n.VulnerabilityID); err == nil {
				c.VulnerabilityID = n.VulnerabilityID
				title := vp.Title
				c.VulnerabilityTitle = &title
				pid := vp.ProjectID
				projectID = &pid
			}
		}
		if projectID != nil {
			c.ProjectID = projectID
			if name, err := r.q.GetProjectName(ctx, *projectID); err == nil {
				c.ProjectName = &name
			}
		}
		return c, nil
	}
}
