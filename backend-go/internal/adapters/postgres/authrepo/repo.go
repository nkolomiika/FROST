// Package authrepo — реализация порта auth.Store поверх sqlc + pgxpool.
// Компаунд-операции (accept-invitation, rotate-refresh, confirm-reset,
// complete-reactivation) выполняются в транзакции.
package authrepo

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nkolomiika/frost/internal/adapters/postgres/sqlc"
	"github.com/nkolomiika/frost/internal/app/auth"
)

// Repo реализует auth.Store.
type Repo struct {
	pool *pgxpool.Pool
	q    *sqlc.Queries
}

// New создаёт репозиторий поверх пула соединений.
func New(pool *pgxpool.Pool) *Repo {
	return &Repo{pool: pool, q: sqlc.New(pool)}
}

var _ auth.Store = (*Repo)(nil)

// tx выполняет fn в транзакции с автоматическим rollback при ошибке.
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

// mapErr переводит pgx.ErrNoRows в доменную auth.ErrNoRows.
func mapErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.ErrNoRows
	}
	return err
}

// ─────────────────────────── users ───────────────────────────

func mapUser(u sqlc.User) *auth.User {
	return &auth.User{
		ID:           u.ID,
		Username:     u.Username,
		Email:        u.Email,
		FullName:     textVal(u.FullName),
		PasswordHash: u.PasswordHash,
		TotpSecret:   textVal(u.TotpSecret),
		TotpEnabled:  u.TotpEnabled,
		Role:         string(u.Role),
		ProjectRole:  string(u.ProjectRole),
		IsActive:     u.IsActive,
		IsLocked:     u.IsLocked,
	}
}

func (r *Repo) GetUserByID(ctx context.Context, id int32) (*auth.User, error) {
	u, err := r.q.GetUserByID(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	return mapUser(u), nil
}

func (r *Repo) GetUserByUsername(ctx context.Context, username string) (*auth.User, error) {
	u, err := r.q.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, mapErr(err)
	}
	return mapUser(u), nil
}

func (r *Repo) GetUserByEmail(ctx context.Context, email string) (*auth.User, error) {
	u, err := r.q.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, mapErr(err)
	}
	return mapUser(u), nil
}

func (r *Repo) UsernameExists(ctx context.Context, username string) (bool, error) {
	return r.q.UsernameExists(ctx, username)
}

func (r *Repo) EmailExists(ctx context.Context, email string) (bool, error) {
	return r.q.EmailExists(ctx, email)
}

// ─────────────────────────── refresh tokens ───────────────────────────

func (r *Repo) InsertRefreshToken(ctx context.Context, userID int32, tokenHash string, expiresAt time.Time) error {
	_, err := r.q.InsertRefreshToken(ctx, sqlc.InsertRefreshTokenParams{
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: toTs(expiresAt),
	})
	return err
}

func (r *Repo) GetRefreshTokenForUser(ctx context.Context, tokenHash string, userID int32) (*auth.RefreshToken, error) {
	t, err := r.q.GetRefreshTokenForUser(ctx, sqlc.GetRefreshTokenForUserParams{TokenHash: tokenHash, UserID: userID})
	if err != nil {
		return nil, mapErr(err)
	}
	return &auth.RefreshToken{ID: t.ID, UserID: t.UserID, ExpiresAt: tsVal(t.ExpiresAt), RevokedAt: tsPtr(t.RevokedAt)}, nil
}

func (r *Repo) RevokeAllUserRefreshTokens(ctx context.Context, userID int32) error {
	return r.q.RevokeAllUserRefreshTokens(ctx, userID)
}

func (r *Repo) RotateRefreshToken(ctx context.Context, oldHash string, userID int32, newHash string, newExpiresAt time.Time) error {
	return r.tx(ctx, func(q *sqlc.Queries) error {
		if err := q.RevokeRefreshToken(ctx, oldHash); err != nil {
			return err
		}
		_, err := q.InsertRefreshToken(ctx, sqlc.InsertRefreshTokenParams{
			UserID:    userID,
			TokenHash: newHash,
			ExpiresAt: toTs(newExpiresAt),
		})
		return err
	})
}

// ─────────────────────────── invitations ───────────────────────────

func (r *Repo) GetInvitationByTokenHash(ctx context.Context, tokenHash string) (*auth.Invitation, error) {
	inv, err := r.q.GetInvitationByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, mapErr(err)
	}
	return &auth.Invitation{
		ID:          inv.ID,
		Email:       inv.Email,
		FullName:    textVal(inv.FullName),
		Role:        string(inv.Role),
		ProjectRole: string(inv.ProjectRole),
		Status:      inv.Status,
		ExpiresAt:   tsVal(inv.ExpiresAt),
	}, nil
}

func (r *Repo) AcceptInvitation(ctx context.Context, invitationID int32, nu auth.NewUser) (*auth.User, error) {
	var user *auth.User
	err := r.tx(ctx, func(q *sqlc.Queries) error {
		created, err := q.CreateUser(ctx, sqlc.CreateUserParams{
			Username:     nu.Username,
			Email:        nu.Email,
			FullName:     toText(nu.FullName),
			PasswordHash: nu.PasswordHash,
			Role:         sqlc.UserRole(nu.Role),
			ProjectRole:  sqlc.ProjectRole(nu.ProjectRole),
			IsActive:     nu.IsActive,
		})
		if err != nil {
			return err
		}
		user = mapUser(created)
		return q.MarkInvitationAccepted(ctx, sqlc.MarkInvitationAcceptedParams{
			ID:             invitationID,
			AcceptedUserID: toInt4(&created.ID),
		})
	})
	if err != nil {
		return nil, err
	}
	return user, nil
}

// ─────────────────────────── password reset ───────────────────────────

func (r *Repo) GetPasswordResetByHash(ctx context.Context, tokenHash string) (*auth.OneTimeToken, error) {
	t, err := r.q.GetPasswordResetByHash(ctx, tokenHash)
	if err != nil {
		return nil, mapErr(err)
	}
	return &auth.OneTimeToken{ID: t.ID, UserID: t.UserID, ExpiresAt: tsVal(t.ExpiresAt), UsedAt: tsPtr(t.UsedAt)}, nil
}

func (r *Repo) ExpireUserUnusedPasswordResetTokens(ctx context.Context, userID int32) error {
	return r.q.ExpireUserUnusedPasswordResetTokens(ctx, userID)
}

func (r *Repo) CreatePasswordResetToken(ctx context.Context, userID int32, tokenHash string, expiresAt time.Time) error {
	_, err := r.q.CreatePasswordResetToken(ctx, sqlc.CreatePasswordResetTokenParams{
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: toTs(expiresAt),
	})
	return err
}

func (r *Repo) ConfirmPasswordReset(ctx context.Context, tokenID, userID int32, newPasswordHash string) error {
	return r.tx(ctx, func(q *sqlc.Queries) error {
		if err := q.UpdateUserPassword(ctx, sqlc.UpdateUserPasswordParams{ID: userID, PasswordHash: newPasswordHash}); err != nil {
			return err
		}
		if err := q.MarkPasswordResetUsed(ctx, tokenID); err != nil {
			return err
		}
		return q.RevokeAllUserRefreshTokens(ctx, userID)
	})
}

// ─────────────────────────── reactivation ───────────────────────────

func (r *Repo) GetReactivationByHash(ctx context.Context, tokenHash string) (*auth.OneTimeToken, error) {
	t, err := r.q.GetReactivationByHash(ctx, tokenHash)
	if err != nil {
		return nil, mapErr(err)
	}
	return &auth.OneTimeToken{ID: t.ID, UserID: t.UserID, ExpiresAt: tsVal(t.ExpiresAt), UsedAt: tsPtr(t.UsedAt)}, nil
}

func (r *Repo) CompleteReactivation(ctx context.Context, tokenID, userID int32) error {
	return r.tx(ctx, func(q *sqlc.Queries) error {
		if err := q.SetUserLocked(ctx, sqlc.SetUserLockedParams{ID: userID, IsLocked: false}); err != nil {
			return err
		}
		return q.MarkReactivationUsed(ctx, tokenID)
	})
}

// ─────────────────────────── mail + audit ───────────────────────────

func (r *Repo) InsertMailJob(ctx context.Context, job auth.NewMailJob) (int32, error) {
	created, err := r.q.InsertMailJob(ctx, sqlc.InsertMailJobParams{
		UserID:         toInt4(job.UserID),
		CreatedBy:      toInt4(job.CreatedBy),
		RecipientEmail: job.RecipientEmail,
		Subject:        job.Subject,
		Template:       job.Template,
		Payload:        job.Payload,
	})
	if err != nil {
		return 0, err
	}
	return created.ID, nil
}

func (r *Repo) InsertAuditLog(ctx context.Context, e auth.AuditEntry) error {
	return r.q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		UserID:     toInt4(e.UserID),
		Action:     e.Action,
		EntityType: toText(e.EntityType),
		EntityID:   toInt4(e.EntityID),
		Details:    e.Details,
		IpAddress:  toText(e.IPAddress),
	})
}

// ─────────────────────────── pgtype helpers ───────────────────────────

func textVal(t pgtype.Text) string {
	if t.Valid {
		return t.String
	}
	return ""
}

func toText(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: s != ""}
}

func tsVal(t pgtype.Timestamptz) time.Time {
	if t.Valid {
		return t.Time
	}
	return time.Time{}
}

func tsPtr(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	tt := t.Time
	return &tt
}

func toTs(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func toInt4(p *int32) pgtype.Int4 {
	if p == nil {
		return pgtype.Int4{}
	}
	return pgtype.Int4{Int32: *p, Valid: true}
}
