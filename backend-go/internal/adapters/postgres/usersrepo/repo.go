// Package usersrepo — реализация порта users.Store поверх sqlc + pgxpool.
// Компаунд-операции (смена/сброс пароля + отзыв токенов, блокировка + отзыв,
// сброс 2FA + отзыв) выполняются атомарно в транзакции.
package usersrepo

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nkolomiika/frost/internal/adapters/postgres/pgconv"
	"github.com/nkolomiika/frost/internal/adapters/postgres/sqlc"
	"github.com/nkolomiika/frost/internal/app/users"
)

// Repo реализует users.Store.
type Repo struct {
	pool *pgxpool.Pool
	q    *sqlc.Queries
}

// New создаёт репозиторий поверх пула соединений.
func New(pool *pgxpool.Pool) *Repo {
	return &Repo{pool: pool, q: sqlc.New(pool)}
}

var _ users.Store = (*Repo)(nil)

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

// mapErr переводит pgx.ErrNoRows в доменную users.ErrNoRows.
func mapErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return users.ErrNoRows
	}
	return err
}

// ─────────────────────────── users ───────────────────────────

func mapUser(u sqlc.User) *users.User {
	return &users.User{
		ID:                u.ID,
		Username:          u.Username,
		Email:             u.Email,
		FullName:          pgconv.TextVal(u.FullName),
		AvatarBucket:      pgconv.TextVal(u.AvatarMinioBucket),
		AvatarKey:         pgconv.TextVal(u.AvatarMinioKey),
		AvatarContentType: pgconv.TextVal(u.AvatarContentType),
		AvatarUploadedAt:  pgconv.TsValPtr(u.AvatarUploadedAt),
		PasswordHash:      u.PasswordHash,
		PasswordChangedAt: pgconv.TsValPtr(u.PasswordChangedAt),
		TotpSecret:        pgconv.TextVal(u.TotpSecret),
		TotpEnabled:       u.TotpEnabled,
		Role:              string(u.Role),
		ProjectRole:       string(u.ProjectRole),
		IsActive:          u.IsActive,
		IsLocked:          u.IsLocked,
		CreatedAt:         pgconv.TsVal(u.CreatedAt),
	}
}

func (r *Repo) GetUserByID(ctx context.Context, id int32) (*users.User, error) {
	u, err := r.q.GetUserByID(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	return mapUser(u), nil
}

func (r *Repo) GetUserByUsername(ctx context.Context, username string) (*users.User, error) {
	u, err := r.q.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, mapErr(err)
	}
	return mapUser(u), nil
}

func (r *Repo) GetUserByEmail(ctx context.Context, email string) (*users.User, error) {
	u, err := r.q.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, mapErr(err)
	}
	return mapUser(u), nil
}

func (r *Repo) ListUsers(ctx context.Context, offset, limit int32) ([]users.User, error) {
	rows, err := r.q.ListUsers(ctx, sqlc.ListUsersParams{Offset: offset, Limit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]users.User, 0, len(rows))
	for _, u := range rows {
		out = append(out, *mapUser(u))
	}
	return out, nil
}

func (r *Repo) CountUsers(ctx context.Context) (int64, error) {
	return r.q.CountUsers(ctx)
}

func (r *Repo) UpdateUserProfile(ctx context.Context, id int32, username, email, fullName string) error {
	return r.q.UpdateUserProfile(ctx, sqlc.UpdateUserProfileParams{
		ID:       id,
		Username: username,
		Email:    email,
		FullName: pgconv.Text(fullName),
	})
}

func (r *Repo) UpdateUserAdmin(ctx context.Context, id int32, fullName, role, projectRole string, isActive bool) error {
	return r.q.UpdateUserAdmin(ctx, sqlc.UpdateUserAdminParams{
		ID:          id,
		FullName:    pgconv.Text(fullName),
		Role:        sqlc.UserRole(role),
		ProjectRole: sqlc.ProjectRole(projectRole),
		IsActive:    isActive,
	})
}

func (r *Repo) SetUserAvatar(ctx context.Context, id int32, bucket, key, contentType string) error {
	return r.q.SetUserAvatar(ctx, sqlc.SetUserAvatarParams{
		ID:                id,
		AvatarMinioBucket: pgconv.Text(bucket),
		AvatarMinioKey:    pgconv.Text(key),
		AvatarContentType: pgconv.Text(contentType),
	})
}

// ─────────────────────────── пароль (+отзыв токенов) ───────────────────────────

func (r *Repo) ChangeOwnPassword(ctx context.Context, id int32, passwordHash string) error {
	return r.tx(ctx, func(q *sqlc.Queries) error {
		if err := q.UpdateUserPassword(ctx, sqlc.UpdateUserPasswordParams{ID: id, PasswordHash: passwordHash}); err != nil {
			return err
		}
		return q.RevokeAllUserRefreshTokens(ctx, id)
	})
}

func (r *Repo) ResetPasswordTemp(ctx context.Context, id int32, passwordHash string) error {
	return r.tx(ctx, func(q *sqlc.Queries) error {
		if err := q.ResetUserPasswordTemp(ctx, sqlc.ResetUserPasswordTempParams{ID: id, PasswordHash: passwordHash}); err != nil {
			return err
		}
		return q.RevokeAllUserRefreshTokens(ctx, id)
	})
}

// ─────────────────────────── 2FA ───────────────────────────

func (r *Repo) SetTotpSecretForSetup(ctx context.Context, id int32, encryptedSecret string) error {
	return r.q.SetUserTotpSecretForSetup(ctx, sqlc.SetUserTotpSecretForSetupParams{
		ID:         id,
		TotpSecret: pgconv.Text(encryptedSecret),
	})
}

func (r *Repo) EnableTotp(ctx context.Context, id int32) error {
	return r.q.EnableUserTotp(ctx, id)
}

func (r *Repo) DisableTotp(ctx context.Context, id int32) error {
	return r.q.DisableUserTotp(ctx, id)
}

func (r *Repo) AdminResetTotp(ctx context.Context, id int32) error {
	return r.tx(ctx, func(q *sqlc.Queries) error {
		if err := q.DisableUserTotp(ctx, id); err != nil {
			return err
		}
		return q.RevokeAllUserRefreshTokens(ctx, id)
	})
}

// ─────────────────────────── блокировка ───────────────────────────

func (r *Repo) LockUser(ctx context.Context, id int32) error {
	return r.tx(ctx, func(q *sqlc.Queries) error {
		if err := q.SetUserLocked(ctx, sqlc.SetUserLockedParams{ID: id, IsLocked: true}); err != nil {
			return err
		}
		return q.RevokeAllUserRefreshTokens(ctx, id)
	})
}

// ─────────────────────────── приглашения ───────────────────────────

func mapInvitation(i sqlc.Invitation) *users.Invitation {
	return &users.Invitation{
		ID:          i.ID,
		Email:       i.Email,
		FullName:    pgconv.TextVal(i.FullName),
		Role:        string(i.Role),
		ProjectRole: string(i.ProjectRole),
		Status:      i.Status,
		ExpiresAt:   pgconv.TsVal(i.ExpiresAt),
		InvitedBy:   pgconv.Int4Val(i.InvitedBy),
		CreatedAt:   pgconv.TsVal(i.CreatedAt),
	}
}

func (r *Repo) GetInvitationByID(ctx context.Context, id int32) (*users.Invitation, error) {
	inv, err := r.q.GetInvitationByID(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	return mapInvitation(inv), nil
}

func (r *Repo) GetActivePendingInvitationByEmail(ctx context.Context, email string) (*users.Invitation, error) {
	inv, err := r.q.GetActivePendingInvitationByEmail(ctx, email)
	if err != nil {
		return nil, mapErr(err)
	}
	return mapInvitation(inv), nil
}

func (r *Repo) ListPendingInvitations(ctx context.Context) ([]users.Invitation, error) {
	rows, err := r.q.ListPendingInvitations(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]users.Invitation, 0, len(rows))
	for _, i := range rows {
		out = append(out, *mapInvitation(i))
	}
	return out, nil
}

func (r *Repo) CreateInvitation(ctx context.Context, ni users.NewInvitation) (*users.Invitation, error) {
	inv, err := r.q.CreateInvitation(ctx, sqlc.CreateInvitationParams{
		Email:       ni.Email,
		FullName:    pgconv.Text(ni.FullName),
		Role:        sqlc.UserRole(ni.Role),
		ProjectRole: sqlc.ProjectRole(ni.ProjectRole),
		TokenHash:   ni.TokenHash,
		ExpiresAt:   pgconv.Ts(ni.ExpiresAt),
		InvitedBy:   pgconv.Int4(ni.InvitedBy),
	})
	if err != nil {
		return nil, err
	}
	return mapInvitation(inv), nil
}

func (r *Repo) UpdateInvitationForResend(ctx context.Context, id int32, tokenHash string, expiresAt time.Time) error {
	return r.q.UpdateInvitationForResend(ctx, sqlc.UpdateInvitationForResendParams{
		ID:        id,
		TokenHash: tokenHash,
		ExpiresAt: pgconv.Ts(expiresAt),
	})
}

func (r *Repo) RevokeInvitation(ctx context.Context, id int32) error {
	return r.q.RevokeInvitation(ctx, id)
}

// ─────────────────────────── реактивация ───────────────────────────

func (r *Repo) ExpireUnusedReactivationTokens(ctx context.Context, userID int32) error {
	return r.q.ExpireUserUnusedReactivationTokens(ctx, userID)
}

func (r *Repo) CreateReactivationToken(ctx context.Context, userID int32, tokenHash string, expiresAt time.Time) error {
	_, err := r.q.CreateReactivationToken(ctx, sqlc.CreateReactivationTokenParams{
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: pgconv.Ts(expiresAt),
	})
	return err
}

// ─────────────────────────── mail + audit ───────────────────────────

func (r *Repo) InsertMailJob(ctx context.Context, job users.NewMailJob) (int32, error) {
	created, err := r.q.InsertMailJob(ctx, sqlc.InsertMailJobParams{
		UserID:         pgconv.Int4(job.UserID),
		CreatedBy:      pgconv.Int4(job.CreatedBy),
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

func (r *Repo) InsertAuditLog(ctx context.Context, e users.AuditEntry) error {
	return r.q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		UserID:     pgconv.Int4(e.UserID),
		Action:     e.Action,
		EntityType: pgconv.Text(e.EntityType),
		EntityID:   pgconv.Int4(e.EntityID),
		Details:    e.Details,
		IpAddress:  pgconv.Text(e.IPAddress),
	})
}
