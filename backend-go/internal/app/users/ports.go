package users

import (
	"context"
	"errors"
	"time"
)

// ErrNoRows — репозиторий не нашёл строку (аналог auth.ErrNoRows). Use-case решает,
// считать ли это доменной ошибкой (404) или нет.
var ErrNoRows = errors.New("no rows")

// Store — порт к хранилищу (реализуется adapters/postgres/usersrepo поверх sqlc).
// Компаундные операции (смена пароля + отзыв токенов, блокировка + отзыв, сброс 2FA
// + отзыв) выполняются атомарно внутри адаптера (транзакция).
type Store interface {
	// users
	GetUserByID(ctx context.Context, id int32) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	ListUsers(ctx context.Context, offset, limit int32) ([]User, error)
	CountUsers(ctx context.Context) (int64, error)

	UpdateUserProfile(ctx context.Context, id int32, username, email, fullName string) error
	UpdateUserAdmin(ctx context.Context, id int32, fullName, role, projectRole string, isActive bool) error
	SetUserAvatar(ctx context.Context, id int32, bucket, key, contentType string) error

	// пароль (+ отзыв всех refresh-токенов) — атомарно
	ChangeOwnPassword(ctx context.Context, id int32, passwordHash string) error // password_changed_at = now()
	ResetPasswordTemp(ctx context.Context, id int32, passwordHash string) error // password_changed_at = NULL

	// 2FA
	SetTotpSecretForSetup(ctx context.Context, id int32, encryptedSecret string) error
	EnableTotp(ctx context.Context, id int32) error
	DisableTotp(ctx context.Context, id int32) error
	AdminResetTotp(ctx context.Context, id int32) error // disable totp + отзыв refresh — атомарно

	// блокировка (soft-delete) + отзыв refresh — атомарно
	LockUser(ctx context.Context, id int32) error

	// приглашения
	GetInvitationByID(ctx context.Context, id int32) (*Invitation, error)
	GetActivePendingInvitationByEmail(ctx context.Context, email string) (*Invitation, error)
	ListPendingInvitations(ctx context.Context) ([]Invitation, error)
	CreateInvitation(ctx context.Context, ni NewInvitation) (*Invitation, error)
	UpdateInvitationForResend(ctx context.Context, id int32, tokenHash string, expiresAt time.Time) error
	RevokeInvitation(ctx context.Context, id int32) error

	// реактивация
	ExpireUnusedReactivationTokens(ctx context.Context, userID int32) error
	CreateReactivationToken(ctx context.Context, userID int32, tokenHash string, expiresAt time.Time) error

	// mail + audit
	InsertMailJob(ctx context.Context, job NewMailJob) (int32, error)
	InsertAuditLog(ctx context.Context, entry AuditEntry) error
}

// Cipher — шифрование TOTP-секрета at-rest (adapters/security.SecretCipher).
type Cipher interface {
	Encrypt(value string) (string, error)
	Decrypt(token string) (string, error)
}

// Storage — порт объектного хранилища аватаров (реализуется adapters/storage.Minio).
type Storage interface {
	Put(ctx context.Context, key string, data []byte, contentType string) error
	Get(ctx context.Context, key string) (data []byte, contentType string, err error)
	Delete(ctx context.Context, key string) error
}
