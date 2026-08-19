package auth

import (
	"context"
	"errors"
	"time"
)

// ErrNoRows — репозиторий не нашёл строку. Use-case решает, ошибка это или нет
// (например, request_password_reset для несуществующего email — не ошибка).
var ErrNoRows = errors.New("no rows")

// Store — порт к хранилищу (реализуется adapters/postgres/authrepo поверх sqlc).
// Компаундные операции (accept-invitation, rotate-refresh, confirm-reset,
// complete-reactivation) атомарны внутри адаптера (транзакция) — так бизнес-логика
// в use-case остаётся без деталей БД.
type Store interface {
	GetUserByID(ctx context.Context, id int32) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UsernameExists(ctx context.Context, username string) (bool, error)
	EmailExists(ctx context.Context, email string) (bool, error)

	InsertRefreshToken(ctx context.Context, userID int32, tokenHash string, expiresAt time.Time) error
	GetRefreshTokenForUser(ctx context.Context, tokenHash string, userID int32) (*RefreshToken, error)
	RevokeAllUserRefreshTokens(ctx context.Context, userID int32) error

	GetInvitationByTokenHash(ctx context.Context, tokenHash string) (*Invitation, error)

	GetPasswordResetByHash(ctx context.Context, tokenHash string) (*OneTimeToken, error)
	ExpireUserUnusedPasswordResetTokens(ctx context.Context, userID int32) error
	CreatePasswordResetToken(ctx context.Context, userID int32, tokenHash string, expiresAt time.Time) error

	GetReactivationByHash(ctx context.Context, tokenHash string) (*OneTimeToken, error)

	InsertMailJob(ctx context.Context, job NewMailJob) (int32, error)
	InsertAuditLog(ctx context.Context, entry AuditEntry) error

	// Атомарные компаунд-операции.
	AcceptInvitation(ctx context.Context, invitationID int32, nu NewUser) (*User, error)
	RotateRefreshToken(ctx context.Context, oldHash string, userID int32, newHash string, newExpiresAt time.Time) error
	ConfirmPasswordReset(ctx context.Context, tokenID, userID int32, newPasswordHash string) error
	CompleteReactivation(ctx context.Context, tokenID, userID int32) error
}

// Tokens — порт выпуска/проверки JWT (реализуется adapters/security.JWTManager).
type Tokens interface {
	CreateAccessToken(userID int64) (string, error)
	CreateRefreshToken(userID int64) (string, error)
	Create2FAPendingToken(userID int64) (string, error)
	Decode(token, expectedType string) (int64, error)
}

// Cipher — расшифровка TOTP-секрета at-rest (adapters/security.SecretCipher).
type Cipher interface {
	Decrypt(token string) (string, error)
}

// TokenConst — типы JWT (совпадают со строками security-адаптера/Python).
const (
	TokenTypeAccess     = "access"
	TokenTypeRefresh    = "refresh"
	TokenType2FAPending = "2fa_pending"
)
