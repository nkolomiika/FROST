// Package auth — use-cases аутентификации (порт app/services.py: AuthService и
// auth-часть UserService) плюс порты к БД/токенам/шифру. Слой не зависит от
// конкретных адаптеров (pgx/http) — только от интерфейсов ниже.
package auth

import "time"

// User — пользователь в терминах домена auth (без pgtype/БД-специфики).
// Role/ProjectRole хранят значение как в БД (имена членов enum: "ADMIN"/"PENTESTER").
type User struct {
	ID           int32
	Username     string
	Email        string
	FullName     string // "" если не задано
	PasswordHash string
	TotpSecret   string // шифртекст (Fernet); расшифровывается в use-case через Cipher
	TotpEnabled  bool
	Role         string
	ProjectRole  string
	IsActive     bool
	IsLocked     bool
}

// RefreshToken — строка refresh_tokens (нужны срок и факт отзыва).
type RefreshToken struct {
	ID        int32
	UserID    int32
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// Invitation — приглашение (для активации).
type Invitation struct {
	ID          int32
	Email       string
	FullName    string
	Role        string
	ProjectRole string
	Status      string // pending | accepted | revoked
	ExpiresAt   time.Time
}

// IsExpired — приглашение ещё pending, но срок ссылки истёк.
func (i Invitation) IsExpired(now time.Time) bool {
	return i.Status == "pending" && !i.ExpiresAt.IsZero() && !i.ExpiresAt.After(now)
}

// OneTimeToken — общая форма одноразового токена (сброс пароля / реактивация).
type OneTimeToken struct {
	ID        int32
	UserID    int32
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// IsUsable — токен ещё не использован и не истёк.
func (t OneTimeToken) IsUsable(now time.Time) bool {
	return t.UsedAt == nil && t.ExpiresAt.After(now)
}

// NewUser — данные для создания пользователя (при активации приглашения).
type NewUser struct {
	Username     string
	Email        string
	FullName     string
	PasswordHash string
	Role         string
	ProjectRole  string
	IsActive     bool
}

// NewMailJob — задание в mail-outbox (отправка — Phase 2 mail-worker).
type NewMailJob struct {
	UserID         *int32
	CreatedBy      *int32
	RecipientEmail string
	Subject        string
	Template       string
	Payload        []byte // JSON
}

// AuditEntry — запись журнала действий.
type AuditEntry struct {
	UserID     *int32
	Action     string
	EntityType string // "" → NULL
	EntityID   *int32
	Details    []byte // JSON, nil → NULL
	IPAddress  string // "" → NULL
}

// LoginOutcome — результат первого шага логина.
type LoginOutcome struct {
	User         *User
	Requires2FA  bool
	PendingToken string // при Requires2FA
	AccessToken  string
	RefreshToken string
}

// TokenPair — выданная пара сессионных токенов.
type TokenPair struct {
	Access  string
	Refresh string
}

// InvitationInfo — публичные данные ссылки-приглашения.
type InvitationInfo struct {
	Valid    bool
	Reason   string // not_found | used | expired (при Valid=false)
	Email    string
	FullName string
}

// TokenInfo — публичная проверка ссылки сброса/реактивации.
type TokenInfo struct {
	Valid    bool
	Reason   string
	Username string
}
