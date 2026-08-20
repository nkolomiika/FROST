// Package users — use-cases управления пользователями (порт роутера users.py и
// не-auth части UserService из app/services.py): профиль, список, приглашения,
// смена пароля/2FA, аватары, реактивация. Слой зависит только от портов ниже
// (Store/Cipher/Storage) — без деталей БД/http.
package users

import "time"

// User — пользователь в терминах домена users (полный набор полей для UserOut,
// в отличие от урезанного auth.User). Role/ProjectRole хранят значение как в БД
// (верхний регистр: "ADMIN"/"PENTESTER", "LEAD"/"PENTESTER").
type User struct {
	ID                int32
	Username          string
	Email             string
	FullName          string // "" если не задано
	AvatarBucket      string
	AvatarKey         string
	AvatarContentType string
	AvatarUploadedAt  *time.Time
	PasswordHash      string
	PasswordChangedAt *time.Time
	TotpSecret        string // шифртекст (Fernet)
	TotpEnabled       bool
	Role              string
	ProjectRole       string
	IsActive          bool
	IsLocked          bool
	CreatedAt         time.Time
}

// Invitation — приглашение (для админ-панели и invite-flow).
type Invitation struct {
	ID          int32
	Email       string
	FullName    string
	Role        string
	ProjectRole string
	Status      string // pending | accepted | revoked
	ExpiresAt   time.Time
	InvitedBy   *int32
	CreatedAt   time.Time
}

// IsExpired — приглашение ещё pending, но срок ссылки истёк.
func (i Invitation) IsExpired(now time.Time) bool {
	return i.Status == "pending" && !i.ExpiresAt.IsZero() && !i.ExpiresAt.After(now)
}

// NewInvitation — данные для создания записи приглашения.
type NewInvitation struct {
	Email       string
	FullName    string
	Role        string
	ProjectRole string
	TokenHash   string
	ExpiresAt   time.Time
	InvitedBy   *int32
}

// InvitationInput — входные данные создания приглашения (из InvitationCreate).
type InvitationInput struct {
	Email       string
	FullName    string
	Role        string // "" → PENTESTER
	ProjectRole string // "" → PENTESTER
}

// ProfileUpdate — частичное обновление собственного профиля (PATCH /users/me).
// nil-поле = не менять; переданное значение (в т.ч. пустая строка) — применить.
type ProfileUpdate struct {
	Username *string
	Email    *string
	FullName *string
}

// AdminUpdate — админское обновление пользователя (PUT /users/{id}).
type AdminUpdate struct {
	Username    *string // приниматься не должно (immutable) — только для проверки на неизменность
	Email       *string // приниматься не должно (immutable)
	FullName    *string
	Role        *string // DB-регистр (UPPERCASE)
	ProjectRole *string // DB-регистр (UPPERCASE)
	IsActive    *bool
}

// TwoFASetup — результат подготовки привязки 2FA.
type TwoFASetup struct {
	Secret     string
	OtpauthURI string
	QR         string
}

// AvatarUpload — загружаемый аватар (сырые байты + оригинальное имя файла).
type AvatarUpload struct {
	Filename string
	Data     []byte
}

// NewMailJob — задание в mail-outbox (рендер/отправка — Phase 2 mail-worker).
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
