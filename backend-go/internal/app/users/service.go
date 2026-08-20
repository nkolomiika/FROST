package users

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/nkolomiika/frost/internal/adapters/security"
	"github.com/nkolomiika/frost/internal/apperr"
)

// Config — параметры use-cases (зеркало нужных полей app/config.py).
type Config struct {
	AppBaseURL              string
	MailPreviewURL          string
	SMTPHost                string
	MailEnabled             bool
	Brand                   string // эмитент в письмах ("FROST")
	MinioBucketName         string // бакет для avatar_minio_bucket
	InviteTokenExpireHours  int    // срок ссылки приглашения (default 168)
	ReactivationExpireHours int    // срок ссылки реактивации (default 24)
}

// Service — use-cases управления пользователями. Зависит только от портов.
type Service struct {
	store   Store
	cipher  Cipher
	storage Storage
	cfg     Config
	now     func() time.Time
}

// NewService собирает use-case-слой. now можно подменить в тестах.
func NewService(store Store, cipher Cipher, storage Storage, cfg Config, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	if cfg.Brand == "" {
		cfg.Brand = "FROST"
	}
	if cfg.InviteTokenExpireHours <= 0 {
		cfg.InviteTokenExpireHours = 168
	}
	if cfg.ReactivationExpireHours <= 0 {
		cfg.ReactivationExpireHours = 24
	}
	return &Service{store: store, cipher: cipher, storage: storage, cfg: cfg, now: now}
}

// MailPreviewURL — превью почты (mailpit) для ответов о постановке письма.
func (s *Service) MailPreviewURL() string {
	if s.cfg.SMTPHost == "mailpit" {
		return s.cfg.MailPreviewURL
	}
	return ""
}

// ─────────────────────────── чтение ───────────────────────────

// GetUser возвращает пользователя по идентификатору (404 если нет).
func (s *Service) GetUser(ctx context.Context, id int32) (*User, error) {
	user, err := s.store.GetUserByID(ctx, id)
	if errors.Is(err, ErrNoRows) {
		return nil, apperr.NotFound("User not found")
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

// ListUsers — постраничный список пользователей (ORDER BY created_at DESC).
func (s *Service) ListUsers(ctx context.Context, page, size int) ([]User, int64, error) {
	total, err := s.store.CountUsers(ctx)
	if err != nil {
		return nil, 0, err
	}
	items, err := s.store.ListUsers(ctx, int32((page-1)*size), int32(size))
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// ─────────────────────────── профиль ───────────────────────────

// UpdateOwnProfile — пользователь меняет свои username/email/full_name.
func (s *Service) UpdateOwnProfile(ctx context.Context, userID int32, in ProfileUpdate, ip string) (*User, error) {
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	username := valueOr(in.Username, user.Username)
	email := valueOr(in.Email, user.Email)
	if err := s.ensureUniqueIdentity(ctx, username, email, user.ID); err != nil {
		return nil, err
	}
	fullName := valueOr(in.FullName, user.FullName)
	if err := s.store.UpdateUserProfile(ctx, user.ID, username, email, fullName); err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &user.ID, Action: "UPDATE", EntityType: "user_profile", EntityID: &user.ID, IPAddress: ip})
	return s.GetUser(ctx, user.ID)
}

// UpdateUser — админское обновление. Email/username неизменяемы (даже админом).
func (s *Service) UpdateUser(ctx context.Context, userID int32, in AdminUpdate, actorID int32, ip string) (*User, error) {
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if in.Email != nil && *in.Email != user.Email {
		return nil, apperr.Validation("An admin can't change a user's email — the user must change it themselves")
	}
	if in.Username != nil && *in.Username != user.Username {
		return nil, apperr.Validation("The username can't be changed — it's tied to the user")
	}
	if err := s.ensureUniqueIdentity(ctx, user.Username, user.Email, user.ID); err != nil {
		return nil, err
	}
	fullName := valueOr(in.FullName, user.FullName)
	role := valueOr(in.Role, user.Role)
	projectRole := valueOr(in.ProjectRole, user.ProjectRole)
	isActive := user.IsActive
	if in.IsActive != nil {
		isActive = *in.IsActive
	}
	if err := s.store.UpdateUserAdmin(ctx, user.ID, fullName, role, projectRole, isActive); err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "UPDATE", EntityType: "user", EntityID: &user.ID, IPAddress: ip})
	return s.GetUser(ctx, user.ID)
}

// ensureUniqueIdentity — конфликт, если username/email уже занят ДРУГИМ пользователем.
func (s *Service) ensureUniqueIdentity(ctx context.Context, username, email string, excludeID int32) error {
	if username != "" {
		other, err := s.store.GetUserByUsername(ctx, username)
		if err != nil && !errors.Is(err, ErrNoRows) {
			return err
		}
		if err == nil && other.ID != excludeID {
			return apperr.Conflict("Username or email is already taken")
		}
	}
	if email != "" {
		other, err := s.store.GetUserByEmail(ctx, email)
		if err != nil && !errors.Is(err, ErrNoRows) {
			return err
		}
		if err == nil && other.ID != excludeID {
			return apperr.Conflict("Username or email is already taken")
		}
	}
	return nil
}

// ─────────────────────────── пароль ───────────────────────────

// ChangeOwnPassword — смена собственного пароля (сверяет текущий, гасит сессии).
func (s *Service) ChangeOwnPassword(ctx context.Context, userID int32, currentPassword, newPassword, ip string) (*User, error) {
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !security.VerifyPassword(currentPassword, user.PasswordHash) {
		return nil, apperr.Unauthorized("Текущий пароль указан неверно")
	}
	hash, err := security.HashPassword(newPassword)
	if err != nil {
		return nil, err
	}
	if err := s.store.ChangeOwnPassword(ctx, user.ID, hash); err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &user.ID, Action: "UPDATE", EntityType: "user_password", EntityID: &user.ID, IPAddress: ip})
	return s.GetUser(ctx, user.ID)
}

// ResetPassword — админский сброс: временный пароль по почте, гасит сессии.
func (s *Service) ResetPassword(ctx context.Context, userID, actorID int32, ip string) (*User, error) {
	if err := s.ensureMailEnabled(); err != nil {
		return nil, err
	}
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	tempPassword := security.GenerateURLSafeToken(12)
	hash, err := security.HashPassword(tempPassword)
	if err != nil {
		return nil, err
	}
	if err := s.store.ResetPasswordTemp(ctx, user.ID, hash); err != nil {
		return nil, err
	}
	payload := mustJSON(map[string]any{
		"username":           firstNonEmpty(user.FullName, user.Username),
		"temporary_password": tempPassword,
	})
	uid := user.ID
	if _, err := s.store.InsertMailJob(ctx, NewMailJob{
		UserID:         &uid,
		CreatedBy:      &actorID,
		RecipientEmail: user.Email,
		Subject:        s.cfg.Brand + ": временный пароль",
		Template:       "temporary_password",
		Payload:        payload,
	}); err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "UPDATE", EntityType: "user_password_reset", EntityID: &user.ID, Details: mustJSON(map[string]any{"email": user.Email}), IPAddress: ip})
	return user, nil
}

// ─────────────────────────── 2FA ───────────────────────────

// Setup2FA готовит привязку: секрет (шифруется at-rest, ещё не включён) + QR.
func (s *Service) Setup2FA(ctx context.Context, userID int32, ip string) (TwoFASetup, error) {
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return TwoFASetup{}, err
	}
	if user.TotpEnabled {
		return TwoFASetup{}, apperr.Validation("Двухфакторная аутентификация уже включена")
	}
	secret, err := security.GenerateTOTPSecret()
	if err != nil {
		return TwoFASetup{}, err
	}
	enc, err := s.cipher.Encrypt(secret)
	if err != nil {
		return TwoFASetup{}, err
	}
	if err := s.store.SetTotpSecretForSetup(ctx, user.ID, enc); err != nil {
		return TwoFASetup{}, err
	}
	otpauth := security.TOTPProvisioningURI(secret, user.Username)
	qr, err := security.TOTPQRPNGDataURL(otpauth)
	if err != nil {
		return TwoFASetup{}, err
	}
	return TwoFASetup{Secret: secret, OtpauthURI: otpauth, QR: qr}, nil
}

// Confirm2FA включает 2FA после первого кода из приложения-аутентификатора.
func (s *Service) Confirm2FA(ctx context.Context, userID int32, code, ip string) (*User, error) {
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user.TotpEnabled {
		return nil, apperr.Validation("Двухфакторная аутентификация уже включена")
	}
	if user.TotpSecret == "" {
		return nil, apperr.Validation("Сначала запросите настройку 2FA")
	}
	secret, err := s.cipher.Decrypt(user.TotpSecret)
	if err != nil || !security.VerifyTOTP(secret, code) {
		return nil, apperr.Validation("Неверный код из приложения-аутентификатора")
	}
	if err := s.store.EnableTotp(ctx, user.ID); err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &user.ID, Action: "UPDATE", EntityType: "user_2fa_enabled", EntityID: &user.ID, IPAddress: ip})
	return s.GetUser(ctx, user.ID)
}

// Disable2FA отключает 2FA (требует пароль; активные сессии НЕ сбрасываются).
func (s *Service) Disable2FA(ctx context.Context, userID int32, password, ip string) (*User, error) {
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !security.VerifyPassword(password, user.PasswordHash) {
		return nil, apperr.Unauthorized("Пароль указан неверно")
	}
	if err := s.store.DisableTotp(ctx, user.ID); err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &user.ID, Action: "UPDATE", EntityType: "user_2fa_disabled", EntityID: &user.ID, IPAddress: ip})
	return s.GetUser(ctx, user.ID)
}

// AdminReset2FA сбрасывает 2FA пользователю (потеря телефона) и гасит его сессии.
func (s *Service) AdminReset2FA(ctx context.Context, userID, actorID int32, ip string) (*User, error) {
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if err := s.store.AdminResetTotp(ctx, user.ID); err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "UPDATE", EntityType: "user_2fa_reset", EntityID: &user.ID, IPAddress: ip})
	return s.GetUser(ctx, user.ID)
}

// ─────────────────────────── блокировка ───────────────────────────

// DeleteUser — мягкое удаление: блокирует аккаунт и отзывает refresh-токены.
func (s *Service) DeleteUser(ctx context.Context, userID, actorID int32, ip string) error {
	if userID == actorID {
		return apperr.Validation("You can't block yourself")
	}
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.store.LockUser(ctx, user.ID); err != nil {
		return err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "DELETE", EntityType: "user", EntityID: &user.ID, IPAddress: ip})
	return nil
}

// RequestReactivation — админ шлёт деактивированному пользователю ссылку-возврат.
// Аккаунт остаётся заблокированным до перехода по ссылке. Возвращает email адресата.
func (s *Service) RequestReactivation(ctx context.Context, userID, actorID int32, ip string) (string, error) {
	if err := s.ensureMailEnabled(); err != nil {
		return "", err
	}
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return "", err
	}
	if !user.IsLocked {
		return "", apperr.Validation("The user is not deactivated")
	}
	if err := s.store.ExpireUnusedReactivationTokens(ctx, user.ID); err != nil {
		return "", err
	}
	rawToken := security.GenerateURLSafeToken(32)
	expiresAt := s.now().UTC().Add(time.Duration(s.cfg.ReactivationExpireHours) * time.Hour)
	if err := s.store.CreateReactivationToken(ctx, user.ID, security.HashTokenSHA256(rawToken), expiresAt); err != nil {
		return "", err
	}
	reactivateURL := strings.TrimRight(s.cfg.AppBaseURL, "/") + "/reactivate?token=" + rawToken
	payload := mustJSON(map[string]any{
		"reactivate_url": reactivateURL,
		"username":       firstNonEmpty(user.FullName, user.Username),
		"expire_hours":   s.cfg.ReactivationExpireHours,
	})
	uid := user.ID
	if _, err := s.store.InsertMailJob(ctx, NewMailJob{
		UserID:         &uid,
		RecipientEmail: user.Email,
		Subject:        s.cfg.Brand + ": возвращение доступа",
		Template:       "reactivation",
		Payload:        payload,
	}); err != nil {
		return "", err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "UPDATE", EntityType: "user_reactivation_requested", EntityID: &user.ID, Details: mustJSON(map[string]any{"email": user.Email}), IPAddress: ip})
	return user.Email, nil
}

// ─────────────────────────── приглашения ───────────────────────────

// CreateInvitation приглашает пользователя по email (User создаётся при активации).
func (s *Service) CreateInvitation(ctx context.Context, in InvitationInput, actorID int32, ip string) (*Invitation, error) {
	if err := s.ensureMailEnabled(); err != nil {
		return nil, err
	}
	if _, err := s.store.GetUserByEmail(ctx, in.Email); err == nil {
		return nil, apperr.Conflict("A user with this email already exists")
	} else if !errors.Is(err, ErrNoRows) {
		return nil, err
	}
	if _, err := s.store.GetActivePendingInvitationByEmail(ctx, in.Email); err == nil {
		return nil, apperr.Conflict("Приглашение для этого email уже отправлено — используйте повторную отправку")
	} else if !errors.Is(err, ErrNoRows) {
		return nil, err
	}
	rawToken := security.GenerateURLSafeToken(32)
	expiresAt := s.now().UTC().Add(time.Duration(s.cfg.InviteTokenExpireHours) * time.Hour)
	actor := actorID
	inv, err := s.store.CreateInvitation(ctx, NewInvitation{
		Email:       in.Email,
		FullName:    in.FullName,
		Role:        defaultRole(in.Role),
		ProjectRole: defaultProjectRole(in.ProjectRole),
		TokenHash:   security.HashTokenSHA256(rawToken),
		ExpiresAt:   expiresAt,
		InvitedBy:   &actor,
	})
	if err != nil {
		return nil, err
	}
	if err := s.enqueueInvitationMail(ctx, inv, rawToken, &actor); err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "CREATE", EntityType: "invitation", EntityID: &inv.ID, Details: mustJSON(map[string]any{"email": inv.Email}), IPAddress: ip})
	return inv, nil
}

// ListInvitations — незавершённые приглашения (pending, в т.ч. истёкшие).
func (s *Service) ListInvitations(ctx context.Context) ([]Invitation, error) {
	return s.store.ListPendingInvitations(ctx)
}

// ResendInvitation перевыпускает токен, продлевает срок и шлёт письмо заново.
func (s *Service) ResendInvitation(ctx context.Context, invitationID, actorID int32, ip string) (*Invitation, error) {
	if err := s.ensureMailEnabled(); err != nil {
		return nil, err
	}
	inv, err := s.getInvitation(ctx, invitationID)
	if err != nil {
		return nil, err
	}
	if inv.Status == "accepted" {
		return nil, apperr.Conflict("Приглашение уже принято")
	}
	rawToken := security.GenerateURLSafeToken(32)
	expiresAt := s.now().UTC().Add(time.Duration(s.cfg.InviteTokenExpireHours) * time.Hour)
	if err := s.store.UpdateInvitationForResend(ctx, inv.ID, security.HashTokenSHA256(rawToken), expiresAt); err != nil {
		return nil, err
	}
	inv, err = s.getInvitation(ctx, invitationID)
	if err != nil {
		return nil, err
	}
	actor := actorID
	if err := s.enqueueInvitationMail(ctx, inv, rawToken, &actor); err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "UPDATE", EntityType: "invitation_resend", EntityID: &inv.ID, Details: mustJSON(map[string]any{"email": inv.Email}), IPAddress: ip})
	return inv, nil
}

// RevokeInvitation отзывает приглашение — ссылка перестаёт работать.
func (s *Service) RevokeInvitation(ctx context.Context, invitationID, actorID int32, ip string) error {
	inv, err := s.getInvitation(ctx, invitationID)
	if err != nil {
		return err
	}
	if inv.Status == "accepted" {
		return apperr.Conflict("Приглашение уже принято — отозвать нельзя")
	}
	if err := s.store.RevokeInvitation(ctx, inv.ID); err != nil {
		return err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "DELETE", EntityType: "invitation", EntityID: &inv.ID, Details: mustJSON(map[string]any{"email": inv.Email}), IPAddress: ip})
	return nil
}

func (s *Service) getInvitation(ctx context.Context, id int32) (*Invitation, error) {
	inv, err := s.store.GetInvitationByID(ctx, id)
	if errors.Is(err, ErrNoRows) {
		return nil, apperr.NotFound("Приглашение не найдено")
	}
	if err != nil {
		return nil, err
	}
	return inv, nil
}

func (s *Service) enqueueInvitationMail(ctx context.Context, inv *Invitation, rawToken string, actorID *int32) error {
	activationURL := strings.TrimRight(s.cfg.AppBaseURL, "/") + "/activate?token=" + rawToken
	payload := mustJSON(map[string]any{
		"invitation_id":  inv.ID,
		"activation_url": activationURL,
		"username":       firstNonEmpty(inv.FullName, inv.Email),
		"expire_hours":   s.cfg.InviteTokenExpireHours,
	})
	_, err := s.store.InsertMailJob(ctx, NewMailJob{
		CreatedBy:      actorID,
		RecipientEmail: inv.Email,
		Subject:        "Приглашение в " + s.cfg.Brand,
		Template:       "invitation",
		Payload:        payload,
	})
	return err
}

// ─────────────────────────── аватары ───────────────────────────

// allowedAvatarMIME — допустимые типы аватара (порт allow-set upload_avatar).
var allowedAvatarMIME = map[string]bool{
	"image/png":  true,
	"image/jpeg": true,
	"image/webp": true,
	"image/gif":  true,
}

const maxAvatarSize = 5 * 1024 * 1024

// EnsureCanViewAvatar — доступ к аватару: только сам пользователь или админ.
func (s *Service) EnsureCanViewAvatar(requesterRole string, requesterID, targetID int32) error {
	if requesterRole != "ADMIN" && requesterID != targetID {
		return apperr.Forbidden("Недостаточно прав для просмотра чужого аватара")
	}
	return nil
}

// UploadAvatar — валидирует размер/тип, удаляет старый объект и грузит новый.
func (s *Service) UploadAvatar(ctx context.Context, userID int32, up AvatarUpload, ip string) (*User, error) {
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(up.Data) > maxAvatarSize {
		return nil, apperr.Validation("Размер аватара превышает 5 МБ")
	}
	mime := sniffAvatarMIME(up.Data)
	if !allowedAvatarMIME[mime] {
		return nil, apperr.Validation("Аватар должен быть изображением PNG, JPEG, WEBP или GIF")
	}
	if user.AvatarKey != "" {
		if err := s.storage.Delete(ctx, user.AvatarKey); err != nil {
			return nil, err
		}
	}
	safeName := sanitizeFilename(up.Filename, "avatar.bin")
	key := uuid.NewString() + "-" + safeName
	if err := s.storage.Put(ctx, key, up.Data, mime); err != nil {
		return nil, err
	}
	if err := s.store.SetUserAvatar(ctx, user.ID, s.cfg.MinioBucketName, key, mime); err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &user.ID, Action: "FILE_UPLOAD", EntityType: "user_avatar", EntityID: &user.ID, IPAddress: ip})
	return s.GetUser(ctx, user.ID)
}

// DownloadAvatar — возвращает пользователя и байты аватара (404 если нет).
func (s *Service) DownloadAvatar(ctx context.Context, userID int32) (*User, []byte, error) {
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	if user.AvatarKey == "" {
		return nil, nil, apperr.NotFound("Аватар не найден")
	}
	data, _, err := s.storage.Get(ctx, user.AvatarKey)
	if err != nil {
		return nil, nil, err
	}
	return user, data, nil
}

// ─────────────────────────── helpers ───────────────────────────

func (s *Service) ensureMailEnabled() error {
	if !s.cfg.MailEnabled {
		return apperr.Validation("Отправка email отключена. Включите SMTP/mail worker или задайте пароль вручную.")
	}
	return nil
}

func (s *Service) audit(ctx context.Context, e AuditEntry) {
	_ = s.store.InsertAuditLog(ctx, e)
}

// sniffAvatarMIME определяет MIME по байтам (net/http.DetectContentType + ручной
// разбор webp RIFF/WEBP, который DetectContentType не распознаёт).
func sniffAvatarMIME(data []byte) string {
	if len(data) >= 12 && string(data[0:4]) == "RIFF" && string(data[8:12]) == "WEBP" {
		return "image/webp"
	}
	ct := http.DetectContentType(data)
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return ct
}

// sanitizeFilename убирает разделители пути, null/непечатаемые символы и ведущие
// точки (порт _sanitize_filename из services.py).
func sanitizeFilename(raw, fallback string) string {
	if raw == "" {
		return fallback
	}
	name := strings.ReplaceAll(raw, "\\", "/")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	name = strings.TrimSpace(name)
	var b strings.Builder
	for _, ch := range name {
		if ch == 0 {
			continue
		}
		if unicode.IsPrint(ch) {
			b.WriteRune(ch)
		}
	}
	name = strings.TrimLeft(b.String(), ".")
	if name == "" {
		return fallback
	}
	return name
}

func defaultRole(role string) string {
	if role == "" {
		return "PENTESTER"
	}
	return role
}

func defaultProjectRole(role string) string {
	if role == "" {
		return "PENTESTER"
	}
	return role
}

func valueOr(p *string, fallback string) string {
	if p == nil {
		return fallback
	}
	return *p
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}
