package auth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/nkolomiika/frost/internal/adapters/security"
	"github.com/nkolomiika/frost/internal/apperr"
)

// Config — параметры use-cases (зеркало нужных полей app/config.py).
type Config struct {
	RefreshTokenTTL  time.Duration
	PasswordResetTTL time.Duration
	AppBaseURL       string
	MailPreviewURL   string
	SMTPHost         string
	MailEnabled      bool
	Brand            string // эмитент в письмах/2FA ("FROST")
}

// Service — use-cases аутентификации. Зависит только от портов.
type Service struct {
	store  Store
	tokens Tokens
	cipher Cipher
	cfg    Config
	now    func() time.Time
}

// NewService собирает use-case-слой. now можно подменить в тестах.
func NewService(store Store, tokens Tokens, cipher Cipher, cfg Config, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	if cfg.Brand == "" {
		cfg.Brand = "FROST"
	}
	return &Service{store: store, tokens: tokens, cipher: cipher, cfg: cfg, now: now}
}

// decodeErr отображает ошибку разбора JWT в доменную (как decode_token в Python).
func decodeErr(err error) error {
	if errors.Is(err, security.ErrWrongTokenType) {
		return apperr.Unauthorized("Некорректный тип токена")
	}
	return apperr.Unauthorized("Токен недействителен или истёк")
}

func (s *Service) issueSession(ctx context.Context, userID int32) (TokenPair, error) {
	access, err := s.tokens.CreateAccessToken(int64(userID))
	if err != nil {
		return TokenPair{}, err
	}
	refresh, err := s.tokens.CreateRefreshToken(int64(userID))
	if err != nil {
		return TokenPair{}, err
	}
	expiresAt := s.now().UTC().Add(s.cfg.RefreshTokenTTL)
	if err := s.store.InsertRefreshToken(ctx, userID, security.HashTokenSHA256(refresh), expiresAt); err != nil {
		return TokenPair{}, err
	}
	return TokenPair{Access: access, Refresh: refresh}, nil
}

// IssueSessionForUser выдаёт сессию без проверки пароля (активация приглашения/реактивация).
func (s *Service) IssueSessionForUser(ctx context.Context, userID int32) (TokenPair, error) {
	return s.issueSession(ctx, userID)
}

// AuthenticateAccessToken извлекает пользователя из access-токена (порт
// dependencies.get_current_user): токен валиден и это access, юзер активен и не заблокирован.
func (s *Service) AuthenticateAccessToken(ctx context.Context, accessToken string) (*User, error) {
	if accessToken == "" {
		return nil, apperr.Unauthorized("Требуется авторизация")
	}
	uid, err := s.tokens.Decode(accessToken, TokenTypeAccess)
	if err != nil {
		return nil, decodeErr(err)
	}
	user, err := s.store.GetUserByID(ctx, int32(uid))
	if errors.Is(err, ErrNoRows) {
		return nil, apperr.Unauthorized("Пользователь не найден или деактивирован")
	}
	if err != nil {
		return nil, err
	}
	if !user.IsActive || user.IsLocked {
		return nil, apperr.Unauthorized("Пользователь не найден или деактивирован")
	}
	return user, nil
}

// Login — первый шаг логина. При включённом 2FA возвращает challenge вместо сессии.
func (s *Service) Login(ctx context.Context, username, password, ip string) (LoginOutcome, error) {
	user, err := s.store.GetUserByUsername(ctx, username)
	if errors.Is(err, ErrNoRows) || (err == nil && !security.VerifyPassword(password, user.PasswordHash)) {
		return LoginOutcome{}, apperr.Unauthorized("Неверный логин или пароль")
	}
	if err != nil {
		return LoginOutcome{}, err
	}
	if !user.IsActive || user.IsLocked {
		return LoginOutcome{}, apperr.Unauthorized("Пользователь деактивирован")
	}
	if user.TotpEnabled {
		pending, err := s.tokens.Create2FAPendingToken(int64(user.ID))
		if err != nil {
			return LoginOutcome{}, err
		}
		s.audit(ctx, AuditEntry{UserID: &user.ID, Action: "LOGIN_2FA_CHALLENGE", IPAddress: ip})
		return LoginOutcome{User: user, Requires2FA: true, PendingToken: pending}, nil
	}
	pair, err := s.issueSession(ctx, user.ID)
	if err != nil {
		return LoginOutcome{}, err
	}
	s.audit(ctx, AuditEntry{UserID: &user.ID, Action: "LOGIN", IPAddress: ip})
	return LoginOutcome{User: user, AccessToken: pair.Access, RefreshToken: pair.Refresh}, nil
}

// Verify2FA — второй шаг логина: сверяет TOTP по pending-токену и выдаёт сессию.
func (s *Service) Verify2FA(ctx context.Context, pendingToken, code, ip string) (TokenPair, *User, error) {
	if pendingToken == "" {
		return TokenPair{}, nil, apperr.Unauthorized("Сессия подтверждения истекла — войдите заново")
	}
	uid, err := s.tokens.Decode(pendingToken, TokenType2FAPending)
	if err != nil {
		return TokenPair{}, nil, decodeErr(err)
	}
	user, err := s.store.GetUserByID(ctx, int32(uid))
	if errors.Is(err, ErrNoRows) {
		return TokenPair{}, nil, apperr.Unauthorized("Пользователь не найден или деактивирован")
	}
	if err != nil {
		return TokenPair{}, nil, err
	}
	if !user.IsActive || user.IsLocked {
		return TokenPair{}, nil, apperr.Unauthorized("Пользователь не найден или деактивирован")
	}
	if !user.TotpEnabled || user.TotpSecret == "" {
		return TokenPair{}, nil, apperr.Unauthorized("Двухфакторная аутентификация не настроена")
	}
	secret, err := s.cipher.Decrypt(user.TotpSecret)
	if err != nil || !security.VerifyTOTP(secret, code) {
		return TokenPair{}, nil, apperr.Unauthorized("Неверный код подтверждения")
	}
	pair, err := s.issueSession(ctx, user.ID)
	if err != nil {
		return TokenPair{}, nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &user.ID, Action: "LOGIN", IPAddress: ip, Details: mustJSON(map[string]any{"twofa": true})})
	return pair, user, nil
}

// Refresh обновляет пару токенов с ротацией refresh. Повторное предъявление уже
// отозванного токена трактуется как replay: гасим все активные токены пользователя.
func (s *Service) Refresh(ctx context.Context, refreshToken, ip string) (TokenPair, error) {
	if refreshToken == "" {
		return TokenPair{}, apperr.Unauthorized("Refresh token отсутствует")
	}
	uid, err := s.tokens.Decode(refreshToken, TokenTypeRefresh)
	if err != nil {
		return TokenPair{}, decodeErr(err)
	}
	userID := int32(uid)
	oldHash := security.HashTokenSHA256(refreshToken)
	existing, err := s.store.GetRefreshTokenForUser(ctx, oldHash, userID)
	if err != nil && !errors.Is(err, ErrNoRows) {
		return TokenPair{}, err
	}
	now := s.now().UTC()
	if existing != nil && existing.RevokedAt != nil {
		if err := s.store.RevokeAllUserRefreshTokens(ctx, userID); err != nil {
			return TokenPair{}, err
		}
		s.audit(ctx, AuditEntry{UserID: &userID, Action: "LOGOUT", IPAddress: ip, Details: mustJSON(map[string]any{"reason": "refresh_token_replay"})})
		return TokenPair{}, apperr.Unauthorized("Refresh token уже использован")
	}
	if existing == nil || !existing.ExpiresAt.After(now) {
		return TokenPair{}, apperr.Unauthorized("Refresh token недействителен")
	}
	user, err := s.store.GetUserByID(ctx, userID)
	if errors.Is(err, ErrNoRows) {
		return TokenPair{}, apperr.Unauthorized("Пользователь деактивирован")
	}
	if err != nil {
		return TokenPair{}, err
	}
	if !user.IsActive || user.IsLocked {
		return TokenPair{}, apperr.Unauthorized("Пользователь деактивирован")
	}
	newAccess, err := s.tokens.CreateAccessToken(int64(userID))
	if err != nil {
		return TokenPair{}, err
	}
	newRefresh, err := s.tokens.CreateRefreshToken(int64(userID))
	if err != nil {
		return TokenPair{}, err
	}
	newExpires := now.Add(s.cfg.RefreshTokenTTL)
	if err := s.store.RotateRefreshToken(ctx, oldHash, userID, security.HashTokenSHA256(newRefresh), newExpires); err != nil {
		return TokenPair{}, err
	}
	return TokenPair{Access: newAccess, Refresh: newRefresh}, nil
}

// Logout отзывает все активные refresh-токены пользователя.
func (s *Service) Logout(ctx context.Context, userID int32, ip string) error {
	if err := s.store.RevokeAllUserRefreshTokens(ctx, userID); err != nil {
		return err
	}
	s.audit(ctx, AuditEntry{UserID: &userID, Action: "LOGOUT", IPAddress: ip})
	return nil
}

// ─────────────────────────── приглашения ───────────────────────────

// GetInvitationInfo — публичные данные ссылки-приглашения (или причина отказа).
func (s *Service) GetInvitationInfo(ctx context.Context, rawToken string) (InvitationInfo, error) {
	inv, err := s.store.GetInvitationByTokenHash(ctx, security.HashTokenSHA256(rawToken))
	if errors.Is(err, ErrNoRows) || (err == nil && inv.Status == "revoked") {
		return InvitationInfo{Valid: false, Reason: "not_found"}, nil
	}
	if err != nil {
		return InvitationInfo{}, err
	}
	if inv.Status == "accepted" {
		return InvitationInfo{Valid: false, Reason: "used"}, nil
	}
	if inv.IsExpired(s.now().UTC()) {
		return InvitationInfo{Valid: false, Reason: "expired"}, nil
	}
	return InvitationInfo{Valid: true, Email: inv.Email, FullName: inv.FullName}, nil
}

// CheckInvitationUsernameAvailable проверяет свободен ли username (нужен валидный токен).
func (s *Service) CheckInvitationUsernameAvailable(ctx context.Context, rawToken, username string) (bool, error) {
	inv, err := s.store.GetInvitationByTokenHash(ctx, security.HashTokenSHA256(rawToken))
	if errors.Is(err, ErrNoRows) {
		return false, apperr.Unauthorized("Приглашение недействительно или истекло")
	}
	if err != nil {
		return false, err
	}
	if inv.Status != "pending" || inv.IsExpired(s.now().UTC()) {
		return false, apperr.Unauthorized("Приглашение недействительно или истекло")
	}
	exists, err := s.store.UsernameExists(ctx, username)
	if err != nil {
		return false, err
	}
	return !exists, nil
}

// AcceptInvitation — активация: приглашённый задаёт username+пароль, создаётся User.
func (s *Service) AcceptInvitation(ctx context.Context, rawToken, username, password, ip string) (*User, error) {
	inv, err := s.store.GetInvitationByTokenHash(ctx, security.HashTokenSHA256(rawToken))
	if errors.Is(err, ErrNoRows) {
		return nil, apperr.Unauthorized("Приглашение недействительно или истекло")
	}
	if err != nil {
		return nil, err
	}
	if inv.Status != "pending" || inv.IsExpired(s.now().UTC()) {
		return nil, apperr.Unauthorized("Приглашение недействительно или истекло")
	}
	if err := s.ensureUniqueIdentity(ctx, username, inv.Email); err != nil {
		return nil, err
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		return nil, err
	}
	user, err := s.store.AcceptInvitation(ctx, inv.ID, NewUser{
		Username:     username,
		Email:        inv.Email,
		FullName:     inv.FullName,
		PasswordHash: hash,
		Role:         inv.Role,
		ProjectRole:  inv.ProjectRole,
		IsActive:     true,
	})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{
		UserID:     &user.ID,
		Action:     "CREATE",
		EntityType: "user",
		EntityID:   &user.ID,
		Details:    mustJSON(map[string]any{"via": "invitation", "invitation_id": inv.ID}),
		IPAddress:  ip,
	})
	return user, nil
}

func (s *Service) ensureUniqueIdentity(ctx context.Context, username, email string) error {
	if username != "" {
		exists, err := s.store.UsernameExists(ctx, username)
		if err != nil {
			return err
		}
		if exists {
			return apperr.Conflict("Username or email is already taken")
		}
	}
	if email != "" {
		exists, err := s.store.EmailExists(ctx, email)
		if err != nil {
			return err
		}
		if exists {
			return apperr.Conflict("Username or email is already taken")
		}
	}
	return nil
}

// ─────────────────────────── сброс пароля ───────────────────────────

// RequestPasswordReset шлёт ссылку на email, если пользователь есть. Всегда без
// ошибки при отсутствии пользователя — иначе форма стала бы оракулом перебора.
func (s *Service) RequestPasswordReset(ctx context.Context, email, ip string) error {
	if !s.cfg.MailEnabled {
		return apperr.Validation("Отправка email отключена. Включите SMTP/mail worker или задайте пароль вручную.")
	}
	user, err := s.store.GetUserByEmail(ctx, email)
	if errors.Is(err, ErrNoRows) || (err == nil && (!user.IsActive || user.IsLocked)) {
		s.audit(ctx, AuditEntry{Action: "UPDATE", EntityType: "password_reset_requested_unknown", Details: mustJSON(map[string]any{"email": email}), IPAddress: ip})
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.store.ExpireUserUnusedPasswordResetTokens(ctx, user.ID); err != nil {
		return err
	}
	rawToken := security.GenerateURLSafeToken(32)
	expiresAt := s.now().UTC().Add(s.cfg.PasswordResetTTL)
	if err := s.store.CreatePasswordResetToken(ctx, user.ID, security.HashTokenSHA256(rawToken), expiresAt); err != nil {
		return err
	}
	resetURL := strings.TrimRight(s.cfg.AppBaseURL, "/") + "/reset-password?token=" + rawToken
	// Рендер тела/HTML письма — Phase 2 (mail-worker) из template+payload.
	payload := mustJSON(map[string]any{
		"reset_url":    resetURL,
		"username":     firstNonEmpty(user.FullName, user.Username),
		"expire_hours": int(s.cfg.PasswordResetTTL.Hours()),
	})
	uid := user.ID
	if _, err := s.store.InsertMailJob(ctx, NewMailJob{
		UserID:         &uid,
		RecipientEmail: user.Email,
		Subject:        s.cfg.Brand + ": восстановление пароля",
		Template:       "password_reset",
		Payload:        payload,
	}); err != nil {
		return err
	}
	s.audit(ctx, AuditEntry{UserID: &uid, Action: "UPDATE", EntityType: "password_reset_requested", EntityID: &uid, IPAddress: ip})
	return nil
}

// MailPreviewURL — превью почты (mailpit) для ответа request_password_reset.
func (s *Service) MailPreviewURL() string {
	if s.cfg.SMTPHost == "mailpit" {
		return s.cfg.MailPreviewURL
	}
	return ""
}

// GetPasswordResetInfo проверяет ссылку до показа формы нового пароля.
func (s *Service) GetPasswordResetInfo(ctx context.Context, rawToken string) (TokenInfo, error) {
	tok, err := s.store.GetPasswordResetByHash(ctx, security.HashTokenSHA256(rawToken))
	if errors.Is(err, ErrNoRows) {
		return TokenInfo{Valid: false, Reason: "not_found"}, nil
	}
	if err != nil {
		return TokenInfo{}, err
	}
	if tok.UsedAt != nil {
		return TokenInfo{Valid: false, Reason: "used"}, nil
	}
	if !tok.IsUsable(s.now().UTC()) {
		return TokenInfo{Valid: false, Reason: "expired"}, nil
	}
	user, err := s.store.GetUserByID(ctx, tok.UserID)
	if errors.Is(err, ErrNoRows) || (err == nil && (!user.IsActive || user.IsLocked)) {
		return TokenInfo{Valid: false, Reason: "not_found"}, nil
	}
	if err != nil {
		return TokenInfo{}, err
	}
	return TokenInfo{Valid: true, Username: user.Username}, nil
}

// ConfirmPasswordReset ставит новый пароль по одноразовой ссылке и гасит все сессии.
func (s *Service) ConfirmPasswordReset(ctx context.Context, rawToken, newPassword, ip string) error {
	tok, err := s.store.GetPasswordResetByHash(ctx, security.HashTokenSHA256(rawToken))
	if errors.Is(err, ErrNoRows) {
		return apperr.Unauthorized("Ссылка недействительна или истекла")
	}
	if err != nil {
		return err
	}
	if !tok.IsUsable(s.now().UTC()) {
		return apperr.Unauthorized("Ссылка недействительна или истекла")
	}
	user, err := s.store.GetUserByID(ctx, tok.UserID)
	if errors.Is(err, ErrNoRows) || (err == nil && (!user.IsActive || user.IsLocked)) {
		return apperr.Unauthorized("Ссылка недействительна или истекла")
	}
	if err != nil {
		return err
	}
	hash, err := security.HashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := s.store.ConfirmPasswordReset(ctx, tok.ID, user.ID, hash); err != nil {
		return err
	}
	s.audit(ctx, AuditEntry{UserID: &user.ID, Action: "UPDATE", EntityType: "password_reset_completed", EntityID: &user.ID, IPAddress: ip})
	return nil
}

// ─────────────────────────── реактивация ───────────────────────────

// GetReactivationInfo — публичная проверка ссылки-возврата до показа кнопки входа.
func (s *Service) GetReactivationInfo(ctx context.Context, rawToken string) (TokenInfo, error) {
	tok, err := s.store.GetReactivationByHash(ctx, security.HashTokenSHA256(rawToken))
	if errors.Is(err, ErrNoRows) {
		return TokenInfo{Valid: false, Reason: "not_found"}, nil
	}
	if err != nil {
		return TokenInfo{}, err
	}
	if tok.UsedAt != nil {
		return TokenInfo{Valid: false, Reason: "used"}, nil
	}
	if !tok.IsUsable(s.now().UTC()) {
		return TokenInfo{Valid: false, Reason: "expired"}, nil
	}
	user, err := s.store.GetUserByID(ctx, tok.UserID)
	// Аккаунт мог уже разблокировать другой способ — тогда ссылка не нужна.
	if errors.Is(err, ErrNoRows) || (err == nil && (!user.IsActive || !user.IsLocked)) {
		return TokenInfo{Valid: false, Reason: "not_found"}, nil
	}
	if err != nil {
		return TokenInfo{}, err
	}
	return TokenInfo{Valid: true, Username: user.Username}, nil
}

// CompleteReactivation разблокирует аккаунт по одноразовой ссылке и возвращает
// пользователя (сессию выдаёт http-слой поверх этого).
func (s *Service) CompleteReactivation(ctx context.Context, rawToken, ip string) (*User, error) {
	tok, err := s.store.GetReactivationByHash(ctx, security.HashTokenSHA256(rawToken))
	if errors.Is(err, ErrNoRows) {
		return nil, apperr.Unauthorized("Ссылка недействительна или истекла")
	}
	if err != nil {
		return nil, err
	}
	if !tok.IsUsable(s.now().UTC()) {
		return nil, apperr.Unauthorized("Ссылка недействительна или истекла")
	}
	user, err := s.store.GetUserByID(ctx, tok.UserID)
	if errors.Is(err, ErrNoRows) || (err == nil && !user.IsActive) {
		return nil, apperr.Unauthorized("Ссылка недействительна или истекла")
	}
	if err != nil {
		return nil, err
	}
	if err := s.store.CompleteReactivation(ctx, tok.ID, user.ID); err != nil {
		return nil, err
	}
	user.IsLocked = false
	s.audit(ctx, AuditEntry{UserID: &user.ID, Action: "UPDATE", EntityType: "user_reactivated", EntityID: &user.ID, IPAddress: ip})
	return user, nil
}

// ─────────────────────────── helpers ───────────────────────────

// audit пишет журнал «best-effort»: провал записи не должен рушить основную операцию.
func (s *Service) audit(ctx context.Context, e AuditEntry) {
	_ = s.store.InsertAuditLog(ctx, e)
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
