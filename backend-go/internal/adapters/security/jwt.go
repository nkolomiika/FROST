package security

import (
	"errors"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Типы JWT — совпадают со строками из app/security.py.
const (
	TokenTypeAccess     = "access"
	TokenTypeRefresh    = "refresh"
	TokenType2FAPending = "2fa_pending"

	twoFAPendingTTL = 5 * time.Minute
)

var (
	// ErrInvalidToken — токен не разобран, подпись неверна или истёк срок.
	ErrInvalidToken = errors.New("токен недействителен или истёк")
	// ErrWrongTokenType — токен корректен, но его тип не совпал с ожидаемым.
	ErrWrongTokenType = errors.New("некорректный тип токена")
)

// JWTManager выпускает и проверяет HS256-токены (порт _encode_token/decode_token).
type JWTManager struct {
	secret        []byte
	accessExpire  time.Duration
	refreshExpire time.Duration
}

// NewJWTManager создаёт менеджер с секретом и сроками жизни токенов.
func NewJWTManager(secret string, accessMinutes, refreshDays int) *JWTManager {
	return &JWTManager{
		secret:        []byte(secret),
		accessExpire:  time.Duration(accessMinutes) * time.Minute,
		refreshExpire: time.Duration(refreshDays) * 24 * time.Hour,
	}
}

func (m *JWTManager) encode(userID int64, tokenType string, ttl time.Duration) (string, error) {
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"sub":  strconv.FormatInt(userID, 10),
		"type": tokenType,
		"exp":  now.Add(ttl).Unix(),
		"iat":  now.Unix(),
		// jti делает токен уникальным: два токена одного юзера в одну секунду
		// не дадут одинаковый SHA-256 хэш на refresh_tokens.token_hash.
		"jti": randomHex(8),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(m.secret)
}

// CreateAccessToken выпускает короткоживущий access-токен.
func (m *JWTManager) CreateAccessToken(userID int64) (string, error) {
	return m.encode(userID, TokenTypeAccess, m.accessExpire)
}

// CreateRefreshToken выпускает долгоживущий refresh-токен.
func (m *JWTManager) CreateRefreshToken(userID int64) (string, error) {
	return m.encode(userID, TokenTypeRefresh, m.refreshExpire)
}

// Create2FAPendingToken выпускает токен «пароль принят, ждём код TOTP».
func (m *JWTManager) Create2FAPendingToken(userID int64) (string, error) {
	return m.encode(userID, TokenType2FAPending, twoFAPendingTTL)
}

// Decode проверяет подпись/срок и тип токена, возвращает id пользователя (sub).
func (m *JWTManager) Decode(token, expectedType string) (int64, error) {
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return m.secret, nil
	})
	if err != nil || !parsed.Valid {
		return 0, ErrInvalidToken
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return 0, ErrInvalidToken
	}
	if t, _ := claims["type"].(string); t != expectedType {
		return 0, ErrWrongTokenType
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return 0, ErrInvalidToken
	}
	id, err := strconv.ParseInt(sub, 10, 64)
	if err != nil {
		return 0, ErrInvalidToken
	}
	return id, nil
}
