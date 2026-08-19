package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// GenerateURLSafeToken возвращает случайный urlsafe-токен без паддинга —
// эквивалент Python secrets.token_urlsafe(nbytes) (по умолчанию 32 байта).
func GenerateURLSafeToken(nbytes int) string {
	if nbytes <= 0 {
		nbytes = 32
	}
	buf := make([]byte, nbytes)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// HashTokenSHA256 возвращает hex SHA-256 токена — так в БД хранятся хэши
// refresh/agent/invite/reset/reactivation токенов (в открытом виде их нет).
func HashTokenSHA256(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// randomHex возвращает hex из n случайных байт (Python secrets.token_hex(n)).
func randomHex(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}
