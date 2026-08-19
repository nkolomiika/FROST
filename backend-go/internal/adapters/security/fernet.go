package security

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/fernet/fernet-go"
)

// SecretCipher шифрует произвольные секреты (TOTP-seed) для хранения в БД.
// Совместим с app/security.py: Fernet поверх ключа, производного от JWT-секрета
// как urlsafe_b64(sha256(jwt_secret)). Существующие Python-шифртексты читаются.
type SecretCipher struct{ key *fernet.Key }

// NewSecretCipher выводит Fernet-ключ из JWT-секрета (тот же вывод, что в Python).
func NewSecretCipher(jwtSecret string) (*SecretCipher, error) {
	digest := sha256.Sum256([]byte(jwtSecret))
	keyStr := base64.URLEncoding.EncodeToString(digest[:])
	k, err := fernet.DecodeKey(keyStr)
	if err != nil {
		return nil, err
	}
	return &SecretCipher{key: k}, nil
}

// Encrypt шифрует значение (эквивалент encrypt_secret).
func (c *SecretCipher) Encrypt(value string) (string, error) {
	tok, err := fernet.EncryptAndSign([]byte(value), c.key)
	if err != nil {
		return "", err
	}
	return string(tok), nil
}

// Decrypt расшифровывает значение (эквивалент decrypt_secret). ttl=0 — без срока.
func (c *SecretCipher) Decrypt(token string) (string, error) {
	msg := fernet.VerifyAndDecrypt([]byte(token), time.Duration(0), []*fernet.Key{c.key})
	if msg == nil {
		return "", errors.New("не удалось расшифровать секрет")
	}
	return string(msg), nil
}
