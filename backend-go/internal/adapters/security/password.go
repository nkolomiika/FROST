// Package security — криптографический адаптер: пароли, JWT, TOTP, шифрование
// секретов at-rest. Точный порт app/security.py Python-бэкенда; форматы
// (bcrypt, SHA-256-hex, HS256-JWT, Fernet, otpauth) совместимы, чтобы во время
// миграции данные, созданные Python-стороной, читались Go-стороной и наоборот.
package security

import "golang.org/x/crypto/bcrypt"

// HashPassword хэширует пароль bcrypt'ом (формат $2b$, совместим с passlib).
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// VerifyPassword проверяет пароль против bcrypt-хэша (в т.ч. созданного passlib).
func VerifyPassword(plain, hashed string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain)) == nil
}
