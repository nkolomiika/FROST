package auth

import (
	"regexp"
	"unicode/utf8"

	"github.com/nkolomiika/frost/internal/apperr"
)

// Правила зеркалят Pydantic-схемы Python (app/schemas.py):
// приглашённый сам задаёт username и пароль при активации, а пароль также
// задаётся при подтверждении сброса. Длины считаем в рунах — как Pydantic
// min_length/max_length (число code points), а не в байтах.

// usernamePattern — тот же паттерн, что USERNAME_PATTERN в Python:
// буквы/цифры/точка/подчёркивание/дефис, 3–100 символов.
var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{3,100}$`)

const (
	passwordMinLen = 8
	passwordMaxLen = 128
)

// validateNewUsername проверяет username, задаваемый при активации приглашения.
func validateNewUsername(username string) error {
	if !usernamePattern.MatchString(username) {
		return apperr.Validation("Имя пользователя: 3–100 символов, латиница/цифры/._-")
	}
	return nil
}

// validateNewPassword проверяет пароль, задаваемый пользователем (активация, сброс).
func validateNewPassword(password string) error {
	n := utf8.RuneCountInString(password)
	if n < passwordMinLen || n > passwordMaxLen {
		return apperr.Validation("Пароль должен содержать от 8 до 128 символов")
	}
	return nil
}
