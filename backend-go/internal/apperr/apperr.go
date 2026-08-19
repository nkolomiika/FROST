// Package apperr — доменные ошибки приложения и их отображение в HTTP-статусы.
// Зеркало app/exceptions.py: те же категории и коды ответов (см. main.py-хендлеры).
package apperr

import (
	"errors"
	"fmt"
	"net/http"
)

// Kind — категория доменной ошибки; определяет HTTP-статус.
type Kind int

const (
	KindInternal     Kind = iota // 400 (базовый PCFError)
	KindNotFound                 // 404
	KindUnauthorized             // 401
	KindForbidden                // 403
	KindConflict                 // 409
	KindValidation               // 422
)

// Error — доменная ошибка с категорией и человекочитаемым сообщением (уходит в `detail`).
type Error struct {
	Kind    Kind
	Message string
}

func (e *Error) Error() string { return e.Message }

// New создаёт доменную ошибку заданной категории.
func New(kind Kind, message string) *Error { return &Error{Kind: kind, Message: message} }

// Newf — как New, но с форматированием.
func Newf(kind Kind, format string, args ...any) *Error {
	return &Error{Kind: kind, Message: fmt.Sprintf(format, args...)}
}

// Конструкторы по категориям — читаются как исключения Python-версии.
func NotFound(msg string) *Error     { return New(KindNotFound, msg) }
func Unauthorized(msg string) *Error { return New(KindUnauthorized, msg) }
func Forbidden(msg string) *Error    { return New(KindForbidden, msg) }
func Conflict(msg string) *Error     { return New(KindConflict, msg) }
func Validation(msg string) *Error   { return New(KindValidation, msg) }

// HTTPStatus возвращает код ответа для ошибки. Не-доменная (нераспознанная)
// ошибка отображается в 500 — её текст наружу не отдаём.
func HTTPStatus(err error) int {
	var e *Error
	if !errors.As(err, &e) {
		return http.StatusInternalServerError
	}
	switch e.Kind {
	case KindNotFound:
		return http.StatusNotFound
	case KindUnauthorized:
		return http.StatusUnauthorized
	case KindForbidden:
		return http.StatusForbidden
	case KindConflict:
		return http.StatusConflict
	case KindValidation:
		return http.StatusUnprocessableEntity
	default:
		return http.StatusBadRequest
	}
}

// Detail возвращает сообщение для тела ответа: для доменных ошибок — их текст,
// для прочих — обобщённое (детали внутренней ошибки наружу не раскрываем).
func Detail(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Message
	}
	return "Внутренняя ошибка сервера"
}
