package auth

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nkolomiika/frost/internal/adapters/security"
	"github.com/nkolomiika/frost/internal/apperr"
)

// Порт валидационных кейсов из backend/tests/test_invitations.py, которые в Python
// обеспечивала Pydantic-схема InvitationAcceptRequest (username-паттерн + длина
// пароля). В Go сгенерированный DTO валидации не несёт, поэтому проверки живут в
// сервисе (validateNewUsername/validateNewPassword) — здесь их и проверяем.

func assertValidation(t *testing.T, err error) {
	t.Helper()
	if apperr.HTTPStatus(err) != 422 {
		t.Fatalf("expected 422 validation, got err=%v status=%d", err, apperr.HTTPStatus(err))
	}
}

// pendingInvite кладёт валидное pending-приглашение под токен "tok".
func pendingInvite(store *fakeStore) {
	store.invitations[security.HashTokenSHA256("tok")] = &Invitation{
		ID: 1, Email: "invitee@example.com", Status: "pending",
		Role: "PENTESTER", ProjectRole: "PENTESTER", ExpiresAt: time.Now().Add(time.Hour),
	}
}

// test_invitation_accept_rejects_bad_username — параметризованный набор Python.
func TestAcceptRejectsBadUsername(t *testing.T) {
	bad := []string{
		"ab",                     // короче 3
		"has space",              // пробел
		"нет-латиницы",           // не латиница
		"bad!char",               // спецсимвол
		"",                       // пусто
		strings.Repeat("a", 101), // длиннее 100
	}
	for _, u := range bad {
		store := newFakeStore()
		pendingInvite(store)
		svc := newTestService(t, store)
		_, err := svc.AcceptInvitation(context.Background(), "tok", u, "longenough1", "")
		if err == nil {
			t.Fatalf("username %q must be rejected", u)
		}
		assertValidation(t, err)
	}
}

// test_invitation_accept_rejects_short_password.
func TestAcceptRejectsShortPassword(t *testing.T) {
	store := newFakeStore()
	pendingInvite(store)
	svc := newTestService(t, store)
	_, err := svc.AcceptInvitation(context.Background(), "tok", "good.name", "short", "")
	assertValidation(t, err)
}

// test_invitation_accept_ok — граничные валидные значения проходят.
func TestAcceptAcceptsValidUsernameAndPassword(t *testing.T) {
	for _, u := range []string{"i.volkov", "abc", "a_b-c.9", strings.Repeat("x", 100)} {
		store := newFakeStore()
		pendingInvite(store)
		svc := newTestService(t, store)
		if _, err := svc.AcceptInvitation(context.Background(), "tok", u, "longenough1", ""); err != nil {
			t.Fatalf("username %q must be accepted: %v", u, err)
		}
	}
}

// Валидация пароля также действует на подтверждение сброса (Python
// PasswordResetConfirmRequest: password min_length=8).
func TestConfirmPasswordResetRejectsShortPassword(t *testing.T) {
	store := newFakeStore()
	svc := newTestService(t, store)
	err := svc.ConfirmPasswordReset(context.Background(), "tok", "short", "")
	assertValidation(t, err)
}

// Пароль ровно в 128 рун — верхняя граница проходит валидатор; 129 — нет.
func TestPasswordBoundaryLengths(t *testing.T) {
	if err := validateNewPassword(strings.Repeat("a", 128)); err != nil {
		t.Fatalf("128 chars must pass: %v", err)
	}
	if err := validateNewPassword(strings.Repeat("a", 129)); err == nil {
		t.Fatalf("129 chars must fail")
	}
	if err := validateNewPassword(strings.Repeat("a", 7)); err == nil {
		t.Fatalf("7 chars must fail")
	}
}
