package auth

import (
	"context"
	"testing"
	"time"

	"github.com/nkolomiika/frost/internal/adapters/security"
)

// Порт backend/tests/test_invitations.py — сервисная часть invite-flow, живущая в
// auth-пакете: get_invitation_info (состояния), проверка доступности username и
// accept_invitation. Не-найденное/валидное состояние уже частично покрыто
// TestInvitationInfoStates; здесь добавлены остальные ветки.

func putInvite(store *fakeStore, raw string, inv *Invitation) {
	store.invitations[security.HashTokenSHA256(raw)] = inv
}

// test_info_used_for_accepted: принятое приглашение → used.
func TestInvitationInfoUsed(t *testing.T) {
	store := newFakeStore()
	svc := newTestService(t, store)
	putInvite(store, "tok", &Invitation{ID: 1, Email: "a@b.c", Status: "accepted", ExpiresAt: time.Now().Add(time.Hour)})
	info, _ := svc.GetInvitationInfo(context.Background(), "tok")
	if info.Valid || info.Reason != "used" {
		t.Fatalf("expected used, got %+v", info)
	}
}

// test_info_expired: pending, но срок истёк → expired.
func TestInvitationInfoExpired(t *testing.T) {
	store := newFakeStore()
	svc := newTestService(t, store)
	putInvite(store, "tok", &Invitation{ID: 1, Email: "a@b.c", Status: "pending", ExpiresAt: time.Now().Add(-time.Hour)})
	info, _ := svc.GetInvitationInfo(context.Background(), "tok")
	if info.Valid || info.Reason != "expired" {
		t.Fatalf("expected expired, got %+v", info)
	}
}

// test_info_revoked_looks_like_not_found: отозванное приглашение неотличимо от несуществующего.
func TestInvitationInfoRevokedLooksLikeNotFound(t *testing.T) {
	store := newFakeStore()
	svc := newTestService(t, store)
	putInvite(store, "tok", &Invitation{ID: 1, Email: "a@b.c", Status: "revoked", ExpiresAt: time.Now().Add(time.Hour)})
	info, _ := svc.GetInvitationInfo(context.Background(), "tok")
	if info.Valid || info.Reason != "not_found" {
		t.Fatalf("expected not_found, got %+v", info)
	}
}

// test_info_valid: pending и в срок → valid с email/full_name.
func TestInvitationInfoValidWithFullName(t *testing.T) {
	store := newFakeStore()
	svc := newTestService(t, store)
	putInvite(store, "tok", &Invitation{ID: 1, Email: "a@b.c", FullName: "Alice", Status: "pending", ExpiresAt: time.Now().Add(time.Hour)})
	info, _ := svc.GetInvitationInfo(context.Background(), "tok")
	if !info.Valid || info.Email != "a@b.c" || info.FullName != "Alice" {
		t.Fatalf("expected valid alice, got %+v", info)
	}
}

// test_username_available_true_when_free: валидный invite + свободный username → true.
func TestUsernameAvailableTrueWhenFree(t *testing.T) {
	store := newFakeStore()
	svc := newTestService(t, store)
	putInvite(store, "tok", &Invitation{ID: 1, Email: "a@b.c", Status: "pending", ExpiresAt: time.Now().Add(time.Hour)})
	ok, err := svc.CheckInvitationUsernameAvailable(context.Background(), "tok", "free.name")
	if err != nil || !ok {
		t.Fatalf("expected available, got ok=%v err=%v", ok, err)
	}
}

// test_username_available_false_when_taken: username уже занят → false.
func TestUsernameAvailableFalseWhenTaken(t *testing.T) {
	store := newFakeStore()
	svc := newTestService(t, store)
	store.addUser(&User{Username: "admin", Email: "admin@x.io", IsActive: true})
	putInvite(store, "tok", &Invitation{ID: 1, Email: "a@b.c", Status: "pending", ExpiresAt: time.Now().Add(time.Hour)})
	ok, err := svc.CheckInvitationUsernameAvailable(context.Background(), "tok", "admin")
	if err != nil || ok {
		t.Fatalf("expected unavailable, got ok=%v err=%v", ok, err)
	}
}

// test_username_check_rejects_invalid_token: без валидного токена → 401.
func TestUsernameCheckRejectsInvalidToken(t *testing.T) {
	store := newFakeStore()
	svc := newTestService(t, store)
	_, err := svc.CheckInvitationUsernameAvailable(context.Background(), "tok", "any.name")
	assertUnauthorized(t, err)
}

// test_accept_rejects_invalid_token: несуществующий токен → 401.
func TestAcceptRejectsInvalidToken(t *testing.T) {
	store := newFakeStore()
	svc := newTestService(t, store)
	_, err := svc.AcceptInvitation(context.Background(), "tok", "some.user", "longenough1", "")
	assertUnauthorized(t, err)
}

// test_accept_rejects_expired: pending, но срок истёк → 401.
func TestAcceptRejectsExpired(t *testing.T) {
	store := newFakeStore()
	svc := newTestService(t, store)
	putInvite(store, "tok", &Invitation{ID: 1, Email: "a@b.c", Status: "pending", ExpiresAt: time.Now().Add(-time.Hour)})
	_, err := svc.AcceptInvitation(context.Background(), "tok", "some.user", "longenough1", "")
	assertUnauthorized(t, err)
}

// test_accept_creates_user_from_invitation: активация создаёт пользователя, роль/email
// наследуются из приглашения, аккаунт активен, приглашение закрывается (single-use).
func TestAcceptCreatesUserFromInvitation(t *testing.T) {
	store := newFakeStore()
	svc := newTestService(t, store)
	hash := security.HashTokenSHA256("tok")
	store.invitations[hash] = &Invitation{
		ID: 1, Email: "invitee@example.com", FullName: "Invited One",
		Role: "ADMIN", ProjectRole: "LEAD", Status: "pending", ExpiresAt: time.Now().Add(time.Hour),
	}

	user, err := svc.AcceptInvitation(context.Background(), "tok", "i.volkov", "longenough1", "")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if user.Username != "i.volkov" {
		t.Fatalf("username: %q", user.Username)
	}
	if user.Email != "invitee@example.com" {
		t.Fatalf("email must come from invitation: %q", user.Email)
	}
	if user.Role != "ADMIN" || user.ProjectRole != "LEAD" {
		t.Fatalf("roles must be inherited from invitation: %+v", user)
	}
	if !user.IsActive {
		t.Fatal("accepted user must be active")
	}
	if store.invitations[hash].Status != "accepted" {
		t.Fatalf("invitation must be single-use (accepted), got %q", store.invitations[hash].Status)
	}
}
