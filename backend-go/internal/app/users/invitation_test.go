package users

import (
	"context"
	"testing"

	"github.com/nkolomiika/frost/internal/apperr"
)

// Порт backend/tests/test_invitations.py — часть create-flow (создание приглашения)
// и роли по умолчанию, живущие в users-сервисе (get_invitation_info/accept/username
// доступны в auth-пакете — см. internal/app/auth/invitation_test.go).

// test_invitation_create_defaults_roles: при пустых ролях приглашение получает
// PENTESTER/PENTESTER (роли применяет defaultRole/defaultProjectRole при создании).
func TestCreateInvitationDefaultsRoles(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	svc := newTestService(store, newFakeStorage())

	inv, err := svc.CreateInvitation(ctx, InvitationInput{Email: "new@example.com"}, 1, "")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if inv.Role != "PENTESTER" || inv.ProjectRole != "PENTESTER" {
		t.Fatalf("roles not defaulted: %+v", inv)
	}
	if len(store.createdInvitations) != 1 {
		t.Fatalf("expected one CreateInvitation call, got %d", len(store.createdInvitations))
	}
	if ni := store.createdInvitations[0]; ni.Role != "PENTESTER" || ni.ProjectRole != "PENTESTER" {
		t.Fatalf("defaults not passed to store: %+v", ni)
	}
}

// test_create_invitation_conflicts_with_existing_user: email уже принадлежит юзеру.
func TestCreateInvitationConflictExistingUser(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	store.add(&User{Username: "taken", Email: "taken@example.com", Role: "PENTESTER", ProjectRole: "PENTESTER", IsActive: true})
	svc := newTestService(store, newFakeStorage())

	_, err := svc.CreateInvitation(ctx, InvitationInput{Email: "taken@example.com"}, 1, "")
	assertKind(t, err, apperr.KindConflict)
}

// test_create_invitation_conflicts_with_active_invite: юзера нет, но есть активный invite.
func TestCreateInvitationConflictActiveInvite(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	store.pendingInvites["pending@example.com"] = &Invitation{ID: 9, Email: "pending@example.com", Status: "pending"}
	svc := newTestService(store, newFakeStorage())

	_, err := svc.CreateInvitation(ctx, InvitationInput{Email: "pending@example.com"}, 1, "")
	assertKind(t, err, apperr.KindConflict)
}

// test_create_invitation_happy_path: нет ни юзера, ни активного invite — приглашение
// создаётся (status pending, token_hash проставлен) и ставится письмо "invitation".
func TestCreateInvitationHappyPath(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	svc := newTestService(store, newFakeStorage())

	inv, err := svc.CreateInvitation(ctx, InvitationInput{Email: "fresh@example.com", Role: "PENTESTER", ProjectRole: "PENTESTER"}, 1, "")
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if inv.Email != "fresh@example.com" || inv.Status != "pending" {
		t.Fatalf("unexpected invitation: %+v", inv)
	}
	if len(store.createdInvitations) != 1 || store.createdInvitations[0].TokenHash == "" {
		t.Fatalf("token hash not set on created invitation: %+v", store.createdInvitations)
	}
	if len(store.mailJobs) != 1 || store.mailJobs[0].Template != "invitation" {
		t.Fatalf("expected one 'invitation' mail job, got %+v", store.mailJobs)
	}
}

// test_avatar_download_forbidden_for_other_non_admin_users (test_user_service_security.py):
// не-админ не может смотреть чужой аватар; сам себя и админ — могут.
func TestEnsureCanViewAvatar(t *testing.T) {
	svc := newTestService(newFakeStore(), newFakeStorage())

	if err := svc.EnsureCanViewAvatar("PENTESTER", 1, 2); err == nil {
		t.Fatal("non-admin viewing another user's avatar must be forbidden")
	} else {
		assertKind(t, err, apperr.KindForbidden)
	}
	if err := svc.EnsureCanViewAvatar("PENTESTER", 1, 1); err != nil {
		t.Fatalf("self view must be allowed: %v", err)
	}
	if err := svc.EnsureCanViewAvatar("ADMIN", 1, 2); err != nil {
		t.Fatalf("admin view must be allowed: %v", err)
	}
}
