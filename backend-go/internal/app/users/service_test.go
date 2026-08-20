package users

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/png"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/nkolomiika/frost/internal/adapters/security"
	"github.com/nkolomiika/frost/internal/apperr"
)

// ─────────────────────────── in-memory fakes ───────────────────────────

type fakeStore struct {
	users      map[int32]*User
	byUsername map[string]int32
	byEmail    map[string]int32
	revoked    map[int32]int // счётчик отзывов refresh-токенов
	mailJobs   []NewMailJob
	audits     []AuditEntry
	nextID     int32

	pendingInvites     map[string]*Invitation // активные pending-приглашения по email
	createdInvitations []NewInvitation        // перехват аргументов CreateInvitation
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		users: map[int32]*User{}, byUsername: map[string]int32{}, byEmail: map[string]int32{},
		revoked: map[int32]int{}, pendingInvites: map[string]*Invitation{}, nextID: 1,
	}
}

func (f *fakeStore) add(u *User) *User {
	if u.ID == 0 {
		u.ID = f.nextID
		f.nextID++
	}
	f.users[u.ID] = u
	f.byUsername[u.Username] = u.ID
	f.byEmail[u.Email] = u.ID
	return u
}

func (f *fakeStore) get(id int32) *User { return f.users[id] }

func (f *fakeStore) GetUserByID(_ context.Context, id int32) (*User, error) {
	if u, ok := f.users[id]; ok {
		cp := *u
		return &cp, nil
	}
	return nil, ErrNoRows
}
func (f *fakeStore) GetUserByUsername(_ context.Context, username string) (*User, error) {
	if id, ok := f.byUsername[username]; ok {
		cp := *f.users[id]
		return &cp, nil
	}
	return nil, ErrNoRows
}
func (f *fakeStore) GetUserByEmail(_ context.Context, email string) (*User, error) {
	if id, ok := f.byEmail[email]; ok {
		cp := *f.users[id]
		return &cp, nil
	}
	return nil, ErrNoRows
}
func (f *fakeStore) ListUsers(_ context.Context, offset, limit int32) ([]User, error) {
	out := []User{}
	for _, u := range f.users {
		out = append(out, *u)
	}
	return out, nil
}
func (f *fakeStore) CountUsers(_ context.Context) (int64, error) { return int64(len(f.users)), nil }

func (f *fakeStore) UpdateUserProfile(_ context.Context, id int32, username, email, fullName string) error {
	u := f.users[id]
	delete(f.byUsername, u.Username)
	delete(f.byEmail, u.Email)
	u.Username, u.Email, u.FullName = username, email, fullName
	f.byUsername[username] = id
	f.byEmail[email] = id
	return nil
}
func (f *fakeStore) UpdateUserAdmin(_ context.Context, id int32, fullName, role, projectRole string, isActive bool) error {
	u := f.users[id]
	u.FullName, u.Role, u.ProjectRole, u.IsActive = fullName, role, projectRole, isActive
	return nil
}
func (f *fakeStore) SetUserAvatar(_ context.Context, id int32, bucket, key, contentType string) error {
	u := f.users[id]
	now := time.Now().UTC()
	u.AvatarBucket, u.AvatarKey, u.AvatarContentType, u.AvatarUploadedAt = bucket, key, contentType, &now
	return nil
}
func (f *fakeStore) ChangeOwnPassword(_ context.Context, id int32, hash string) error {
	now := time.Now().UTC()
	f.users[id].PasswordHash, f.users[id].PasswordChangedAt = hash, &now
	f.revoked[id]++
	return nil
}
func (f *fakeStore) ResetPasswordTemp(_ context.Context, id int32, hash string) error {
	f.users[id].PasswordHash, f.users[id].PasswordChangedAt = hash, nil
	f.revoked[id]++
	return nil
}
func (f *fakeStore) SetTotpSecretForSetup(_ context.Context, id int32, enc string) error {
	f.users[id].TotpSecret = enc
	return nil
}
func (f *fakeStore) EnableTotp(_ context.Context, id int32) error {
	f.users[id].TotpEnabled = true
	return nil
}
func (f *fakeStore) DisableTotp(_ context.Context, id int32) error {
	f.users[id].TotpEnabled, f.users[id].TotpSecret = false, ""
	return nil
}
func (f *fakeStore) AdminResetTotp(_ context.Context, id int32) error {
	f.users[id].TotpEnabled, f.users[id].TotpSecret = false, ""
	f.revoked[id]++
	return nil
}
func (f *fakeStore) LockUser(_ context.Context, id int32) error {
	f.users[id].IsLocked = true
	f.revoked[id]++
	return nil
}
func (f *fakeStore) GetInvitationByID(context.Context, int32) (*Invitation, error) {
	return nil, ErrNoRows
}
func (f *fakeStore) GetActivePendingInvitationByEmail(_ context.Context, email string) (*Invitation, error) {
	if inv, ok := f.pendingInvites[email]; ok {
		cp := *inv
		return &cp, nil
	}
	return nil, ErrNoRows
}
func (f *fakeStore) ListPendingInvitations(context.Context) ([]Invitation, error) { return nil, nil }
func (f *fakeStore) CreateInvitation(_ context.Context, ni NewInvitation) (*Invitation, error) {
	f.createdInvitations = append(f.createdInvitations, ni)
	inv := &Invitation{ID: f.nextID, Email: ni.Email, FullName: ni.FullName, Role: ni.Role, ProjectRole: ni.ProjectRole, Status: "pending", ExpiresAt: ni.ExpiresAt, InvitedBy: ni.InvitedBy}
	f.nextID++
	return inv, nil
}
func (f *fakeStore) UpdateInvitationForResend(context.Context, int32, string, time.Time) error {
	return nil
}
func (f *fakeStore) RevokeInvitation(context.Context, int32) error               { return nil }
func (f *fakeStore) ExpireUnusedReactivationTokens(context.Context, int32) error { return nil }
func (f *fakeStore) CreateReactivationToken(context.Context, int32, string, time.Time) error {
	return nil
}
func (f *fakeStore) InsertMailJob(_ context.Context, job NewMailJob) (int32, error) {
	f.mailJobs = append(f.mailJobs, job)
	return int32(len(f.mailJobs)), nil
}
func (f *fakeStore) InsertAuditLog(_ context.Context, e AuditEntry) error {
	f.audits = append(f.audits, e)
	return nil
}

// fakeCipher — тождественное «шифрование» (для проверки логики без Fernet).
type fakeCipher struct{}

func (fakeCipher) Encrypt(v string) (string, error) { return v, nil }
func (fakeCipher) Decrypt(t string) (string, error) { return t, nil }

// fakeStorage — in-memory object storage.
type fakeStorage struct {
	objects  map[string][]byte
	deleted  []string
	putCalls int
}

func newFakeStorage() *fakeStorage { return &fakeStorage{objects: map[string][]byte{}} }

func (s *fakeStorage) Put(_ context.Context, key string, data []byte, _ string) error {
	s.objects[key] = data
	s.putCalls++
	return nil
}
func (s *fakeStorage) Get(_ context.Context, key string) ([]byte, string, error) {
	return s.objects[key], "", nil
}
func (s *fakeStorage) Delete(_ context.Context, key string) error {
	s.deleted = append(s.deleted, key)
	delete(s.objects, key)
	return nil
}

func newTestService(store *fakeStore, storage *fakeStorage) *Service {
	return NewService(store, fakeCipher{}, storage, Config{MailEnabled: true, MinioBucketName: "frost"}, nil)
}

func assertKind(t *testing.T, err error, kind apperr.Kind) {
	t.Helper()
	if err == nil {
		t.Fatalf("ожидалась ошибка kind=%v, получили nil", kind)
	}
	var e *apperr.Error
	if !errors.As(err, &e) || e.Kind != kind {
		t.Fatalf("ожидался apperr kind=%v, получили %v", kind, err)
	}
}

func pngBytes(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// ─────────────────────────── avatar ───────────────────────────

func TestUploadAvatarSniffAndSize(t *testing.T) {
	ctx := context.Background()

	t.Run("valid png accepted, key stored, bucket set", func(t *testing.T) {
		store := newFakeStore()
		store.add(&User{Username: "u", Email: "u@x.io", Role: "PENTESTER", ProjectRole: "PENTESTER", IsActive: true})
		storage := newFakeStorage()
		svc := newTestService(store, storage)
		user, err := svc.UploadAvatar(ctx, 1, AvatarUpload{Filename: "me.png", Data: pngBytes(t)}, "")
		if err != nil {
			t.Fatalf("unexpected: %v", err)
		}
		if user.AvatarKey == "" || user.AvatarContentType != "image/png" || user.AvatarBucket != "frost" {
			t.Fatalf("avatar not set correctly: %+v", user)
		}
		if storage.putCalls != 1 {
			t.Fatalf("expected one put, got %d", storage.putCalls)
		}
	})

	t.Run("oversize rejected", func(t *testing.T) {
		store := newFakeStore()
		store.add(&User{Username: "u", Email: "u@x.io", Role: "PENTESTER", ProjectRole: "PENTESTER"})
		svc := newTestService(store, newFakeStorage())
		big := make([]byte, maxAvatarSize+1)
		_, err := svc.UploadAvatar(ctx, 1, AvatarUpload{Filename: "big.png", Data: big}, "")
		assertKind(t, err, apperr.KindValidation)
	})

	t.Run("non-image rejected", func(t *testing.T) {
		store := newFakeStore()
		store.add(&User{Username: "u", Email: "u@x.io", Role: "PENTESTER", ProjectRole: "PENTESTER"})
		svc := newTestService(store, newFakeStorage())
		_, err := svc.UploadAvatar(ctx, 1, AvatarUpload{Filename: "x.txt", Data: []byte("not an image, just text content here")}, "")
		assertKind(t, err, apperr.KindValidation)
	})

	t.Run("old object deleted before upload", func(t *testing.T) {
		store := newFakeStore()
		store.add(&User{Username: "u", Email: "u@x.io", Role: "PENTESTER", ProjectRole: "PENTESTER", AvatarKey: "old-key"})
		storage := newFakeStorage()
		svc := newTestService(store, storage)
		if _, err := svc.UploadAvatar(ctx, 1, AvatarUpload{Filename: "new.png", Data: pngBytes(t)}, ""); err != nil {
			t.Fatal(err)
		}
		if len(storage.deleted) != 1 || storage.deleted[0] != "old-key" {
			t.Fatalf("old key not deleted: %v", storage.deleted)
		}
	})
}

func TestSniffAvatarMIMEWebp(t *testing.T) {
	data := make([]byte, 16)
	copy(data[0:4], "RIFF")
	copy(data[8:12], "WEBP")
	if got := sniffAvatarMIME(data); got != "image/webp" {
		t.Fatalf("webp not detected: %q", got)
	}
}

// ─────────────────────────── unique identity ───────────────────────────

func TestUpdateOwnProfileUniqueness(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	store.add(&User{Username: "alice", Email: "alice@x.io", Role: "PENTESTER", ProjectRole: "PENTESTER", IsActive: true})
	store.add(&User{Username: "bob", Email: "bob@x.io", Role: "PENTESTER", ProjectRole: "PENTESTER", IsActive: true})
	svc := newTestService(store, newFakeStorage())

	t.Run("no-op self keeps identity (no false conflict)", func(t *testing.T) {
		newName := "Alice A."
		if _, err := svc.UpdateOwnProfile(ctx, 1, ProfileUpdate{FullName: &newName}, ""); err != nil {
			t.Fatalf("unexpected conflict: %v", err)
		}
	})

	t.Run("email taken by another -> conflict", func(t *testing.T) {
		taken := "bob@x.io"
		_, err := svc.UpdateOwnProfile(ctx, 1, ProfileUpdate{Email: &taken}, "")
		assertKind(t, err, apperr.KindConflict)
	})
}

// ─────────────────────────── admin update immutability ───────────────────────────

func TestUpdateUserImmutability(t *testing.T) {
	ctx := context.Background()
	mk := func() (*fakeStore, *Service) {
		store := newFakeStore()
		store.add(&User{Username: "alice", Email: "alice@x.io", FullName: "Alice", Role: "PENTESTER", ProjectRole: "PENTESTER", IsActive: true})
		return store, newTestService(store, newFakeStorage())
	}

	t.Run("email change rejected", func(t *testing.T) {
		_, svc := mk()
		newEmail := "changed@x.io"
		_, err := svc.UpdateUser(ctx, 1, AdminUpdate{Email: &newEmail}, 9, "")
		assertKind(t, err, apperr.KindValidation)
	})

	t.Run("username change rejected", func(t *testing.T) {
		_, svc := mk()
		newName := "alice2"
		_, err := svc.UpdateUser(ctx, 1, AdminUpdate{Username: &newName}, 9, "")
		assertKind(t, err, apperr.KindValidation)
	})

	t.Run("same email/username ok, role/is_active applied", func(t *testing.T) {
		store, svc := mk()
		sameEmail, sameName, role := "alice@x.io", "alice", "ADMIN"
		active := false
		user, err := svc.UpdateUser(ctx, 1, AdminUpdate{Email: &sameEmail, Username: &sameName, Role: &role, IsActive: &active}, 9, "")
		if err != nil {
			t.Fatalf("unexpected: %v", err)
		}
		if user.Role != "ADMIN" || user.IsActive {
			t.Fatalf("fields not applied: %+v", user)
		}
		if store.get(1).Role != "ADMIN" {
			t.Fatal("role not persisted")
		}
	})
}

// ─────────────────────────── 2FA ───────────────────────────

func TestSetup2FA(t *testing.T) {
	ctx := context.Background()

	t.Run("already enabled -> 422", func(t *testing.T) {
		store := newFakeStore()
		store.add(&User{Username: "u", Email: "u@x.io", Role: "PENTESTER", ProjectRole: "PENTESTER", TotpEnabled: true})
		svc := newTestService(store, newFakeStorage())
		_, err := svc.Setup2FA(ctx, 1, "")
		assertKind(t, err, apperr.KindValidation)
	})

	t.Run("stores secret, returns uri+qr, not enabled", func(t *testing.T) {
		store := newFakeStore()
		store.add(&User{Username: "u", Email: "u@x.io", Role: "PENTESTER", ProjectRole: "PENTESTER"})
		svc := newTestService(store, newFakeStorage())
		setup, err := svc.Setup2FA(ctx, 1, "")
		if err != nil {
			t.Fatal(err)
		}
		if setup.Secret == "" || setup.OtpauthURI == "" || setup.QR == "" {
			t.Fatalf("empty setup fields: %+v", setup)
		}
		if store.get(1).TotpSecret == "" || store.get(1).TotpEnabled {
			t.Fatal("secret must be stored and 2FA still disabled")
		}
	})
}

func TestConfirm2FA(t *testing.T) {
	ctx := context.Background()
	secret, err := security.GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("no secret -> 422", func(t *testing.T) {
		store := newFakeStore()
		store.add(&User{Username: "u", Email: "u@x.io", Role: "PENTESTER", ProjectRole: "PENTESTER"})
		svc := newTestService(store, newFakeStorage())
		_, err := svc.Confirm2FA(ctx, 1, "123456", "")
		assertKind(t, err, apperr.KindValidation)
	})

	t.Run("wrong code -> 422", func(t *testing.T) {
		store := newFakeStore()
		store.add(&User{Username: "u", Email: "u@x.io", Role: "PENTESTER", ProjectRole: "PENTESTER", TotpSecret: secret})
		svc := newTestService(store, newFakeStorage())
		_, err := svc.Confirm2FA(ctx, 1, "000000", "")
		assertKind(t, err, apperr.KindValidation)
	})

	t.Run("valid code enables 2FA", func(t *testing.T) {
		store := newFakeStore()
		store.add(&User{Username: "u", Email: "u@x.io", Role: "PENTESTER", ProjectRole: "PENTESTER", TotpSecret: secret})
		svc := newTestService(store, newFakeStorage())
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		user, err := svc.Confirm2FA(ctx, 1, code, "")
		if err != nil {
			t.Fatalf("unexpected: %v", err)
		}
		if !user.TotpEnabled {
			t.Fatal("2FA not enabled")
		}
	})
}

func TestDisable2FA(t *testing.T) {
	ctx := context.Background()
	hash, _ := security.HashPassword("s3cret-pass")

	t.Run("wrong password -> 401", func(t *testing.T) {
		store := newFakeStore()
		store.add(&User{Username: "u", Email: "u@x.io", Role: "PENTESTER", ProjectRole: "PENTESTER", PasswordHash: hash, TotpEnabled: true, TotpSecret: "s"})
		svc := newTestService(store, newFakeStorage())
		_, err := svc.Disable2FA(ctx, 1, "wrong", "")
		assertKind(t, err, apperr.KindUnauthorized)
	})

	t.Run("correct password disables without session revoke", func(t *testing.T) {
		store := newFakeStore()
		store.add(&User{Username: "u", Email: "u@x.io", Role: "PENTESTER", ProjectRole: "PENTESTER", PasswordHash: hash, TotpEnabled: true, TotpSecret: "s"})
		svc := newTestService(store, newFakeStorage())
		user, err := svc.Disable2FA(ctx, 1, "s3cret-pass", "")
		if err != nil {
			t.Fatalf("unexpected: %v", err)
		}
		if user.TotpEnabled {
			t.Fatal("2FA still enabled")
		}
		if store.revoked[1] != 0 {
			t.Fatal("disable must not revoke sessions")
		}
	})
}
