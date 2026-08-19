package auth

import (
	"context"
	"testing"
	"time"

	"github.com/nkolomiika/frost/internal/adapters/security"
	"github.com/nkolomiika/frost/internal/apperr"
)

// fakeStore — in-memory реализация Store для проверки бизнес-логики без БД.
type fakeStore struct {
	users        map[int32]*User
	byUsername   map[string]int32
	byEmail      map[string]int32
	refresh      map[string]*RefreshToken // ключ — token_hash
	invitations  map[string]*Invitation   // ключ — token_hash
	resets       map[string]*OneTimeToken // ключ — token_hash
	reactivation map[string]*OneTimeToken
	mailJobs     []NewMailJob
	audits       []AuditEntry
	nextID       int32
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		users: map[int32]*User{}, byUsername: map[string]int32{}, byEmail: map[string]int32{},
		refresh: map[string]*RefreshToken{}, invitations: map[string]*Invitation{},
		resets: map[string]*OneTimeToken{}, reactivation: map[string]*OneTimeToken{}, nextID: 1,
	}
}

func (f *fakeStore) addUser(u *User) *User {
	if u.ID == 0 {
		u.ID = f.nextID
		f.nextID++
	}
	f.users[u.ID] = u
	f.byUsername[u.Username] = u.ID
	f.byEmail[u.Email] = u.ID
	return u
}

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
func (f *fakeStore) UsernameExists(_ context.Context, username string) (bool, error) {
	_, ok := f.byUsername[username]
	return ok, nil
}
func (f *fakeStore) EmailExists(_ context.Context, email string) (bool, error) {
	_, ok := f.byEmail[email]
	return ok, nil
}
func (f *fakeStore) InsertRefreshToken(_ context.Context, userID int32, hash string, exp time.Time) error {
	f.refresh[hash] = &RefreshToken{ID: f.nextID, UserID: userID, ExpiresAt: exp}
	f.nextID++
	return nil
}
func (f *fakeStore) GetRefreshTokenForUser(_ context.Context, hash string, userID int32) (*RefreshToken, error) {
	if t, ok := f.refresh[hash]; ok && t.UserID == userID {
		cp := *t
		return &cp, nil
	}
	return nil, ErrNoRows
}
func (f *fakeStore) RevokeAllUserRefreshTokens(_ context.Context, userID int32) error {
	now := time.Now().UTC()
	for _, t := range f.refresh {
		if t.UserID == userID && t.RevokedAt == nil {
			t.RevokedAt = &now
		}
	}
	return nil
}
func (f *fakeStore) GetInvitationByTokenHash(_ context.Context, hash string) (*Invitation, error) {
	if i, ok := f.invitations[hash]; ok {
		cp := *i
		return &cp, nil
	}
	return nil, ErrNoRows
}
func (f *fakeStore) GetPasswordResetByHash(_ context.Context, hash string) (*OneTimeToken, error) {
	if t, ok := f.resets[hash]; ok {
		cp := *t
		return &cp, nil
	}
	return nil, ErrNoRows
}
func (f *fakeStore) ExpireUserUnusedPasswordResetTokens(_ context.Context, userID int32) error {
	now := time.Now().UTC()
	for _, t := range f.resets {
		if t.UserID == userID && t.UsedAt == nil {
			t.UsedAt = &now
		}
	}
	return nil
}
func (f *fakeStore) CreatePasswordResetToken(_ context.Context, userID int32, hash string, exp time.Time) error {
	f.resets[hash] = &OneTimeToken{ID: f.nextID, UserID: userID, ExpiresAt: exp}
	f.nextID++
	return nil
}
func (f *fakeStore) GetReactivationByHash(_ context.Context, hash string) (*OneTimeToken, error) {
	if t, ok := f.reactivation[hash]; ok {
		cp := *t
		return &cp, nil
	}
	return nil, ErrNoRows
}
func (f *fakeStore) InsertMailJob(_ context.Context, job NewMailJob) (int32, error) {
	f.mailJobs = append(f.mailJobs, job)
	id := f.nextID
	f.nextID++
	return id, nil
}
func (f *fakeStore) InsertAuditLog(_ context.Context, e AuditEntry) error {
	f.audits = append(f.audits, e)
	return nil
}
func (f *fakeStore) AcceptInvitation(_ context.Context, invID int32, nu NewUser) (*User, error) {
	u := f.addUser(&User{
		Username: nu.Username, Email: nu.Email, FullName: nu.FullName, PasswordHash: nu.PasswordHash,
		Role: nu.Role, ProjectRole: nu.ProjectRole, IsActive: nu.IsActive,
	})
	for _, inv := range f.invitations {
		if inv.ID == invID {
			inv.Status = "accepted"
		}
	}
	cp := *u
	return &cp, nil
}
func (f *fakeStore) RotateRefreshToken(_ context.Context, oldHash string, userID int32, newHash string, newExp time.Time) error {
	now := time.Now().UTC()
	if t, ok := f.refresh[oldHash]; ok {
		t.RevokedAt = &now
	}
	f.refresh[newHash] = &RefreshToken{ID: f.nextID, UserID: userID, ExpiresAt: newExp}
	f.nextID++
	return nil
}
func (f *fakeStore) ConfirmPasswordReset(_ context.Context, tokenID, userID int32, newHash string) error {
	f.users[userID].PasswordHash = newHash
	now := time.Now().UTC()
	for _, t := range f.resets {
		if t.ID == tokenID {
			t.UsedAt = &now
		}
	}
	return f.RevokeAllUserRefreshTokens(context.Background(), userID)
}
func (f *fakeStore) CompleteReactivation(_ context.Context, tokenID, userID int32) error {
	f.users[userID].IsLocked = false
	now := time.Now().UTC()
	for _, t := range f.reactivation {
		if t.ID == tokenID {
			t.UsedAt = &now
		}
	}
	return nil
}

// --- test harness ---

const testSecret = "test-secret-key-at-least-32-chars-long!!"

func newTestService(t *testing.T, store *fakeStore) *Service {
	t.Helper()
	cipher, err := security.NewSecretCipher(testSecret)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	jwt := security.NewJWTManager(testSecret, 30, 30)
	cfg := Config{RefreshTokenTTL: 30 * 24 * time.Hour, PasswordResetTTL: 2 * time.Hour, AppBaseURL: "https://app", MailEnabled: true}
	return NewService(store, jwt, cipher, cfg, nil)
}

func mkUser(store *fakeStore, username, password string) *User {
	hash, _ := security.HashPassword(password)
	return store.addUser(&User{Username: username, Email: username + "@x.io", PasswordHash: hash, Role: "PENTESTER", ProjectRole: "PENTESTER", IsActive: true})
}

func assertUnauthorized(t *testing.T, err error) {
	t.Helper()
	if apperr.HTTPStatus(err) != 401 {
		t.Fatalf("expected 401, got err=%v status=%d", err, apperr.HTTPStatus(err))
	}
}

func TestLoginSuccessNoTOTP(t *testing.T) {
	store := newFakeStore()
	mkUser(store, "alice", "pw12345")
	svc := newTestService(t, store)
	out, err := svc.Login(context.Background(), "alice", "pw12345", "1.2.3.4")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if out.Requires2FA || out.AccessToken == "" || out.RefreshToken == "" {
		t.Fatalf("unexpected outcome: %+v", out)
	}
	if len(store.refresh) != 1 {
		t.Fatalf("expected 1 refresh token stored, got %d", len(store.refresh))
	}
}

func TestLoginWrongPassword(t *testing.T) {
	store := newFakeStore()
	mkUser(store, "alice", "pw12345")
	svc := newTestService(t, store)
	_, err := svc.Login(context.Background(), "alice", "nope", "")
	assertUnauthorized(t, err)
}

func TestLoginUnknownUser(t *testing.T) {
	store := newFakeStore()
	svc := newTestService(t, store)
	_, err := svc.Login(context.Background(), "ghost", "x", "")
	assertUnauthorized(t, err)
}

func TestLoginDeactivated(t *testing.T) {
	store := newFakeStore()
	u := mkUser(store, "bob", "pw12345")
	u.IsLocked = true
	svc := newTestService(t, store)
	_, err := svc.Login(context.Background(), "bob", "pw12345", "")
	assertUnauthorized(t, err)
}

func TestLoginWithTOTPReturnsChallenge(t *testing.T) {
	store := newFakeStore()
	u := mkUser(store, "carol", "pw12345")
	cipher, _ := security.NewSecretCipher(testSecret)
	secret, _ := security.GenerateTOTPSecret()
	enc, _ := cipher.Encrypt(secret)
	u.TotpEnabled = true
	u.TotpSecret = enc
	svc := newTestService(t, store)

	out, err := svc.Login(context.Background(), "carol", "pw12345", "")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if !out.Requires2FA || out.PendingToken == "" {
		t.Fatalf("expected 2fa challenge, got %+v", out)
	}
	if len(store.refresh) != 0 {
		t.Fatalf("no session should be issued before 2fa verify")
	}
	// verify with a wrong code fails
	if _, _, err := svc.Verify2FA(context.Background(), out.PendingToken, "000000", ""); err == nil {
		t.Fatalf("expected wrong-code failure")
	}
}

func TestRefreshReplayRevokesAll(t *testing.T) {
	store := newFakeStore()
	mkUser(store, "dave", "pw12345")
	svc := newTestService(t, store)
	out, _ := svc.Login(context.Background(), "dave", "pw12345", "")

	// first refresh: rotates, old token revoked
	pair, err := svc.Refresh(context.Background(), out.RefreshToken, "")
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	// reuse the OLD refresh token -> replay -> all revoked + error
	if _, err := svc.Refresh(context.Background(), out.RefreshToken, ""); err == nil {
		t.Fatalf("expected replay error")
	}
	// the freshly-issued token must now also be revoked
	if _, err := svc.Refresh(context.Background(), pair.Refresh, ""); err == nil {
		t.Fatalf("expected all tokens revoked after replay")
	}
}

func TestRefreshRotationHappyPath(t *testing.T) {
	store := newFakeStore()
	mkUser(store, "erin", "pw12345")
	svc := newTestService(t, store)
	out, _ := svc.Login(context.Background(), "erin", "pw12345", "")
	pair, err := svc.Refresh(context.Background(), out.RefreshToken, "")
	if err != nil || pair.Access == "" || pair.Refresh == "" {
		t.Fatalf("rotation failed: err=%v pair=%+v", err, pair)
	}
	if pair.Refresh == out.RefreshToken {
		t.Fatalf("refresh token should rotate")
	}
}

func TestPasswordResetUnknownEmailNoLeak(t *testing.T) {
	store := newFakeStore()
	svc := newTestService(t, store)
	if err := svc.RequestPasswordReset(context.Background(), "ghost@x.io", ""); err != nil {
		t.Fatalf("should not error for unknown email: %v", err)
	}
	if len(store.mailJobs) != 0 {
		t.Fatalf("no mail job for unknown email")
	}
}

func TestPasswordResetKnownEmailEnqueues(t *testing.T) {
	store := newFakeStore()
	mkUser(store, "frank", "pw12345")
	svc := newTestService(t, store)
	if err := svc.RequestPasswordReset(context.Background(), "frank@x.io", ""); err != nil {
		t.Fatalf("reset request: %v", err)
	}
	if len(store.mailJobs) != 1 || len(store.resets) != 1 {
		t.Fatalf("expected 1 mail job and 1 reset token, got jobs=%d resets=%d", len(store.mailJobs), len(store.resets))
	}
}

func TestInvitationInfoStates(t *testing.T) {
	store := newFakeStore()
	svc := newTestService(t, store)
	// unknown token
	info, _ := svc.GetInvitationInfo(context.Background(), "nope")
	if info.Valid || info.Reason != "not_found" {
		t.Fatalf("unknown invite: %+v", info)
	}
	// valid pending
	raw := "raw-invite-token"
	store.invitations[security.HashTokenSHA256(raw)] = &Invitation{
		ID: 1, Email: "new@x.io", FullName: "New", Role: "PENTESTER", ProjectRole: "PENTESTER",
		Status: "pending", ExpiresAt: time.Now().Add(time.Hour),
	}
	info, _ = svc.GetInvitationInfo(context.Background(), raw)
	if !info.Valid || info.Email != "new@x.io" {
		t.Fatalf("valid invite: %+v", info)
	}
}
