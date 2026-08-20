package projects

import (
	"context"
	"strings"
	"testing"
)

// rtCipher — обратимый шифр для проверки round-trip (Encrypt/Decrypt взаимны).
type rtCipher struct{}

func (rtCipher) Encrypt(v string) (string, error) { return "enc:" + v, nil }
func (rtCipher) Decrypt(t string) (string, error) { return strings.TrimPrefix(t, "enc:"), nil }

// create_credential шифрует пароль и не пишет его в аудит.
func TestCreateCredentialEncryptsPasswordAndExcludesItFromAudit(t *testing.T) {
	f := newFakeStore()
	f.project = &Project{ID: 1}
	f.insertedCredID = 700
	svc := NewService(f, rtCipher{}, fixedNow)

	uname := "dbuser"
	actor := Actor{ID: 3, Username: "creator"}
	result, err := svc.CreateCredential(context.Background(), 1, &uname, nil, "s3cr3t-pw", actor)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	// В БД лёг только шифртекст, а не сам пароль.
	if f.insertedCred == nil {
		t.Fatal("InsertCredential not called")
	}
	if f.insertedCred.PasswordEncrypted == "s3cr3t-pw" {
		t.Fatal("password stored in plaintext")
	}
	if got, _ := (rtCipher{}).Decrypt(f.insertedCred.PasswordEncrypted); got != "s3cr3t-pw" {
		t.Fatalf("decrypt(stored) = %q, want s3cr3t-pw", got)
	}
	// Выдача содержит расшифрованный пароль и username.
	if result.Password != "s3cr3t-pw" {
		t.Fatalf("result.Password = %q", result.Password)
	}
	if result.Username == nil || *result.Username != "dbuser" {
		t.Fatalf("result.Username = %v", result.Username)
	}
	// Пароль никогда не попадает в журнал аудита.
	if len(f.audits) != 1 {
		t.Fatalf("audits = %d, want 1", len(f.audits))
	}
	if strings.Contains(string(f.audits[0].Details), "s3cr3t-pw") {
		t.Fatalf("audit details leak password: %s", f.audits[0].Details)
	}
}

// update_credential с пустым паролем оставляет старый шифртекст.
func TestUpdateCredentialKeepsPasswordWhenBlank(t *testing.T) {
	f := newFakeStore()
	// existing.password_encrypted = encrypt("keep-me")
	f.credential = &Credential{ID: 7, ProjectID: 1, Password: "enc:keep-me", CreatedBy: 4}
	svc := NewService(f, rtCipher{}, fixedNow)

	newUser := "admin"
	actor := Actor{ID: 9, Username: "editor"}
	// Присылаем только username; password=nil означает «не менять».
	result, err := svc.UpdateCredential(context.Background(), 1, 7, &newUser, nil, nil, actor)
	if err != nil {
		t.Fatalf("UpdateCredential: %v", err)
	}
	if f.updatedCred == nil {
		t.Fatal("UpdateCredential store method not called")
	}
	if f.updatedCred.username == nil || *f.updatedCred.username != "admin" {
		t.Fatalf("stored username = %v, want admin", f.updatedCred.username)
	}
	if f.updatedCred.passwordEncrypted != "enc:keep-me" {
		t.Fatalf("stored password_encrypted = %q, want unchanged enc:keep-me", f.updatedCred.passwordEncrypted)
	}
	// Возврат содержит расшифрованный старый пароль.
	if result.Password != "keep-me" {
		t.Fatalf("result.Password = %q, want keep-me", result.Password)
	}
}

// _serialize (decryptCredential) расшифровывает пароль при выдаче.
func TestSerializeRoundTripsPassword(t *testing.T) {
	f := newFakeStore()
	svc := NewService(f, rtCipher{}, fixedNow)

	uname := "dbuser"
	cred := &Credential{ID: 3, ProjectID: 1, Username: &uname, Password: "enc:p@ss", CreatedBy: 1}
	if err := svc.decryptCredential(cred); err != nil {
		t.Fatalf("decryptCredential: %v", err)
	}
	if cred.Password != "p@ss" {
		t.Fatalf("password = %q, want p@ss", cred.Password)
	}
	if cred.Username == nil || *cred.Username != "dbuser" {
		t.Fatalf("username = %v", cred.Username)
	}
}
