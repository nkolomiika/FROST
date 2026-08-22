package integrations

import (
	"context"
	"strings"
	"testing"
	"time"
)

// fakeStore — in-memory реализация Store.
type fakeStore struct {
	rows map[string]row
}

type row struct {
	enc       []byte
	updatedAt time.Time
}

func newFakeStore() *fakeStore { return &fakeStore{rows: map[string]row{}} }

func (f *fakeStore) GetEncrypted(_ context.Context, key string) ([]byte, error) {
	r, ok := f.rows[key]
	if !ok {
		return nil, ErrNoRows
	}
	return r.enc, nil
}
func (f *fakeStore) ListMeta(context.Context) ([]StoredMeta, error) {
	out := make([]StoredMeta, 0, len(f.rows))
	for k, r := range f.rows {
		out = append(out, StoredMeta{KeyName: k, UpdatedAt: r.updatedAt})
	}
	return out, nil
}
func (f *fakeStore) Upsert(_ context.Context, key string, enc []byte, _ *int32) error {
	f.rows[key] = row{enc: enc, updatedAt: time.Now()}
	return nil
}
func (f *fakeStore) Delete(_ context.Context, key string) error {
	delete(f.rows, key)
	return nil
}

// fakeCipher — обратимый «шифр» для тестов (проверяем, что at-rest ≠ plaintext).
type fakeCipher struct{}

func (fakeCipher) Encrypt(v string) (string, error) { return "ENC(" + v + ")", nil }
func (fakeCipher) Decrypt(t string) (string, error) {
	return strings.TrimSuffix(strings.TrimPrefix(t, "ENC("), ")"), nil
}

func newSvc() (*Service, *fakeStore) {
	fs := newFakeStore()
	return NewService(fs, fakeCipher{}), fs
}

// Set → GetIntegrationKey роундтрип: значение зашифровано at-rest, читается обратно.
func TestSetGetRoundtrip_Encrypted(t *testing.T) {
	svc, fs := newSvc()
	ctx := context.Background()

	it, err := svc.Set(ctx, KeyGithubToken, "ghp_secret", 42)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if !it.Configured {
		t.Fatal("expected configured=true after Set")
	}

	// at-rest: НЕ plaintext, а вывод шифра
	stored := string(fs.rows[KeyGithubToken].enc)
	if strings.Contains(stored, "ghp_secret") == false || stored != "ENC(ghp_secret)" {
		t.Fatalf("value not encrypted at rest: %q", stored)
	}

	got, ok, err := svc.GetIntegrationKey(ctx, KeyGithubToken)
	if err != nil || !ok {
		t.Fatalf("GetIntegrationKey: ok=%v err=%v", ok, err)
	}
	if got != "ghp_secret" {
		t.Fatalf("roundtrip mismatch: %q", got)
	}
}

// GetIntegrationKey для незаданного ключа → ok=false, без ошибки.
func TestGetIntegrationKey_Unset(t *testing.T) {
	svc, _ := newSvc()
	_, ok, err := svc.GetIntegrationKey(context.Background(), KeyHIBP)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for unset key")
	}
}

// List отдаёт ВСЕ известные ключи; configured=true только у заданных.
func TestList_AllKnownKeys_ConfiguredFlag(t *testing.T) {
	svc, _ := newSvc()
	ctx := context.Background()
	if _, err := svc.Set(ctx, KeyDehashed, "k", 1); err != nil {
		t.Fatalf("Set: %v", err)
	}
	items, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != len(KnownKeys) {
		t.Fatalf("expected %d items, got %d", len(KnownKeys), len(items))
	}
	byName := map[string]Item{}
	for _, it := range items {
		byName[it.KeyName] = it
	}
	if !byName[KeyDehashed].Configured || byName[KeyDehashed].UpdatedAt == nil {
		t.Fatalf("dehashed should be configured with updated_at: %+v", byName[KeyDehashed])
	}
	if byName[KeyGithubToken].Configured {
		t.Fatal("github_token should be unconfigured")
	}
	// секрет наружу не утекает — Item не содержит значения (по типу).
}

// Пустое значение через Set удаляет ключ.
func TestSet_EmptyDeletes(t *testing.T) {
	svc, fs := newSvc()
	ctx := context.Background()
	if _, err := svc.Set(ctx, KeySnusbase, "v", 1); err != nil {
		t.Fatalf("Set: %v", err)
	}
	it, err := svc.Set(ctx, KeySnusbase, "", 1)
	if err != nil {
		t.Fatalf("Set empty: %v", err)
	}
	if it.Configured {
		t.Fatal("expected configured=false after clearing")
	}
	if _, ok := fs.rows[KeySnusbase]; ok {
		t.Fatal("row should be deleted on empty value")
	}
}

// Неизвестный ключ отвергается.
func TestSet_UnknownKeyRejected(t *testing.T) {
	svc, _ := newSvc()
	if _, err := svc.Set(context.Background(), "totally_unknown", "v", 1); err == nil {
		t.Fatal("expected error for unknown key")
	}
}
