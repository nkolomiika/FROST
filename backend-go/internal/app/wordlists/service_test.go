package wordlists

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/nkolomiika/frost/internal/apperr"
)

// fakeStore — in-memory Store для тестов.
type fakeStore struct {
	rows      map[int32]Wordlist
	nextID    int32
	inserted  *NewWordlist
	deleted   []int32
	failInsrt bool
}

func newFakeStore() *fakeStore { return &fakeStore{rows: map[int32]Wordlist{}, nextID: 1} }

func (f *fakeStore) Insert(_ context.Context, in NewWordlist) (Wordlist, error) {
	f.inserted = &in
	if f.failInsrt {
		return Wordlist{}, apperr.Conflict("dup")
	}
	id := f.nextID
	f.nextID++
	wl := Wordlist{ID: id, Name: in.Name, ObjectKey: in.ObjectKey, SizeBytes: in.SizeBytes, Lines: in.Lines, UploadedBy: in.UploadedBy}
	f.rows[id] = wl
	return wl, nil
}
func (f *fakeStore) List(context.Context) ([]Wordlist, error) {
	out := make([]Wordlist, 0, len(f.rows))
	for _, w := range f.rows {
		out = append(out, w)
	}
	return out, nil
}
func (f *fakeStore) Get(_ context.Context, id int32) (Wordlist, error) {
	w, ok := f.rows[id]
	if !ok {
		return Wordlist{}, ErrNoRows
	}
	return w, nil
}
func (f *fakeStore) Delete(_ context.Context, id int32) (int64, error) {
	f.deleted = append(f.deleted, id)
	if _, ok := f.rows[id]; !ok {
		return 0, nil
	}
	delete(f.rows, id)
	return 1, nil
}

// fakeStorage — in-memory MinIO-seam.
type fakeStorage struct {
	objs    map[string][]byte
	putErr  error
	deleted []string
	failGet bool
}

func newFakeStorage() *fakeStorage { return &fakeStorage{objs: map[string][]byte{}} }

func (f *fakeStorage) Put(_ context.Context, key string, data []byte, _ string) error {
	if f.putErr != nil {
		return f.putErr
	}
	f.objs[key] = append([]byte(nil), data...)
	return nil
}
func (f *fakeStorage) Get(_ context.Context, key string) ([]byte, string, error) {
	if f.failGet {
		return nil, "", apperr.NotFound("missing")
	}
	d, ok := f.objs[key]
	if !ok {
		return nil, "", apperr.NotFound("missing")
	}
	return d, "text/plain", nil
}
func (f *fakeStorage) Delete(_ context.Context, key string) error {
	f.deleted = append(f.deleted, key)
	delete(f.objs, key)
	return nil
}

func TestUpload_StoresServerKeyAndCountsLines(t *testing.T) {
	store := newFakeStore()
	st := newFakeStorage()
	svc := NewService(store, st)
	uid := int32(42)

	wl, err := svc.Upload(context.Background(), "my subs.txt", []byte("a\nb\n\nc\n"), &uid)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if wl.Lines == nil || *wl.Lines != 3 {
		t.Fatalf("lines = %v, want 3", wl.Lines)
	}
	if wl.SizeBytes == nil || *wl.SizeBytes != 7 {
		t.Fatalf("size = %v, want 7", wl.SizeBytes)
	}
	// object_key серверный (wordlists/<uuid>), НЕ имя файла пользователя.
	if !strings.HasPrefix(wl.ObjectKey, objectKeyPrefix) {
		t.Fatalf("object key not server-generated: %q", wl.ObjectKey)
	}
	if strings.Contains(wl.ObjectKey, "subs") {
		t.Fatalf("user filename leaked into object key: %q", wl.ObjectKey)
	}
	if _, ok := st.objs[wl.ObjectKey]; !ok {
		t.Fatalf("bytes not stored under key %q", wl.ObjectKey)
	}
	if wl.Name != "my subs.txt" {
		t.Fatalf("name label lost: %q", wl.Name)
	}
}

func TestUpload_RejectsBinaryAndOversize(t *testing.T) {
	svc := NewService(newFakeStore(), newFakeStorage())
	if _, err := svc.Upload(context.Background(), "x", []byte("ok\nnul\x00here\n"), nil); err == nil {
		t.Fatal("expected binary reject")
	}
	if _, err := svc.Upload(context.Background(), "x", nil, nil); err == nil {
		t.Fatal("expected empty reject")
	}
	big := make([]byte, MaxUploadBytes+1)
	for i := range big {
		big[i] = 'a'
	}
	if _, err := svc.Upload(context.Background(), "x", big, nil); err == nil {
		t.Fatal("expected oversize reject")
	}
}

func TestUpload_RollbackObjectOnInsertFail(t *testing.T) {
	store := newFakeStore()
	store.failInsrt = true
	st := newFakeStorage()
	svc := NewService(store, st)
	if _, err := svc.Upload(context.Background(), "x", []byte("a\nb\n"), nil); err == nil {
		t.Fatal("expected insert error")
	}
	if len(st.deleted) != 1 {
		t.Fatalf("orphan object not cleaned up: deleted=%v", st.deleted)
	}
}

func TestList_BundledTiersAndCustom(t *testing.T) {
	store := newFakeStore()
	st := newFakeStorage()
	svc := NewService(store, st)
	_, _ = svc.Upload(context.Background(), "custom.txt", []byte("a\n"), nil)

	listing, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(listing.Bundled) != 3 {
		t.Fatalf("want 3 bundled tiers, got %d", len(listing.Bundled))
	}
	tiers := map[string]bool{}
	for _, b := range listing.Bundled {
		tiers[b.Tier] = true
	}
	if !tiers["small"] || !tiers["medium"] || !tiers["large"] {
		t.Fatalf("bundled tiers wrong: %+v", listing.Bundled)
	}
	if len(listing.Custom) != 1 {
		t.Fatalf("want 1 custom, got %d", len(listing.Custom))
	}
}

func TestDelete_RemovesObjectAndRow(t *testing.T) {
	store := newFakeStore()
	st := newFakeStorage()
	svc := NewService(store, st)
	wl, _ := svc.Upload(context.Background(), "c.txt", []byte("a\n"), nil)

	if err := svc.Delete(context.Background(), wl.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(st.deleted) != 1 || st.deleted[0] != wl.ObjectKey {
		t.Fatalf("object not deleted: %v", st.deleted)
	}
	if _, ok := store.rows[wl.ID]; ok {
		t.Fatal("row not deleted")
	}
	// Повторное удаление → 404.
	if err := svc.Delete(context.Background(), wl.ID); err == nil {
		t.Fatal("expected 404 on missing")
	}
}

func TestMaterialize_BundledTierNoTemp(t *testing.T) {
	t.Setenv("RECON_WORDLIST_DIR", "/wl")
	svc := NewService(newFakeStore(), newFakeStorage())
	path, cleanup, err := svc.Materialize(context.Background(), 0, "medium")
	if err != nil {
		t.Fatalf("materialize tier: %v", err)
	}
	defer cleanup()
	if path != "/wl/n0kovo_subdomains_medium.txt" {
		t.Fatalf("bundled path wrong: %q", path)
	}
}

func TestMaterialize_CustomStreamsToTemp(t *testing.T) {
	store := newFakeStore()
	st := newFakeStorage()
	svc := NewService(store, st)
	wl, _ := svc.Upload(context.Background(), "c.txt", []byte("admin\nlogin\n"), nil)

	path, cleanup, err := svc.Materialize(context.Background(), int(wl.ID), "medium")
	if err != nil {
		t.Fatalf("materialize custom: %v", err)
	}
	if path == "" {
		t.Fatal("empty temp path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read temp: %v", err)
	}
	if string(data) != "admin\nlogin\n" {
		t.Fatalf("temp content wrong: %q", data)
	}
	// Серверный temp-путь, не пользовательское имя.
	if strings.Contains(path, "c.txt") {
		t.Fatalf("user filename leaked into temp path: %q", path)
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("cleanup did not remove temp: %v", err)
	}
}

func TestMaterialize_CustomMissing404(t *testing.T) {
	svc := NewService(newFakeStore(), newFakeStorage())
	if _, _, err := svc.Materialize(context.Background(), 999, "medium"); err == nil {
		t.Fatal("expected 404 for missing custom wordlist")
	}
}
