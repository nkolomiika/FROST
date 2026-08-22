package recon

import (
	"context"
	"testing"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
)

// jsBulkStore моделирует проектный скоуп bulk-удаления JS-находок (как SQL):
// удаляются только id, принадлежащие проекту. Остальные методы Store не нужны.
type jsBulkStore struct {
	Store
	files map[int32]int32 // jsFileID -> projectID
}

func (s *jsBulkStore) BulkDeleteJSFiles(_ context.Context, projectID int32, ids []int32) (int64, error) {
	var n int64
	for _, id := range ids {
		if s.files[id] == projectID {
			delete(s.files, id)
			n++
		}
	}
	return n, nil
}

func TestDeleteJSFilesBulk_ScopedToProject(t *testing.T) {
	st := &jsBulkStore{files: map[int32]int32{1: 7, 2: 7, 3: 9}} // 3 — чужой проект
	svc := stubService(st, reconnet.Settings{}, Config{MaxAttempts: 3})

	deleted, err := svc.DeleteJSFilesBulk(context.Background(), 7, []int32{1, 2, 3, 404})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("want deleted=2 (own ids only), got %d", deleted)
	}
	if _, ok := st.files[3]; !ok {
		t.Fatalf("foreign-project js file 3 must NOT be deleted")
	}
}

func TestDeleteJSFilesBulk_EmptyIsNoop(t *testing.T) {
	st := &jsBulkStore{files: map[int32]int32{1: 7}}
	svc := stubService(st, reconnet.Settings{}, Config{MaxAttempts: 3})

	deleted, err := svc.DeleteJSFilesBulk(context.Background(), 7, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("want deleted=0 for empty list, got %d", deleted)
	}
	if _, ok := st.files[1]; !ok {
		t.Fatalf("no-op must not touch data")
	}
}
