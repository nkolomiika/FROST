package inventory

import (
	"context"
	"testing"
)

// bulkInvStore моделирует проектный скоуп bulk-удаления (как это делает SQL):
// удаляются только id, принадлежащие проекту; чужие/несуществующие игнорируются.
type bulkInvStore struct {
	*fakeInvStore
	hosts     map[int32]int32 // hostID -> projectID
	endpoints map[int32]int32 // endpointID -> projectID (через host∈проекта)
	audits    []AuditEntry
}

func newBulkInvStore() *bulkInvStore {
	return &bulkInvStore{fakeInvStore: &fakeInvStore{}, hosts: map[int32]int32{}, endpoints: map[int32]int32{}}
}

func (b *bulkInvStore) BulkDeleteHosts(_ context.Context, projectID int32, ids []int32) (int64, error) {
	var n int64
	for _, id := range ids {
		if b.hosts[id] == projectID {
			delete(b.hosts, id)
			n++
		}
	}
	return n, nil
}

func (b *bulkInvStore) BulkDeleteEndpoints(_ context.Context, projectID int32, ids []int32) (int64, error) {
	var n int64
	for _, id := range ids {
		if b.endpoints[id] == projectID {
			delete(b.endpoints, id)
			n++
		}
	}
	return n, nil
}

func (b *bulkInvStore) InsertAudit(_ context.Context, e AuditEntry) error {
	b.audits = append(b.audits, e)
	return nil
}

func TestDeleteHostsBulk_OnlyProjectMatchingIDs(t *testing.T) {
	st := newBulkInvStore()
	// проект 1 владеет 10,11; проект 2 владеет 12 (чужой)
	st.hosts = map[int32]int32{10: 1, 11: 1, 12: 2}
	svc := NewService(st, nil)

	deleted, err := svc.DeleteHostsBulk(context.Background(), 1, []int32{10, 11, 12, 999}, 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("want deleted=2 (own ids only), got %d", deleted)
	}
	if _, ok := st.hosts[12]; !ok {
		t.Fatalf("foreign-project host 12 must NOT be deleted")
	}
	if len(st.audits) != 1 || st.audits[0].EntityType != "hosts.bulk_delete" || st.audits[0].Action != "DELETE" {
		t.Fatalf("want exactly one hosts.bulk_delete audit, got %+v", st.audits)
	}
}

func TestDeleteHostsBulk_EmptyIsNoop(t *testing.T) {
	st := newBulkInvStore()
	st.hosts = map[int32]int32{10: 1}
	svc := NewService(st, nil)

	deleted, err := svc.DeleteHostsBulk(context.Background(), 1, nil, 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("want deleted=0 for empty list, got %d", deleted)
	}
	if len(st.audits) != 0 {
		t.Fatalf("empty bulk must not write audit, got %+v", st.audits)
	}
	if _, ok := st.hosts[10]; !ok {
		t.Fatalf("no-op must not touch data")
	}
}

func TestDeleteEndpointsBulk_ScopedToProjectHosts(t *testing.T) {
	st := newBulkInvStore()
	// эндпоинты 100,101 в проекте 1; 200 — в проекте 2 (host чужого проекта)
	st.endpoints = map[int32]int32{100: 1, 101: 1, 200: 2}
	svc := NewService(st, nil)

	deleted, err := svc.DeleteEndpointsBulk(context.Background(), 1, []int32{100, 101, 200}, 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("want deleted=2, got %d", deleted)
	}
	if _, ok := st.endpoints[200]; !ok {
		t.Fatalf("endpoint whose host is in another project must NOT be deleted")
	}
	if len(st.audits) != 1 || st.audits[0].EntityType != "endpoints.bulk_delete" {
		t.Fatalf("want exactly one endpoints.bulk_delete audit, got %+v", st.audits)
	}
}
