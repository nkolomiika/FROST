package projects

import (
	"context"
	"reflect"
	"testing"
)

func TestHideIPsBulk_DedupsTrimsAndAudits(t *testing.T) {
	f := newFakeStore()
	f.bulkHideReturn = 2 // стор «реально скрыл» 2 новых адреса
	svc := NewService(f, noopCipher{}, fixedNow)

	// вход с пробелами, дублями и пустыми — сервис нормализует до [1.1.1.1, 2.2.2.2]
	hidden, err := svc.HideIPsBulk(context.Background(), 5, []string{" 1.1.1.1 ", "1.1.1.1", "", "2.2.2.2"}, 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hidden != 2 {
		t.Fatalf("want hidden=2 (from store), got %d", hidden)
	}
	want := []string{"1.1.1.1", "2.2.2.2"}
	if !reflect.DeepEqual(f.bulkHideCapture, want) {
		t.Fatalf("store must receive deduped/trimmed ips %v, got %v", want, f.bulkHideCapture)
	}
	if len(f.audits) != 1 || f.audits[0].EntityType != "ip_address" || f.audits[0].Action != "DELETE" {
		t.Fatalf("want exactly one ip_address DELETE audit, got %+v", f.audits)
	}
}

func TestHideIPsBulk_EmptyIsNoop(t *testing.T) {
	f := newFakeStore()
	svc := NewService(f, noopCipher{}, fixedNow)

	// только пустые/пробельные — после нормализации список пуст → no-op
	hidden, err := svc.HideIPsBulk(context.Background(), 5, []string{"", "   "}, 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hidden != 0 {
		t.Fatalf("want hidden=0 for empty list, got %d", hidden)
	}
	if f.bulkHideCapture != nil {
		t.Fatalf("store must not be called for empty list, got %v", f.bulkHideCapture)
	}
	if len(f.audits) != 0 {
		t.Fatalf("empty bulk must not write audit, got %+v", f.audits)
	}
}
