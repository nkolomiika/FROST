package tasks

import (
	"context"
	"errors"
	"testing"

	"github.com/nkolomiika/frost/internal/apperr"
)

// fakeClient — in-memory порт Client для unit-тестов сервиса.
type fakeClient struct {
	listItems  []Task
	listTotal  int64
	listErr    error
	gotParams  ListParams
	detail     *TaskDetail
	getErr     error
	gotKey     string
	calledGet  bool
	calledList bool
}

func (f *fakeClient) List(_ context.Context, p ListParams) ([]Task, int64, error) {
	f.calledList = true
	f.gotParams = p
	return f.listItems, f.listTotal, f.listErr
}

func (f *fakeClient) Get(_ context.Context, key string) (*TaskDetail, error) {
	f.calledGet = true
	f.gotKey = key
	return f.detail, f.getErr
}

func TestServiceList_PassthroughAndNormalise(t *testing.T) {
	fc := &fakeClient{
		listItems: []Task{{Key: "STS-1", Summary: "a"}},
		listTotal: 1,
	}
	svc := NewService(fc, Config{ProjectKey: "STS"})

	items, total, err := svc.List(context.Background(), ListParams{
		Query: "  hello  ", Category: "InProgress", Page: 0, Size: 0,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].Key != "STS-1" {
		t.Fatalf("passthrough failed: items=%v total=%d", items, total)
	}
	if fc.gotParams.Query != "hello" {
		t.Errorf("query not trimmed: %q", fc.gotParams.Query)
	}
	if fc.gotParams.Category != CategoryInProgress {
		t.Errorf("category not normalised: %q", fc.gotParams.Category)
	}
	if fc.gotParams.Page != 1 || fc.gotParams.Size != 1 {
		t.Errorf("page/size not clamped: page=%d size=%d", fc.gotParams.Page, fc.gotParams.Size)
	}
}

func TestServiceList_UnknownCategoryBecomesAll(t *testing.T) {
	fc := &fakeClient{}
	svc := NewService(fc, Config{})
	if _, _, err := svc.List(context.Background(), ListParams{Category: "garbage", Page: 2, Size: 10}); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if fc.gotParams.Category != "" {
		t.Errorf("unknown category should fall back to all, got %q", fc.gotParams.Category)
	}
	if fc.gotParams.Page != 2 || fc.gotParams.Size != 10 {
		t.Errorf("valid page/size mutated: %d/%d", fc.gotParams.Page, fc.gotParams.Size)
	}
}

func TestServiceGet_KeyValidation(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		wantErr bool
		wantKey string // ключ, который должен уйти в клиент (uppercased)
	}{
		{"good", "STS-123", false, "STS-123"},
		{"lowercase ok, uppercased", "sts-7", false, "STS-7"},
		{"empty", "", true, ""},
		{"no number", "STS-", true, ""},
		{"no project", "-5", true, ""},
		{"injection", "STS-1 OR 1=1", true, ""},
		{"spaces", "  STS-9  ", false, "STS-9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fc := &fakeClient{detail: &TaskDetail{Task: Task{Key: "STS-123"}}}
			svc := NewService(fc, Config{})
			_, err := svc.Get(context.Background(), tc.key)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected validation error for %q", tc.key)
				}
				var e *apperr.Error
				if !errors.As(err, &e) || e.Kind != apperr.KindValidation {
					t.Fatalf("expected validation kind, got %v", err)
				}
				if fc.calledGet {
					t.Errorf("client should not be called for invalid key %q", tc.key)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err for %q: %v", tc.key, err)
			}
			if fc.gotKey != tc.wantKey {
				t.Errorf("key passed to client = %q, want %q", fc.gotKey, tc.wantKey)
			}
		})
	}
}

func TestServiceGet_PropagatesClientError(t *testing.T) {
	sentinel := apperr.New(apperr.KindInternal, "Интеграция с Jira не настроена")
	fc := &fakeClient{getErr: sentinel}
	svc := NewService(fc, Config{})
	_, err := svc.Get(context.Background(), "STS-1")
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel propagated, got %v", err)
	}
}

func TestServiceList_PropagatesClientError(t *testing.T) {
	sentinel := apperr.New(apperr.KindInternal, "Jira недоступна")
	fc := &fakeClient{listErr: sentinel}
	svc := NewService(fc, Config{})
	_, _, err := svc.List(context.Background(), ListParams{})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel propagated, got %v", err)
	}
}
