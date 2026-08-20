package mailer

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
)

type fakeStore struct {
	jobs   map[int32]*Job
	status map[int32]string // "" | sent | pending | failed
}

func newFake() *fakeStore { return &fakeStore{jobs: map[int32]*Job{}, status: map[int32]string{}} }

func (f *fakeStore) ClaimPending(_ context.Context, _, _ int32) ([]int32, error) {
	var ids []int32
	for id := range f.jobs {
		ids = append(ids, id)
	}
	return ids, nil
}
func (f *fakeStore) MarkProcessing(_ context.Context, id int32) (*Job, error) {
	if f.status[id] == "sent" {
		return nil, nil
	}
	j, ok := f.jobs[id]
	if !ok {
		return nil, nil
	}
	j.Attempts++
	f.status[id] = "processing"
	cp := *j
	return &cp, nil
}
func (f *fakeStore) MarkSent(_ context.Context, id int32) error { f.status[id] = "sent"; return nil }
func (f *fakeStore) MarkPending(_ context.Context, id int32, _ string) error {
	f.status[id] = "pending"
	return nil
}
func (f *fakeStore) MarkFailed(_ context.Context, id int32, _ string) error {
	f.status[id] = "failed"
	return nil
}

type fakeSender struct {
	err  error
	sent []string
}

func (s *fakeSender) Send(to, subject, text, html string) error {
	if s.err != nil {
		return s.err
	}
	s.sent = append(s.sent, to)
	return nil
}

func newSvc(store Store, sender Sender, max int32) *Service {
	return NewService(store, sender, max, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestSendSuccess(t *testing.T) {
	store := newFake()
	store.jobs[1] = &Job{ID: 1, RecipientEmail: "a@x.io", Subject: "s", Template: "password_reset", Payload: []byte(`{"username":"u","reset_url":"https://x/y","expire_hours":2}`)}
	sender := &fakeSender{}
	svc := newSvc(store, sender, 5)
	if err := svc.ProcessOne(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if store.status[1] != "sent" || len(sender.sent) != 1 {
		t.Fatalf("expected sent, got %s sent=%v", store.status[1], sender.sent)
	}
}

func TestSendRetryThenFail(t *testing.T) {
	store := newFake()
	store.jobs[1] = &Job{ID: 1, RecipientEmail: "a@x.io", Subject: "s", Template: "invitation", Payload: []byte(`{"username":"u","activation_url":"https://x/z"}`)}
	sender := &fakeSender{err: errors.New("smtp down")}
	svc := newSvc(store, sender, 2)
	// attempt 1 -> attempts=1 < 2 -> pending
	_ = svc.ProcessOne(context.Background(), 1)
	if store.status[1] != "pending" {
		t.Fatalf("attempt1 expected pending, got %s", store.status[1])
	}
	// attempt 2 -> attempts=2 >= 2 -> failed
	_ = svc.ProcessOne(context.Background(), 1)
	if store.status[1] != "failed" {
		t.Fatalf("attempt2 expected failed, got %s", store.status[1])
	}
}

func TestUnknownTemplateFails(t *testing.T) {
	store := newFake()
	store.jobs[1] = &Job{ID: 1, Template: "bogus", Payload: []byte(`{}`)}
	svc := newSvc(store, &fakeSender{}, 1)
	_ = svc.ProcessOne(context.Background(), 1)
	if store.status[1] != "failed" {
		t.Fatalf("expected failed on unknown template, got %s", store.status[1])
	}
}

func TestAlreadySentSkipped(t *testing.T) {
	store := newFake()
	store.jobs[1] = &Job{ID: 1, Template: "password_reset", Payload: []byte(`{}`)}
	store.status[1] = "sent"
	sender := &fakeSender{}
	svc := newSvc(store, sender, 5)
	if err := svc.ProcessOne(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 0 {
		t.Fatalf("already-sent job must not resend")
	}
}
