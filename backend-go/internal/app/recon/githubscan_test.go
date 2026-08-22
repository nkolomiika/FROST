package recon

import (
	"context"
	"encoding/json"
	"testing"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
)

// fakeResolver — сид резолвера интеграций (github_token).
type fakeResolver struct {
	token string
	ok    bool
}

func (f fakeResolver) GetIntegrationKey(context.Context, string) (string, bool, error) {
	return f.token, f.ok, nil
}

// fakeSink — сид приёмника утечек: захватывает записанное.
type fakeSink struct {
	projectID int32
	jobID     *int32
	recs      []LeakRecord
	called    int
}

func (f *fakeSink) WriteLeaks(_ context.Context, projectID int32, jobID *int32, recs []LeakRecord) error {
	f.called++
	f.projectID = projectID
	f.jobID = jobID
	f.recs = recs
	return nil
}

// github_scan-задача: сид trufflehog возвращает находки → они пишутся в единое
// хранилище утечек (source=github), а job помечается done с корректным result.
func TestRunGithubScan_StagesParsedLeaks(t *testing.T) {
	store := &stubStore{claimByID: map[int32]*JobClaim{
		1: {ID: 1, ProjectID: 7, CreatedBy: 3, Kind: KindGithubScan, Raw: "https://github.com/owner/repo"},
	}}
	svc := stubService(store, reconnet.Settings{}, Config{WorkerEnabled: true, MaxAttempts: 3, ResultMaxItems: 200})

	sink := &fakeSink{}
	svc.AttachLeaks(fakeResolver{token: "ghp_xxx", ok: true}, sink)

	var gotToken, gotTarget string
	svc.githubScan = func(_ context.Context, target, token string) ([]reconnet.GithubSecret, error) {
		gotTarget, gotToken = target, token
		return []reconnet.GithubSecret{
			{Detector: "AWS", Verified: true, Raw: "AKIA...", Repo: "https://github.com/owner/repo", File: "cfg.yml", Link: "https://github.com/owner/repo/blob/x/cfg.yml"},
			{Detector: "Generic", Verified: false, Raw: "token123", Repo: "https://github.com/owner/repo", File: "app.js"},
		}, nil
	}

	if err := svc.RunReconJob(context.Background(), 1); err != nil {
		t.Fatalf("RunReconJob: %v", err)
	}

	// токен и цель прокинуты в сканер
	if gotToken != "ghp_xxx" {
		t.Fatalf("token not passed to scanner: %q", gotToken)
	}
	if gotTarget != "https://github.com/owner/repo" {
		t.Fatalf("target not passed: %q", gotTarget)
	}

	// находки записаны в единое хранилище утечек
	if sink.called != 1 || len(sink.recs) != 2 {
		t.Fatalf("expected 2 leaks written, got called=%d recs=%d", sink.called, len(sink.recs))
	}
	if sink.projectID != 7 || sink.jobID == nil || *sink.jobID != 1 {
		t.Fatalf("wrong scope: project=%d jobID=%v", sink.projectID, sink.jobID)
	}
	r0 := sink.recs[0]
	if r0.Source != "github" || r0.Kind != "secret" || r0.Value != "AKIA..." || r0.Subject != "https://github.com/owner/repo" || !r0.Verified {
		t.Fatalf("unexpected first leak: %+v", r0)
	}
	if r0.Detail["detector"] != "AWS" || r0.Detail["file"] != "cfg.yml" {
		t.Fatalf("detail missing github fields: %+v", r0.Detail)
	}

	// job помечен done, result содержит счётчики
	blob, ok := store.doneResults[1]
	if !ok {
		t.Fatalf("job not marked done")
	}
	var res githubScanResult
	if err := json.Unmarshal(blob, &res); err != nil {
		t.Fatalf("result json: %v", err)
	}
	if res.Total != 2 || res.Verified != 1 {
		t.Fatalf("unexpected result: %+v", res)
	}
}

// Без github_token скан идёт анонимно (пустой токен передаётся в сканер).
func TestRunGithubScan_NoToken_Anonymous(t *testing.T) {
	store := &stubStore{claimByID: map[int32]*JobClaim{
		1: {ID: 1, ProjectID: 7, CreatedBy: 3, Kind: KindGithubScan, Raw: "https://github.com/org"},
	}}
	svc := stubService(store, reconnet.Settings{}, Config{WorkerEnabled: true, MaxAttempts: 3, ResultMaxItems: 200})
	sink := &fakeSink{}
	svc.AttachLeaks(fakeResolver{ok: false}, sink) // токен не задан

	var gotToken = "sentinel"
	svc.githubScan = func(_ context.Context, _, token string) ([]reconnet.GithubSecret, error) {
		gotToken = token
		return nil, nil
	}
	if err := svc.RunReconJob(context.Background(), 1); err != nil {
		t.Fatalf("RunReconJob: %v", err)
	}
	if gotToken != "" {
		t.Fatalf("expected empty token for anonymous scan, got %q", gotToken)
	}
	if sink.called != 1 || len(sink.recs) != 0 {
		t.Fatalf("expected sink called with 0 recs, got called=%d recs=%d", sink.called, len(sink.recs))
	}
}

// Валидация цели: createGithubScanJob отвергает не-github URL.
func TestCreateGithubScanJob_RejectsNonGithub(t *testing.T) {
	store := &stubStore{}
	svc := stubService(store, reconnet.Settings{}, Config{WorkerEnabled: true, MaxAttempts: 3})
	if _, err := svc.CreateJob(context.Background(), KindGithubScan, 7, 3, "https://gitlab.com/owner/repo"); err == nil {
		t.Fatal("expected validation error for non-github URL")
	}
}
