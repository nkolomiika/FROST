package recon

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
)

// fakeBreachSource — сид breach-источника для стадии утечек. enabled решает
// активность; block заставляет Search висеть на ctx (для теста отмены).
type fakeBreachSource struct {
	name    string
	enabled bool
	leaks   []reconnet.BreachLeak
	block   bool

	mu    sync.Mutex
	calls []reconnet.BreachTarget
}

func (f *fakeBreachSource) Name() string                     { return f.name }
func (f *fakeBreachSource) Enabled(reconnet.BreachKeys) bool { return f.enabled }
func (f *fakeBreachSource) Search(ctx context.Context, t reconnet.BreachTarget) ([]reconnet.BreachLeak, error) {
	f.mu.Lock()
	f.calls = append(f.calls, t)
	f.mu.Unlock()
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.leaks, nil
}

func (f *fakeBreachSource) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// Стадия утечек: github-скан + активные breach-источники пишут в единое хранилище
// (один вызов sink); неактивный источник (нет ключа) мягко самопропускается с
// пометкой и НЕ вызывается.
func TestRunFarmLeaks_GithubAndBreachSources(t *testing.T) {
	store := &stubStore{}
	svc := stubService(store, reconnet.Settings{FarmMaxConcurrency: 4}, Config{})
	sink := &fakeSink{}
	svc.AttachLeaks(fakeResolver{token: "ghp_xxx", ok: true}, sink)

	var gotToken, gotEmailToken string
	svc.githubScan = func(_ context.Context, target, token string) ([]reconnet.GithubSecret, error) {
		gotToken = token
		return []reconnet.GithubSecret{{Detector: "AWS", Verified: true, Raw: "AKIA", Repo: target, File: "cfg.yml"}}, nil
	}
	svc.githubEmailScan = func(_ context.Context, _, token string) ([]reconnet.GithubEmail, []string, error) {
		gotEmailToken = token
		return []reconnet.GithubEmail{{Email: "dev@corp.com", Name: "Dev", Repos: []string{"owner/repo"}}}, nil, nil
	}
	enabledSrc := &fakeBreachSource{name: "hibp", enabled: true, leaks: []reconnet.BreachLeak{
		{Source: "hibp", Kind: "account", Subject: "a@b.com", Detail: map[string]any{"breach": "Adobe"}},
	}}
	disabledSrc := &fakeBreachSource{name: "dehashed", enabled: false}
	svc.breachSources = func(reconnet.BreachKeys) []reconnet.BreachSource {
		return []reconnet.BreachSource{enabledSrc, disabledSrc}
	}

	cfg := FarmConfig{
		Concurrency:        4,
		StageLeaks:         true,
		StageAccountSearch: true,
		LeaksGithub:        []string{"https://github.com/owner/repo"},
		LeaksDomains:       []string{"b.com"},
		LeaksEmails:        []string{"a@b.com"},
	}
	var was atomic.Bool
	prog := newProgressTracker(nil)
	res := newFarmRunResult()

	if canceled := svc.runFarmLeaks(context.Background(), svc, cfg, 7, 1, prog, res, &was); canceled {
		t.Fatal("unexpected cancel")
	}

	if gotToken != "ghp_xxx" {
		t.Fatalf("github token not passed: %q", gotToken)
	}
	if gotEmailToken != "ghp_xxx" {
		t.Fatalf("github email token not passed: %q", gotEmailToken)
	}
	// 1 github secret + 1 github account email + 2 breach (enabled src × {domain,email})
	// = 4 записи, один sink-вызов.
	if sink.called != 1 {
		t.Fatalf("sink must be called once, got %d", sink.called)
	}
	if len(sink.recs) != 4 {
		t.Fatalf("want 4 leak records, got %d: %+v", len(sink.recs), sink.recs)
	}
	if sink.projectID != 7 || sink.jobID == nil || *sink.jobID != 1 {
		t.Fatalf("wrong scope: project=%d jobID=%v", sink.projectID, sink.jobID)
	}
	// активный источник опрошен по обеим целям, неактивный не тронут.
	if enabledSrc.callCount() != 2 {
		t.Fatalf("enabled source must be called for 2 targets, got %d", enabledSrc.callCount())
	}
	if disabledSrc.callCount() != 0 {
		t.Fatalf("disabled source must not be called, got %d", disabledSrc.callCount())
	}
	// мягкая пометка о пропуске источника без ключа.
	if !containsSubstr(res.Errors, "dehashed пропущен") {
		t.Fatalf("expected soft skip note for keyless source, got %v", res.Errors)
	}
	// проверяем присутствие source и КОНКРЕТНОГО РЕСУРСА-ИСТОЧНИКА в записях.
	var sawSecret, sawAccount, sawHIBP bool
	for _, r := range sink.recs {
		switch r.Source {
		case "github":
			switch r.Kind {
			case "secret":
				sawSecret = true
				if r.Value != "AKIA" || !r.Verified {
					t.Fatalf("github secret record wrong: %+v", r)
				}
				// ресурс-источник секрета: repo+file.
				if r.Detail["repo"] == nil || r.Detail["file"] != "cfg.yml" {
					t.Fatalf("github secret detail missing resource: %+v", r.Detail)
				}
			case "account":
				sawAccount = true
				if r.Subject != "dev@corp.com" || r.Value != "" || r.Verified {
					t.Fatalf("github account record wrong: %+v", r)
				}
				// ресурс-источник аккаунта: repo, где почта засветилась.
				if r.Detail["repo"] != "owner/repo" {
					t.Fatalf("github account detail missing repo: %+v", r.Detail)
				}
			default:
				t.Fatalf("unexpected github kind: %+v", r)
			}
		case "hibp":
			sawHIBP = true
			if r.Kind != "account" || r.Subject != "a@b.com" || r.Verified {
				t.Fatalf("hibp record wrong: %+v", r)
			}
		}
	}
	if !sawSecret || !sawAccount || !sawHIBP {
		t.Fatalf("secret+account+hibp expected in records: %+v", sink.recs)
	}
	if res.LeaksFound != 4 {
		t.Fatalf("LeaksFound=%d, want 4", res.LeaksFound)
	}
}

// Контекст leaks не подключён → стадия мягко пропускается (без паники, без sink).
func TestRunFarmLeaks_NoLeaksContextSoftSkips(t *testing.T) {
	svc := stubService(&stubStore{}, reconnet.Settings{}, Config{})
	cfg := FarmConfig{LeaksDomains: []string{"b.com"}}
	var was atomic.Bool
	res := newFarmRunResult()
	if canceled := svc.runFarmLeaks(context.Background(), svc, cfg, 7, 1, newProgressTracker(nil), res, &was); canceled {
		t.Fatal("unexpected cancel")
	}
	if !containsSubstr(res.Errors, "контекст leaks не подключён") {
		t.Fatalf("expected soft-skip note, got %v", res.Errors)
	}
}

// Отмена во время стадии утечек: блокирующий источник обрывается по ctx →
// runFarmLeaks возвращает true (прогон уходит в cancelled).
func TestRunFarmLeaks_CancelReturnsTrue(t *testing.T) {
	svc := stubService(&stubStore{}, reconnet.Settings{FarmMaxConcurrency: 2}, Config{})
	svc.AttachLeaks(fakeResolver{ok: true}, &fakeSink{})
	svc.breachSources = func(reconnet.BreachKeys) []reconnet.BreachSource {
		return []reconnet.BreachSource{&fakeBreachSource{name: "hibp", enabled: true, block: true}}
	}
	cfg := FarmConfig{Concurrency: 2, StageAccountSearch: true, LeaksDomains: []string{"b.com"}}

	ctx, cancel := context.WithCancel(context.Background())
	var was atomic.Bool
	was.Store(true) // имитируем сигнал отмены всего прогона
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()

	canceled := svc.runFarmLeaks(ctx, svc, cfg, 7, 1, newProgressTracker(nil), newFarmRunResult(), &was)
	if !canceled {
		t.Fatal("expected runFarmLeaks to report cancel")
	}
}

// End-to-end через runFarm: stage_leaks гоняет github-скан и стейджит утечку в sink
// с тем же job_id/project_id, что и прогон.
func TestRunFarm_LeaksStageWiredIn(t *testing.T) {
	withFastPoll(t)
	raw := `{"mode":"passive","stage_subdomains":false,"stage_ports":false,"stage_endpoints":false,"stage_js":false,"stage_leaks":true,"leaks_github":["https://github.com/owner/repo"]}`
	store := &stubStore{
		domainHostnames: []string{"example.com"},
		allHostnames:    []string{"api.example.com"},
		claimByID:       map[int32]*JobClaim{1: farmClaimRaw(1, 7, raw)},
	}
	svc := stubService(store, reconnet.Settings{FarmMaxConcurrency: 2, SubsMaxResults: 100, FarmMaxTargets: 64, PortscanMaxTargets: 64}, Config{WorkerEnabled: true, MaxAttempts: 3, ResultMaxItems: 200})
	sink := &fakeSink{}
	svc.AttachLeaks(fakeResolver{ok: false}, sink) // токенов/ключей нет
	svc.githubScan = func(_ context.Context, target, _ string) ([]reconnet.GithubSecret, error) {
		return []reconnet.GithubSecret{{Detector: "AWS", Verified: false, Raw: "AKIA", Repo: target}}, nil
	}
	// email-майнинг засеян пустым — стадия остаётся герметичной (без сети).
	svc.githubEmailScan = func(_ context.Context, _, _ string) ([]reconnet.GithubEmail, []string, error) {
		return nil, nil, nil
	}

	if err := svc.RunReconJob(context.Background(), 1); err != nil {
		t.Fatalf("RunReconJob: %v", err)
	}
	if sink.called != 1 || len(sink.recs) != 1 {
		t.Fatalf("expected github leak staged, got called=%d recs=%d", sink.called, len(sink.recs))
	}
	if sink.projectID != 7 || sink.jobID == nil || *sink.jobID != 1 {
		t.Fatalf("leak not staged under run scope: project=%d job=%v", sink.projectID, sink.jobID)
	}
	if sink.recs[0].Source != "github" {
		t.Fatalf("unexpected leak source: %+v", sink.recs[0])
	}
}
