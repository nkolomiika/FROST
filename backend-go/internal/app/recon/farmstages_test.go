package recon

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
)

// farmClaimRaw — claim прогона фермы с произвольным raw-конфигом (тумблеры стадий).
func farmClaimRaw(id, projectID int32, raw string) *JobClaim {
	return &JobClaim{ID: id, ProjectID: projectID, Kind: KindFarmRun, Raw: raw}
}

// stage_subdomains off → discovery пропускается, поздние стадии работают по
// существующим хостам проекта; stage_ports off → nmap не зовётся; endpoints/js off →
// их сторы не трогаются.
func TestRunFarm_StageToggles_SkipStages(t *testing.T) {
	withFastPoll(t)
	raw := `{"mode":"passive","stage_subdomains":false,"stage_ports":false,"stage_endpoints":false,"stage_js":false}`
	store := &stubStore{
		domainHostnames: []string{"example.com"},
		allHostnames:    []string{"api.example.com"},
		claimByID:       map[int32]*JobClaim{1: farmClaimRaw(1, 7, raw)},
	}
	svc := stubService(store, reconnet.Settings{FarmMaxConcurrency: 2, SubsMaxResults: 100, FarmMaxTargets: 64, PortscanMaxTargets: 64}, Config{WorkerEnabled: true, MaxAttempts: 3, ResultMaxItems: 200})

	collectorCalled := false
	svc.collector = func(context.Context, []string) (map[string]bool, []string, []string) {
		collectorCalled = true
		return map[string]bool{}, nil, nil
	}
	scannerCalled := false
	svc.farmScanner = func(context.Context, string, reconnet.NmapPhase) ([]reconnet.NmapPort, string) {
		scannerCalled = true
		return nil, ""
	}
	epCalled, jsCalled := false, false
	svc.endpointScanner = func(context.Context, string, string, reconnet.EndpointToolConfig) ([]reconnet.EndpointHit, string) {
		epCalled = true
		return nil, ""
	}
	svc.jsMiner = func(context.Context, string) ([]reconnet.ScannedFile, []string) {
		jsCalled = true
		return nil, nil
	}
	// dry-пробив существующего хоста проекта: живой, веб-порт 80.
	svc.dryProber = func(context.Context, string) ([]dryHost, []string) {
		return []dryHost{{hostname: "api.example.com", ip: strp("1.2.3.4"), alive: true, ports: []dryPort{{port: 80, state: stateOPEN, httpStatus: intp(200)}}}}, nil
	}

	if err := svc.RunReconJob(context.Background(), 1); err != nil {
		t.Fatalf("RunReconJob: %v", err)
	}
	if collectorCalled {
		t.Fatal("stage_subdomains off → passive collector must NOT run")
	}
	if scannerCalled {
		t.Fatal("stage_ports off → nmap scanner must NOT run")
	}
	if epCalled {
		t.Fatal("stage_endpoints off → endpoint scanner must NOT run")
	}
	if jsCalled {
		t.Fatal("stage_js off → js miner must NOT run")
	}
	if len(store.stagedEndpointInserts) != 0 || len(store.stagedJsInserts) != 0 {
		t.Fatalf("no endpoint/js staging expected, got %d/%d", len(store.stagedEndpointInserts), len(store.stagedJsInserts))
	}
	// Существующий хост зарезолвлен и застейджен (source=project) для пере-скана.
	if len(store.stagedInserts) != 1 || store.stagedInserts[0].Hostname != "api.example.com" || store.stagedInserts[0].Source != stagedSourceProject {
		t.Fatalf("expected 1 project-sourced staged host, got %+v", store.stagedInserts)
	}
	var res FarmRunResult
	_ = json.Unmarshal(store.doneResults[1], &res)
	if res.RootsScanned != 0 || res.SubdomainsFound != 0 {
		t.Fatalf("subdomains skipped → roots/subs must be 0, got %+v", res)
	}
}

// Стадия эндпоинтов стейджит in-scope URL (дедуп), out-of-scope отбрасывает.
func TestRunFarmEndpoints_StagesInScopeDedup(t *testing.T) {
	store := &stubStore{}
	svc := stubService(store, reconnet.Settings{FarmMaxConcurrency: 3}, Config{})
	svc.endpointScanner = func(_ context.Context, tool, host string, _ reconnet.EndpointToolConfig) ([]reconnet.EndpointHit, string) {
		return []reconnet.EndpointHit{
			{URL: "https://api.example.com/a"},
			{URL: "https://api.example.com/a"}, // дубль
			{URL: "https://evil.com/x"},        // out-of-scope
			{URL: "https://sub.example.com/b"}, // поддомен корня — in-scope
		}, ""
	}
	accums := map[string]*stagedHostAccum{"api.example.com": {hostname: "api.example.com", alive: true}}
	order := []string{"api.example.com"}
	cfg := FarmConfig{Katana: true, Concurrency: 3, CrawlDepth: 2}
	var was atomic.Bool
	prog := newProgressTracker(nil)
	res := newFarmRunResult()

	if canceled := svc.runFarmEndpoints(context.Background(), svc, cfg, svc.settings, []string{"example.com"}, accums, order, 7, 1, prog, res, &was); canceled {
		t.Fatal("unexpected cancel")
	}
	if len(store.stagedEndpointInserts) != 2 {
		t.Fatalf("want 2 in-scope endpoints (dedup, no evil.com), got %d: %+v", len(store.stagedEndpointInserts), store.stagedEndpointInserts)
	}
	seen := map[string]string{}
	for _, e := range store.stagedEndpointInserts {
		seen[e.URL] = e.Host
		if e.Source != "katana" || e.ProjectID != 7 || e.JobID != 1 {
			t.Fatalf("staged endpoint fields wrong: %+v", e)
		}
	}
	if seen["https://api.example.com/a"] != "api.example.com" || seen["https://sub.example.com/b"] != "sub.example.com" {
		t.Fatalf("scoped hosts wrong: %+v", seen)
	}
	if res.EndpointsFound != 2 {
		t.Fatalf("EndpointsFound=%d, want 2", res.EndpointsFound)
	}
}

// Стадия JS стейджит секреты и эндпоинты отдельными строками (kind).
func TestRunFarmJS_StagesSecretsAndEndpoints(t *testing.T) {
	store := &stubStore{}
	svc := stubService(store, reconnet.Settings{FarmMaxConcurrency: 2}, Config{})
	svc.jsMiner = func(_ context.Context, host string) ([]reconnet.ScannedFile, []string) {
		return []reconnet.ScannedFile{{
			Hostname:  host,
			URL:       "https://" + host + "/app.js",
			Secrets:   []reconnet.Secret{{Kind: "aws_access_key", MatchPreview: "AKIAZZ", Severity: "high"}},
			Endpoints: []string{"/api/v1/users"},
		}}, nil
	}
	accums := map[string]*stagedHostAccum{"api.example.com": {hostname: "api.example.com", alive: true}}
	order := []string{"api.example.com"}
	cfg := FarmConfig{Concurrency: 2}
	var was atomic.Bool
	prog := newProgressTracker(nil)
	res := newFarmRunResult()

	if canceled := svc.runFarmJS(context.Background(), svc, cfg, svc.settings, accums, order, 7, 1, prog, res, &was); canceled {
		t.Fatal("unexpected cancel")
	}
	if len(store.stagedJsInserts) != 2 {
		t.Fatalf("want 2 staged js rows (secret+endpoint), got %d", len(store.stagedJsInserts))
	}
	var sawSecret, sawEndpoint bool
	for _, j := range store.stagedJsInserts {
		switch j.Kind {
		case stagedJsSecret:
			sawSecret = true
			if j.Value != "AKIAZZ" || j.Severity == nil || *j.Severity != "high" {
				t.Fatalf("secret row wrong: %+v", j)
			}
		case stagedJsEndpoint:
			sawEndpoint = true
			if j.Value != "/api/v1/users" || j.Severity != nil {
				t.Fatalf("endpoint row wrong: %+v", j)
			}
		}
	}
	if !sawSecret || !sawEndpoint {
		t.Fatalf("both kinds expected, got %+v", store.stagedJsInserts)
	}
	if res.JsFound != 2 {
		t.Fatalf("JsFound=%d, want 2", res.JsFound)
	}
}

// Отсутствие бинаря инструмента → стадия эндпоинтов молча самопропускается (без
// ошибок, без строк), прогон не валится.
func TestRunFarmEndpoints_MissingBinariesSoftSkip(t *testing.T) {
	store := &stubStore{}
	// Реальный путь (endpointScanner=nil) с несуществующими бинарями.
	svc := stubService(store, reconnet.Settings{
		FarmMaxConcurrency: 2,
		KatanaBin:          "frost-no-such-katana",
		GauBin:             "frost-no-such-gau",
		WaybackurlsBin:     "frost-no-such-wayback",
	}, Config{})
	accums := map[string]*stagedHostAccum{"api.example.com": {hostname: "api.example.com", alive: true}}
	order := []string{"api.example.com"}
	cfg := FarmConfig{Katana: true, Gau: true, Waybackurls: true, Concurrency: 2, CrawlDepth: 2}
	var was atomic.Bool
	prog := newProgressTracker(nil)
	res := newFarmRunResult()

	if canceled := svc.runFarmEndpoints(context.Background(), svc, cfg, svc.settings, []string{"example.com"}, accums, order, 7, 1, prog, res, &was); canceled {
		t.Fatal("unexpected cancel")
	}
	if len(store.stagedEndpointInserts) != 0 {
		t.Fatalf("missing binaries → no staged endpoints, got %d", len(store.stagedEndpointInserts))
	}
	if len(res.Errors) != 0 {
		t.Fatalf("soft-skip must not add errors, got %v", res.Errors)
	}
	if res.EndpointsFound != 0 {
		t.Fatalf("EndpointsFound=%d, want 0", res.EndpointsFound)
	}
}

// Отчёт включает staged-эндпоинты и JS + summary-счётчики.
func TestFarmReport_IncludesEndpointsAndJs(t *testing.T) {
	store := &stubStore{
		stagedByJob: map[int32][]StagedHost{5: {{ID: 1, Hostname: "a.com", Alive: true}}},
		stagedEndpointsByJob: map[int32][]StagedEndpoint{
			5: {{ID: 1, Host: "a.com", URL: "https://a.com/x", Source: "gau"}},
		},
		stagedJsByJob: map[int32][]StagedJs{
			5: {
				{ID: 1, Host: "a.com", URL: "https://a.com/app.js", Kind: stagedJsSecret, Value: "AKIA", Severity: strp("high")},
				{ID: 2, Host: "a.com", URL: "https://a.com/app.js", Kind: stagedJsEndpoint, Value: "/y"},
			},
		},
		jobForProject: func(_, jobID int32, _ string) (JobView, error) {
			return JobView{ID: jobID, Status: "done"}, nil
		},
	}
	svc := stubService(store, reconnet.Settings{}, Config{})
	jid := int32(5)
	rep, err := svc.FarmReport(context.Background(), 7, &jid)
	if err != nil {
		t.Fatalf("FarmReport: %v", err)
	}
	if len(rep.Endpoints) != 1 || rep.Summary.EndpointsTotal != 1 {
		t.Fatalf("endpoints array/summary wrong: %+v / %+v", rep.Endpoints, rep.Summary)
	}
	if len(rep.Js) != 2 || rep.Summary.JsTotal != 2 {
		t.Fatalf("js array/summary wrong: %+v / %+v", rep.Js, rep.Summary)
	}
	// Существующая форма хостов не сломана.
	if rep.Summary.HostsTotal != 1 || len(rep.Hosts) != 1 {
		t.Fatalf("hosts shape changed: %+v", rep.Summary)
	}
}

// Импорт endpoint_ids: создаёт endpoints только для хостов, существующих в проекте;
// прочие пропускаются.
func TestImportStagedEndpoints_OnlyExistingHosts(t *testing.T) {
	store := &stubStore{
		originHostMap: map[string]int32{"a.com": 10},
		stagedEndpointsByID: map[int32]StagedEndpoint{
			1: {ID: 1, Host: "a.com", URL: "https://a.com/x?q=1"},
			2: {ID: 2, Host: "b.com", URL: "https://b.com/y"},                 // хоста нет в проекте
			3: {ID: 3, Host: "a.com", URL: "https://a.com/z", Imported: true}, // уже импортирован
		},
	}
	var captured EndpointImportInput
	store.importEndpointFn = func(in EndpointImportInput) (bool, error) {
		captured = in
		return true, nil
	}
	svc := stubService(store, reconnet.Settings{}, Config{})
	n, err := svc.ImportStagedEndpoints(context.Background(), 7, 99, []int32{1, 2, 3})
	if err != nil {
		t.Fatalf("ImportStagedEndpoints: %v", err)
	}
	if n != 1 {
		t.Fatalf("imported=%d, want 1 (b.com skipped, id3 already imported)", n)
	}
	if store.importEndpointCalls != 1 || captured.HostID != 10 || captured.Path != "/x?q=1" {
		t.Fatalf("ImportEndpoint call wrong: calls=%d in=%+v", store.importEndpointCalls, captured)
	}
	if len(store.markedEndpointsImp) != 1 || store.markedEndpointsImp[0] != 1 {
		t.Fatalf("markedEndpointsImp=%v, want [1]", store.markedEndpointsImp)
	}
}

// Импорт js_ids: группирует по URL, создаёт js_file с секретами+эндпоинтами.
func TestImportStagedJs_GroupsByURL(t *testing.T) {
	store := &stubStore{
		originHostMap: map[string]int32{"a.com": 10},
		stagedJsByID: map[int32]StagedJs{
			1: {ID: 1, Host: "a.com", URL: "https://a.com/app.js", Kind: stagedJsSecret, Value: "AKIA", Severity: strp("high")},
			2: {ID: 2, Host: "a.com", URL: "https://a.com/app.js", Kind: stagedJsEndpoint, Value: "/api"},
			3: {ID: 3, Host: "ghost.com", URL: "https://ghost.com/x.js", Kind: stagedJsSecret, Value: "X"}, // хоста нет
		},
	}
	svc := stubService(store, reconnet.Settings{}, Config{})
	n, err := svc.ImportStagedJs(context.Background(), 7, 99, []int32{1, 2, 3})
	if err != nil {
		t.Fatalf("ImportStagedJs: %v", err)
	}
	if n != 2 {
		t.Fatalf("imported rows=%d, want 2 (ghost.com skipped)", n)
	}
	if len(store.jsFiles) != 1 {
		t.Fatalf("want 1 persisted js_file (grouped by url), got %d", len(store.jsFiles))
	}
	f := store.jsFiles[0]
	if f.HostID != 10 || f.URL != "https://a.com/app.js" || len(f.Secrets) != 1 || len(f.Endpoints) != 1 {
		t.Fatalf("persisted js_file wrong: %+v", f)
	}
	if f.Secrets[0].MatchPreview != "AKIA" || f.Secrets[0].Severity != "high" {
		t.Fatalf("secret carried wrong: %+v", f.Secrets[0])
	}
	if len(store.markedJsImp) != 2 {
		t.Fatalf("markedJsImp=%v, want [1 2]", store.markedJsImp)
	}
}

// Комбинированный импорт возвращает по-типовые счётчики.
func TestImportStagedReport_Combined(t *testing.T) {
	store := &stubStore{
		originHostMap:       map[string]int32{"a.com": 10},
		stagedByID:          map[int32]StagedHost{1: {ID: 1, Hostname: "a.com", Alive: true}},
		stagedEndpointsByID: map[int32]StagedEndpoint{2: {ID: 2, Host: "a.com", URL: "https://a.com/x"}},
		stagedJsByID:        map[int32]StagedJs{3: {ID: 3, Host: "a.com", URL: "https://a.com/app.js", Kind: stagedJsEndpoint, Value: "/y"}},
	}
	svc := stubService(store, reconnet.Settings{}, Config{})
	res, err := svc.ImportStagedReport(context.Background(), 7, 99, []int32{1}, []int32{2}, []int32{3})
	if err != nil {
		t.Fatalf("ImportStagedReport: %v", err)
	}
	if res.ImportedHosts != 1 || res.ImportedEndpoints != 1 || res.ImportedJs != 1 {
		t.Fatalf("combined import counts wrong: %+v", res)
	}
}

// ClearStagedReport чистит все три staged-таблицы и суммирует удалённое.
func TestClearStagedReport_ClearsAllThree(t *testing.T) {
	store := &stubStore{clearStagedN: 2, clearEndpointsN: 3, clearJsN: 5}
	svc := stubService(store, reconnet.Settings{}, Config{})
	jid := int32(9)
	n, err := svc.ClearStagedReport(context.Background(), 7, &jid)
	if err != nil {
		t.Fatalf("ClearStagedReport: %v", err)
	}
	if n != 10 {
		t.Fatalf("cleared total=%d, want 10 (2+3+5)", n)
	}
}
