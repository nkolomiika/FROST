package recon

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
)

func TestParseRunConfig(t *testing.T) {
	// Пусто → дефолты (mode=both).
	if got := parseRunConfig(""); got.Mode != "both" || got.WordlistSize != "medium" {
		t.Fatalf("empty raw → %+v, want defaults", got)
	}
	// Валидный JSON накладывается поверх дефолтов.
	got := parseRunConfig(`{"mode":"passive","port_scan_scope":"all"}`)
	if got.Mode != "passive" || got.PortScanScope != "all" {
		t.Fatalf("overrides not applied: %+v", got)
	}
	if !got.Subfinder { // непереданное поле осталось дефолтным
		t.Fatalf("default tool flag lost: %+v", got)
	}
	// Битый JSON → дефолты, без паники.
	if got := parseRunConfig("{not json"); got.Mode != "both" {
		t.Fatalf("bad json → %+v, want defaults", got)
	}
}

func TestRunSettings_PortScopeAndConcurrency(t *testing.T) {
	svc := stubService(&stubStore{}, reconnet.Settings{FarmMaxConcurrency: 1, PortscanTopPorts: 1000}, Config{})

	top := svc.runSettings(FarmConfig{PortScanScope: "top1000", Concurrency: 7})
	if top.PortscanTopPorts != 1000 {
		t.Errorf("top1000 → PortscanTopPorts=%d, want 1000", top.PortscanTopPorts)
	}
	if top.FarmMaxConcurrency != 7 {
		t.Errorf("concurrency override = %d, want 7", top.FarmMaxConcurrency)
	}
	all := svc.runSettings(FarmConfig{PortScanScope: "all", Concurrency: 3})
	if all.PortscanTopPorts != 0 {
		t.Errorf("all scope → PortscanTopPorts=%d, want 0 (-p-)", all.PortscanTopPorts)
	}
}

func TestProgressTracker_SnapshotAndConcurrentSteps(t *testing.T) {
	var mu sync.Mutex
	var last RunProgress
	tr := newProgressTracker(func(blob []byte) {
		mu.Lock()
		defer mu.Unlock()
		_ = json.Unmarshal(blob, &last)
	})
	tr.update(func(p *RunProgress) { p.Stage = "subdomains"; p.Percent = 5 })

	// Два одновременных шага (пассив + актив) видны вместе.
	a := tr.addStep(RunStep{Tool: "subfinder", Args: "subfinder -d x -silent", Target: "x"})
	b := tr.addStep(RunStep{Tool: "dnsx", Args: "dnsx -d x -w wl", Target: "x"})
	mu.Lock()
	snap := last
	mu.Unlock()
	if len(snap.Steps) != 2 {
		t.Fatalf("want 2 concurrent steps, got %d", len(snap.Steps))
	}
	tools := snap.Steps[0].Tool + "," + snap.Steps[1].Tool
	if !strings.Contains(tools, "subfinder") || !strings.Contains(tools, "dnsx") {
		t.Fatalf("both tools should be present: %q", tools)
	}
	tr.removeStep(a)
	tr.removeStep(b)
	mu.Lock()
	defer mu.Unlock()
	if len(last.Steps) != 0 {
		t.Fatalf("steps not cleared: %d", len(last.Steps))
	}
	if last.Stage != "subdomains" || last.Percent != 5 {
		t.Fatalf("stage/percent lost across step churn: %+v", last)
	}
}

func TestRunSubdomains_PassiveAndActiveConcurrent(t *testing.T) {
	svc := stubService(&stubStore{}, reconnet.Settings{FarmMaxConcurrency: 4, SubsMaxResults: 100}, Config{})
	// Инъекция пассивного сборщика (dnsx-брут в тесте недоступен — деградирует).
	svc.collector = func(_ context.Context, roots []string) (map[string]bool, []string, []string) {
		out := map[string]bool{}
		for _, r := range roots {
			out["api."+r] = true
		}
		return out, []string{"subfinder"}, nil
	}

	// Захватываем все снимки, чтобы убедиться, что пассивный шаг был активен.
	var mu sync.Mutex
	sawSubfinderStep := false
	tr := newProgressTracker(func(blob []byte) {
		var p RunProgress
		if json.Unmarshal(blob, &p) != nil {
			return
		}
		mu.Lock()
		for _, st := range p.Steps {
			if st.Tool == "subfinder" {
				sawSubfinderStep = true
			}
		}
		mu.Unlock()
	})

	cfg := FarmConfig{Mode: "both", WordlistSize: "medium", Concurrency: 4}
	rs := svc.runSettings(cfg)
	subs, sources, errs := svc.runSubdomains(context.Background(), svc, cfg, rs, []string{"example.com"}, tr)

	if !subs["api.example.com"] {
		t.Fatalf("passive subs missing: %v", subs)
	}
	if len(sources) == 0 {
		t.Fatalf("sources empty")
	}
	// В "both" при отсутствии словаря брут пропускается с мягкой пометкой.
	if !containsSubstr(errs, "dnsx-брут пропущен") {
		t.Fatalf("expected soft skip note for missing wordlist, got %v", errs)
	}
	if !sawSubfinderStep {
		t.Fatalf("passive subfinder step was never surfaced in progress")
	}
}

func containsSubstr(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
