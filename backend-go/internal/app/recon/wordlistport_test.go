package recon

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
)

// fakeMaterializer — сид WordlistMaterializer для тестов.
type fakeMaterializer struct {
	lastCustomID int
	lastTier     string
	cleaned      atomic.Bool
	err          error
	path         string
}

func (f *fakeMaterializer) Materialize(_ context.Context, customID int, tier string) (string, func(), error) {
	f.lastCustomID = customID
	f.lastTier = tier
	if f.err != nil {
		return "", nil, f.err
	}
	return f.path, func() { f.cleaned.Store(true) }, nil
}

// resolveWordlist без материализатора → бандл-путь тира, cleanup — no-op, без ошибки.
func TestResolveWordlist_NilMaterializerFallsBackToTier(t *testing.T) {
	t.Setenv("RECON_WORDLIST_DIR", "/wl")
	svc := stubService(&stubStore{}, reconnet.Settings{}, Config{})
	path, cleanup, softErr := svc.resolveWordlist(context.Background(), 7, "large")
	defer cleanup()
	if softErr != "" {
		t.Fatalf("nil materializer should not error: %q", softErr)
	}
	if path != "/wl/n0kovo_subdomains_huge.txt" {
		t.Fatalf("fallback tier path wrong: %q", path)
	}
}

// resolveWordlist делегирует материализатору (кастомный id → его путь).
func TestResolveWordlist_DelegatesToMaterializer(t *testing.T) {
	svc := stubService(&stubStore{}, reconnet.Settings{}, Config{})
	fm := &fakeMaterializer{path: "/tmp/frost-wordlist-x.txt"}
	svc.AttachWordlists(fm)
	path, cleanup, softErr := svc.resolveWordlist(context.Background(), 9, "medium")
	if softErr != "" {
		t.Fatalf("unexpected soft err: %q", softErr)
	}
	if path != "/tmp/frost-wordlist-x.txt" || fm.lastCustomID != 9 || fm.lastTier != "medium" {
		t.Fatalf("delegation wrong: path=%q id=%d tier=%q", path, fm.lastCustomID, fm.lastTier)
	}
	cleanup()
	if !fm.cleaned.Load() {
		t.Fatal("cleanup not propagated")
	}
}

// Ошибка материализации кастомного словаря → мягкая деградация к бандл-тиру.
func TestResolveWordlist_ErrorFallsBackWithSoftErr(t *testing.T) {
	t.Setenv("RECON_WORDLIST_DIR", "/wl")
	svc := stubService(&stubStore{}, reconnet.Settings{}, Config{})
	svc.AttachWordlists(&fakeMaterializer{err: errors.New("minio down")})
	path, cleanup, softErr := svc.resolveWordlist(context.Background(), 3, "small")
	defer cleanup()
	if softErr == "" {
		t.Fatal("expected soft error on materialize failure")
	}
	if path != "/wl/n0kovo_subdomains_small.txt" {
		t.Fatalf("fallback path wrong: %q", path)
	}
}

// runFarmEndpoints в active-режиме с кастомным словарём материализует ffuf-словарь,
// гоняет ffuf через seam и стейджит его находки; cleanup вызывается по завершении.
func TestRunFarmEndpoints_FfufActiveMode(t *testing.T) {
	store := &stubStore{}
	svc := stubService(store, reconnet.Settings{FarmMaxConcurrency: 2}, Config{})
	fm := &fakeMaterializer{path: "/tmp/frost-wordlist-ffuf.txt"}
	svc.AttachWordlists(fm)

	var gotFfufWL string
	svc.endpointScanner = func(_ context.Context, tool, host string, cfg reconnet.EndpointToolConfig) ([]reconnet.EndpointHit, string) {
		if tool == "ffuf" {
			gotFfufWL = cfg.FfufWordlist
			return []reconnet.EndpointHit{{URL: "https://api.example.com/admin", Source: "ffuf"}}, ""
		}
		if tool == "katana" {
			return []reconnet.EndpointHit{{URL: "https://api.example.com/crawled", Source: "katana"}}, ""
		}
		return nil, ""
	}

	accums := map[string]*stagedHostAccum{"api.example.com": {hostname: "api.example.com", alive: true}}
	order := []string{"api.example.com"}
	cfg := FarmConfig{
		Katana:              true,
		EndpointsMode:       "active",
		EndpointsWordlistID: 12,
		Concurrency:         2,
		CrawlDepth:          2,
	}
	var was atomic.Bool
	prog := newProgressTracker(nil)
	res := newFarmRunResult()

	if canceled := svc.runFarmEndpoints(context.Background(), svc, cfg, svc.settings, []string{"example.com"}, accums, order, 7, 1, prog, res, &was); canceled {
		t.Fatal("unexpected cancel")
	}
	// Материализатор вызван с кастомным id и путь проброшен в ffuf.
	if fm.lastCustomID != 12 {
		t.Fatalf("materialize custom id = %d, want 12", fm.lastCustomID)
	}
	if gotFfufWL != "/tmp/frost-wordlist-ffuf.txt" {
		t.Fatalf("ffuf wordlist path not passed: %q", gotFfufWL)
	}
	if !fm.cleaned.Load() {
		t.Fatal("ffuf wordlist temp not cleaned up")
	}
	// Оба инструмента active-режима застейджены (katana + ffuf), пассивных нет.
	sources := map[string]bool{}
	for _, e := range store.stagedEndpointInserts {
		sources[e.Source] = true
	}
	if !sources["ffuf"] || !sources["katana"] {
		t.Fatalf("active tools not staged: %+v", store.stagedEndpointInserts)
	}
}
