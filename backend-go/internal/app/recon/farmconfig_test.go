package recon

import (
	"encoding/json"
	"testing"
)

func TestFarmConfigRoundTrip(t *testing.T) {
	want := DefaultFarmConfig()
	blob, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := DefaultFarmConfig()
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != want {
		t.Fatalf("round-trip mismatch:\n got=%+v\nwant=%+v", got, want)
	}
}

func TestFarmConfigDefaultsOverMissingFields(t *testing.T) {
	// Только одно поле в сохранённом блобе — остальные должны остаться дефолтными.
	cfg := DefaultFarmConfig()
	if err := json.Unmarshal([]byte(`{"mode":"passive"}`), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.Mode != "passive" {
		t.Fatalf("mode not applied: %q", cfg.Mode)
	}
	if cfg.RateLimit != 20 || cfg.Concurrency != 10 || !cfg.Subfinder || cfg.KatanaDepth != 3 {
		t.Fatalf("defaults not preserved: %+v", cfg)
	}
	// Высокоуровневые ручки тоже должны остаться дефолтными.
	if cfg.WordlistSize != "medium" || cfg.PortScanScope != "top1000" || cfg.CrawlDepth != 3 {
		t.Fatalf("high-level defaults not preserved: %+v", cfg)
	}
}

func TestFarmConfigDefaults_HighLevelKnobs(t *testing.T) {
	c := DefaultFarmConfig()
	if c.Mode != "both" {
		t.Fatalf("default mode = %q, want both", c.Mode)
	}
	if c.WordlistSize != "medium" {
		t.Fatalf("default wordlist_size = %q, want medium", c.WordlistSize)
	}
	if c.PortScanScope != "top1000" {
		t.Fatalf("default port_scan_scope = %q, want top1000", c.PortScanScope)
	}
	if c.RateLimit != 20 || c.Concurrency != 10 || c.CrawlDepth != 3 {
		t.Fatalf("numeric defaults off: %+v", c)
	}
}

func TestFarmConfigSanitize_HighLevelKnobs(t *testing.T) {
	c := FarmConfig{Mode: "both", WordlistSize: "bogus", PortScanScope: "bogus", CrawlDepth: 99}
	c.Sanitize()
	if c.Mode != "both" {
		t.Fatalf("both mode dropped: %q", c.Mode)
	}
	if c.WordlistSize != "medium" {
		t.Fatalf("wordlist_size not normalized: %q", c.WordlistSize)
	}
	if c.PortScanScope != "top1000" {
		t.Fatalf("port_scan_scope not normalized: %q", c.PortScanScope)
	}
	if c.CrawlDepth != 10 {
		t.Fatalf("crawl_depth not clamped: %d", c.CrawlDepth)
	}
	// Валидные значения сохраняются.
	ok := FarmConfig{Mode: "passive", WordlistSize: "large", PortScanScope: "all", CrawlDepth: 1}
	ok.Sanitize()
	if ok.Mode != "passive" || ok.WordlistSize != "large" || ok.PortScanScope != "all" || ok.CrawlDepth != 1 {
		t.Fatalf("valid high-level values altered: %+v", ok)
	}
}

func TestFarmConfigDefaults_WordlistAndEndpointsMode(t *testing.T) {
	c := DefaultFarmConfig()
	if c.SubdomainWordlistID != 0 || c.EndpointsWordlistID != 0 {
		t.Fatalf("default wordlist ids must be 0: %+v", c)
	}
	if c.EndpointsMode != "both" {
		t.Fatalf("default endpoints_mode = %q, want both", c.EndpointsMode)
	}
}

func TestFarmConfig_BackCompatMissingNewFields(t *testing.T) {
	// Старый сохранённый блоб без новых ключей → дефолты доклеиваются.
	cfg := DefaultFarmConfig()
	if err := json.Unmarshal([]byte(`{"mode":"active"}`), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.EndpointsMode != "both" || cfg.SubdomainWordlistID != 0 || cfg.EndpointsWordlistID != 0 {
		t.Fatalf("new fields not defaulted on old blob: %+v", cfg)
	}
}

func TestFarmConfigSanitize_WordlistAndEndpointsMode(t *testing.T) {
	c := FarmConfig{EndpointsMode: "bogus", SubdomainWordlistID: -3, EndpointsWordlistID: -1}
	c.Sanitize()
	if c.EndpointsMode != "both" {
		t.Fatalf("endpoints_mode not normalized: %q", c.EndpointsMode)
	}
	if c.SubdomainWordlistID != 0 || c.EndpointsWordlistID != 0 {
		t.Fatalf("negative ids not clamped: %+v", c)
	}
	// Валидные значения сохраняются.
	ok := FarmConfig{EndpointsMode: "active", SubdomainWordlistID: 5, EndpointsWordlistID: 7}
	ok.Sanitize()
	if ok.EndpointsMode != "active" || ok.SubdomainWordlistID != 5 || ok.EndpointsWordlistID != 7 {
		t.Fatalf("valid wordlist/mode values altered: %+v", ok)
	}
}

func TestEndpointTools_ModeSelection(t *testing.T) {
	base := FarmConfig{Katana: true, Gau: true, Waybackurls: true}

	both := base
	both.EndpointsMode = "both"
	both.EndpointsWordlistID = 4
	if got := endpointTools(both); !hasAll(got, "katana", "gau", "waybackurls", "ffuf") {
		t.Fatalf("both mode tools wrong: %v", got)
	}

	passive := base
	passive.EndpointsMode = "passive"
	passive.EndpointsWordlistID = 4 // ffuf активный — в passive НЕ включается
	got := endpointTools(passive)
	if hasAny(got, "katana", "ffuf") || !hasAll(got, "gau", "waybackurls") {
		t.Fatalf("passive mode tools wrong: %v", got)
	}

	active := base
	active.EndpointsMode = "active"
	active.EndpointsWordlistID = 4
	got = endpointTools(active)
	if hasAny(got, "gau", "waybackurls") || !hasAll(got, "katana", "ffuf") {
		t.Fatalf("active mode tools wrong: %v", got)
	}

	// active без кастомного словаря эндпоинтов → ffuf пропускается (бандл-тиры не
	// годятся для дир-фаззинга).
	activeNoWL := base
	activeNoWL.EndpointsMode = "active"
	activeNoWL.EndpointsWordlistID = 0
	if hasAny(endpointTools(activeNoWL), "ffuf") {
		t.Fatalf("ffuf must be skipped without custom endpoints wordlist: %v", endpointTools(activeNoWL))
	}

	// Пустой mode (старый конфиг) → both.
	empty := base
	empty.EndpointsMode = ""
	if !hasAll(endpointTools(empty), "katana", "gau", "waybackurls") {
		t.Fatalf("empty mode should default to both: %v", endpointTools(empty))
	}
}

func hasAll(got []string, want ...string) bool {
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

func hasAny(got []string, want ...string) bool {
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	for _, w := range want {
		if set[w] {
			return true
		}
	}
	return false
}

func TestFarmConfigSanitizeClamps(t *testing.T) {
	c := FarmConfig{
		Mode:           "bogus",
		RateLimit:      100000,
		Concurrency:    -5,
		KatanaDepth:    99,
		SubsMaxResults: 0,
		HttpxThreads:   99999,
	}
	c.Sanitize()
	if c.Mode != "both" {
		t.Fatalf("mode not normalized: %q", c.Mode)
	}
	if c.RateLimit != 500 {
		t.Fatalf("rate_limit not clamped: %d", c.RateLimit)
	}
	if c.Concurrency != 1 {
		t.Fatalf("concurrency not clamped: %d", c.Concurrency)
	}
	if c.KatanaDepth != 10 {
		t.Fatalf("katana_depth not clamped: %d", c.KatanaDepth)
	}
	if c.SubsMaxResults != 1 {
		t.Fatalf("subs_max_results not clamped: %d", c.SubsMaxResults)
	}
	if c.HttpxThreads != 1000 {
		t.Fatalf("httpx_threads not clamped: %d", c.HttpxThreads)
	}

	// Валидный passive-режим сохраняется.
	p := DefaultFarmConfig()
	p.Mode = "passive"
	p.Sanitize()
	if p.Mode != "passive" {
		t.Fatalf("passive mode dropped: %q", p.Mode)
	}
}
