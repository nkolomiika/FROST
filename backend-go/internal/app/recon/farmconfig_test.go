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
	if c.Mode != "active" {
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
