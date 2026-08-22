package recon

import (
	"context"
	"strings"
	"testing"
	"time"
)

// KatanaArgs строит корректную команду (глубина, rate-limit, крауль JS).
func TestKatanaArgs(t *testing.T) {
	got := strings.Join(KatanaArgs("example.com", EndpointToolConfig{CrawlDepth: 3, RateLimit: 20}), " ")
	for _, want := range []string{"-u https://example.com", "-d 3", "-jc", "-silent", "-rl 20"} {
		if !strings.Contains(got, want) {
			t.Fatalf("katana args missing %q: %s", want, got)
		}
	}
	// depth<1 зажимается в 1; rate=0 не добавляет -rl.
	got = strings.Join(KatanaArgs("x.com", EndpointToolConfig{CrawlDepth: 0}), " ")
	if !strings.Contains(got, "-d 1") || strings.Contains(got, "-rl") {
		t.Fatalf("depth clamp / no-rl wrong: %s", got)
	}
}

// Нет бинаря → инструменты стадии эндпоинтов молча самопропускаются (nil, "").
func TestEndpointTools_MissingBinarySoftSkip(t *testing.T) {
	s := Settings{
		KatanaBin:        "frost-no-such-katana",
		GauBin:           "frost-no-such-gau",
		WaybackurlsBin:   "frost-no-such-wayback",
		EndpointsTimeout: 2 * time.Second,
	}
	ctx := context.Background()
	if hits, e := KatanaURLs(ctx, "example.com", EndpointToolConfig{CrawlDepth: 2}, s); hits != nil || e != "" {
		t.Fatalf("katana soft-skip failed: hits=%v err=%q", hits, e)
	}
	if hits, e := GauURLs(ctx, "example.com", s); hits != nil || e != "" {
		t.Fatalf("gau soft-skip failed: hits=%v err=%q", hits, e)
	}
	if hits, e := WaybackURLs(ctx, "example.com", s); hits != nil || e != "" {
		t.Fatalf("waybackurls soft-skip failed: hits=%v err=%q", hits, e)
	}
}

// hitsFromLines оставляет только http(s)-URL, отбрасывает мусор.
func TestHitsFromLines(t *testing.T) {
	out := "https://a.com/x\n\n  http://b.com/y  \nnot-a-url\nftp://c.com/z\n"
	hits := hitsFromLines(out, "gau")
	if len(hits) != 2 {
		t.Fatalf("want 2 url hits, got %d: %+v", len(hits), hits)
	}
	if hits[0].URL != "https://a.com/x" || hits[1].URL != "http://b.com/y" || hits[0].Source != "gau" {
		t.Fatalf("parsed hits wrong: %+v", hits)
	}
}
