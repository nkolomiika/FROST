package recon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWordlistPath_TierMapping(t *testing.T) {
	t.Setenv("RECON_WORDLIST_DIR", "/wl")
	cases := map[string]string{
		"small":  "/wl/n0kovo_subdomains_small.txt",
		"medium": "/wl/n0kovo_subdomains_medium.txt",
		"large":  "/wl/n0kovo_subdomains_huge.txt",
		"":       "/wl/n0kovo_subdomains_medium.txt", // пустое → medium
		"bogus":  "/wl/n0kovo_subdomains_medium.txt", // неизвестное → medium
	}
	for size, want := range cases {
		if got := WordlistPath(size); got != want {
			t.Errorf("WordlistPath(%q) = %q, want %q", size, got, want)
		}
	}
}

func TestWordlistDir_DefaultAndOverride(t *testing.T) {
	t.Setenv("RECON_WORDLIST_DIR", "")
	if got := WordlistDir(); got != DefaultWordlistDir {
		t.Errorf("WordlistDir default = %q, want %q", got, DefaultWordlistDir)
	}
	t.Setenv("RECON_WORDLIST_DIR", "/custom")
	if got := WordlistDir(); got != "/custom" {
		t.Errorf("WordlistDir override = %q, want /custom", got)
	}
}

func TestWordlistExists(t *testing.T) {
	dir := t.TempDir()
	if WordlistExists("") {
		t.Error("empty path should not exist")
	}
	if WordlistExists(filepath.Join(dir, "missing.txt")) {
		t.Error("missing file should not exist")
	}
	if WordlistExists(dir) {
		t.Error("directory should not count as a wordlist file")
	}
	f := filepath.Join(dir, "wl.txt")
	if err := os.WriteFile(f, []byte("a\nb\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !WordlistExists(f) {
		t.Error("written file should exist")
	}
	empty := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if WordlistExists(empty) {
		t.Error("0-byte file (partial download) should not count as a wordlist")
	}
}

func TestDNSXBruteArgs(t *testing.T) {
	args := DNSXBruteArgs("example.com", DNSXBruteConfig{WordlistPath: "/wl/m.txt", RateLimit: 20, Threads: 10})
	joined := strings.Join(args, " ")
	for _, want := range []string{"-d example.com", "-w /wl/m.txt", "-silent", "-rl 20", "-t 10"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args %q missing %q", joined, want)
		}
	}
	// Нулевые rate/threads не добавляют флагов.
	bare := strings.Join(DNSXBruteArgs("x.com", DNSXBruteConfig{WordlistPath: "/w"}), " ")
	if strings.Contains(bare, "-rl") || strings.Contains(bare, "-t ") {
		t.Errorf("bare args unexpectedly carry rate/thread flags: %q", bare)
	}
}
