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

func TestEnumerateWordlists_RecursiveOriginalNames(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RECON_WORDLIST_DIR", dir)
	// Корневой n0kovo (3 строки, без хвостового \n у последней) + вложенный SecLists.
	if err := os.WriteFile(filepath.Join(dir, "n0kovo_subdomains_small.txt"), []byte("a\nb\nc"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "seclists", "Discovery", "Web-Content")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "common.txt"), []byte("admin\nlogin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Не-.txt и пустой .txt игнорируются.
	if err := os.WriteFile(filepath.Join(dir, "readme.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "empty.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	files, err := EnumerateWordlists()
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("want 2 files, got %d: %+v", len(files), files)
	}
	// Стабильно отсортировано по Path: n0kovo... < seclists/...
	if files[0].Path != "n0kovo_subdomains_small.txt" || files[0].Category != "n0kovo" || files[0].Lines != 3 {
		t.Fatalf("n0kovo entry wrong: %+v", files[0])
	}
	if files[1].Path != "seclists/Discovery/Web-Content/common.txt" ||
		files[1].Name != "common.txt" ||
		files[1].Category != "seclists/Discovery/Web-Content" ||
		files[1].Lines != 2 {
		t.Fatalf("seclists entry wrong: %+v", files[1])
	}
}

func TestEnumerateWordlists_MissingDirIsEmpty(t *testing.T) {
	t.Setenv("RECON_WORDLIST_DIR", filepath.Join(t.TempDir(), "does-not-exist"))
	files, err := EnumerateWordlists()
	if err != nil {
		t.Fatalf("missing dir should not error: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("missing dir should yield empty list, got %+v", files)
	}
}

func TestResolveWordlistPath_ValidatesUnderDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("RECON_WORDLIST_DIR", dir)
	sub := filepath.Join(dir, "seclists", "Discovery", "DNS")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	rel := "seclists/Discovery/DNS/subdomains-top1million-5000.txt"
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(rel)), []byte("www\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Валидный существующий путь → абсолютный путь под dir.
	abs, ok := ResolveWordlistPath(rel)
	if !ok || abs != filepath.Join(dir, filepath.FromSlash(rel)) {
		t.Fatalf("valid path not resolved: abs=%q ok=%v", abs, ok)
	}
	// Traversal/абсолютный/несуществующий → отказ.
	for _, bad := range []string{
		"../../etc/passwd",
		"/etc/passwd",
		"seclists/../../secret.txt",
		"seclists/Discovery/DNS/missing.txt", // не существует
		"", "..", ".",
	} {
		if _, ok := ResolveWordlistPath(bad); ok {
			t.Fatalf("bad path %q must be rejected", bad)
		}
	}
}

func TestSanitizeWordlistRelPath(t *testing.T) {
	if got := SanitizeWordlistRelPath("seclists/Discovery/DNS/x.txt"); got != "seclists/Discovery/DNS/x.txt" {
		t.Fatalf("valid path altered: %q", got)
	}
	// Clean нормализует внутренние './'.
	if got := SanitizeWordlistRelPath("seclists/./a/b.txt"); got != "seclists/a/b.txt" {
		t.Fatalf("clean wrong: %q", got)
	}
	for _, bad := range []string{"", "..", ".", "/abs.txt", "../up.txt", "a/../../b.txt"} {
		if got := SanitizeWordlistRelPath(bad); got != "" {
			t.Fatalf("bad path %q not dropped: %q", bad, got)
		}
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
