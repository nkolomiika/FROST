package recon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// FfufArgs строит корректную команду: словарь, URL с FUZZ, match-коды, json-вывод.
func TestFfufArgs(t *testing.T) {
	got := strings.Join(FfufArgs("example.com", "/wl/paths.txt", "/tmp/out.json", FfufConfig{RateLimit: 30, Threads: 40}), " ")
	for _, want := range []string{
		"-w /wl/paths.txt",
		"-u https://example.com/FUZZ",
		"-mc " + ffufDefaultMatchCodes,
		"-of json",
		"-o /tmp/out.json",
		"-s",
		"-rate 30",
		"-t 40",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("ffuf args missing %q: %s", want, got)
		}
	}
	// Свои match-коды переопределяют дефолт; нулевые rate/threads не добавляют флагов.
	bare := strings.Join(FfufArgs("x.com", "/w", "/o", FfufConfig{MatchCodes: "200"}), " ")
	if !strings.Contains(bare, "-mc 200") || strings.Contains(bare, "-rate") || strings.Contains(bare, "-t ") {
		t.Fatalf("bare/override args wrong: %s", bare)
	}
}

// Нет бинаря → ffuf молча самопропускается (nil, "").
func TestFfufDirFuzz_MissingBinarySoftSkip(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "w.txt")
	if err := os.WriteFile(wl, []byte("admin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := Settings{FfufBin: "frost-no-such-ffuf", EndpointsTimeout: 2 * time.Second}
	if hits, e := FfufDirFuzz(context.Background(), "example.com", wl, FfufConfig{}, s); hits != nil || e != "" {
		t.Fatalf("ffuf soft-skip failed: hits=%v err=%q", hits, e)
	}
}

// Пустой/несуществующий словарь → ffuf самопропускается (не запускает бинарь).
func TestFfufDirFuzz_MissingWordlistSoftSkip(t *testing.T) {
	s := Settings{FfufBin: "frost-no-such-ffuf", EndpointsTimeout: 2 * time.Second}
	if hits, e := FfufDirFuzz(context.Background(), "example.com", "/no/such/wordlist", FfufConfig{}, s); hits != nil || e != "" {
		t.Fatalf("ffuf missing-wordlist soft-skip failed: hits=%v err=%q", hits, e)
	}
}

// Небезопасный host (ведущий '-') → ffuf не запускается (flag-инъекция).
func TestFfufDirFuzz_UnsafeHostSkipped(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "w.txt")
	_ = os.WriteFile(wl, []byte("admin\n"), 0o644)
	s := Settings{FfufBin: "ffuf", EndpointsTimeout: 2 * time.Second}
	if hits, e := FfufDirFuzz(context.Background(), "-oINJECT", wl, FfufConfig{}, s); hits != nil || e != "" {
		t.Fatalf("unsafe host must be skipped: hits=%v err=%q", hits, e)
	}
}

// readFfufOutput парсит results[].url, отбрасывает не-http значения.
func TestReadFfufOutput(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "out.json")
	body := `{"results":[{"url":"https://x.com/admin","status":200},{"url":"","status":301},{"url":"ftp://x/y","status":200},{"url":"https://x.com/login","status":403}]}`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	hits := readFfufOutput(p)
	if len(hits) != 2 {
		t.Fatalf("want 2 http hits, got %d: %+v", len(hits), hits)
	}
	if hits[0].URL != "https://x.com/admin" || hits[0].Source != "ffuf" || hits[1].URL != "https://x.com/login" {
		t.Fatalf("parsed hits wrong: %+v", hits)
	}
	// Пустой/битый файл → nil.
	if readFfufOutput(filepath.Join(dir, "missing.json")) != nil {
		t.Fatal("missing file should parse to nil")
	}
}
