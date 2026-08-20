package recon

import (
	"strings"
	"testing"
)

// Дополняет jsscan_test.go до паритета с test_jsscan.py: специфичные ключи,
// приоритет специфичного над generic, требования generic (подсказка+длина),
// фильтрация статики/шумных путей и дедуп js-ссылок.

func TestFindSecrets_catchesPrefixedKeys(t *testing.T) {
	text := `const c={awsKey:"AKIAIOSFODNN7EXAMPLE",` +
		`g:"AIzaSyA1234567890abcdefghijklmnopqrstuv",` +
		`gh:"ghp_0123456789abcdefghijklmnopqrstuvwxyz"};` +
		`var pk="-----BEGIN RSA PRIVATE KEY-----MIIB";`
	kinds := map[string]Secret{}
	for _, s := range FindSecrets(text) {
		kinds[s.Kind] = s
	}
	if kinds["aws_access_key"].Severity != "high" {
		t.Errorf("aws_access_key severity = %q, want high", kinds["aws_access_key"].Severity)
	}
	for _, want := range []string{"google_api_key", "github_pat", "private_key"} {
		if _, ok := kinds[want]; !ok {
			t.Errorf("%s not found in %v", want, kinds)
		}
	}
}

func TestFindSecrets_specificWinsOverGeneric(t *testing.T) {
	// apiKey="AKIA…" ловится и aws_access_key, и generic — остаётся специфичный.
	secrets := FindSecrets(`apiKey: "AKIAIOSFODNN7EXAMPLE"`)
	if len(secrets) != 1 || secrets[0].Kind != "aws_access_key" {
		t.Errorf("kinds = %v, want only [aws_access_key]", secrets)
	}
}

func TestFindSecrets_genericNeedsHintAndLength(t *testing.T) {
	// Подсказка + длинный литерал → находка.
	if got := FindSecrets(`password: "s3cr3tValue1234567"`); len(got) == 0 {
		t.Errorf("hint+long should be found")
	}
	// Короткий литерал под ключом-подсказкой — не секрет.
	if got := FindSecrets(`password: "short"`); len(got) != 0 {
		t.Errorf("short value should not be a secret, got %v", got)
	}
	// Длинная строка без подсказки — тоже нет.
	if got := FindSecrets(`label = "just-a-very-long-plain-label-string"`); len(got) != 0 {
		t.Errorf("no-hint long string should not be a secret, got %v", got)
	}
}

func TestRedact_hidesTheMiddle(t *testing.T) {
	if got := Redact("AKIAIOSFODNN7EXAMPLE"); got != "AKIA…MPLE" {
		t.Errorf("Redact = %q, want AKIA…MPLE", got)
	}
	if got := Redact("secret12"); !strings.Contains(got, "***") {
		t.Errorf("Redact(secret12) = %q, want to contain ***", got)
	}
	if got := Redact(""); got != "" {
		t.Errorf("Redact(\"\") = %q, want empty", got)
	}
}

func TestFindPaths_keepsRoutesDropsStatic(t *testing.T) {
	text := `fetch("/api/v1/users");axios.get("/admin/settings");` +
		`img.src="/assets/logo.png";load("vendor/app.chunk");` +
		`u="https://api.acme.com/v2/orders";x="node_modules/lib";`
	set := asSet(FindPaths(text))
	for _, want := range []string{"/api/v1/users", "/admin/settings", "https://api.acme.com/v2/orders"} {
		if !set[want] {
			t.Errorf("expected %q in %v", want, set)
		}
	}
	if set["/assets/logo.png"] { // статика отсеяна
		t.Errorf("static /assets/logo.png should be dropped: %v", set)
	}
	for p := range set {
		if strings.Contains(p, "node_modules") {
			t.Errorf("node_modules should be dropped: %v", set)
		}
	}
}

func TestExtractJSURLs_resolvesRelativeAndSkipsAnalytics(t *testing.T) {
	html := `<script src="/static/app.bundle.js"></script>` +
		`<script src="https://cdn.acme.com/vendor.js"></script>` +
		`<script src="https://www.google-analytics.com/ga.js"></script>` +
		`<link href="/style.css">`
	set := asSet(ExtractJSURLs(html, "https://acme.com/"))
	if !set["https://acme.com/static/app.bundle.js"] { // относительный → абсолютный
		t.Errorf("relative not resolved: %v", set)
	}
	if !set["https://cdn.acme.com/vendor.js"] {
		t.Errorf("cdn vendor.js missing: %v", set)
	}
	for u := range set {
		if strings.Contains(u, "google-analytics") {
			t.Errorf("analytics should be denied: %v", set)
		}
		if strings.HasSuffix(u, ".css") {
			t.Errorf(".css should not be picked: %v", set)
		}
	}
}

func TestExtractJSURLs_dedups(t *testing.T) {
	html := `<script src="/a.js"></script><script src="/a.js"></script>`
	got := ExtractJSURLs(html, "https://acme.com/")
	if len(got) != 1 || got[0] != "https://acme.com/a.js" {
		t.Errorf("got %v, want [https://acme.com/a.js]", got)
	}
}
