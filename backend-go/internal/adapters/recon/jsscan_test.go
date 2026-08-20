package recon

import "testing"

func TestRedact(t *testing.T) {
	cases := map[string]string{
		"":             "",
		"short":        "s***",
		"abcd1234efgh": "abcd…efgh",
	}
	for in, want := range cases {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFindSecrets(t *testing.T) {
	text := `const k = "AKIAIOSFODNN7EXAMPLE"; var api_key = "abcdef1234567890ABCD";`
	secrets := FindSecrets(text)
	byKind := map[string]Secret{}
	for _, s := range secrets {
		byKind[s.Kind] = s
	}
	aws, ok := byKind["aws_access_key"]
	if !ok {
		t.Fatalf("aws_access_key not found in %v", secrets)
	}
	if aws.Severity != "high" {
		t.Errorf("aws severity = %q, want high", aws.Severity)
	}
	if aws.MatchPreview != "AKIA…MPLE" {
		t.Errorf("aws preview = %q, want AKIA…MPLE", aws.MatchPreview)
	}
	if _, ok := byKind["generic_api_key"]; !ok {
		t.Errorf("generic_api_key not found in %v", secrets)
	}
	// Полный секрет не должен попадать в preview.
	for _, s := range secrets {
		if s.MatchPreview == "AKIAIOSFODNN7EXAMPLE" {
			t.Errorf("full secret leaked in preview")
		}
	}
}

func TestFindSecrets_dedup(t *testing.T) {
	text := `"AKIAIOSFODNN7EXAMPLE" "AKIAIOSFODNN7EXAMPLE"`
	if got := len(FindSecrets(text)); got != 1 {
		t.Errorf("want 1 deduped secret, got %d", got)
	}
}

func TestFindPaths(t *testing.T) {
	text := `fetch("/api/v1/users"); load("foo/bar"); img("/img/logo.png"); x("data:xyz");`
	paths := FindPaths(text)
	set := map[string]bool{}
	for _, p := range paths {
		set[p] = true
	}
	if !set["/api/v1/users"] {
		t.Errorf("expected /api/v1/users in %v", paths)
	}
	if !set["foo/bar"] {
		t.Errorf("expected foo/bar in %v", paths)
	}
	if set["/img/logo.png"] {
		t.Errorf("static .png should be filtered out: %v", paths)
	}
}

func TestExtractJSURLs(t *testing.T) {
	html := `<script src="/static/app.js"></script><script src="https://google-analytics.com/ga.js"></script>`
	urls := ExtractJSURLs(html, "https://example.com/")
	if len(urls) != 1 || urls[0] != "https://example.com/static/app.js" {
		t.Fatalf("want [https://example.com/static/app.js], got %v", urls)
	}
}
