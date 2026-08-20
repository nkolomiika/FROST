package recon

import "testing"

func asSet(items []string) map[string]bool {
	s := map[string]bool{}
	for _, it := range items {
		s[it] = true
	}
	return s
}

func TestParseRoots_dedupsAndDropsIPAndComments(t *testing.T) {
	raw := "Example.com\n# comment\nexample.com\n10.0.0.1\napi.example.com, www.example.com\nbadword"
	got := ParseRoots(raw)
	want := []string{"example.com", "api.example.com", "www.example.com"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestInScope(t *testing.T) {
	cases := []struct {
		name, root string
		want       bool
	}{
		{"api.example.com", "example.com", true},
		{"example.com", "example.com", true},
		{"evil.com", "example.com", false},
		{"notexample.com", "example.com", false}, // без точки-границы
	}
	for _, c := range cases {
		if got := InScope(c.name, c.root); got != c.want {
			t.Errorf("InScope(%q,%q) = %v, want %v", c.name, c.root, got, c.want)
		}
	}
}

func TestParseCrtsh_extractsNamesSplitsAndStripsWildcards(t *testing.T) {
	raw := `[{"name_value":"*.api.example.com\nwww.example.com","common_name":"example.com"},` +
		`{"name_value":"mail.example.com"},` +
		`{"name_value":"out.of.scope.evil.com"}]`
	got := asSet(ParseCrtsh(raw, "example.com"))
	want := map[string]bool{
		"api.example.com": true, "www.example.com": true,
		"example.com": true, "mail.example.com": true,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k := range want {
		if !got[k] {
			t.Errorf("missing %q in %v", k, got)
		}
	}
}

func TestParseCrtsh_handlesGarbage(t *testing.T) {
	if got := ParseCrtsh("", "example.com"); len(got) != 0 {
		t.Errorf("empty → %v, want none", got)
	}
	if got := ParseCrtsh("not json", "example.com"); len(got) != 0 {
		t.Errorf("not json → %v, want none", got)
	}
	if got := ParseCrtsh(`{"not":"a list"}`, "example.com"); len(got) != 0 {
		t.Errorf("non-list → %v, want none", got)
	}
}

func TestParseSubfinder_filtersScopeAndIP(t *testing.T) {
	text := "api.example.com\nWWW.Example.com\n10.0.0.1\nevil.com\n\n"
	got := asSet(ParseSubfinder(text, "example.com"))
	want := map[string]bool{"api.example.com": true, "www.example.com": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k := range want {
		if !got[k] {
			t.Errorf("missing %q in %v", k, got)
		}
	}
}
