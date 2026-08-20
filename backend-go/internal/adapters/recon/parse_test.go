package recon

import (
	"reflect"
	"sort"
	"testing"
)

func targetMap(targets []*ParsedTarget) map[string]*ParsedTarget {
	m := map[string]*ParsedTarget{}
	for _, t := range targets {
		m[t.Hostname] = t
	}
	return m
}

func TestParseTargets_basic(t *testing.T) {
	raw := "example.com\nsub.example.com, 1.2.3.4\n# comment\n// note\n..."
	targets, errs := ParseTargets(raw)
	m := targetMap(targets)
	if len(m) != 3 {
		t.Fatalf("want 3 targets, got %d (%v)", len(m), keysOf(m))
	}
	if _, ok := m["example.com"]; !ok {
		t.Errorf("example.com missing")
	}
	if tgt := m["1.2.3.4"]; tgt == nil || !tgt.IsIP {
		t.Errorf("1.2.3.4 should be IP target")
	}
	if tgt := m["sub.example.com"]; tgt == nil || tgt.IsIP {
		t.Errorf("sub.example.com should be domain")
	}
	if len(errs) != 1 {
		t.Errorf("want 1 parse error, got %v", errs)
	}
}

func TestParseTargets_portsAndScheme(t *testing.T) {
	targets, _ := ParseTargets("example.com:8443\nhttps://example.com\nexample.com:80")
	m := targetMap(targets)
	tgt := m["example.com"]
	if tgt == nil || !tgt.HasExplicit {
		t.Fatalf("expected explicit ports on example.com")
	}
	if tgt.ExplicitPorts[8443] != "https" {
		t.Errorf("8443 should be https, got %q", tgt.ExplicitPorts[8443])
	}
	if tgt.ExplicitPorts[443] != "https" {
		t.Errorf("https:// should add port 443 https, got %q", tgt.ExplicitPorts[443])
	}
	if tgt.ExplicitPorts[80] != "http" {
		t.Errorf("80 should be http, got %q", tgt.ExplicitPorts[80])
	}
}

func TestParseTargets_dedup(t *testing.T) {
	targets, _ := ParseTargets("example.com\nexample.com")
	if len(targets) != 1 {
		t.Fatalf("want 1 deduped target, got %d", len(targets))
	}
}

func TestParseIPTargets_rejectsHostnames(t *testing.T) {
	targets, errs := ParseIPTargets("1.2.3.4\nexample.com")
	if len(targets) != 1 || targets[0].Hostname != "1.2.3.4" {
		t.Fatalf("want only the IP target, got %v", targets)
	}
	found := false
	for _, e := range errs {
		if e == "example.com: не IP-адрес — используйте импорт хостов" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected hostname-rejection error, got %v", errs)
	}
}

func TestCandidatesFor_topPortsWhenNoExplicit(t *testing.T) {
	targets, _ := ParseTargets("example.com")
	cands := CandidatesFor(targets[0])
	if len(cands) != len(TopWebPorts) {
		t.Fatalf("want %d top-port candidates, got %d", len(TopWebPorts), len(cands))
	}
	for _, c := range cands {
		if !c.Inferred {
			t.Errorf("top-port candidate should be inferred")
		}
	}
}

func TestTrimExcessPorts(t *testing.T) {
	targets, _ := ParseTargets("example.com:81,example.com:82,example.com:83")
	errs := TrimExcessPorts(targets, 2)
	if len(targets[0].ExplicitPorts) != 2 {
		t.Fatalf("want 2 ports left, got %d", len(targets[0].ExplicitPorts))
	}
	if _, ok := targets[0].ExplicitPorts[81]; !ok {
		t.Errorf("lowest port 81 should remain")
	}
	if len(errs) != 1 {
		t.Errorf("want 1 trim error, got %v", errs)
	}
}

func TestParseRoots(t *testing.T) {
	roots := ParseRoots("example.com\n*.example.com\n1.2.3.4\nlocalhost\n# comment\nExample.com")
	want := []string{"example.com"}
	if !reflect.DeepEqual(roots, want) {
		t.Fatalf("want %v, got %v", want, roots)
	}
}

func keysOf(m map[string]*ParsedTarget) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
