package recon

import (
	"context"
	"strings"
	"testing"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
)

// Порт backend/tests/test_host_farm_service.py. Разбор целей и кандидаты живут в
// adapters/recon (reconnet); классификация/счётчики persist — в app/recon.

func parsedMap(raw string) map[string]*reconnet.ParsedTarget {
	targets, _ := reconnet.ParseTargets(raw)
	m := map[string]*reconnet.ParsedTarget{}
	for _, t := range targets {
		m[t.Hostname] = t
	}
	return m
}

// ─────────────────────────── parse ───────────────────────────

func TestParse_workedExample(t *testing.T) {
	m := parsedMap("https://example.com\nwww.example.com\nhttp://example.com\nwww.example.com")
	if len(m) != 2 {
		t.Fatalf("want {example.com,www.example.com}, got %v", keysOfPT(m))
	}
	ex := m["example.com"]
	if ex.ExplicitPorts[80] != "http" || ex.ExplicitPorts[443] != "https" || len(ex.ExplicitPorts) != 2 {
		t.Errorf("example.com explicit = %v, want {80:http,443:https}", ex.ExplicitPorts)
	}
	if !ex.HasExplicit {
		t.Errorf("example.com should have explicit ports")
	}
	www := m["www.example.com"]
	if www.HasExplicit || len(www.ExplicitPorts) != 0 {
		t.Errorf("www.example.com should be scheme-less: %+v", www)
	}
}

func TestParse_stripsAndDedups(t *testing.T) {
	targets, errs := reconnet.ParseTargets("https://user:pass@example.com:8443/admin?x=1#frag\nexample.com:8443")
	if len(targets) != 1 || targets[0].Hostname != "example.com" {
		t.Fatalf("want single example.com, got %v", targets)
	}
	if targets[0].ExplicitPorts[8443] != "https" {
		t.Errorf("explicit = %v, want {8443:https}", targets[0].ExplicitPorts)
	}
	if len(errs) != 0 {
		t.Errorf("want no errors, got %v", errs)
	}
}

func TestParse_schemeConflictHTTPSWins(t *testing.T) {
	m := parsedMap("http://a.com:8080\nhttps://a.com:8080")
	if got := m["a.com"].ExplicitPorts[8080]; got != "https" {
		t.Errorf("8080 scheme = %q, want https", got)
	}
}

func TestParse_ipIPv6AndIDN(t *testing.T) {
	m6 := parsedMap("[2001:db8::1]:8443")
	if v := m6["2001:db8::1"]; v == nil || !v.IsIP || v.ExplicitPorts[8443] != "https" {
		t.Errorf("ipv6 target wrong: %+v", v)
	}
	mip := parsedMap("10.0.0.5")
	if v := mip["10.0.0.5"]; v == nil || !v.IsIP || v.HasExplicit {
		t.Errorf("ipv4 literal wrong: %+v", v)
	}
	targets, _ := reconnet.ParseTargets("пример.рф")
	if len(targets) != 1 || !strings.HasPrefix(targets[0].Hostname, "xn--") {
		t.Errorf("IDN should punycode to xn--, got %v", targets)
	}
}

func TestParse_rejectsInvalid(t *testing.T) {
	targets, errs := reconnet.ParseTargets("*.evil.com\nftp://x.com\nbad_host.com\nhttp://\n# a comment\n\n")
	if len(targets) != 0 {
		t.Errorf("want no valid targets, got %v", targets)
	}
	if len(errs) != 4 {
		t.Errorf("want 4 parse errors, got %d: %v", len(errs), errs)
	}
}

func TestCandidates_explicitVsInferred(t *testing.T) {
	m := parsedMap("https://a.com\nb.com")
	explicit := reconnet.CandidatesFor(m["a.com"])
	if len(explicit) != 1 || explicit[0].Port != 443 || explicit[0].Scheme != "https" || explicit[0].Inferred {
		t.Errorf("explicit candidates = %+v, want [{443 https false}]", explicit)
	}
	inferred := reconnet.CandidatesFor(m["b.com"])
	ports := map[int]bool{}
	for _, c := range inferred {
		if !c.Inferred {
			t.Errorf("candidate %+v should be inferred", c)
		}
		ports[c.Port] = true
	}
	if len(ports) != len(reconnet.TopWebPorts) {
		t.Errorf("inferred ports = %v, want top-web set", ports)
	}
}

// ─────────────────────────── probe port classification (buildPorts/statusFor) ─────

func TestBuildPorts_explicitDeadWrittenInferredDeadSkipped(t *testing.T) {
	probes := []reconnet.ProbeResult{
		{Hostname: "h", Port: 443, Scheme: "https", Inferred: false, Responded: false}, // explicit dead → FILTERED
		{Hostname: "h", Port: 80, Scheme: "http", Inferred: true, Responded: false},    // inferred dead → skipped
		{Hostname: "h", Port: 8080, Scheme: "http", Inferred: true, Responded: true},   // inferred alive → OPEN
	}
	writes, results := buildPorts(probes, nil)
	if len(writes) != 2 || len(results) != 2 {
		t.Fatalf("want 2 written ports (explicit-dead + inferred-alive), got %d", len(writes))
	}
	byPort := map[int32]PortResult{}
	for _, r := range results {
		byPort[r.PortNumber] = r
	}
	if byPort[443].State != "filtered" {
		t.Errorf("explicit dead port state = %q, want filtered", byPort[443].State)
	}
	if byPort[8080].State != "open" {
		t.Errorf("live port state = %q, want open", byPort[8080].State)
	}
	if _, ok := byPort[80]; ok {
		t.Errorf("inferred dead port must be skipped")
	}
}

func TestStatusFor(t *testing.T) {
	if statusFor(true, true) != statusUNKNOWN {
		t.Errorf("blocked → UNKNOWN")
	}
	if statusFor(false, true) != statusUP {
		t.Errorf("responded → UP")
	}
	if statusFor(false, false) != statusDOWN {
		t.Errorf("no response → DOWN")
	}
}

// ─────────────────────────── persist classification ───────────────────────────

func TestPersistHosts_createsAndClassifiesPorts(t *testing.T) {
	store := &stubStore{}
	svc := stubService(store, reconnet.Settings{}, Config{MaxAttempts: 3})
	targets, _ := reconnet.ParseTargets("https://example.com\nwww.example.com")
	resolved := map[string]reconnet.ResolvedHost{
		"example.com":     {IP: "1.1.1.1", IPs: []string{"1.1.1.1"}},
		"www.example.com": {IP: "2.2.2.2", IPs: []string{"2.2.2.2"}},
	}
	probes := []reconnet.ProbeResult{
		{Hostname: "example.com", Port: 443, Scheme: "https", Inferred: false, Responded: true, HTTPStatus: intp(200)},
		{Hostname: "www.example.com", Port: 443, Scheme: "https", Inferred: true, Responded: true, HTTPStatus: intp(200)},
		{Hostname: "www.example.com", Port: 80, Scheme: "http", Inferred: true, Responded: false},
	}
	res := svc.persistHosts(context.Background(), 101, 7, targets, resolved, probes, nil)

	if res.HostsCreated != 2 {
		t.Errorf("hosts_created = %d, want 2", res.HostsCreated)
	}
	if res.HostsOnline != 2 {
		t.Errorf("hosts_online = %d, want 2", res.HostsOnline)
	}
	if res.PortsCreated != 2 { // example:443 + www:443; www:80 inferred+dead skipped
		t.Errorf("ports_created = %d, want 2", res.PortsCreated)
	}
	if store.auditCount != 1 {
		t.Errorf("audit logged %d times, want 1", store.auditCount)
	}
}

func TestPersistHosts_offlineExplicitFiltered(t *testing.T) {
	store := &stubStore{}
	svc := stubService(store, reconnet.Settings{}, Config{MaxAttempts: 3})
	targets, _ := reconnet.ParseTargets("https://dead.example") // explicit 443
	resolved := map[string]reconnet.ResolvedHost{"dead.example": {IP: "1.2.3.4", IPs: []string{"1.2.3.4"}}}
	probes := []reconnet.ProbeResult{{Hostname: "dead.example", Port: 443, Scheme: "https", Inferred: false, Responded: false}}

	res := svc.persistHosts(context.Background(), 101, 7, targets, resolved, probes, nil)

	if res.HostsOffline != 1 || res.HostsOnline != 0 {
		t.Errorf("offline=%d online=%d, want 1/0", res.HostsOffline, res.HostsOnline)
	}
	if res.PortsCreated != 1 { // explicit port recorded even when it didn't respond
		t.Errorf("ports_created = %d, want 1", res.PortsCreated)
	}
	if len(res.Hosts) != 1 || res.Hosts[0].Status != "down" {
		t.Fatalf("host status = %v, want down", res.Hosts)
	}
	if len(res.Hosts[0].Ports) != 1 || res.Hosts[0].Ports[0].State != "filtered" || res.Hosts[0].Ports[0].HTTPStatus != nil {
		t.Errorf("port = %+v, want filtered/nil-status", res.Hosts[0].Ports)
	}
}

func TestPersistHosts_blockedInternalTarget(t *testing.T) {
	store := &stubStore{}
	svc := stubService(store, reconnet.Settings{}, Config{MaxAttempts: 3})
	targets, _ := reconnet.ParseTargets("intranet.corp")
	resolved := map[string]reconnet.ResolvedHost{"intranet.corp": {IP: "10.0.0.5", Blocked: true, Error: "internal"}}

	res := svc.persistHosts(context.Background(), 101, 7, targets, resolved, nil, nil)

	if len(res.Hosts) != 1 || res.Hosts[0].Status != "unknown" {
		t.Fatalf("status = %v, want unknown (not probed, not offline)", res.Hosts)
	}
	if res.PortsCreated != 0 {
		t.Errorf("ports_created = %d, want 0", res.PortsCreated)
	}
	if res.HostsOnline != 0 || res.HostsOffline != 0 {
		t.Errorf("online=%d offline=%d, want 0/0", res.HostsOnline, res.HostsOffline)
	}
}

func intp(v int) *int { return &v }

func keysOfPT(m map[string]*reconnet.ParsedTarget) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
