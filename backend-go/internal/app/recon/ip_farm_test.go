package recon

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
)

// Порт backend/tests/test_ip_farm_service.py. Обратный резолв, order_addrs,
// merge_names и is_cloudflare_ip живут в adapters/recon и app/inventory (вне
// scope этого пакета) — см. отчёт о gap'ах. Здесь — разбор IP-целей, wiring
// persist и short-circuit create_job.

// ─────────────────────────── parse ───────────────────────────

func TestParseIP_acceptsWithAndWithoutPorts(t *testing.T) {
	targets, errs := reconnet.ParseIPTargets("1.2.3.4\n1.2.3.4:8443\nhttps://5.6.7.8:443\n[2001:db8::1]:8443")
	m := map[string]*reconnet.ParsedTarget{}
	for _, t := range targets {
		m[t.Hostname] = t
	}
	if len(m) != 3 {
		t.Fatalf("want 3 IP targets, got %v", targets)
	}
	if m["1.2.3.4"].ExplicitPorts[8443] != "https" {
		t.Errorf("1.2.3.4 explicit = %v", m["1.2.3.4"].ExplicitPorts)
	}
	if m["5.6.7.8"].ExplicitPorts[443] != "https" {
		t.Errorf("5.6.7.8 explicit = %v", m["5.6.7.8"].ExplicitPorts)
	}
	if m["2001:db8::1"].ExplicitPorts[8443] != "https" {
		t.Errorf("2001:db8::1 explicit = %v", m["2001:db8::1"].ExplicitPorts)
	}
	for _, tg := range targets {
		if !tg.IsIP {
			t.Errorf("%s should be IP", tg.Hostname)
		}
	}
	if len(errs) != 0 {
		t.Errorf("want no errors, got %v", errs)
	}
}

func TestParseIP_rejectsHostnamesWithHint(t *testing.T) {
	targets, errs := reconnet.ParseIPTargets("1.2.3.4\nexample.com")
	if len(targets) != 1 || targets[0].Hostname != "1.2.3.4" {
		t.Fatalf("want only 1.2.3.4, got %v", targets)
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e, "example.com: не IP-адрес") {
			found = true
		}
	}
	if !found {
		t.Errorf("want hostname rejection hint, got %v", errs)
	}
}

// ─────────────────────────── persist wiring ───────────────────────────

func TestPersistIPs_createsIPOnlyHost(t *testing.T) {
	store := &stubStore{persistIPFn: func(in IPPersistInput) (IPPersistOutcome, error) {
		// reconrepo вычисляет is_cloudflare (CIDR + детект) — здесь фейк отдаёт готовое.
		return IPPersistOutcome{HostCreated: true, IsCloudflare: boolPtr(true), PortsCreated: len(in.Ports)}, nil
	}}
	svc := stubService(store, reconnet.Settings{}, Config{MaxAttempts: 3})
	targets, _ := reconnet.ParseIPTargets("104.16.0.1:443")
	resolved := map[string]reconnet.ResolvedHost{"104.16.0.1": {IP: "104.16.0.1", IPs: []string{"104.16.0.1"}}}
	reverse := map[string]reconnet.ReverseResult{
		"104.16.0.1": {IP: "104.16.0.1", Names: []reconnet.ResolvedName{{Hostname: "cf.acme.com", Source: "ptr", Confirmed: true}}},
	}
	probes := []reconnet.ProbeResult{{Hostname: "104.16.0.1", Port: 443, Scheme: "https", Responded: true, HTTPStatus: intp(200)}}

	res := svc.persistIPs(context.Background(), 101, 7, targets, resolved, reverse, probes, nil)

	if res.IPsCreated != 1 || res.IPsOnline != 1 || res.HostnamesFound != 1 {
		t.Errorf("created=%d online=%d hostnames=%d, want 1/1/1", res.IPsCreated, res.IPsOnline, res.HostnamesFound)
	}
	if len(res.IPs) != 1 {
		t.Fatalf("want 1 ip result, got %v", res.IPs)
	}
	ip := res.IPs[0]
	if ip.IsCloudflare == nil || !*ip.IsCloudflare {
		t.Errorf("is_cloudflare = %v, want true", ip.IsCloudflare)
	}
	if len(ip.Hostnames) != 1 || ip.Hostnames[0].Hostname != "cf.acme.com" {
		t.Errorf("hostnames = %+v, want [cf.acme.com]", ip.Hostnames)
	}
	if ip.AttachedToExistingHost {
		t.Errorf("fresh ip host should not be attached")
	}
	if store.auditCount != 1 {
		t.Errorf("audit count = %d, want 1", store.auditCount)
	}
}

func TestPersistIPs_reusesExistingIPHost(t *testing.T) {
	store := &stubStore{persistIPFn: func(in IPPersistInput) (IPPersistOutcome, error) {
		return IPPersistOutcome{HostID: 9, IPExisted: true, Attached: true, PortsCreated: len(in.Ports)}, nil
	}}
	svc := stubService(store, reconnet.Settings{}, Config{MaxAttempts: 3})
	targets, _ := reconnet.ParseIPTargets("1.2.3.4:443")
	resolved := map[string]reconnet.ResolvedHost{"1.2.3.4": {IP: "1.2.3.4", IPs: []string{"1.2.3.4"}}}
	reverse := map[string]reconnet.ReverseResult{"1.2.3.4": {IP: "1.2.3.4"}}
	probes := []reconnet.ProbeResult{{Hostname: "1.2.3.4", Port: 443, Scheme: "https", Responded: true, HTTPStatus: intp(200)}}

	res := svc.persistIPs(context.Background(), 101, 7, targets, resolved, reverse, probes, nil)

	if len(res.IPs) != 1 || !res.IPs[0].AttachedToExistingHost {
		t.Fatalf("want attached ip result, got %v", res.IPs)
	}
	if res.IPs[0].HostID == nil || *res.IPs[0].HostID != 9 {
		t.Errorf("host_id = %v, want 9", res.IPs[0].HostID)
	}
	if res.IPsUpdated != 1 || res.IPsCreated != 0 {
		t.Errorf("updated=%d created=%d, want 1/0", res.IPsUpdated, res.IPsCreated)
	}
}

func TestPersistIPs_commitsPerIPOffline(t *testing.T) {
	store := &stubStore{}
	svc := stubService(store, reconnet.Settings{}, Config{MaxAttempts: 3})
	targets, _ := reconnet.ParseIPTargets("1.2.3.4\n5.6.7.8")
	resolved := map[string]reconnet.ResolvedHost{
		"1.2.3.4": {IP: "1.2.3.4", IPs: []string{"1.2.3.4"}},
		"5.6.7.8": {IP: "5.6.7.8", IPs: []string{"5.6.7.8"}},
	}
	reverse := map[string]reconnet.ReverseResult{"1.2.3.4": {IP: "1.2.3.4"}, "5.6.7.8": {IP: "5.6.7.8"}}

	res := svc.persistIPs(context.Background(), 101, 7, targets, resolved, reverse, nil, nil)

	if res.IPsOffline != 2 { // ни один порт не ответил
		t.Errorf("ips_offline = %d, want 2", res.IPsOffline)
	}
}

func TestPersistIPs_blockedInternalIPIsUnknown(t *testing.T) {
	store := &stubStore{}
	svc := stubService(store, reconnet.Settings{}, Config{MaxAttempts: 3})
	targets, _ := reconnet.ParseIPTargets("10.0.0.5")
	resolved := map[string]reconnet.ResolvedHost{"10.0.0.5": {IP: "10.0.0.5", IPs: []string{"10.0.0.5"}, Blocked: true, Error: "internal"}}
	reverse := map[string]reconnet.ReverseResult{"10.0.0.5": {IP: "10.0.0.5"}}

	res := svc.persistIPs(context.Background(), 101, 7, targets, resolved, reverse, nil, nil)

	if res.IPsOnline != 0 || res.IPsOffline != 0 {
		t.Errorf("online=%d offline=%d, want 0/0", res.IPsOnline, res.IPsOffline)
	}
	if res.PortsCreated != 0 {
		t.Errorf("ports_created = %d, want 0", res.PortsCreated)
	}
}

// ─────────────────────────── create_job short-circuit ───────────────────────────

func TestCreateIPsJob_allExistingFinishesImmediately(t *testing.T) {
	store := &stubStore{existingOriginIPs: func(addrs []string) []string { return addrs }}
	svc := stubService(store, reconnet.Settings{FarmMaxTargets: 256}, Config{WorkerEnabled: true, MaxAttempts: 3})

	view, err := svc.CreateJob(context.Background(), KindIPs, 101, 7, "1.2.3.4\n5.6.7.8")
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if view.Status != jobDone {
		t.Errorf("status = %q, want done", view.Status)
	}
	if store.captured.TargetsTotal == nil || *store.captured.TargetsTotal != 0 {
		t.Errorf("targets_total = %v, want 0", store.captured.TargetsTotal)
	}
	var res map[string]any
	if err := json.Unmarshal(store.captured.Result, &res); err != nil {
		t.Fatalf("result not JSON: %v", err)
	}
	if res["ips_skipped"] != float64(2) {
		t.Errorf("ips_skipped = %v, want 2", res["ips_skipped"])
	}
}
