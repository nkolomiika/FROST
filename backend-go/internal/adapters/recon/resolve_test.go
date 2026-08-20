package recon

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

// Порт reverse/DNS-хелперов из backend/tests/test_ip_farm_service.py и
// test_host_farm_service.py (order_addrs, merge_names, reverse_resolve). DNS
// подменяется через интерфейс dnsResolver — как monkeypatch socket в Python.

// mockResolver подменяет PTR (LookupAddr) и прямой резолв (LookupNetIP).
// Отсутствующий ключ → ошибка резолвера (как socket.herror/gaierror).
type mockResolver struct {
	ptr map[string][]string     // ip -> PTR-имена
	fwd map[string][]netip.Addr // host -> адреса
	// boom: если true — любой вызов проваливает тест (флаг выключен).
	boom func()
}

func (m mockResolver) LookupAddr(_ context.Context, ip string) ([]string, error) {
	if m.boom != nil {
		m.boom()
	}
	if names, ok := m.ptr[ip]; ok {
		return names, nil
	}
	return nil, errors.New("no ptr")
}

func (m mockResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if m.boom != nil {
		m.boom()
	}
	if a, ok := m.fwd[host]; ok {
		return a, nil
	}
	return nil, errors.New("nxdomain")
}

func withResolver(t *testing.T, m dnsResolver) {
	t.Helper()
	prev := resolver
	resolver = m
	t.Cleanup(func() { resolver = prev })
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("bad addr %q: %v", s, err)
	}
	return a
}

func reverseSettings() Settings {
	return Settings{
		FarmReverseDNSEnabled: true,
		FarmReverseDNSTimeout: time.Second,
		FarmMaxConcurrency:    4,
	}
}

// test_order_addrs_ipv4_first_and_dedups.
func TestOrderAddrs_ipv4FirstAndDedups(t *testing.T) {
	addrs := []netip.Addr{
		mustAddr(t, "2606:4700::1"),
		mustAddr(t, "1.1.1.1"),
		mustAddr(t, "1.0.0.1"),
		mustAddr(t, "1.1.1.1"), // дубль
	}
	got := orderAddrs(addrs)
	want := []string{"1.1.1.1", "1.0.0.1", "2606:4700::1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("orderAddrs = %v, want %v", got, want)
	}
	if got := orderAddrs(nil); len(got) != 0 {
		t.Fatalf("orderAddrs(nil) = %v, want empty", got)
	}
}

// test_merge_names_prefers_ptr_and_ors_confirmation.
func TestMergeNames_prefersPTRAndORsConfirmation(t *testing.T) {
	merged := mergeNames([]ResolvedName{
		{Hostname: "a.com", Source: SourceProject, Confirmed: true},
		{Hostname: "a.com", Source: SourcePTR, Confirmed: false},
		{Hostname: "b.com", Source: SourcePTR, Confirmed: false},
	})
	type tup struct {
		h, s string
		c    bool
	}
	var got []tup
	for _, n := range merged {
		got = append(got, tup{n.Hostname, n.Source, n.Confirmed})
	}
	want := []tup{
		{"a.com", SourcePTR, true}, // подтверждённые выше, ptr над project, OR confirmed
		{"b.com", SourcePTR, false},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeNames = %v, want %v", got, want)
	}
}

// test_reverse_confirms_matching_forward.
func TestReverseResolve_confirmsMatchingForward(t *testing.T) {
	withResolver(t, mockResolver{
		ptr: map[string][]string{"1.2.3.4": {"api.acme.com"}},
		fwd: map[string][]netip.Addr{"api.acme.com": {mustAddr(t, "1.2.3.4")}},
	})
	res := ReverseResolve(context.Background(), []string{"1.2.3.4"}, nil, reverseSettings())
	names := res["1.2.3.4"].Names
	if len(names) != 1 || names[0].Hostname != "api.acme.com" || names[0].Source != SourcePTR || !names[0].Confirmed {
		t.Fatalf("got %+v", names)
	}
}

// test_reverse_keeps_unconfirmed_ptr_name.
func TestReverseResolve_keepsUnconfirmedPTR(t *testing.T) {
	withResolver(t, mockResolver{
		ptr: map[string][]string{"1.2.3.4": {"stale.acme.com"}},
		fwd: map[string][]netip.Addr{"stale.acme.com": {mustAddr(t, "9.9.9.9")}},
	})
	res := ReverseResolve(context.Background(), []string{"1.2.3.4"}, nil, reverseSettings())
	names := res["1.2.3.4"].Names
	if len(names) != 1 || names[0].Hostname != "stale.acme.com" || names[0].Confirmed {
		t.Fatalf("stale PTR must be kept unconfirmed, got %+v", names)
	}
}

// test_reverse_survives_missing_ptr.
func TestReverseResolve_survivesMissingPTR(t *testing.T) {
	withResolver(t, mockResolver{})
	res := ReverseResolve(context.Background(), []string{"1.2.3.4"}, nil, reverseSettings())
	if names := res["1.2.3.4"].Names; len(names) != 0 {
		t.Fatalf("want no names, got %+v", names)
	}
}

// test_reverse_adds_project_hostname.
func TestReverseResolve_addsProjectHostname(t *testing.T) {
	withResolver(t, mockResolver{
		fwd: map[string][]netip.Addr{"cdn.acme.com": {mustAddr(t, "1.2.3.4")}},
	})
	res := ReverseResolve(context.Background(), []string{"1.2.3.4"}, []string{"cdn.acme.com", "other.acme.com"}, reverseSettings())
	names := res["1.2.3.4"].Names
	if len(names) != 1 || names[0].Hostname != "cdn.acme.com" || names[0].Source != SourceProject || !names[0].Confirmed {
		t.Fatalf("got %+v", names)
	}
}

// test_reverse_merges_ptr_and_project_into_one_name.
func TestReverseResolve_mergesPTRAndProject(t *testing.T) {
	withResolver(t, mockResolver{
		ptr: map[string][]string{"1.2.3.4": {"api.acme.com"}},
		fwd: map[string][]netip.Addr{"api.acme.com": {mustAddr(t, "1.2.3.4")}},
	})
	res := ReverseResolve(context.Background(), []string{"1.2.3.4"}, []string{"api.acme.com"}, reverseSettings())
	names := res["1.2.3.4"].Names
	if len(names) != 1 || names[0].Source != SourcePTR || !names[0].Confirmed {
		t.Fatalf("must merge into single ptr+confirmed name, got %+v", names)
	}
}

// test_reverse_returns_several_names_for_one_ip.
func TestReverseResolve_severalNamesForOneIP(t *testing.T) {
	withResolver(t, mockResolver{
		ptr: map[string][]string{"1.2.3.4": {"api.acme.com", "www.acme.com"}},
		fwd: map[string][]netip.Addr{
			"api.acme.com": {mustAddr(t, "1.2.3.4")},
			"www.acme.com": {mustAddr(t, "1.2.3.4")},
		},
	})
	res := ReverseResolve(context.Background(), []string{"1.2.3.4"}, nil, reverseSettings())
	names := res["1.2.3.4"].Names
	var hosts []string
	for _, n := range names {
		hosts = append(hosts, n.Hostname)
		if !n.Confirmed {
			t.Fatalf("all names must be confirmed, got %+v", names)
		}
	}
	if !reflect.DeepEqual(hosts, []string{"api.acme.com", "www.acme.com"}) {
		t.Fatalf("hosts = %v", hosts)
	}
}

// test_reverse_disabled_does_no_lookups.
func TestReverseResolve_disabledDoesNoLookups(t *testing.T) {
	withResolver(t, mockResolver{boom: func() {
		t.Fatal("резолв не должен вызываться при выключенном флаге")
	}})
	s := reverseSettings()
	s.FarmReverseDNSEnabled = false
	res := ReverseResolve(context.Background(), []string{"1.2.3.4"}, []string{"acme.com"}, s)
	if names := res["1.2.3.4"].Names; len(names) != 0 {
		t.Fatalf("want no names when disabled, got %+v", names)
	}
}
