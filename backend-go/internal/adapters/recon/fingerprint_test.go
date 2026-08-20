package recon

import (
	"context"
	"reflect"
	"testing"
)

func sp(s string) *string { return &s }

// Реальный формат httpx-pd v1.10 -json (claude.com за Cloudflare).
const httpxJSONL = `{"input":"https://claude.com:443/","url":"https://claude.com:443/","webserver":"cloudflare",` +
	`"tech":["Cloudflare","Cloudflare Bot Management","HSTS","HTTP/3"],"cdn_name":null}
{"input":"https://api.acme.com:443/","url":"https://api.acme.com:443/","webserver":"nginx",` +
	`"tech":["Nginx:1.25.3","PHP:8.2.1","WordPress"]}`

func TestParseHttpxJSONL_extractsStackWithVersions(t *testing.T) {
	parsed := ParseHttpxJSONL(httpxJSONL)
	acme := map[string]*string{}
	for _, tech := range parsed["https://api.acme.com:443/"] {
		acme[tech.Name] = tech.Version
	}
	if v := acme["Nginx"]; v == nil || *v != "1.25.3" {
		t.Errorf("Nginx version = %v, want 1.25.3", v)
	}
	if v := acme["PHP"]; v == nil || *v != "8.2.1" {
		t.Errorf("PHP version = %v, want 8.2.1", v)
	}
	if v, ok := acme["WordPress"]; !ok || v != nil {
		t.Errorf("WordPress version = %v, want nil", v)
	}
}

func TestParseHttpxJSONL_flagsCloudflareFromTech(t *testing.T) {
	parsed := ParseHttpxJSONL(httpxJSONL)
	var names []string
	for _, tech := range parsed["https://claude.com:443/"] {
		names = append(names, tech.Name)
	}
	want := []string{"Cloudflare", "Cloudflare Bot Management", "HSTS", "HTTP/3"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("tech names = %v, want %v", names, want)
	}
	if !HasCloudflare(parsed["https://claude.com:443/"]) {
		t.Errorf("claude.com should be flagged Cloudflare")
	}
	if HasCloudflare(parsed["https://api.acme.com:443/"]) {
		t.Errorf("api.acme.com should NOT be Cloudflare")
	}
}

func TestParseHttpxJSONL_addsCdnNameAsTech(t *testing.T) {
	// tech без Cloudflare, но cdn_name говорит cloudflare → добавляем как технологию.
	line := `{"input":"https://x/","tech":["Nginx"],"cdn_name":"cloudflare"}`
	techs := ParseHttpxJSONL(line)["https://x/"]
	if !HasCloudflare(techs) {
		t.Errorf("cdn_name=cloudflare should flag Cloudflare, got %v", techs)
	}
}

func TestParseHttpxJSONL_skipsGarbageLines(t *testing.T) {
	if got := ParseHttpxJSONL(""); len(got) != 0 {
		t.Errorf("empty input should be {}, got %v", got)
	}
	if got := ParseHttpxJSONL("not json\n{bad}"); len(got) != 0 {
		t.Errorf("garbage input should be {}, got %v", got)
	}
}

func TestParseWhatwebJSON_dropsMetaKeepsStack(t *testing.T) {
	raw := `[{"plugins":{"Country":{"string":["ZZ"]},"HTTPServer":{"string":["nginx/1.25.3"]},"PHP":{"version":["8.2"]}}}]`
	names := map[string]bool{}
	for _, tech := range ParseWhatwebJSON(raw) {
		names[tech.Name] = true
	}
	if !names["nginx"] || !names["PHP"] {
		t.Errorf("expected nginx and PHP in %v", names)
	}
	if names["Country"] {
		t.Errorf("Country meta-plugin should be dropped: %v", names)
	}
}

func TestUrlFor_wrapsIPv6(t *testing.T) {
	got := urlFor(ProbeResult{Hostname: "2001:db8::1", Port: 8443, Scheme: "https", Responded: true})
	if got != "https://[2001:db8::1]:8443/" {
		t.Errorf("ipv6 url = %q, want https://[2001:db8::1]:8443/", got)
	}
	got = urlFor(ProbeResult{Hostname: "acme.com", Port: 443, Scheme: "https", Responded: true})
	if got != "https://acme.com:443/" {
		t.Errorf("host url = %q, want https://acme.com:443/", got)
	}
}

func TestDetectServices_mapsEngineOutputToPorts(t *testing.T) {
	// Движок нормализовал URL (убрал слэш) — матчинг по urlKey всё равно сойдётся.
	detector := func(ctx context.Context, urls []string) (map[string][]Tech, error) {
		return map[string][]Tech{
			"https://acme.com:443": {{Name: "Cloudflare"}, {Name: "Nginx", Version: sp("1.25.3")}},
		}, nil
	}
	probes := []ProbeResult{
		{Hostname: "acme.com", Port: 443, Scheme: "https", Responded: true},
		{Hostname: "acme.com", Port: 80, Scheme: "http", Inferred: true, Responded: false}, // не ответил
	}
	result := DetectServices(context.Background(), probes, Settings{}, detector, nil)

	techs := result[TechKey{Host: "acme.com", Port: 443}]
	var names []string
	for _, tech := range techs {
		names = append(names, tech.Name)
	}
	if !reflect.DeepEqual(names, []string{"Cloudflare", "Nginx"}) {
		t.Errorf("names = %v, want [Cloudflare Nginx]", names)
	}
	if !HasCloudflare(techs) {
		t.Errorf("expected Cloudflare in %v", techs)
	}
}

func TestDetectServices_emptyWhenNothingResponded(t *testing.T) {
	boom := func(ctx context.Context, urls []string) (map[string][]Tech, error) {
		t.Fatalf("detector should not be called when nothing responded")
		return nil, nil
	}
	probes := []ProbeResult{{Hostname: "acme.com", Port: 80, Scheme: "http", Inferred: true, Responded: false}}
	if got := DetectServices(context.Background(), probes, Settings{}, boom, nil); len(got) != 0 {
		t.Errorf("want empty, got %v", got)
	}
}

func TestDetectServices_regateDropsReboundHost(t *testing.T) {
	// Хост, который к моменту детекта резолвится во внутренний адрес, из выхода
	// наружу исключается (anti-rebind).
	var seenURLs []string
	detector := func(ctx context.Context, urls []string) (map[string][]Tech, error) {
		seenURLs = append(seenURLs, urls...)
		out := map[string][]Tech{}
		for _, u := range urls {
			out[u] = []Tech{{Name: "Nginx"}}
		}
		return out, nil
	}
	resolve := func(ctx context.Context, hosts []string) map[string]ResolvedHost {
		return map[string]ResolvedHost{
			"ext.com":    {IP: "8.8.8.8", IPs: []string{"8.8.8.8"}},
			"rebind.com": {IP: "10.0.0.1", IPs: []string{"10.0.0.1"}, Blocked: true},
		}
	}
	probes := []ProbeResult{
		{Hostname: "ext.com", Port: 443, Scheme: "https", Responded: true},
		{Hostname: "rebind.com", Port: 443, Scheme: "https", Responded: true},
	}
	result := DetectServices(context.Background(), probes, Settings{}, detector, resolve)

	if !reflect.DeepEqual(seenURLs, []string{"https://ext.com:443/"}) {
		t.Errorf("detector saw %v, want only https://ext.com:443/", seenURLs)
	}
	if _, ok := result[TechKey{Host: "ext.com", Port: 443}]; !ok {
		t.Errorf("ext.com:443 should be in result %v", result)
	}
	if _, ok := result[TechKey{Host: "rebind.com", Port: 443}]; ok {
		t.Errorf("rebind.com:443 should be dropped, got %v", result)
	}
}
