package recon

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestFarmConfigRoundTrip(t *testing.T) {
	want := DefaultFarmConfig()
	blob, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := DefaultFarmConfig()
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round-trip mismatch:\n got=%+v\nwant=%+v", got, want)
	}
}

func TestFarmConfigDefaultsOverMissingFields(t *testing.T) {
	// Только одно поле в сохранённом блобе — остальные должны остаться дефолтными.
	cfg := DefaultFarmConfig()
	if err := json.Unmarshal([]byte(`{"mode":"passive"}`), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.Mode != "passive" {
		t.Fatalf("mode not applied: %q", cfg.Mode)
	}
	if cfg.RateLimit != 20 || cfg.Concurrency != 10 || !cfg.Subfinder || cfg.KatanaDepth != 3 {
		t.Fatalf("defaults not preserved: %+v", cfg)
	}
	// Высокоуровневые ручки тоже должны остаться дефолтными.
	if cfg.WordlistSize != "medium" || cfg.PortScanScope != "top1000" || cfg.CrawlDepth != 3 {
		t.Fatalf("high-level defaults not preserved: %+v", cfg)
	}
}

func TestFarmConfigDefaults_HighLevelKnobs(t *testing.T) {
	c := DefaultFarmConfig()
	if c.Mode != "both" {
		t.Fatalf("default mode = %q, want both", c.Mode)
	}
	if c.WordlistSize != "medium" {
		t.Fatalf("default wordlist_size = %q, want medium", c.WordlistSize)
	}
	if c.PortScanScope != "top1000" {
		t.Fatalf("default port_scan_scope = %q, want top1000", c.PortScanScope)
	}
	if c.RateLimit != 20 || c.Concurrency != 10 || c.CrawlDepth != 3 {
		t.Fatalf("numeric defaults off: %+v", c)
	}
}

func TestFarmConfigSanitize_HighLevelKnobs(t *testing.T) {
	c := FarmConfig{Mode: "both", WordlistSize: "bogus", PortScanScope: "bogus", CrawlDepth: 99}
	c.Sanitize()
	if c.Mode != "both" {
		t.Fatalf("both mode dropped: %q", c.Mode)
	}
	if c.WordlistSize != "medium" {
		t.Fatalf("wordlist_size not normalized: %q", c.WordlistSize)
	}
	if c.PortScanScope != "top1000" {
		t.Fatalf("port_scan_scope not normalized: %q", c.PortScanScope)
	}
	if c.CrawlDepth != 10 {
		t.Fatalf("crawl_depth not clamped: %d", c.CrawlDepth)
	}
	// Валидные значения сохраняются.
	ok := FarmConfig{Mode: "passive", WordlistSize: "large", PortScanScope: "all", CrawlDepth: 1}
	ok.Sanitize()
	if ok.Mode != "passive" || ok.WordlistSize != "large" || ok.PortScanScope != "all" || ok.CrawlDepth != 1 {
		t.Fatalf("valid high-level values altered: %+v", ok)
	}
}

func TestFarmConfigDefaults_WordlistAndEndpointsMode(t *testing.T) {
	c := DefaultFarmConfig()
	if c.SubdomainWordlistID != 0 || c.EndpointsWordlistID != 0 {
		t.Fatalf("default wordlist ids must be 0: %+v", c)
	}
	if c.EndpointsMode != "both" {
		t.Fatalf("default endpoints_mode = %q, want both", c.EndpointsMode)
	}
}

func TestFarmConfig_BackCompatMissingNewFields(t *testing.T) {
	// Старый сохранённый блоб без новых ключей → дефолты доклеиваются.
	cfg := DefaultFarmConfig()
	if err := json.Unmarshal([]byte(`{"mode":"active"}`), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.EndpointsMode != "both" || cfg.SubdomainWordlistID != 0 || cfg.EndpointsWordlistID != 0 {
		t.Fatalf("new fields not defaulted on old blob: %+v", cfg)
	}
}

func TestFarmConfigSanitize_WordlistAndEndpointsMode(t *testing.T) {
	c := FarmConfig{EndpointsMode: "bogus", SubdomainWordlistID: -3, EndpointsWordlistID: -1}
	c.Sanitize()
	if c.EndpointsMode != "both" {
		t.Fatalf("endpoints_mode not normalized: %q", c.EndpointsMode)
	}
	if c.SubdomainWordlistID != 0 || c.EndpointsWordlistID != 0 {
		t.Fatalf("negative ids not clamped: %+v", c)
	}
	// Валидные значения сохраняются.
	ok := FarmConfig{EndpointsMode: "active", SubdomainWordlistID: 5, EndpointsWordlistID: 7}
	ok.Sanitize()
	if ok.EndpointsMode != "active" || ok.SubdomainWordlistID != 5 || ok.EndpointsWordlistID != 7 {
		t.Fatalf("valid wordlist/mode values altered: %+v", ok)
	}
}

func TestFarmConfigSanitize_WordlistPaths(t *testing.T) {
	// Дефолты пусты.
	if d := DefaultFarmConfig(); d.SubdomainWordlistPath != "" || d.EndpointsWordlistPath != "" {
		t.Fatalf("default wordlist paths must be empty: %+v", d)
	}
	// Валидный относительный путь → вычищается и сохраняется.
	c := FarmConfig{
		SubdomainWordlistPath: "seclists/Discovery/DNS/subdomains-top1million-5000.txt",
		EndpointsWordlistPath: "n0kovo_subdomains_small.txt",
	}
	c.Sanitize()
	if c.SubdomainWordlistPath != "seclists/Discovery/DNS/subdomains-top1million-5000.txt" {
		t.Fatalf("valid subdomain path altered: %q", c.SubdomainWordlistPath)
	}
	if c.EndpointsWordlistPath != "n0kovo_subdomains_small.txt" {
		t.Fatalf("valid endpoints path altered: %q", c.EndpointsWordlistPath)
	}
	// Traversal / абсолютный / выход наружу → "".
	for _, bad := range []string{"../../etc/passwd", "/etc/passwd", "a/../../b.txt", "..", "."} {
		c := FarmConfig{SubdomainWordlistPath: bad, EndpointsWordlistPath: bad}
		c.Sanitize()
		if c.SubdomainWordlistPath != "" || c.EndpointsWordlistPath != "" {
			t.Fatalf("bad path %q not dropped: sub=%q ep=%q", bad, c.SubdomainWordlistPath, c.EndpointsWordlistPath)
		}
	}
}

func TestFarmConfig_BackCompatMissingWordlistPaths(t *testing.T) {
	// Старый блоб без path-полей → пустые пути (не паникуем, дефолты держатся).
	cfg := DefaultFarmConfig()
	if err := json.Unmarshal([]byte(`{"subdomain_wordlist_id":5}`), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	cfg.Sanitize()
	if cfg.SubdomainWordlistPath != "" || cfg.EndpointsWordlistPath != "" {
		t.Fatalf("missing path fields should stay empty: %+v", cfg)
	}
	if cfg.SubdomainWordlistID != 5 {
		t.Fatalf("id lost: %+v", cfg)
	}
}

func TestEndpointTools_ModeSelection(t *testing.T) {
	base := FarmConfig{Katana: true, Gau: true, Waybackurls: true}

	both := base
	both.EndpointsMode = "both"
	both.EndpointsWordlistID = 4
	if got := endpointTools(both); !hasAll(got, "katana", "gau", "waybackurls", "ffuf") {
		t.Fatalf("both mode tools wrong: %v", got)
	}

	passive := base
	passive.EndpointsMode = "passive"
	passive.EndpointsWordlistID = 4 // ffuf активный — в passive НЕ включается
	got := endpointTools(passive)
	if hasAny(got, "katana", "ffuf") || !hasAll(got, "gau", "waybackurls") {
		t.Fatalf("passive mode tools wrong: %v", got)
	}

	active := base
	active.EndpointsMode = "active"
	active.EndpointsWordlistID = 4
	got = endpointTools(active)
	if hasAny(got, "gau", "waybackurls") || !hasAll(got, "katana", "ffuf") {
		t.Fatalf("active mode tools wrong: %v", got)
	}

	// active без кастомного словаря эндпоинтов → ffuf пропускается (бандл-тиры не
	// годятся для дир-фаззинга).
	activeNoWL := base
	activeNoWL.EndpointsMode = "active"
	activeNoWL.EndpointsWordlistID = 0
	if hasAny(endpointTools(activeNoWL), "ffuf") {
		t.Fatalf("ffuf must be skipped without custom endpoints wordlist: %v", endpointTools(activeNoWL))
	}

	// active с забандленным словарём ПО ПУТИ (без id) → ffuf включается.
	activePath := base
	activePath.EndpointsMode = "active"
	activePath.EndpointsWordlistID = 0
	activePath.EndpointsWordlistPath = "seclists/Discovery/Web-Content/common.txt"
	if !hasAll(endpointTools(activePath), "ffuf") {
		t.Fatalf("ffuf must run when endpoints wordlist path is set: %v", endpointTools(activePath))
	}

	// Пустой mode (старый конфиг) → both.
	empty := base
	empty.EndpointsMode = ""
	if !hasAll(endpointTools(empty), "katana", "gau", "waybackurls") {
		t.Fatalf("empty mode should default to both: %v", endpointTools(empty))
	}
}

func hasAll(got []string, want ...string) bool {
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

func hasAny(got []string, want ...string) bool {
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	for _, w := range want {
		if set[w] {
			return true
		}
	}
	return false
}

func TestFarmConfigDefaults_Leaks(t *testing.T) {
	c := DefaultFarmConfig()
	if c.StageLeaks {
		t.Fatalf("stage_leaks default = true, want false")
	}
	if c.LeaksGithub != nil || c.LeaksDomains != nil || c.LeaksEmails != nil {
		t.Fatalf("leaks input lists must default to nil: %+v", c)
	}
}

func TestFarmConfigSanitize_LeaksInputs(t *testing.T) {
	c := FarmConfig{
		LeaksGithub: []string{
			" https://github.com/owner/repo ",   // trim
			"https://github.com/owner/repo.git", // канон = тот же repo → дубль
			"https://gitlab.com/x/y",            // не github → drop
			"https://github.com/org",            // org-форма
			"",                                  // пусто → drop
		},
		LeaksDomains: []string{"Example.COM", "example.com", "not a domain", "b.co.", "no-dot"},
		LeaksEmails:  []string{"A@B.com", "a@b.com", "bad", "no@dot", "two@@x.com"},
	}
	c.Sanitize()

	if len(c.LeaksGithub) != 2 {
		t.Fatalf("github: want 2 (repo canon + org, gitlab/dupes dropped), got %v", c.LeaksGithub)
	}
	if c.LeaksGithub[0] != "https://github.com/owner/repo" || c.LeaksGithub[1] != "https://github.com/org" {
		t.Fatalf("github canonical/order wrong: %v", c.LeaksGithub)
	}
	if len(c.LeaksDomains) != 2 || c.LeaksDomains[0] != "example.com" || c.LeaksDomains[1] != "b.co" {
		t.Fatalf("domains normalization wrong: %v", c.LeaksDomains)
	}
	if len(c.LeaksEmails) != 1 || c.LeaksEmails[0] != "a@b.com" {
		t.Fatalf("emails normalization wrong: %v", c.LeaksEmails)
	}
}

func TestFarmConfigSanitize_LeaksCap(t *testing.T) {
	many := make([]string, 0, 250)
	for i := 0; i < 250; i++ {
		many = append(many, "d"+itoaTest(i)+".com")
	}
	c := FarmConfig{LeaksDomains: many}
	c.Sanitize()
	if len(c.LeaksDomains) != leaksInputCap {
		t.Fatalf("cap not applied: got %d, want %d", len(c.LeaksDomains), leaksInputCap)
	}
}

func itoaTest(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestFarmConfigSanitizeClamps(t *testing.T) {
	c := FarmConfig{
		Mode:           "bogus",
		RateLimit:      100000,
		Concurrency:    -5,
		KatanaDepth:    99,
		SubsMaxResults: 0,
		HttpxThreads:   99999,
	}
	c.Sanitize()
	if c.Mode != "both" {
		t.Fatalf("mode not normalized: %q", c.Mode)
	}
	if c.RateLimit != 500 {
		t.Fatalf("rate_limit not clamped: %d", c.RateLimit)
	}
	if c.Concurrency != 1 {
		t.Fatalf("concurrency not clamped: %d", c.Concurrency)
	}
	if c.KatanaDepth != 10 {
		t.Fatalf("katana_depth not clamped: %d", c.KatanaDepth)
	}
	if c.SubsMaxResults != 1 {
		t.Fatalf("subs_max_results not clamped: %d", c.SubsMaxResults)
	}
	if c.HttpxThreads != 1000 {
		t.Fatalf("httpx_threads not clamped: %d", c.HttpxThreads)
	}

	// Валидный passive-режим сохраняется.
	p := DefaultFarmConfig()
	p.Mode = "passive"
	p.Sanitize()
	if p.Mode != "passive" {
		t.Fatalf("passive mode dropped: %q", p.Mode)
	}
}
