package recon

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// mockDoer — сим HTTP round-trip: захватывает запрос и отдаёт заранее заданный
// ответ. Реальная сеть в тестах не дёргается.
type mockDoer struct {
	status  int
	body    string
	lastReq *http.Request
	err     error
}

func (m *mockDoer) Do(req *http.Request) (*http.Response, error) {
	m.lastReq = req
	if m.err != nil {
		return nil, m.err
	}
	code := m.status
	if code == 0 {
		code = 200
	}
	return &http.Response{
		StatusCode: code,
		Body:       io.NopCloser(strings.NewReader(m.body)),
		Header:     make(http.Header),
	}, nil
}

// HIBP по почте: мок отдаёт массив брешей → парсятся в account-находки, ключ уходит
// в заголовок hibp-api-key, почта — в путь (не аргумент процесса).
func TestHIBPSource_ParsesBreaches(t *testing.T) {
	doer := &mockDoer{body: `[{"Name":"Adobe","Domain":"adobe.com","BreachDate":"2013-10-04","PwnCount":152445165}]`}
	src := &hibpSource{key: "hibp-key-xxx", cfg: BreachHTTPConfig{Doer: doer}}

	if !src.Enabled(BreachKeys{HIBP: "hibp-key-xxx"}) {
		t.Fatal("hibp must be enabled when key present")
	}
	leaks, err := src.Search(context.Background(), BreachTarget{Kind: BreachTargetEmail, Value: "a@b.com"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(leaks) != 1 {
		t.Fatalf("want 1 leak, got %d", len(leaks))
	}
	l := leaks[0]
	if l.Source != "hibp" || l.Kind != "account" || l.Subject != "a@b.com" || l.Value != "" {
		t.Fatalf("unexpected leak: %+v", l)
	}
	if l.Detail["breach"] != "Adobe" {
		t.Fatalf("detail missing breach name: %+v", l.Detail)
	}
	// Ключ — в заголовке, почта — в URL-пути (а не в argv).
	if doer.lastReq.Header.Get("hibp-api-key") != "hibp-key-xxx" {
		t.Fatalf("api key not sent in header: %q", doer.lastReq.Header.Get("hibp-api-key"))
	}
	if !strings.Contains(doer.lastReq.URL.Path, "a@b.com") {
		t.Fatalf("account not in URL path: %s", doer.lastReq.URL.Path)
	}
}

// HIBP 404 = «чистая» почта → пусто без ошибки.
func TestHIBPSource_404IsEmpty(t *testing.T) {
	src := &hibpSource{key: "k", cfg: BreachHTTPConfig{Doer: &mockDoer{status: 404}}}
	leaks, err := src.Search(context.Background(), BreachTarget{Kind: BreachTargetEmail, Value: "clean@b.com"})
	if err != nil || len(leaks) != 0 {
		t.Fatalf("404 must be empty/no-error, got leaks=%d err=%v", len(leaks), err)
	}
}

// Dehashed: basic-auth из "user:pass", entries → credential-находки с паролем.
func TestDehashedSource_ParsesEntries(t *testing.T) {
	doer := &mockDoer{body: `{"entries":[{"email":"a@b.com","username":"neo","password":"trinity","database_name":"LinkedIn"}]}`}
	src := &dehashedSource{key: "acct@x.com:apikey123", cfg: BreachHTTPConfig{Doer: doer}}

	leaks, err := src.Search(context.Background(), BreachTarget{Kind: BreachTargetDomain, Value: "b.com"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(leaks) != 1 {
		t.Fatalf("want 1 leak, got %d", len(leaks))
	}
	l := leaks[0]
	if l.Source != "dehashed" || l.Kind != "credential" || l.Subject != "a@b.com" || l.Value != "trinity" {
		t.Fatalf("unexpected leak: %+v", l)
	}
	if l.Detail["database"] != "LinkedIn" {
		t.Fatalf("detail missing database: %+v", l.Detail)
	}
	// basic-auth разобран из ключа, домен ушёл в query (query:domain:b.com).
	u, p, ok := doer.lastReq.BasicAuth()
	if !ok || u != "acct@x.com" || p != "apikey123" {
		t.Fatalf("basic auth wrong: u=%q p=%q ok=%v", u, p, ok)
	}
	if got := doer.lastReq.URL.Query().Get("query"); got != "domain:b.com" {
		t.Fatalf("query param wrong: %q", got)
	}
}

// Источник без ключа: Enabled==false и Search самопропускается (пусто, без сети).
func TestBreachSource_NoKeySelfSkips(t *testing.T) {
	doer := &mockDoer{err: context.DeadlineExceeded} // если дёрнут сеть — тест упадёт
	sources := AllBreachSources(BreachKeys{}, BreachHTTPConfig{Doer: doer})
	if len(sources) != 6 {
		t.Fatalf("want 6 sources, got %d", len(sources))
	}
	for _, src := range sources {
		// Бесплатные keyless-источники (ProxyNova, LeakCheck public) активны ВСЕГДА,
		// в «self-skip без ключа» не участвуют, и их Search не дёргаем (пошёл бы в сеть).
		if src.Name() == "proxynova" || src.Name() == "leakcheck" {
			if !src.Enabled(BreachKeys{}) {
				t.Fatalf("%s (free) must be enabled without a key", src.Name())
			}
			continue
		}
		if src.Enabled(BreachKeys{}) {
			t.Fatalf("source %s must be disabled without key", src.Name())
		}
		leaks, err := src.Search(context.Background(), BreachTarget{Kind: BreachTargetEmail, Value: "a@b.com"})
		if err != nil || len(leaks) != 0 {
			t.Fatalf("source %s with no key must self-skip, got leaks=%d err=%v", src.Name(), len(leaks), err)
		}
	}
	if doer.lastReq != nil {
		t.Fatal("no HTTP request should be made when keys are absent")
	}
}

// LeakCheck public (keyless): парсит success/found/fields/sources; password в fields
// → kind=credential; названия дампов кладёт в detail.breaches.
func TestLeakCheckPublicParses(t *testing.T) {
	doer := &mockDoer{body: `{"success":true,"found":3,"fields":["username","password"],"sources":[{"name":"Canva.com","date":"2019-05"},{"name":"StockX.com","date":"2019-07"}]}`}
	sources := AllBreachSources(BreachKeys{}, BreachHTTPConfig{Doer: doer})
	var lc BreachSource
	for _, s := range sources {
		if s.Name() == "leakcheck" {
			lc = s
		}
	}
	if lc == nil || !lc.Enabled(BreachKeys{}) {
		t.Fatal("leakcheck (public) must be enabled without a key")
	}
	leaks, err := lc.Search(context.Background(), BreachTarget{Kind: BreachTargetEmail, Value: "x@y.com"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(leaks) != 1 || leaks[0].Kind != "credential" || leaks[0].Source != "leakcheck" || leaks[0].Subject != "x@y.com" {
		t.Fatalf("unexpected leak: %+v", leaks)
	}
	br, _ := leaks[0].Detail["breaches"].([]string)
	if len(br) != 2 || br[0] != "Canva.com" {
		t.Fatalf("breaches not parsed: %+v", leaks[0].Detail)
	}
}

// HIBP по домену: Domain Search endpoint отдаёт карту {alias:[breaches]} → каждый
// alias раскрывается в account-находку subject=<alias>@<domain> (утёкший email-аккаунт),
// ключ уходит в заголовок, домен — в путь (не аргумент процесса).
func TestHIBPSource_DomainSearch(t *testing.T) {
	doer := &mockDoer{body: `{"john":["Adobe","LinkedIn"],"sales":["Dropbox"]}`}
	src := &hibpSource{key: "hibp-key-xxx", cfg: BreachHTTPConfig{Doer: doer}}

	leaks, err := src.Search(context.Background(), BreachTarget{Kind: BreachTargetDomain, Value: "corp.com"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(leaks) != 2 {
		t.Fatalf("want 2 account leaks, got %d: %+v", len(leaks), leaks)
	}
	// собираем по subject (порядок из map недетерминирован).
	bySubject := map[string]BreachLeak{}
	for _, l := range leaks {
		if l.Source != "hibp" || l.Kind != "account" || l.Value != "" {
			t.Fatalf("unexpected leak shape: %+v", l)
		}
		bySubject[l.Subject] = l
	}
	john, ok := bySubject["john@corp.com"]
	if !ok {
		t.Fatalf("john@corp.com not emitted: %+v", leaks)
	}
	// ресурс-источник: конкретные breach-базы + домен.
	breaches, _ := john.Detail["breaches"].([]string)
	if len(breaches) != 2 || breaches[0] != "Adobe" {
		t.Fatalf("john breaches wrong: %+v", john.Detail)
	}
	if john.Detail["domain"] != "corp.com" {
		t.Fatalf("john domain missing: %+v", john.Detail)
	}
	if _, ok := bySubject["sales@corp.com"]; !ok {
		t.Fatalf("sales@corp.com not emitted: %+v", leaks)
	}
	// ключ в заголовке, домен в пути /breacheddomain/<domain>.
	if doer.lastReq.Header.Get("hibp-api-key") != "hibp-key-xxx" {
		t.Fatalf("api key not in header")
	}
	if !strings.Contains(doer.lastReq.URL.Path, "breacheddomain/corp.com") {
		t.Fatalf("domain endpoint/path wrong: %s", doer.lastReq.URL.Path)
	}
}

// Dehashed по домену: entries без пароля → account-находки с subject=<email>
// (утёкшие email-аккаунты домена), с указанием breach-базы в detail.
func TestDehashedSource_DomainAccounts(t *testing.T) {
	doer := &mockDoer{body: `{"entries":[{"email":"a@corp.com","database_name":"Collection1"},{"email":"b@corp.com","database_name":"LinkedIn"}]}`}
	src := &dehashedSource{key: "acct@x.com:apikey123", cfg: BreachHTTPConfig{Doer: doer}}

	leaks, err := src.Search(context.Background(), BreachTarget{Kind: BreachTargetDomain, Value: "corp.com"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(leaks) != 2 {
		t.Fatalf("want 2 account leaks, got %d: %+v", len(leaks), leaks)
	}
	for _, l := range leaks {
		if l.Source != "dehashed" || l.Kind != "account" || l.Value != "" {
			t.Fatalf("want account leak without password, got %+v", l)
		}
		if l.Detail["database"] == "" || l.Detail["database"] == nil {
			t.Fatalf("account leak missing breach database resource: %+v", l.Detail)
		}
	}
	if leaks[0].Subject != "a@corp.com" {
		t.Fatalf("subject should be discovered email: %+v", leaks[0])
	}
}
