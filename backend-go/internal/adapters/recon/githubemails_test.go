package recon

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// routeDoer — сим HTTP round-trip с ответом по подстроке URL. Считает вызовы и
// хранит порядок запрошенных URL. Реальная сеть в тестах не дёргается.
type routeDoer struct {
	routes map[string]string // подстрока URL -> тело ответа (200)
	calls  []string
}

func (d *routeDoer) Do(req *http.Request) (*http.Response, error) {
	u := req.URL.String()
	d.calls = append(d.calls, u)
	for sub, body := range d.routes {
		if strings.Contains(u, sub) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		}
	}
	return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
}

// Repo target: коммиты парсятся в author/committer email, дедуп по почте, noreply/bot/
// пустые выброшены, оставшиеся уникальные — с указанием репозитория (ресурс-источник).
func TestScanGithubEmails_RepoDedupAndFilter(t *testing.T) {
	page1 := `[
	  {"commit":{"author":{"name":"Alice","email":"alice@corp.com"},"committer":{"name":"Alice","email":"alice@corp.com"}}},
	  {"commit":{"author":{"name":"Bob","email":"bob@corp.com"},"committer":{"name":"GitHub","email":"noreply@users.noreply.github.com"}}},
	  {"commit":{"author":{"name":"dependabot[bot]","email":"49699333+dependabot[bot]@users.noreply.github.com"},"committer":{"name":"ci[bot]","email":"ci@buildserver.internal"}}},
	  {"commit":{"author":{"name":"Empty","email":""},"committer":{"name":"","email":""}}}
	]`
	doer := &routeDoer{routes: map[string]string{"/repos/owner/repo/commits": page1}}
	cfg := GithubEmailConfig{Doer: doer, MaxCommitPages: 3}

	emails, notes, err := ScanGithubEmails(context.Background(), cfg, "https://github.com/owner/repo", "")
	if err != nil {
		t.Fatalf("ScanGithubEmails: %v", err)
	}
	// alice (dedup author+committer) + bob = 2. noreply/bot/empty отброшены.
	if len(emails) != 2 {
		t.Fatalf("want 2 unique emails, got %d: %+v", len(emails), emails)
	}
	byEmail := map[string]GithubEmail{}
	for _, e := range emails {
		byEmail[e.Email] = e
	}
	alice, ok := byEmail["alice@corp.com"]
	if !ok {
		t.Fatalf("alice missing: %+v", emails)
	}
	if alice.Name != "Alice" || len(alice.Repos) != 1 || alice.Repos[0] != "owner/repo" {
		t.Fatalf("alice resource wrong: %+v", alice)
	}
	if _, ok := byEmail["bob@corp.com"]; !ok {
		t.Fatalf("bob missing: %+v", emails)
	}
	if _, ok := byEmail["noreply@users.noreply.github.com"]; ok {
		t.Fatalf("noreply must be dropped")
	}
	// одна страница (page1 < 100) → без note о cap.
	for _, n := range notes {
		if strings.Contains(n, "предел страниц") {
			t.Fatalf("unexpected page-cap note on short history: %v", notes)
		}
	}
	// токен пуст → без Authorization (проверяем анонимный путь не падает).
}

// Page cap: страница из 100 коммитов держит пагинацию; при достижении предела
// возвращается note (история усечена), число запросов равно MaxCommitPages.
func TestScanGithubEmails_PageCap(t *testing.T) {
	// 100 одинаковых коммитов на страницу → пагинация не останавливается по «короткой» странице.
	one := `{"commit":{"author":{"name":"A","email":"a@corp.com"},"committer":{"name":"A","email":"a@corp.com"}}}`
	full := "[" + strings.TrimSuffix(strings.Repeat(one+",", 100), ",") + "]"
	doer := &routeDoer{routes: map[string]string{"/repos/owner/repo/commits": full}}
	cfg := GithubEmailConfig{Doer: doer, MaxCommitPages: 2}

	emails, notes, err := ScanGithubEmails(context.Background(), cfg, "https://github.com/owner/repo", "tok")
	if err != nil {
		t.Fatalf("ScanGithubEmails: %v", err)
	}
	if len(emails) != 1 {
		t.Fatalf("want 1 unique email after dedup, got %d", len(emails))
	}
	// ровно MaxCommitPages запросов к commits.
	if len(doer.calls) != 2 {
		t.Fatalf("want 2 paged requests (cap), got %d: %v", len(doer.calls), doer.calls)
	}
	var sawCap bool
	for _, n := range notes {
		if strings.Contains(n, "предел страниц") {
			sawCap = true
		}
	}
	if !sawCap {
		t.Fatalf("expected page-cap note, got %v", notes)
	}
}

// Org/user target: перечисляются репозитории, затем коммиты по каждому; почты
// собираются со всех репозиториев (ресурс-источник в Repos).
func TestScanGithubEmails_OrgListsReposThenCommits(t *testing.T) {
	repos := `[{"name":"r1","owner":{"login":"acme"}},{"name":"r2","owner":{"login":"acme"}}]`
	c1 := `[{"commit":{"author":{"name":"A","email":"a@acme.com"},"committer":{"name":"A","email":"a@acme.com"}}}]`
	c2 := `[{"commit":{"author":{"name":"B","email":"b@acme.com"},"committer":{"name":"B","email":"b@acme.com"}}}]`
	doer := &routeDoer{routes: map[string]string{
		"/users/acme/repos":      repos,
		"/repos/acme/r1/commits": c1,
		"/repos/acme/r2/commits": c2,
	}}
	cfg := GithubEmailConfig{Doer: doer, MaxCommitPages: 1, MaxRepos: 10}

	emails, _, err := ScanGithubEmails(context.Background(), cfg, "https://github.com/acme", "")
	if err != nil {
		t.Fatalf("ScanGithubEmails: %v", err)
	}
	if len(emails) != 2 {
		t.Fatalf("want 2 emails across repos, got %d: %+v", len(emails), emails)
	}
	byEmail := map[string]GithubEmail{}
	for _, e := range emails {
		byEmail[e.Email] = e
	}
	if a, ok := byEmail["a@acme.com"]; !ok || len(a.Repos) != 1 || a.Repos[0] != "acme/r1" {
		t.Fatalf("a resource wrong: %+v", byEmail)
	}
	if b, ok := byEmail["b@acme.com"]; !ok || b.Repos[0] != "acme/r2" {
		t.Fatalf("b resource wrong: %+v", byEmail)
	}
}

// Token present → Authorization: Bearer <token> уходит в заголовок (не в argv).
func TestScanGithubEmails_TokenHeader(t *testing.T) {
	doer := &authCapturingDoer{body: `[]`}
	cfg := GithubEmailConfig{Doer: doer, MaxCommitPages: 1}
	if _, _, err := ScanGithubEmails(context.Background(), cfg, "https://github.com/owner/repo", "ghp_secret"); err != nil {
		t.Fatalf("ScanGithubEmails: %v", err)
	}
	if doer.auth != "Bearer ghp_secret" {
		t.Fatalf("token not sent as Authorization header: %q", doer.auth)
	}
}

type authCapturingDoer struct {
	body string
	auth string
}

func (d *authCapturingDoer) Do(req *http.Request) (*http.Response, error) {
	d.auth = req.Header.Get("Authorization")
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(d.body)), Header: make(http.Header)}, nil
}
