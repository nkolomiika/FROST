package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// GitHub email-майнинг: помимо секрет-скана trufflehog вытаскиваем УТЁКШИЕ
// EMAIL-АККАУНТЫ из истории коммитов через GitHub REST API. По repo — коммиты
// напрямую, по org/user — публичные репозитории, затем коммиты по каждому. Всё
// идёт через HTTPDoer-сим (тот же, что у breach-источников), поэтому тесты
// подсовывают мок round-trip и реальная сеть не дёргается.
//
// БЕЗОПАСНОСТЬ: owner/repo/имя уходят как path-сегменты (url.PathEscape) и query,
// НИКОГДА как аргументы процесса. Шелла тут нет. github_token (если есть) — только
// в заголовок Authorization для повышения rate-limit; при отсутствии — анонимно.
//
// ПОЛНОТА: и число страниц коммитов, и число репозиториев ограничены (cap). При
// достижении предела возвращается note — чтобы прогон НЕ выдавал усечённую историю
// за полную.

// GithubEmailConfig — сетевой конфиг email-майнинга + пределы обхода.
type GithubEmailConfig struct {
	Doer      HTTPDoer
	Timeout   time.Duration
	UserAgent string
	// MaxCommitPages — предел страниц коммитов на репозиторий (по 100 коммитов).
	MaxCommitPages int
	// MaxRepos — предел репозиториев при обходе org/user.
	MaxRepos int
}

func (c GithubEmailConfig) doer() HTTPDoer {
	if c.Doer != nil {
		return c.Doer
	}
	return &http.Client{Timeout: c.timeout()}
}

func (c GithubEmailConfig) timeout() time.Duration {
	if c.Timeout <= 0 {
		return 15 * time.Second
	}
	return c.Timeout
}

func (c GithubEmailConfig) ua() string {
	if c.UserAgent == "" {
		return "frost-recon"
	}
	return c.UserAgent
}

func (c GithubEmailConfig) pages() int {
	if c.MaxCommitPages <= 0 {
		return 3 // ~300 коммитов на репозиторий
	}
	return c.MaxCommitPages
}

func (c GithubEmailConfig) repos() int {
	if c.MaxRepos <= 0 {
		return 10
	}
	return c.MaxRepos
}

// GithubEmail — уникальная почта автора/коммиттера из истории коммитов.
type GithubEmail struct {
	Email string   // сама почта (утёкший аккаунт)
	Name  string   // имя автора, если есть
	Repos []string // owner/repo, где почта встретилась (может быть несколько)
}

// ScanGithubEmails обходит цель (repo или org/user) и возвращает УНИКАЛЬНЫЕ
// почты из истории коммитов (author/committer), выбросив noreply/bot/пустые.
// notes — мягкие пометки (достигнут cap страниц/репозиториев, ошибки API): прогон
// на них не валится. Ошибку возвращает только на неразбираемую цель.
func ScanGithubEmails(ctx context.Context, cfg GithubEmailConfig, rawTarget, token string) (emails []GithubEmail, notes []string, err error) {
	target, err := ParseGithubTarget(rawTarget)
	if err != nil {
		return nil, nil, err
	}

	// Дедуп по почте (lower-case), с сохранением порядка первой встречи и списка
	// репозиториев, где почта засветилась.
	seen := make(map[string]int) // lower(email) -> индекс в out
	var out []GithubEmail
	add := func(email, name, repo string) {
		email = strings.TrimSpace(email)
		if isNoreplyOrBot(email, name) {
			return
		}
		key := strings.ToLower(email)
		if idx, ok := seen[key]; ok {
			out[idx].Repos = appendUniqueStr(out[idx].Repos, repo)
			if out[idx].Name == "" && name != "" {
				out[idx].Name = name
			}
			return
		}
		seen[key] = len(out)
		out = append(out, GithubEmail{Email: email, Name: strings.TrimSpace(name), Repos: appendUniqueStr(nil, repo)})
	}

	var repos []repoRef
	if target.IsOrg {
		var n []string
		repos, n = githubListRepos(ctx, cfg, target.Org, token)
		notes = append(notes, n...)
	} else {
		repos = []repoRef{{Owner: target.Owner, Name: target.RepoName}}
	}

	for _, r := range repos {
		commits, n := githubRepoCommitEmails(ctx, cfg, r, token)
		notes = append(notes, n...)
		for _, c := range commits {
			add(c.email, c.name, r.Owner+"/"+r.Name)
		}
	}
	return out, notes, nil
}

// repoRef — минимальная ссылка на репозиторий для REST-обхода.
type repoRef struct {
	Owner string
	Name  string
}

// commitEmail — сырое извлечение (почта+имя) из одного коммита (до дедупа/фильтра).
type commitEmail struct {
	email string
	name  string
}

// githubListRepos перечисляет публичные репозитории org/user (bounded). Пробует
// /users/{name}/repos, при 404 — /orgs/{name}/repos. Возвращает note при усечении
// списка по MaxRepos или ошибке API (прогон не валится).
func githubListRepos(ctx context.Context, cfg GithubEmailConfig, name, token string) ([]repoRef, []string) {
	var notes []string
	maxRepos := cfg.repos()
	q := url.Values{"per_page": {strconv.Itoa(maxRepos)}, "type": {"public"}, "sort": {"updated"}}
	for _, base := range []string{"https://api.github.com/users/", "https://api.github.com/orgs/"} {
		endpoint := base + url.PathEscape(name) + "/repos?" + q.Encode()
		body, ok, err := githubDo(ctx, cfg, endpoint, token)
		if err != nil {
			notes = append(notes, "github repos "+name+": "+ErrLabel(err))
			return nil, notes
		}
		if !ok {
			continue // 404 → пробуем следующий тип (user→org)
		}
		var raw []struct {
			Name  string `json:"name"`
			Owner struct {
				Login string `json:"login"`
			} `json:"owner"`
		}
		if json.Unmarshal(body, &raw) != nil {
			return nil, notes
		}
		refs := make([]repoRef, 0, len(raw))
		for _, r := range raw {
			if r.Name == "" {
				continue
			}
			owner := r.Owner.Login
			if owner == "" {
				owner = name
			}
			refs = append(refs, repoRef{Owner: owner, Name: r.Name})
		}
		if len(refs) >= maxRepos {
			notes = append(notes, "github repos "+name+": достигнут предел репозиториев ("+strconv.Itoa(maxRepos)+"), обход не полный")
			refs = refs[:maxRepos]
		}
		return refs, notes
	}
	return nil, notes
}

// githubRepoCommitEmails тянет коммиты одного репозитория (bounded по страницам) и
// извлекает author/committer email+name. При достижении предела страниц добавляет
// note (история усечена). Ошибки/404 — мягкие: возвращаем что успели.
func githubRepoCommitEmails(ctx context.Context, cfg GithubEmailConfig, r repoRef, token string) ([]commitEmail, []string) {
	if r.Owner == "" || r.Name == "" {
		return nil, nil
	}
	var out []commitEmail
	var notes []string
	maxPages := cfg.pages()
	slug := r.Owner + "/" + r.Name
	for page := 1; page <= maxPages; page++ {
		q := url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}
		endpoint := "https://api.github.com/repos/" + url.PathEscape(r.Owner) + "/" + url.PathEscape(r.Name) + "/commits?" + q.Encode()
		body, ok, err := githubDo(ctx, cfg, endpoint, token)
		if err != nil {
			notes = append(notes, "github commits "+slug+": "+ErrLabel(err))
			return out, notes
		}
		if !ok {
			break // 404/409 (пустой репозиторий) → находок нет
		}
		var commits []struct {
			Commit struct {
				Author struct {
					Name  string `json:"name"`
					Email string `json:"email"`
				} `json:"author"`
				Committer struct {
					Name  string `json:"name"`
					Email string `json:"email"`
				} `json:"committer"`
			} `json:"commit"`
		}
		if json.Unmarshal(body, &commits) != nil {
			break
		}
		if len(commits) == 0 {
			break
		}
		for _, c := range commits {
			out = append(out, commitEmail{email: c.Commit.Author.Email, name: c.Commit.Author.Name})
			out = append(out, commitEmail{email: c.Commit.Committer.Email, name: c.Commit.Committer.Name})
		}
		if len(commits) < 100 {
			break // последняя (неполная) страница
		}
		if page == maxPages {
			notes = append(notes, "github commits "+slug+": достигнут предел страниц ("+strconv.Itoa(maxPages)+"×100), история не полная")
		}
	}
	return out, notes
}

// githubDo выполняет GET к GitHub REST API через сим. 404 → (nil,false,nil) (нет
// ресурса), 2xx → тело, прочее → ошибка (мягкая для прогона). token (если есть) —
// в Authorization для повышения rate-limit.
func githubDo(ctx context.Context, cfg GithubEmailConfig, endpoint, token string) ([]byte, bool, error) {
	c, cancel := context.WithTimeout(ctx, cfg.timeout())
	defer cancel()
	req, err := http.NewRequestWithContext(c, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, false, fmt.Errorf("github: %w", err)
	}
	req.Header.Set("User-Agent", cfg.ua())
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := cfg.doer().Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("github: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode/100 != 2 {
		return nil, false, fmt.Errorf("github: http_%d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, false, fmt.Errorf("github: %w", err)
	}
	return body, true, nil
}

// isNoreplyOrBot отсеивает служебные/бот-почты и пустые: GitHub noreply,
// *[bot]-аккаунты, пустая строка. Такие в утечки не идут.
func isNoreplyOrBot(email, name string) bool {
	e := strings.ToLower(strings.TrimSpace(email))
	if e == "" {
		return true
	}
	if strings.HasSuffix(e, "@users.noreply.github.com") {
		return true
	}
	if strings.Contains(e, "[bot]") {
		return true
	}
	if strings.Contains(strings.ToLower(name), "[bot]") {
		return true
	}
	return false
}

func appendUniqueStr(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
