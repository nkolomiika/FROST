package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

// GitHub secret-scan через trufflehog (bundled в рекон-образе). Публичные репозитории
// сканируются БЕЗ токена (rate-limited); при наличии github_token он прокидывается
// в GITHUB_TOKEN. Цель — repo-URL (--repo=<url>) либо org/user (--org=<name>).

// GithubScanConfig — настройки github-скана.
type GithubScanConfig struct {
	TrufflehogBin string
	Timeout       time.Duration
}

// GithubSecret — одна распарсенная находка trufflehog github.
type GithubSecret struct {
	Detector string
	Verified bool
	Raw      string
	Repo     string
	File     string
	Link     string
	Commit   string
	Line     int64
}

// GithubTarget — разобранная цель скана: либо конкретный repo-URL, либо org/user.
type GithubTarget struct {
	IsOrg    bool
	Repo     string // полный URL репозитория (для --repo)
	Org      string // имя org/user (для --org)
	Owner    string // владелец репозитория (для REST /repos/{owner}/{repo})
	RepoName string // имя репозитория без .git (для REST /repos/{owner}/{repo})
}

// ParseGithubTarget разбирает github-URL в цель скана. Один сегмент пути → org/user
// (--org), два и более → репозиторий (--repo). Ошибка — не github.com/пустой путь.
func ParseGithubTarget(raw string) (GithubTarget, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return GithubTarget{}, fmt.Errorf("пустой URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return GithubTarget{}, fmt.Errorf("некорректный URL: %w", err)
	}
	host := strings.ToLower(u.Hostname())
	if host != "github.com" && !strings.HasSuffix(host, ".github.com") {
		return GithubTarget{}, fmt.Errorf("ожидался github.com URL, получен %q", host)
	}
	segs := make([]string, 0, 4)
	for _, s := range strings.Split(strings.Trim(u.Path, "/"), "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	if len(segs) == 0 {
		return GithubTarget{}, fmt.Errorf("URL не содержит org/user или репозитория")
	}
	if len(segs) == 1 {
		return GithubTarget{IsOrg: true, Org: segs[0]}, nil
	}
	// owner/repo — нормализуем к https://github.com/owner/repo (без .git и хвоста).
	repoName := strings.TrimSuffix(segs[1], ".git")
	repoURL := "https://" + host + "/" + segs[0] + "/" + repoName
	return GithubTarget{Repo: repoURL, Owner: segs[0], RepoName: repoName}, nil
}

// ScanGithub запускает trufflehog github по цели и парсит JSON-строки в находки.
// token пуст → анонимный скан (публичные репозитории). Отсутствие бинаря (LookPath)
// → ошибка (воркер не падает, скан завершается с понятной ошибкой).
func ScanGithub(ctx context.Context, cfg GithubScanConfig, rawTarget, token string) ([]GithubSecret, error) {
	bin := cfg.TrufflehogBin
	if bin == "" {
		bin = "trufflehog"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return nil, fmt.Errorf("trufflehog не найден (%s): %w", bin, err)
	}
	target, err := ParseGithubTarget(rawTarget)
	if err != nil {
		return nil, err
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// --json: построчный JSON; --no-update: не ходить за апдейтами; верификация
	// включена (verified → критично).
	args := []string{"github", "--json", "--no-update"}
	if target.IsOrg {
		args = append(args, "--org="+target.Org)
	} else {
		args = append(args, "--repo="+target.Repo)
	}
	cmd := exec.CommandContext(c, bin, args...)
	if token != "" {
		cmd.Env = append(os.Environ(), "GITHUB_TOKEN="+token)
	}
	out, err := cmd.Output()
	if err != nil {
		// trufflehog отдаёт ненулевой код при находках — вывод всё равно валиден.
		if len(out) == 0 {
			return nil, fmt.Errorf("trufflehog github: %w", err)
		}
	}
	return parseGithubOutput(out), nil
}

// GithubScanConfigFrom собирает конфиг github-скана из Settings (переиспользует
// TrufflehogBin майнинга JS; таймаут — отдельный, github-скан длиннее).
func (s Settings) GithubScanConfigFrom() GithubScanConfig {
	return GithubScanConfig{TrufflehogBin: s.TrufflehogBin, Timeout: s.GithubScanTimeout}
}

// parseGithubOutput парсит построчный JSON trufflehog github в находки.
func parseGithubOutput(out []byte) []GithubSecret {
	var res []GithubSecret
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var m struct {
			DetectorName   string `json:"DetectorName"`
			Verified       bool   `json:"Verified"`
			Raw            string `json:"Raw"`
			SourceMetadata struct {
				Data struct {
					Github struct {
						Link       string `json:"link"`
						Repository string `json:"repository"`
						File       string `json:"file"`
						Commit     string `json:"commit"`
						Line       int64  `json:"line"`
					} `json:"Github"`
				} `json:"Data"`
			} `json:"SourceMetadata"`
		}
		if json.Unmarshal([]byte(line), &m) != nil || m.DetectorName == "" || m.Raw == "" {
			continue
		}
		gh := m.SourceMetadata.Data.Github
		res = append(res, GithubSecret{
			Detector: m.DetectorName,
			Verified: m.Verified,
			Raw:      m.Raw,
			Repo:     gh.Repository,
			File:     gh.File,
			Link:     gh.Link,
			Commit:   gh.Commit,
			Line:     gh.Line,
		})
	}
	return res
}
