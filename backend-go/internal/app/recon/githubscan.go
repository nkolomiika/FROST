package recon

import (
	"context"
	"errors"
	"time"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
	"github.com/nkolomiika/frost/internal/apperr"
)

// GitHub secret-scan (kind='github_scan') на ОБЫЧНОЙ дорожке воркера. Резолвит
// github_token из workspace-интеграций (если есть — trufflehog идёт авторизованно,
// иначе анонимно по публичным репозиториям), гоняет trufflehog github и складывает
// находки в ЕДИНОЕ хранилище утечек (source=github) через LeakSink. Дизайн приёмника
// generic — linkedin/breach-сканеры позже пишут туда же с другим source.

// IntegrationResolver — порт получения workspace-ключа (github_token и т.п.).
// Реализует integrations.Service.
type IntegrationResolver interface {
	GetIntegrationKey(ctx context.Context, name string) (string, bool, error)
}

// LeakRecord — одна находка утечки для приёмника (source-agnostic).
type LeakRecord struct {
	Source   string
	Kind     string
	Subject  string
	Value    string
	Detail   map[string]any
	Verified bool
}

// LeakSink — приёмник находок утечек (пишет в единое хранилище recon_leaks).
// Реализует адаптер поверх leaks.Service в composition root.
type LeakSink interface {
	WriteLeaks(ctx context.Context, projectID int32, jobID *int32, recs []LeakRecord) error
}

// githubScanResult — итог github-скана (job.result).
type githubScanResult struct {
	Target   string `json:"target"`
	Total    int    `json:"total"`
	Verified int    `json:"verified"`
}

// createGithubScanJob валидирует github-цель и ставит скан в фон (kind=github_scan).
func (s *Service) createGithubScanJob(ctx context.Context, projectID, actorID int32, raw string) (JobView, error) {
	if _, err := reconnet.ParseGithubTarget(raw); err != nil {
		return JobView{}, apperr.Validation("Ожидался github.com URL (репозиторий или org/user)")
	}
	tt := int32(1)
	return s.store.InsertJob(ctx, NewJob{
		ProjectID: projectID, CreatedBy: actorID, Kind: KindGithubScan, Status: jobPending,
		TargetsTotal: &tt, Raw: raw,
	})
}

// runGithubScanner — сид-обёртка github-скана (nil-сид → реальный trufflehog github).
func (s *Service) runGithubScanner(ctx context.Context, target, token string) ([]reconnet.GithubSecret, error) {
	if s.githubScan != nil {
		return s.githubScan(ctx, target, token)
	}
	return reconnet.ScanGithub(ctx, s.settings.GithubScanConfigFrom(), target, token)
}

// runGithubEmailScanner — сид-обёртка email-майнинга github (nil-сид → реальный
// reconnet.ScanGithubEmails через дефолтный http.Client с bounded-пределами).
func (s *Service) runGithubEmailScanner(ctx context.Context, target, token string) ([]reconnet.GithubEmail, []string, error) {
	if s.githubEmailScan != nil {
		return s.githubEmailScan(ctx, target, token)
	}
	cfg := reconnet.GithubEmailConfig{Timeout: 15 * time.Second, UserAgent: "frost-recon"}
	return reconnet.ScanGithubEmails(ctx, cfg, target, token)
}

// runGithubScan прогоняет github-скан: резолвит токен, гоняет trufflehog, парсит
// находки → LeakRecord (source=github) и пишет их в единое хранилище утечек.
func (s *Service) runGithubScan(ctx context.Context, claim *JobClaim) (any, error) {
	if s.leakSink == nil || s.integrations == nil {
		return nil, errors.New("контекст leaks не подключён (AttachLeaks)")
	}

	// github_token — опционален: есть → авторизованный скан; нет → анонимный.
	token, _, err := s.integrations.GetIntegrationKey(ctx, "github_token")
	if err != nil {
		return nil, err
	}

	secrets, err := s.runGithubScanner(ctx, claim.Raw, token)
	if err != nil {
		return nil, err
	}

	res := githubScanResult{Target: claim.Raw, Total: len(secrets)}
	recs := make([]LeakRecord, 0, len(secrets))
	for _, sec := range secrets {
		if sec.Verified {
			res.Verified++
		}
		recs = append(recs, LeakRecord{
			Source:   "github",
			Kind:     "secret",
			Subject:  sec.Repo,
			Value:    sec.Raw,
			Verified: sec.Verified,
			Detail: map[string]any{
				"repo":     sec.Repo,
				"file":     sec.File,
				"link":     sec.Link,
				"commit":   sec.Commit,
				"detector": sec.Detector,
				"verified": sec.Verified,
			},
		})
	}
	jobID := claim.ID
	if err := s.leakSink.WriteLeaks(ctx, claim.ProjectID, &jobID, recs); err != nil {
		return nil, err
	}
	s.audit(ctx, claim.CreatedBy, "github_scan", detailsFrom(res, claim.ProjectID))
	return res, nil
}
