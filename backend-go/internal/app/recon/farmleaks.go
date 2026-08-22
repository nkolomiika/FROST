package recon

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
	"golang.org/x/sync/errgroup"
)

// Стадия утечек полного прогона фермы (gated: stage_leaks). Переносит скан утечек
// ВНУТРЬ прогона: по каждому github-URL гоняет trufflehog (секреты), по каждому
// домену/почте — breach-пробив по всем сконфигурированным источникам. Все находки
// уходят в ЕДИНОЕ хранилище recon_leaks через тот же LeakSink, что и standalone
// github-скан, с тем же job_id/project_id — поэтому появляются в GET /leaks и в
// потоке отчёта. Стадия cancelable per-step, уважает cfg.Concurrency; источник без
// ключа мягко самопропускается (как dnsx-брут без словаря), не роняя прогон.

// runFarmLeaks — стадия утечек. Возвращает true при отмене всего прогона (caller
// уходит в finalizeCancelled).
func (s *Service) runFarmLeaks(ctx context.Context, runSvc *Service, cfg FarmConfig, projectID, jobID int32, prog *progressTracker, result *FarmRunResult, wasCancelled *atomic.Bool) bool {
	prog.update(func(p *RunProgress) { p.Stage = "leaks"; p.Percent = pctLeaks })

	// Контекст leaks не подключён (AttachLeaks) → мягко пропускаем стадию.
	if s.leakSink == nil || s.integrations == nil {
		result.Errors = append(result.Errors, "стадия утечек пропущена: контекст leaks не подключён")
		return false
	}

	// github_token опционален: есть → авторизованный скан, нет → анонимный.
	githubToken, _, _ := s.integrations.GetIntegrationKey(ctx, "github_token")
	keys := s.resolveBreachKeys(ctx)
	sources := runSvc.breachSourcesFor(keys)

	// Leaks и Account search — ДВА независимых этапа с раздельными тумблерами, но
	// общей плумбингой (единый recon_leaks, один прогресс-бэнд). Github-скан gated
	// на StageLeaks, breach-пробив по доменам/почтам — на StageAccountSearch.
	ghURLs := cfg.LeaksGithub
	if !cfg.StageLeaks {
		ghURLs = nil
	}

	// Цели breach-пробива: домены + почты (только если включён поиск учёток).
	targets := make([]reconnet.BreachTarget, 0, len(cfg.LeaksDomains)+len(cfg.LeaksEmails))
	if cfg.StageAccountSearch {
		for _, d := range cfg.LeaksDomains {
			targets = append(targets, reconnet.BreachTarget{Kind: reconnet.BreachTargetDomain, Value: d})
		}
		for _, e := range cfg.LeaksEmails {
			targets = append(targets, reconnet.BreachTarget{Kind: reconnet.BreachTargetEmail, Value: e})
		}
	}

	// LinkedIn-энумерация: по названиям компаний достаём сотрудников через поисковик
	// (без логина/ключей), генерим вероятные почты по доменам прогона и добавляем их
	// в цели breach-пробива; самих людей эмитим как account-находки (source=linkedin).
	// Синхронно, каждая компания — видимый шаг (несколько HTTP-запросов). На cancel —
	// как и breach-находки: накопленное отбрасывается (return true до WriteLeaks).
	var linkedinRecs []LeakRecord
	if cfg.StageAccountSearch {
		// Дедуп собранных/сгенерированных почт против уже заданных email-целей.
		genSeen := make(map[string]struct{})
		for _, tg := range targets {
			if tg.Kind == reconnet.BreachTargetEmail {
				genSeen[strings.ToLower(tg.Value)] = struct{}{}
			}
		}
		addEmail := func(em string, rec *LeakRecord) {
			le := strings.ToLower(strings.TrimSpace(em))
			if le == "" {
				return
			}
			if _, ok := genSeen[le]; ok {
				return
			}
			genSeen[le] = struct{}{}
			targets = append(targets, reconnet.BreachTarget{Kind: reconnet.BreachTargetEmail, Value: em})
			if rec != nil {
				linkedinRecs = append(linkedinRecs, *rec)
			}
		}

		// LinkedIn: компании → сотрудники → сгенерированные почты (+ люди как находки).
		for _, company := range cfg.LeaksCompanies {
			if ctx.Err() != nil {
				break
			}
			stepCtx, stepCancel := context.WithCancel(ctx)
			id := prog.addStep(RunStep{Tool: "linkedin", Args: `site:linkedin.com/in "` + company + `"`, Target: company, StartedAt: time.Now()}, stepCancel)
			people, note := reconnet.EnumerateLinkedIn(stepCtx, company, s.settings)
			if note != "" {
				result.Errors = append(result.Errors, note)
			}
			for _, p := range people {
				linkedinRecs = append(linkedinRecs, linkedinLeakRecord(p, company, cfg.LeaksDomains))
			}
			for _, em := range reconnet.GenerateEmails(people, cfg.LeaksDomains, leaksInputCap) {
				addEmail(em, nil)
			}
			prog.removeStep(id)
			stepCancel()
		}

		// Email-harvest через Google CSE: реальные почты доменов из веба → в breach-цели
		// и как account-находки (source=web). Только при настроенном CSE (key+cx).
		if len(cfg.LeaksDomains) > 0 && strings.TrimSpace(s.settings.GoogleCSEKey) != "" && strings.TrimSpace(s.settings.GoogleCSECx) != "" {
			stepCtx, stepCancel := context.WithCancel(ctx)
			id := prog.addStep(RunStep{Tool: "email-harvest", Args: `google cse "@domain"`, Target: strings.Join(cfg.LeaksDomains, ","), StartedAt: time.Now()}, stepCancel)
			emails, note := reconnet.HarvestEmailsCSE(stepCtx, cfg.LeaksDomains, s.settings)
			if note != "" {
				result.Errors = append(result.Errors, note)
			}
			for _, em := range emails {
				rec := webEmailLeakRecord(em)
				addEmail(em, &rec)
			}
			prog.removeStep(id)
			stepCancel()
		}
	}

	// Активные источники — только те, у кого есть ключ; для неактивных — мягкая
	// пометка (лишь когда есть что пробивать), прогон не валится.
	var enabled []reconnet.BreachSource
	for _, src := range sources {
		if src.Enabled(keys) {
			enabled = append(enabled, src)
		} else if len(targets) > 0 {
			result.Errors = append(result.Errors, "breach-источник "+src.Name()+" пропущен: ключ не задан")
		}
	}

	limit := cfg.Concurrency
	if limit < 1 {
		limit = 1
	}

	var mu sync.Mutex
	var recs []LeakRecord

	// Домены прогона — для пометки github-почт, чей домен совпал (детект, не фильтр:
	// эмитим ВСЕ найденные аккаунты).
	domainSet := make(map[string]struct{}, len(cfg.LeaksDomains))
	for _, d := range cfg.LeaksDomains {
		domainSet[strings.ToLower(strings.TrimSpace(d))] = struct{}{}
	}

	// Плавный рост процента по мере готовности единиц работы (band [pctLeaks..pctDone-1]).
	// Каждый github-URL даёт ДВЕ единицы: секрет-скан + email-майнинг.
	totalUnits := len(ghURLs)*2 + len(targets)*len(enabled)
	var doneUnits atomic.Int64
	bump := func() {
		d := int(doneUnits.Add(1))
		if totalUnits > 0 {
			pct := pctLeaks + (pctDone-1-pctLeaks)*d/totalUnits
			prog.update(func(p *RunProgress) {
				if pct > p.Percent {
					p.Percent = pct
				}
			})
		}
	}

	var eg errgroup.Group
	eg.SetLimit(limit)

	// ── github secret-scan по каждому URL (переиспользует github-сим скана) ──
	for _, ghURL := range ghURLs {
		ghURL := ghURL
		eg.Go(func() error {
			stepCtx, stepCancel := context.WithCancel(ctx)
			defer stepCancel()
			id := prog.addStep(RunStep{Tool: "trufflehog-github", Args: "trufflehog github " + githubArgDisplay(ghURL), Target: ghURL, StartedAt: time.Now()}, stepCancel)
			defer prog.removeStep(id)
			secrets, err := runSvc.runGithubScanner(stepCtx, ghURL, githubToken)
			mu.Lock()
			for _, sec := range secrets {
				recs = append(recs, githubLeakRecord(sec))
			}
			if err != nil {
				result.Errors = append(result.Errors, "github-скан "+ghURL+": "+reconnet.ErrLabel(err))
			}
			if stepCtx.Err() != nil && ctx.Err() == nil {
				result.Errors = append(result.Errors, "процесс отменён: trufflehog-github "+ghURL)
			}
			mu.Unlock()
			bump()
			return nil
		})

		// ── github email-майнинг по тому же URL (аккаунты из истории коммитов) ──
		eg.Go(func() error {
			stepCtx, stepCancel := context.WithCancel(ctx)
			defer stepCancel()
			id := prog.addStep(RunStep{Tool: "github-emails", Args: "github commit emails " + githubArgDisplay(ghURL), Target: ghURL, StartedAt: time.Now()}, stepCancel)
			defer prog.removeStep(id)
			emails, notes, err := runSvc.runGithubEmailScanner(stepCtx, ghURL, githubToken)
			mu.Lock()
			for _, em := range emails {
				recs = append(recs, githubEmailLeakRecord(em, domainSet))
			}
			// Пределы обхода/ошибки API — мягкие пометки (история могла быть усечена).
			for _, n := range notes {
				result.Errors = append(result.Errors, "github-emails "+ghURL+": "+n)
			}
			if err != nil {
				result.Errors = append(result.Errors, "github-emails "+ghURL+": "+reconnet.ErrLabel(err))
			}
			if stepCtx.Err() != nil && ctx.Err() == nil {
				result.Errors = append(result.Errors, "процесс отменён: github-emails "+ghURL)
			}
			mu.Unlock()
			bump()
			return nil
		})
	}

	// ── breach-пробив: каждая цель × каждый активный источник ──
	for _, tgt := range targets {
		for _, src := range enabled {
			tgt, src := tgt, src
			eg.Go(func() error {
				stepCtx, stepCancel := context.WithCancel(ctx)
				defer stepCancel()
				// Ключ источника в args НЕ светим — только имя и цель.
				id := prog.addStep(RunStep{Tool: src.Name(), Args: src.Name() + " breach search (" + tgt.Kind + ": " + tgt.Value + ")", Target: tgt.Value, StartedAt: time.Now()}, stepCancel)
				defer prog.removeStep(id)
				found, err := src.Search(stepCtx, tgt)
				mu.Lock()
				for _, lk := range found {
					recs = append(recs, breachLeakRecord(lk))
				}
				if err != nil {
					result.Errors = append(result.Errors, "breach "+src.Name()+" "+tgt.Value+": "+reconnet.ErrLabel(err))
				}
				if stepCtx.Err() != nil && ctx.Err() == nil {
					result.Errors = append(result.Errors, "процесс отменён: "+src.Name()+" "+tgt.Value)
				}
				mu.Unlock()
				bump()
				return nil
			})
		}
	}

	_ = eg.Wait()
	recs = append(recs, linkedinRecs...) // LinkedIn-люди (найдены до errgroup)
	if wasCancelled.Load() {
		return true
	}

	if len(recs) > 0 {
		if err := s.leakSink.WriteLeaks(ctx, projectID, &jobID, recs); err != nil {
			result.Errors = append(result.Errors, reconnet.ErrLabel(err))
		}
	}
	result.LeaksFound = len(recs)
	prog.update(func(p *RunProgress) { p.LeaksFound = len(recs) })
	return false
}

// resolveBreachKeys собирает workspace-ключи breach-источников через резолвер
// интеграций. Незаданный ключ — пустая строка (источник самопропустится).
func (s *Service) resolveBreachKeys(ctx context.Context) reconnet.BreachKeys {
	get := func(name string) string {
		v, _, err := s.integrations.GetIntegrationKey(ctx, name)
		if err != nil {
			return ""
		}
		return v
	}
	return reconnet.BreachKeys{
		HIBP:      get("hibp"),
		Dehashed:  get("dehashed"),
		IntelX:    get("intelx"),
		LeakCheck: get("leakcheck"),
		Snusbase:  get("snusbase"),
		ProxyNova: get("proxynova"),
	}
}

// breachSourcesFor — реестр breach-источников (сид breachSources в тестах; nil →
// реальный reconnet.AllBreachSources). Возвращает ВСЕ источники (активность решает
// вызывающий по Enabled(keys)).
func (s *Service) breachSourcesFor(keys reconnet.BreachKeys) []reconnet.BreachSource {
	if s.breachSources != nil {
		return s.breachSources(keys)
	}
	return reconnet.AllBreachSources(keys, reconnet.BreachHTTPConfig{Timeout: 15 * time.Second, UserAgent: "frost-recon"})
}

// githubArgDisplay — человекочитаемые аргументы trufflehog github (без секретов).
func githubArgDisplay(raw string) string {
	t, err := reconnet.ParseGithubTarget(raw)
	if err != nil {
		return raw
	}
	if t.IsOrg {
		return "--org=" + t.Org
	}
	return "--repo=" + t.Repo
}

// githubLeakRecord — находка trufflehog github → запись хранилища утечек
// (source=github, kind=secret), зеркало standalone github-скана.
func githubLeakRecord(sec reconnet.GithubSecret) LeakRecord {
	return LeakRecord{
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
	}
}

// githubEmailLeakRecord — почта из истории коммитов github → запись хранилища
// утечек (source=github, kind=account, subject=<email>, value=""). detail несёт
// КОНКРЕТНЫЙ РЕСУРС-ИСТОЧНИК: repo(s), где почта засветилась, + имя автора. Домены
// прогона используются только для пометки matched_domain (не для фильтра — эмитим
// все найденные аккаунты). Breach-данные не верифицируются.
func githubEmailLeakRecord(em reconnet.GithubEmail, domainSet map[string]struct{}) LeakRecord {
	detail := map[string]any{
		"repos": em.Repos,
		"name":  em.Name,
	}
	if len(em.Repos) > 0 {
		detail["repo"] = em.Repos[0] // первый репозиторий для удобства UI
	}
	if len(domainSet) > 0 {
		if at := strings.LastIndexByte(em.Email, '@'); at >= 0 {
			if _, ok := domainSet[strings.ToLower(em.Email[at+1:])]; ok {
				detail["matched_domain"] = true
			}
		}
	}
	return LeakRecord{
		Source:   "github",
		Kind:     "account",
		Subject:  em.Email,
		Value:    "",
		Verified: false,
		Detail:   detail,
	}
}

// linkedinLeakRecord — сотрудник, найденный через LinkedIn (search-engine) → запись
// хранилища утечек (source=linkedin, kind=account). subject — первая сгенерированная
// вероятная почта (если есть домен прогона), иначе ФИО. detail несёт имя, компанию,
// подпись-профиль и предполагаемую почту (не верифицируется).
func linkedinLeakRecord(p reconnet.LinkedInPerson, company string, domains []string) LeakRecord {
	name := strings.TrimSpace(p.First + " " + p.Last)
	detail := map[string]any{
		"name":     name,
		"company":  company,
		"resource": "linkedin",
	}
	if p.Headline != "" {
		detail["headline"] = p.Headline
	}
	subject := name
	if em := reconnet.GenerateEmails([]reconnet.LinkedInPerson{p}, domains, 1); len(em) > 0 {
		subject = em[0]
		detail["guessed_email"] = em[0]
	}
	return LeakRecord{
		Source:   "linkedin",
		Kind:     "account",
		Subject:  subject,
		Value:    "",
		Verified: false,
		Detail:   detail,
	}
}

// webEmailLeakRecord — реальная почта домена, найденная в открытом вебе через CSE
// (пасты/GitHub/доки) → находка (source=web, kind=account). Не верифицируется.
func webEmailLeakRecord(email string) LeakRecord {
	return LeakRecord{
		Source:   "web",
		Kind:     "account",
		Subject:  email,
		Value:    "",
		Verified: false,
		Detail: map[string]any{
			"resource": "web",
			"note":     "email found on the public web (Google CSE)",
		},
	}
}

// breachLeakRecord — находка breach-источника → запись хранилища утечек
// (source=<hibp|dehashed|…>, kind=credential|account). Breach-данные не
// верифицируются (verified=false).
func breachLeakRecord(lk reconnet.BreachLeak) LeakRecord {
	return LeakRecord{
		Source:   lk.Source,
		Kind:     lk.Kind,
		Subject:  lk.Subject,
		Value:    lk.Value,
		Verified: false,
		Detail:   lk.Detail,
	}
}
