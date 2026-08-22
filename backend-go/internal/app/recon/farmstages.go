package recon

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

// Стадии полного прогона фермы, вынесенные из farmrun.go: резолв+liveness (общий
// для веток «поддомены вкл/выкл»), стадия эндпоинтов (katana/gau/waybackurls) и
// стадия JS-майнинга (trufflehog+regex). Все три — cancelable per-step (свой stepCtx
// на каждый инструмент), уважают cfg.Concurrency/RateLimit и стейджат результат.

// stagedSourceProject — провенанс staged-хоста, взятого из существующих хостов
// проекта (стадия поддоменов выключена — работаем по известным хостам).
const stagedSourceProject = "project"

// stageResolve гоняет dry-пробив (dnsx-резолв + httpx-liveness) по targets БЕЗ
// персиста и наполняет accums/order (по строке на открытый хост). source — провенанс
// staged-хоста, targetLabel — подпись цели в прогрессе. Возвращает true, если весь
// прогон отменён (caller уходит в finalizeCancelled).
func (s *Service) stageResolve(ctx context.Context, runSvc *Service, targets []string, source, targetLabel string, accums map[string]*stagedHostAccum, order *[]string, prog *progressTracker, result *FarmRunResult, wasCancelled *atomic.Bool) bool {
	if len(targets) == 0 {
		return false
	}
	// dnsx-резолв и httpx-liveness — единый dry-вызов, но во фронте это два видимых
	// шага; оба вешаем на один stepCtx, чтобы cancel любого оборвал вызов.
	stepCtx, stepCancel := context.WithCancel(ctx)
	resolveID := prog.addStep(RunStep{Tool: "dnsx", Args: "dnsx -resp -silent (resolve)", Target: targetLabel, StartedAt: time.Now()}, stepCancel)
	httpxID := prog.addStep(RunStep{Tool: "httpx-pd", Args: "httpx-pd -json -td -cdn (liveness)", Target: "resolved", StartedAt: time.Now()}, stepCancel)
	dryHosts, dryErrs := runSvc.probeHostsDry(stepCtx, strings.Join(targets, "\n"))
	prog.removeStep(resolveID)
	prog.removeStep(httpxID)
	stepCancel()
	result.Errors = append(result.Errors, dryErrs...)
	if wasCancelled.Load() {
		return true
	}
	if stepCtx.Err() != nil {
		// per-step cancel: шаг оборван, но прогон НЕ валим — мягкая пометка.
		result.Errors = append(result.Errors, "процесс отменён: dnsx/httpx-pd "+targetLabel)
	}
	alive := 0
	for _, dh := range dryHosts {
		a := &stagedHostAccum{hostname: dh.hostname, isIP: dh.isIP, ip: dh.ip, alive: dh.alive, source: source, ports: map[int]StagedPort{}}
		for _, p := range dh.ports {
			a.ports[p.port] = StagedPort{Port: p.port, Proto: "tcp", State: strings.ToLower(p.state), Service: strOrNil(p.service), Version: p.version, HTTPStatus: p.httpStatus}
		}
		accums[dh.hostname] = a
		*order = append(*order, dh.hostname)
		if dh.alive {
			alive++
		}
	}
	result.HostsCreated = len(*order)
	result.HostsOnline = alive
	prog.update(func(p *RunProgress) { p.HostsFound = len(*order) })
	return false
}

// seedAccumsFromProject засевает аккумулятор существующими хостами проекта БЕЗ
// пробива (dnsx/httpx). Используется, когда стадия поддоменов выключена: оператор
// хочет пере-скан известных хостов, повторный резолв+liveness тут лишний и только
// зря гоняет dnsx/httpx. Все хосты помечаются живыми (alive=true) — фетчи стадий
// JS/эндпоинтов сами отсеют недоступные, а стадия портов резолвит nmap-ом сама.
func seedAccumsFromProject(existing []string, source string, accums map[string]*stagedHostAccum, order *[]string, result *FarmRunResult, prog *progressTracker) {
	for _, hn := range existing {
		if hn == "" || accums[hn] != nil {
			continue
		}
		accums[hn] = &stagedHostAccum{hostname: hn, isIP: reconnet.IsIPLiteral(hn), alive: true, source: source, ports: map[int]StagedPort{}}
		*order = append(*order, hn)
	}
	result.HostsCreated = len(*order)
	result.HostsOnline = len(*order)
	prog.update(func(p *RunProgress) { p.HostsFound = len(*order) })
}

// aliveDomainHosts — живые хосты-домены (не IP-литералы) в порядке открытия. Именно
// по ним гоняются стадии эндпоинтов и JS (архивы/краул/JS осмысленны для доменов).
func aliveDomainHosts(accums map[string]*stagedHostAccum, order []string) []string {
	out := make([]string, 0, len(order))
	for _, hn := range order {
		a := accums[hn]
		if a != nil && a.alive && !a.isIP {
			out = append(out, hn)
		}
	}
	return out
}

// scopeMatcher решает, в scope ли URL: его host совпадает с одним из живых хостов
// либо является поддоменом одного из корней проекта. Отсекает out-of-scope URL из
// архивов (gau/waybackurls нередко тянут сторонние домены).
type scopeMatcher struct {
	hosts map[string]bool
	roots []string
}

func newScopeMatcher(roots, hosts []string) scopeMatcher {
	set := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		set[strings.ToLower(h)] = true
	}
	return scopeMatcher{hosts: set, roots: roots}
}

// match возвращает host URL и признак scope.
func (m scopeMatcher) match(rawURL string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "", false
	}
	h := strings.ToLower(u.Hostname())
	if m.hosts[h] {
		return h, true
	}
	for _, r := range m.roots {
		if h == r || strings.HasSuffix(h, "."+r) {
			return h, true
		}
	}
	return h, false
}

// endpointTools — включённые инструменты стадии эндпоинтов с учётом EndpointsMode:
//
//	passive → gau + waybackurls (пассивные архивы);
//	active  → katana (краул) + ffuf (дир-фаззинг);
//	both    → всё.
//
// Тумблеры Katana/Gau/Waybackurls остаются доп.фильтром внутри режима (back-compat).
// ffuf добавляется только когда задан кастомный словарь эндпоинтов (>0): бандл-тиры —
// словари ПОДДОМЕНОВ, для дир-фаззинга не годятся, поэтому при 0 ffuf пропускаем.
func endpointTools(cfg FarmConfig) []string {
	mode := cfg.EndpointsMode
	switch mode {
	case "passive", "active", "both":
	default:
		mode = "both"
	}
	passive := mode == "passive" || mode == "both"
	active := mode == "active" || mode == "both"

	var tools []string
	if active && cfg.Katana {
		tools = append(tools, "katana")
	}
	if passive && cfg.Gau {
		tools = append(tools, "gau")
	}
	if passive && cfg.Waybackurls {
		tools = append(tools, "waybackurls")
	}
	if active && (cfg.EndpointsWordlistID > 0 || cfg.EndpointsWordlistPath != "") {
		tools = append(tools, "ffuf")
	}
	return tools
}

// containsTool — есть ли инструмент в наборе.
func containsTool(tools []string, name string) bool {
	for _, t := range tools {
		if t == name {
			return true
		}
	}
	return false
}

// scanEndpointTool — вызов одного инструмента эндпоинтов (сид endpointScanner в
// тестах; nil → реальный бинарь).
func (s *Service) scanEndpointTool(ctx context.Context, tool, host string, cfg reconnet.EndpointToolConfig) ([]reconnet.EndpointHit, string) {
	if s.endpointScanner != nil {
		return s.endpointScanner(ctx, tool, host, cfg)
	}
	switch tool {
	case "katana":
		return reconnet.KatanaURLs(ctx, host, cfg, s.settings)
	case "gau":
		return reconnet.GauURLs(ctx, host, s.settings)
	case "waybackurls":
		return reconnet.WaybackURLs(ctx, host, s.settings)
	case "ffuf":
		return reconnet.FfufDirFuzz(ctx, host, cfg.FfufWordlist, reconnet.FfufConfig{RateLimit: cfg.RateLimit, Threads: cfg.Threads}, s.settings)
	}
	return nil, ""
}

// runFarmEndpoints гоняет katana/gau/waybackurls по живым хостам, собирает in-scope
// URL (дедуп) и стейджит их в recon_farm_staged_endpoints. Каждый вызов инструмента —
// видимый RunStep под своим stepCtx (per-step cancel). Возвращает true при отмене
// всего прогона.
func (s *Service) runFarmEndpoints(ctx context.Context, runSvc *Service, cfg FarmConfig, rs reconnet.Settings, roots []string, accums map[string]*stagedHostAccum, order []string, projectID, jobID int32, prog *progressTracker, result *FarmRunResult, wasCancelled *atomic.Bool) bool {
	hosts := aliveDomainHosts(accums, order)
	tools := endpointTools(cfg)
	prog.update(func(p *RunProgress) { p.Stage = "endpoints"; p.Percent = pctEndpoints })
	if len(hosts) == 0 || len(tools) == 0 {
		return false
	}
	scope := newScopeMatcher(roots, hosts)
	toolCfg := reconnet.EndpointToolConfig{CrawlDepth: cfg.CrawlDepth, RateLimit: cfg.RateLimit, Threads: cfg.Concurrency}

	// ffuf-словарь материализуем ОДИН раз (общий для всех хостов) и чистим после.
	// Кастомный (>0) стримится из MinIO во temp; при недоступности FfufDirFuzz
	// самопропускается (словарь по пути не существует). Ярлык — без пути наружу.
	ffufLabel := "custom#" + strconv.Itoa(cfg.EndpointsWordlistID)
	if cfg.EndpointsWordlistID <= 0 && cfg.EndpointsWordlistPath != "" {
		ffufLabel = cfg.EndpointsWordlistPath // относительный путь под WordlistDir
	}
	ffufCleanup := func() {}
	if containsTool(tools, "ffuf") {
		path, cleanup, wlErr := s.resolveWordlist(ctx, cfg.EndpointsWordlistID, cfg.EndpointsWordlistPath, cfg.WordlistSize)
		toolCfg.FfufWordlist = path
		ffufCleanup = cleanup
		if wlErr != "" {
			result.Errors = append(result.Errors, wlErr)
		}
	}
	defer ffufCleanup()

	limit := cfg.Concurrency
	if limit < 1 {
		limit = 1
	}
	var mu sync.Mutex
	seen := map[string]bool{}
	var staged []StagedEndpointInput

	for _, tool := range tools {
		var eg errgroup.Group
		eg.SetLimit(limit)
		for _, host := range hosts {
			host, tool := host, tool
			eg.Go(func() error {
				stepCtx, stepCancel := context.WithCancel(ctx)
				defer stepCancel()
				// Реальные флаги запуска тула (без путей) — чтобы видно было, как он крутится.
				argsDisp := tool
				switch tool {
				case "katana":
					argsDisp = "katana -jc -silent"
				case "gau":
					argsDisp = "gau -subs"
				case "waybackurls":
					argsDisp = "waybackurls"
				case "ffuf":
					// Путь словаря не светим — только ярлык (custom#id).
					argsDisp = "ffuf -w " + ffufLabel + " -u https://" + host + "/FUZZ -mc " + reconnet.FfufDefaultMatchCodes()
				}
				id := prog.addStep(RunStep{Tool: tool, Args: argsDisp + " (" + host + ")", Target: host, StartedAt: time.Now()}, stepCancel)
				defer prog.removeStep(id)
				hits, e := runSvc.scanEndpointTool(stepCtx, tool, host, toolCfg)
				mu.Lock()
				for _, hit := range hits {
					// Общий потолок на прогон: staged/seen росли без предела (в отличие
					// от leaks/JS), архивные тулы дают миллионы URL → OOM + распухшая БД.
					if rs.EndpointsMaxTotal > 0 && len(staged) >= rs.EndpointsMaxTotal {
						break
					}
					uh, ok := scope.match(hit.URL)
					if !ok || seen[hit.URL] {
						continue
					}
					seen[hit.URL] = true
					staged = append(staged, StagedEndpointInput{
						ProjectID: projectID, JobID: jobID, Host: uh, URL: hit.URL,
						Method: strOrNil(hit.Method), Source: tool,
					})
				}
				if e != "" {
					result.Errors = append(result.Errors, e)
				}
				if stepCtx.Err() != nil && ctx.Err() == nil {
					result.Errors = append(result.Errors, "процесс отменён: "+tool+" "+host)
				}
				mu.Unlock()
				return nil
			})
		}
		_ = eg.Wait()
		if wasCancelled.Load() {
			return true
		}
	}

	if len(staged) > 0 {
		if err := s.store.InsertStagedEndpoints(ctx, staged); err != nil {
			result.Errors = append(result.Errors, reconnet.ErrLabel(err))
		}
	}
	result.EndpointsFound = len(staged)
	prog.update(func(p *RunProgress) { p.EndpointsFound = len(staged) })
	return false
}

// mineHostJS — JS-майнинг одного хоста (сид jsMiner в тестах; nil → DiscoverAndScan,
// та же цепочка discover+download+MineJS, что и у js-farm/probeJS).
func (s *Service) mineHostJS(ctx context.Context, host string, budget *semaphore.Weighted) ([]reconnet.ScannedFile, []string) {
	if s.jsMiner != nil {
		return s.jsMiner(ctx, host)
	}
	return reconnet.DiscoverAndScan(ctx, []string{host}, s.settings, budget)
}

// runFarmJS гоняет JS-майнинг (trufflehog+regex через MineJS) по живым хостам и
// стейджит находки в recon_farm_staged_js: по строке на секрет (kind='secret') и на
// эндпоинт (kind='endpoint'). Каждый хост — видимый RunStep под своим stepCtx
// (per-step cancel). Возвращает true при отмене всего прогона.
func (s *Service) runFarmJS(ctx context.Context, runSvc *Service, cfg FarmConfig, rs reconnet.Settings, accums map[string]*stagedHostAccum, order []string, projectID, jobID int32, prog *progressTracker, result *FarmRunResult, wasCancelled *atomic.Bool) bool {
	hosts := aliveDomainHosts(accums, order)
	prog.update(func(p *RunProgress) { p.Stage = "js"; p.Percent = pctJS })
	if len(hosts) == 0 {
		return false
	}
	limit := cfg.Concurrency
	if limit < 1 {
		limit = 1
	}
	// Общий байт-бюджет скана JS на весь прогон: конкурентные хосты делят один пул
	// RAM (иначе cfg.Concurrency × JSMaxConcurrency × размер = перемножение пика).
	inflight := rs.JSMaxInflightBytes
	if inflight < 1 {
		inflight = 256 << 20
	}
	jsBudget := semaphore.NewWeighted(int64(inflight))
	var mu sync.Mutex
	seen := map[string]bool{}
	var staged []StagedJsInput
	add := func(host, u, kind, value string, sev *string) {
		key := kind + "\x00" + u + "\x00" + value
		if value == "" || seen[key] {
			return
		}
		seen[key] = true
		staged = append(staged, StagedJsInput{
			ProjectID: projectID, JobID: jobID, Host: host, URL: u, Kind: kind, Value: value, Severity: sev,
		})
	}

	// Прогресс JS-стадии растёт по мере готовности хостов (а не прыгает на pctJS и
	// висит там, пока крутятся все trufflehog'и) — band [pctJS..pctDone-2].
	total := len(hosts)
	var jsDone atomic.Int64
	var eg errgroup.Group
	eg.SetLimit(limit)
	for _, host := range hosts {
		host := host
		eg.Go(func() error {
			stepCtx, stepCancel := context.WithCancel(ctx)
			defer stepCancel()
			// Показываем реальные параметры запуска trufflehog; пути temp-файлов не светим.
			id := prog.addStep(RunStep{Tool: "js-mine", Args: "trufflehog filesystem --json --no-update + regex (" + host + ")", Target: host, StartedAt: time.Now()}, stepCancel)
			defer prog.removeStep(id)
			files, errs := runSvc.mineHostJS(stepCtx, host, jsBudget)
			mu.Lock()
			for _, f := range files {
				for _, sec := range f.Secrets {
					sev := sec.Severity
					add(f.Hostname, f.URL, stagedJsSecret, sec.MatchPreview, &sev)
				}
				for _, ep := range f.Endpoints {
					add(f.Hostname, f.URL, stagedJsEndpoint, ep, nil)
				}
			}
			result.Errors = append(result.Errors, errs...)
			if stepCtx.Err() != nil && ctx.Err() == nil {
				result.Errors = append(result.Errors, "процесс отменён: js-mine "+host)
			}
			mu.Unlock()
			d := int(jsDone.Add(1))
			if total > 0 {
				pct := pctJS + (pctLeaks-2-pctJS)*d/total
				prog.update(func(p *RunProgress) {
					if pct > p.Percent {
						p.Percent = pct
					}
				})
			}
			return nil
		})
	}
	_ = eg.Wait()
	if wasCancelled.Load() {
		return true
	}

	if len(staged) > 0 {
		if err := s.store.InsertStagedJs(ctx, staged); err != nil {
			result.Errors = append(result.Errors, reconnet.ErrLabel(err))
		}
	}
	result.JsFound = len(staged)
	prog.update(func(p *RunProgress) { p.JsFound = len(staged) })
	return false
}
