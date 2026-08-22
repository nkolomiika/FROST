package recon

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
	"golang.org/x/sync/errgroup"
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

// endpointTools — включённые инструменты стадии эндпоинтов (по тем же тумблерам
// конфига, что и раньше: Katana/Gau/Waybackurls).
func endpointTools(cfg FarmConfig) []string {
	var tools []string
	if cfg.Katana {
		tools = append(tools, "katana")
	}
	if cfg.Gau {
		tools = append(tools, "gau")
	}
	if cfg.Waybackurls {
		tools = append(tools, "waybackurls")
	}
	return tools
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
	toolCfg := reconnet.EndpointToolConfig{CrawlDepth: cfg.CrawlDepth, RateLimit: cfg.RateLimit}
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
				id := prog.addStep(RunStep{Tool: tool, Args: tool + " (" + host + ")", Target: host, StartedAt: time.Now()}, stepCancel)
				defer prog.removeStep(id)
				hits, e := runSvc.scanEndpointTool(stepCtx, tool, host, toolCfg)
				mu.Lock()
				for _, hit := range hits {
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
func (s *Service) mineHostJS(ctx context.Context, host string) ([]reconnet.ScannedFile, []string) {
	if s.jsMiner != nil {
		return s.jsMiner(ctx, host)
	}
	return reconnet.DiscoverAndScan(ctx, []string{host}, s.settings)
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

	var eg errgroup.Group
	eg.SetLimit(limit)
	for _, host := range hosts {
		host := host
		eg.Go(func() error {
			stepCtx, stepCancel := context.WithCancel(ctx)
			defer stepCancel()
			id := prog.addStep(RunStep{Tool: "js-mine", Args: "trufflehog + regex JS (" + host + ")", Target: host, StartedAt: time.Now()}, stepCancel)
			defer prog.removeStep(id)
			files, errs := runSvc.mineHostJS(stepCtx, host)
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
