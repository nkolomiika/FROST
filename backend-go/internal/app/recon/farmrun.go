package recon

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
	"golang.org/x/sync/errgroup"
)

// Полный прогон фермы (kind='farm_run'): один клик гоняет весь стек над корневыми
// доменами проекта. Пассивный сбор (subfinder/crt.sh) и активный брут (dnsx по
// тир-словарю) идут ОДНОВРЕМЕННО в общем bounded-пуле; дальше слитый набор
// кандидатов уходит в резолв+liveness (httpx) и скан портов (nmap). По ходу
// раннер пишет живой прогресс (стадия, процент, активные шаги) в job.progress.

// проценты-вехи стадий (грубые, для прогресс-бара).
const (
	pctSubdomains = 5
	pctResolve    = 45
	pctPorts      = 80
	pctDone       = 100
)

// parseRunConfig достаёт FarmConfig из raw задачи (там лежит JSON конфига, с
// которым запущен прогон). Пусто/битое → дефолты.
func parseRunConfig(raw string) FarmConfig {
	cfg := DefaultFarmConfig()
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return cfg
	}
	_ = json.Unmarshal([]byte(raw), &cfg)
	return cfg
}

// runSettings копирует сетевой тюнинг и накладывает высокоуровневые ручки конфига:
// конкурентность, лимит поддоменов и скоуп скана портов (top1000 → --top-ports,
// all → -p-).
func (s *Service) runSettings(cfg FarmConfig) reconnet.Settings {
	rs := s.settings
	if cfg.Concurrency > 0 {
		rs.FarmMaxConcurrency = cfg.Concurrency
		rs.ServicesMaxConcurrency = cfg.Concurrency
	}
	if cfg.SubsMaxResults > 0 {
		rs.SubsMaxResults = cfg.SubsMaxResults
	}
	if cfg.PortScanScope == "all" {
		rs.PortscanTopPorts = 0 // 0 → nmap -p- (все порты)
	} else {
		rs.PortscanTopPorts = 1000
	}
	return rs
}

// ─────────────────────────── прогресс ───────────────────────────

// progressTracker — потокобезопасный снимок прогресса, который persist'ится в
// job.progress на каждом изменении (best-effort). Активные шаги живут в map по
// авто-id; Steps в снимке пересобираются отсортированными по времени старта.
type progressTracker struct {
	mu      sync.Mutex
	p       RunProgress
	steps   map[int]RunStep
	seq     int
	persist func([]byte)
}

func newProgressTracker(persist func([]byte)) *progressTracker {
	return &progressTracker{steps: map[int]RunStep{}, persist: persist, p: RunProgress{Steps: []RunStep{}, Errors: []string{}}}
}

// snapshotLocked пересобирает Steps и persist'ит копию (вызывать под mu).
func (t *progressTracker) snapshotLocked() {
	steps := make([]RunStep, 0, len(t.steps))
	for _, st := range t.steps {
		steps = append(steps, st)
	}
	sort.Slice(steps, func(i, j int) bool { return steps[i].StartedAt.Before(steps[j].StartedAt) })
	t.p.Steps = steps
	if t.p.Errors == nil {
		t.p.Errors = []string{}
	}
	blob, err := json.Marshal(t.p)
	if err == nil && t.persist != nil {
		t.persist(blob)
	}
}

func (t *progressTracker) update(fn func(*RunProgress)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	fn(&t.p)
	t.snapshotLocked()
}

// addStep регистрирует активный шаг (инструмент+аргументы+цель) и возвращает id
// для последующего removeStep.
func (t *progressTracker) addStep(step RunStep) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.seq++
	id := t.seq
	t.steps[id] = step
	t.snapshotLocked()
	return id
}

func (t *progressTracker) removeStep(id int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.steps, id)
	t.snapshotLocked()
}

// ─────────────────────────── оркестрация ───────────────────────────

// runFarm — прогон задачи kind='farm_run'. claim.Raw хранит JSON FarmConfig, с
// которым запущен прогон; claim.ID нужен для обновления прогресса.
func (s *Service) runFarm(ctx context.Context, claim *JobClaim) (*FarmRunResult, error) {
	cfg := parseRunConfig(claim.Raw)
	cfg.Sanitize()
	rs := s.runSettings(cfg)
	runSvc := *s // производный сервис с настройками прогона (store/log общие)
	runSvc.settings = rs

	result := newFarmRunResult()
	result.Mode = cfg.Mode
	result.WordlistSize = cfg.WordlistSize

	prog := newProgressTracker(func(blob []byte) {
		if err := s.store.UpdateJobProgress(ctx, claim.ID, blob); err != nil {
			s.log.Warn("farm run progress persist", "id", claim.ID, "err", err)
		}
	})
	prog.update(func(p *RunProgress) { p.Stage = "subdomains"; p.Percent = pctSubdomains })

	roots, err := s.subsRoots(ctx, claim.ProjectID, "")
	if err != nil {
		return nil, err
	}
	if len(roots) == 0 {
		result.Errors = append(result.Errors, "В проекте нет корневых доменов для прогона фермы")
		prog.update(func(p *RunProgress) { p.Stage = "done"; p.Percent = pctDone; p.Done = true; p.Errors = result.Errors })
		return result, nil
	}
	result.RootsScanned = len(roots)

	// ── стадия 1: поддомены (пассив ‖ актив одновременно) ──
	subs, sources, subErrs := s.runSubdomains(ctx, &runSvc, cfg, rs, roots, prog)
	capped := reconnet.SortedCapped(subs, rs.SubsMaxResults)
	result.SubdomainsFound = len(capped)
	result.SourcesUsed = sortedSet(mapFromSlice(sources))
	result.Errors = append(result.Errors, subErrs...)
	prog.update(func(p *RunProgress) { p.SubsFound = len(capped); p.Stage = "resolve"; p.Percent = pctResolve })

	// ── стадия 2: резолв + liveness (dnsx resolve → httpx-pd) с персистом хостов ──
	newSubs := s.filterNewSubs(ctx, claim.ProjectID, capped)
	result.SubdomainsNew = len(newSubs)
	if len(newSubs) > rs.FarmMaxTargets {
		result.Errors = append(result.Errors, "Поддоменов больше лимита пробива — часть не резолвилась")
		newSubs = newSubs[:rs.FarmMaxTargets]
	}
	if len(newSubs) > 0 {
		resolveID := prog.addStep(RunStep{Tool: "dnsx", Args: "dnsx -resp -silent (resolve)", Target: "новые поддомены", StartedAt: time.Now()})
		httpxID := prog.addStep(RunStep{Tool: "httpx-pd", Args: "httpx-pd -json -td -cdn (liveness)", Target: "resolved", StartedAt: time.Now()})
		hostRes, herr := runSvc.probeHosts(ctx, claim.ProjectID, claim.CreatedBy, strings.Join(newSubs, "\n"), nil, true)
		prog.removeStep(resolveID)
		prog.removeStep(httpxID)
		if herr != nil {
			return nil, herr
		}
		result.HostsCreated = hostRes.HostsCreated
		result.HostsOnline = hostRes.HostsOnline
		result.Errors = append(result.Errors, hostRes.Errors...)
		prog.update(func(p *RunProgress) { p.HostsFound = hostRes.HostsCreated + hostRes.HostsUpdated })
	}
	prog.update(func(p *RunProgress) { p.Stage = "ports"; p.Percent = pctPorts })

	// ── стадия 3: скан портов (nmap) над целями проекта ──
	// Цели берём как create_job портов: hostname/IP всех хостов проекта. Пустой
	// raw в probePorts не сканирует ничего, поэтому список собираем явно.
	scanKeys, skErr := s.store.ProjectScanTargets(ctx, claim.ProjectID)
	if skErr != nil {
		result.Errors = append(result.Errors, reconnet.ErrLabel(skErr))
	}
	scanKeys = dedup(scanKeys)
	if len(scanKeys) > rs.PortscanMaxTargets {
		scanKeys = scanKeys[:rs.PortscanMaxTargets]
	}
	if len(scanKeys) > 0 {
		nmapArgs := "nmap -Pn --open --top-ports 1000"
		if rs.PortscanTopPorts == 0 {
			nmapArgs = "nmap -Pn --open -p-"
		}
		portID := prog.addStep(RunStep{Tool: "nmap", Args: nmapArgs, Target: "цели проекта", StartedAt: time.Now()})
		portRes, perr := runSvc.probePorts(ctx, claim.ProjectID, claim.CreatedBy, strings.Join(scanKeys, "\n"), nil)
		prog.removeStep(portID)
		if perr != nil {
			// Скан портов не критичен для прогона: фиксируем как ошибку, но завершаем.
			result.Errors = append(result.Errors, reconnet.ErrLabel(perr))
		} else {
			result.PortsFound = portRes.PortsFound
			result.Errors = append(result.Errors, portRes.Errors...)
		}
	}

	prog.update(func(p *RunProgress) {
		p.Stage = "done"
		p.Percent = pctDone
		p.Done = true
		p.PortsFound = result.PortsFound
		p.Errors = result.Errors
	})
	return result, nil
}

// runSubdomains гоняет пассивный сбор и активный брут по корням ОДНОВРЕМЕННО в
// одном bounded-пуле (SetLimit=concurrency). Пассивные и активные шаги видны в
// прогрессе вместе, пока оба в полёте. Возвращает слитый набор, использованные
// источники и ошибки.
func (s *Service) runSubdomains(ctx context.Context, runSvc *Service, cfg FarmConfig, rs reconnet.Settings, roots []string, prog *progressTracker) (map[string]bool, []string, []string) {
	passive := cfg.Mode == "passive" || cfg.Mode == "both"
	active := cfg.Mode == "active" || cfg.Mode == "both"

	wl := reconnet.WordlistPath(cfg.WordlistSize)
	var softErrs []string
	if active && !reconnet.WordlistExists(wl) {
		// Словарь тира не забандлен в образ — брут пропускаем, прогон не валим.
		s.log.Warn("farm run: wordlist tier missing, active brute skipped", "size", cfg.WordlistSize, "path", wl)
		softErrs = append(softErrs, "dnsx-брут пропущен: словарь тира '"+cfg.WordlistSize+"' недоступен в образе")
		active = false
	}
	brute := reconnet.DNSXBruteConfig{WordlistPath: wl, RateLimit: cfg.RateLimit, Threads: cfg.Concurrency}

	collector := runSvc.collector
	if collector == nil {
		collector = reconnet.DefaultSubCollector(rs)
	}

	var mu sync.Mutex
	subs := map[string]bool{}
	usedSet := map[string]bool{}
	errs := append([]string(nil), softErrs...)

	limit := cfg.Concurrency
	if limit < 1 {
		limit = 1
	}
	var eg errgroup.Group
	eg.SetLimit(limit)
	for _, root := range roots {
		root := root
		if passive {
			eg.Go(func() error {
				id := prog.addStep(RunStep{Tool: "subfinder", Args: "subfinder -d " + root + " -silent", Target: root, StartedAt: time.Now()})
				defer prog.removeStep(id)
				got, used, e := collector(ctx, []string{root})
				mu.Lock()
				for k := range got {
					subs[k] = true
				}
				for _, u := range used {
					usedSet[u] = true
				}
				errs = append(errs, e...)
				mu.Unlock()
				return nil
			})
		}
		if active {
			eg.Go(func() error {
				id := prog.addStep(RunStep{Tool: "dnsx", Args: "dnsx " + strings.Join(reconnet.DNSXBruteArgs(root, brute), " "), Target: root, StartedAt: time.Now()})
				defer prog.removeStep(id)
				got, e := reconnet.DNSXBrute(ctx, root, brute, rs)
				mu.Lock()
				for _, sub := range got {
					subs[sub] = true
				}
				if len(got) > 0 {
					usedSet["dnsx-brute"] = true
				}
				if e != "" {
					errs = append(errs, e)
				}
				mu.Unlock()
				return nil
			})
		}
	}
	_ = eg.Wait()

	used := make([]string, 0, len(usedSet))
	for u := range usedSet {
		used = append(used, u)
	}
	return subs, used, errs
}

// filterNewSubs оставляет только поддомены, которых ещё нет среди хостов проекта.
func (s *Service) filterNewSubs(ctx context.Context, projectID int32, capped []string) []string {
	existingRows, err := s.store.ProjectAllHostnames(ctx, projectID)
	if err != nil {
		return capped
	}
	existing := map[string]bool{}
	for _, h := range existingRows {
		if n := reconnet.NormalizeRoot(h); n != "" {
			existing[n] = true
		}
	}
	var out []string
	for _, sub := range capped {
		if !existing[sub] {
			out = append(out, sub)
		}
	}
	return out
}

func mapFromSlice(list []string) map[string]bool {
	out := make(map[string]bool, len(list))
	for _, v := range list {
		out[v] = true
	}
	return out
}
