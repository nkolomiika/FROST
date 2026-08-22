package recon

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
	"golang.org/x/sync/errgroup"
)

// errFarmCancelled — сентинел: runFarm вернул его → прогон остановлен по запросу
// пользователя (cancel_requested). RunReconJob по нему помечает задачу cancelled
// (не failed). Отмена ≠ провал.
var errFarmCancelled = errors.New("farm run cancelled")

// farmCancelPollInterval — период опроса управляющих колонок отмены. Переменная
// (не const) — тесты снижают её, чтобы не ждать реальные 2с.
var farmCancelPollInterval = 2 * time.Second

// Полный прогон фермы (kind='farm_run'): один клик гоняет весь стек над корневыми
// доменами проекта. Пассивный сбор (subfinder/crt.sh) и активный брут (dnsx по
// тир-словарю) идут ОДНОВРЕМЕННО в общем bounded-пуле; дальше слитый набор
// кандидатов уходит в резолв+liveness (httpx) и скан портов (nmap). По ходу
// раннер пишет живой прогресс (стадия, процент, активные шаги) в job.progress.

// проценты-вехи стадий (грубые, для прогресс-бара).
const (
	// Вехи прогресса подобраны под РЕАЛЬНОЕ время стадий, а не равными долями:
	// JS-майнинг обычно самый долгий, поэтому под него оставлен большой band
	// [pctJS..pctDone], внутри которого процент растёт по мере готовности хостов.
	pctSubdomains = 3
	pctResolve    = 10
	pctPorts      = 30
	pctEndpoints  = 45
	pctJS         = 55
	// Стадия утечек (gated: stage_leaks) идёт последней перед done; JS-band ужат
	// до [pctJS..pctLeaks-2], чтобы освободить хвост под неё.
	pctLeaks = 90
	pctDone  = 100
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
	// Скоуп портов. Явные -p (web-набор / кастомный список) применяются ТОЛЬКО для
	// своего scope — чтобы скрытое поле кастом-портов не перетирало web/top1000/all.
	rs.PortscanTopPorts = 1000
	rs.PortscanPorts = ""
	switch cfg.PortScanScope {
	case "all":
		rs.PortscanTopPorts = 0 // 0 → nmap -p- (все порты)
	case "web":
		rs.PortscanPorts = reconnet.WebPorts
	case "custom":
		if p := strings.TrimSpace(cfg.PortScanPorts); p != "" {
			rs.PortscanPorts = p // пусто → фолбэк на top1000
		}
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
	cancels map[int]context.CancelFunc // id → отмена контекста шага (per-step cancel)
	seq     int
	persist func([]byte)
}

func newProgressTracker(persist func([]byte)) *progressTracker {
	return &progressTracker{steps: map[int]RunStep{}, cancels: map[int]context.CancelFunc{}, persist: persist, p: RunProgress{Steps: []RunStep{}, Errors: []string{}}}
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

// addStep регистрирует активный шаг (инструмент+аргументы+цель), проставляет ему
// стабильный id (= seq) и запоминает cancel его контекста для per-step отмены.
// Возвращает id (тот же, что уходит во фронт в RunStep.ID) для removeStep/отмены.
func (t *progressTracker) addStep(step RunStep, cancel context.CancelFunc) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.seq++
	id := t.seq
	step.ID = id
	t.steps[id] = step
	if cancel != nil {
		t.cancels[id] = cancel
	}
	t.snapshotLocked()
	return id
}

func (t *progressTracker) removeStep(id int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.steps, id)
	delete(t.cancels, id)
	t.snapshotLocked()
}

// cancelStep рвёт контекст шага по id (если он ещё в полёте). Идемпотентно:
// снятый/неизвестный id — no-op.
func (t *progressTracker) cancelStep(id int) {
	t.mu.Lock()
	fn := t.cancels[id]
	t.mu.Unlock()
	if fn != nil {
		fn()
	}
}

// ─────────────────────────── оркестрация ───────────────────────────

// runFarm — прогон задачи kind='farm_run'. claim.Raw хранит JSON FarmConfig, с
// которым запущен прогон; claim.ID нужен для обновления прогресса.
//
// Отмена. API и recon-worker — разные процессы, общаются через Postgres, поэтому
// отмена сигналится в БД: cancel_requested (весь прогон) / cancel_steps (один шаг).
// Внутри крутится поллер (~2с), который читает эти колонки и рвёт нужные контексты:
// корневой (весь прогон, → errFarmCancelled) или контекст конкретного шага
// (per-step, → мягкая пометка, прогон продолжается).
func (s *Service) runFarm(parentCtx context.Context, claim *JobClaim) (*FarmRunResult, error) {
	cfg := parseRunConfig(claim.Raw)
	cfg.Sanitize()
	rs := s.runSettings(cfg)
	runSvc := *s // производный сервис с настройками прогона (store/log общие)
	runSvc.settings = rs

	// Корневой контекст прогона — отменяемый: cancel() рвёт все шаги разом.
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	result := newFarmRunResult()
	result.Mode = cfg.Mode
	result.WordlistSize = cfg.WordlistSize

	// Персист прогресса идёт через parentCtx: даже после cancel() корневого ctx
	// финальный снимок "cancelled" должен записаться.
	prog := newProgressTracker(func(blob []byte) {
		if err := s.store.UpdateJobProgress(parentCtx, claim.ID, blob); err != nil {
			s.log.Warn("farm run progress persist", "id", claim.ID, "err", err)
		}
	})

	// ── поллер отмены: читает cancel_requested/cancel_steps раз в ~2с ──
	var wasCancelled atomic.Bool
	pollDone := make(chan struct{})
	var pollWG sync.WaitGroup
	pollWG.Add(1)
	go s.cancelPoller(ctx, claim.ID, prog, &wasCancelled, cancel, pollDone, &pollWG)
	defer func() { close(pollDone); pollWG.Wait() }()

	// finalizeCancelled — общий выход по отмене всего прогона: частичный result +
	// финальный снимок stage="cancelled", и сентинел errFarmCancelled наверх.
	finalizeCancelled := func() (*FarmRunResult, error) {
		result.Errors = append(result.Errors, "Прогон отменён пользователем")
		prog.update(func(p *RunProgress) {
			p.Stage = "cancelled"
			p.Done = true
			p.PortsFound = result.PortsFound
			p.Errors = result.Errors
		})
		return result, errFarmCancelled
	}

	// roots нужны и для стадии поддоменов, и как scope-фильтр стадии эндпоинтов.
	roots, err := s.subsRoots(ctx, claim.ProjectID, "")
	if err != nil {
		if wasCancelled.Load() {
			return finalizeCancelled()
		}
		return nil, err
	}

	// accums — накопитель staged-хостов по имени; order хранит порядок открытия.
	// Наполняется стадией поддоменов (свежие живые хосты) ИЛИ, если она выключена,
	// существующими хостами проекта — чтобы поздние стадии (порты/эндпоинты/JS)
	// работали по известным хостам (пере-скан).
	accums := map[string]*stagedHostAccum{}
	var order []string

	if cfg.StageSubdomains {
		prog.update(func(p *RunProgress) { p.Stage = "subdomains"; p.Percent = pctSubdomains })
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
		if wasCancelled.Load() {
			return finalizeCancelled()
		}
		prog.update(func(p *RunProgress) { p.SubsFound = len(capped); p.Stage = "resolve"; p.Percent = pctResolve })

		// ── стадия 2: резолв + liveness (dnsx resolve → httpx-pd) БЕЗ персиста ──
		newSubs := s.filterNewSubs(ctx, claim.ProjectID, capped)
		result.SubdomainsNew = len(newSubs)
		if len(newSubs) > rs.FarmMaxTargets {
			result.Errors = append(result.Errors, "Поддоменов больше лимита пробива — часть не резолвилась")
			newSubs = newSubs[:rs.FarmMaxTargets]
		}
		if canceled := s.stageResolve(ctx, &runSvc, newSubs, stagedSourceSub, "новые поддомены", accums, &order, prog, result, &wasCancelled); canceled {
			return finalizeCancelled()
		}
	} else {
		// Стадия поддоменов выключена: пере-скан известных хостов проекта. Резолв+
		// liveness (dnsx/httpx) НЕ гоняем — берём готовые хосты как есть; стадии
		// JS/эндпоинтов/портов работают по ним напрямую (фетчи сами отсеют мёртвые).
		prog.update(func(p *RunProgress) { p.Stage = "resolve"; p.Percent = pctResolve })
		existing, herr := s.store.ProjectAllHostnames(ctx, claim.ProjectID)
		if herr != nil {
			if wasCancelled.Load() {
				return finalizeCancelled()
			}
			return nil, herr
		}
		existing = dedup(existing)
		if len(existing) > rs.FarmMaxTargets {
			existing = existing[:rs.FarmMaxTargets]
		}
		seedAccumsFromProject(existing, stagedSourceProject, accums, &order, result, prog)
	}
	if wasCancelled.Load() {
		return finalizeCancelled()
	}

	// ── стадия портов: прогрессивный nmap -sV (gated: stage_ports) ──
	prog.update(func(p *RunProgress) { p.Stage = "ports"; p.Percent = pctPorts })
	if cfg.StagePorts {
		if canceled := s.runFarmPorts(ctx, &runSvc, cfg, rs, accums, order, prog, result, &wasCancelled); canceled {
			return finalizeCancelled()
		}
	}

	// ── вставка staged-строк хостов (по строке на каждый открытый хост) ──
	totalPorts := 0
	inputs := make([]StagedHostInput, 0, len(order))
	for _, hn := range order {
		a := accums[hn]
		ports := stagedPortsSorted(a.ports)
		totalPorts += len(ports)
		inputs = append(inputs, StagedHostInput{
			ProjectID: claim.ProjectID, JobID: claim.ID, Hostname: a.hostname,
			IP: a.ip, Alive: a.alive, Source: a.source, Ports: ports,
		})
	}
	if len(inputs) > 0 {
		if err := s.store.InsertStagedHosts(ctx, inputs); err != nil {
			result.Errors = append(result.Errors, reconnet.ErrLabel(err))
		}
	}
	result.PortsFound = totalPorts
	prog.update(func(p *RunProgress) { p.PortsFound = totalPorts })
	if wasCancelled.Load() {
		return finalizeCancelled()
	}

	// ── стадия эндпоинтов: katana + gau + waybackurls (gated: stage_endpoints) ──
	if cfg.StageEndpoints {
		if canceled := s.runFarmEndpoints(ctx, &runSvc, cfg, rs, roots, accums, order, claim.ProjectID, claim.ID, prog, result, &wasCancelled); canceled {
			return finalizeCancelled()
		}
	}
	if wasCancelled.Load() {
		return finalizeCancelled()
	}

	// ── стадия JS-майнинга: trufflehog + regex по живым хостам (gated: stage_js) ──
	if cfg.StageJs {
		if canceled := s.runFarmJS(ctx, &runSvc, cfg, rs, accums, order, claim.ProjectID, claim.ID, prog, result, &wasCancelled); canceled {
			return finalizeCancelled()
		}
	}
	if wasCancelled.Load() {
		return finalizeCancelled()
	}

	// ── стадия утечек: github secret-scan + breach-пробив по доменам/почтам
	//    (gated: stage_leaks); находки → единое хранилище recon_leaks ──
	if cfg.StageLeaks || cfg.StageAccountSearch {
		if canceled := s.runFarmLeaks(ctx, &runSvc, cfg, claim.ProjectID, claim.ID, prog, result, &wasCancelled); canceled {
			return finalizeCancelled()
		}
	}
	if wasCancelled.Load() {
		return finalizeCancelled()
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

// cancelPoller опрашивает БД (~раз в 2с) на предмет сигналов отмены прогона и
// применяет их к живым контекстам: cancel_requested → рвём корневой ctx всего
// прогона (wasCancelled=true), каждый новый id из cancel_steps → рвём контекст
// того шага (однократно, actioned-множество против повторов). Останавливается по
// ctx (корневой отменён) либо по pollDone (runFarm завершился).
func (s *Service) cancelPoller(ctx context.Context, jobID int32, prog *progressTracker, wasCancelled *atomic.Bool, cancel context.CancelFunc, pollDone <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(farmCancelPollInterval)
	defer ticker.Stop()
	actioned := map[int32]bool{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-pollDone:
			return
		case <-ticker.C:
			cr, steps, err := s.store.GetFarmCancelState(ctx, jobID)
			if err != nil {
				continue
			}
			if cr {
				wasCancelled.Store(true)
				cancel()
				return
			}
			for _, sid := range steps {
				if actioned[sid] {
					continue
				}
				actioned[sid] = true
				prog.cancelStep(int(sid))
			}
		}
	}
}

// runSubdomains гоняет пассивный сбор и активный брут по корням ОДНОВРЕМЕННО в
// одном bounded-пуле (SetLimit=concurrency). Пассивные и активные шаги видны в
// прогрессе вместе, пока оба в полёте. Возвращает слитый набор, использованные
// источники и ошибки.
func (s *Service) runSubdomains(ctx context.Context, runSvc *Service, cfg FarmConfig, rs reconnet.Settings, roots []string, prog *progressTracker) (map[string]bool, []string, []string) {
	passive := cfg.Mode == "passive" || cfg.Mode == "both"
	active := cfg.Mode == "active" || cfg.Mode == "both"

	// Словарь брута: кастомный (SubdomainWordlistID>0) материализуется во ВРЕМЕННЫЙ
	// серверный файл из MinIO, иначе — бандл-тир WordlistSize. resolveWordlist
	// возвращает cleanup (удаляет temp), который зовём после eg.Wait() (defer).
	var softErrs []string
	wl := reconnet.WordlistPath(cfg.WordlistSize)
	wlCleanup := func() {}
	if active {
		var wlErr string
		wl, wlCleanup, wlErr = s.resolveWordlist(ctx, cfg.SubdomainWordlistID, cfg.SubdomainWordlistPath, cfg.WordlistSize)
		if wlErr != "" {
			softErrs = append(softErrs, wlErr)
		}
		if !reconnet.WordlistExists(wl) {
			// Словарь недоступен (нет бандл-тира в образе / пустой) — брут пропускаем,
			// прогон не валим.
			s.log.Warn("farm run: wordlist missing, active brute skipped", "size", cfg.WordlistSize, "custom_id", cfg.SubdomainWordlistID, "path", wl)
			softErrs = append(softErrs, "dnsx-брут пропущен: словарь недоступен")
			active = false
		}
	}
	defer wlCleanup()
	// Ярлык словаря для прогресса — БЕЗ полного пути (temp/бандл-путь не светим).
	wlLabel := cfg.WordlistSize
	if cfg.SubdomainWordlistID > 0 {
		wlLabel = "custom#" + strconv.Itoa(cfg.SubdomainWordlistID)
	} else if cfg.SubdomainWordlistPath != "" {
		wlLabel = cfg.SubdomainWordlistPath // относительный путь под WordlistDir — не секрет
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
				// Свой контекст шага: per-step cancel рвёт только его, не весь прогон.
				stepCtx, stepCancel := context.WithCancel(ctx)
				defer stepCancel()
				id := prog.addStep(RunStep{Tool: "subfinder", Args: "subfinder -d " + root + " -silent", Target: root, StartedAt: time.Now()}, stepCancel)
				defer prog.removeStep(id)
				got, used, e := collector(stepCtx, []string{root})
				mu.Lock()
				for k := range got {
					subs[k] = true
				}
				for _, u := range used {
					usedSet[u] = true
				}
				errs = append(errs, e...)
				// per-step cancel (шаг оборван, но корневой ctx жив) → мягкая пометка.
				if stepCtx.Err() != nil && ctx.Err() == nil {
					errs = append(errs, "процесс отменён: subfinder "+root)
				}
				mu.Unlock()
				return nil
			})
		}
		if active {
			eg.Go(func() error {
				stepCtx, stepCancel := context.WithCancel(ctx)
				defer stepCancel()
				id := prog.addStep(RunStep{Tool: "dnsx", Args: "dnsx -d " + root + " -w " + wlLabel + " -silent", Target: root, StartedAt: time.Now()}, stepCancel)
				defer prog.removeStep(id)
				got, e := reconnet.DNSXBrute(stepCtx, root, brute, rs)
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
				if stepCtx.Err() != nil && ctx.Err() == nil {
					errs = append(errs, "процесс отменён: dnsx "+root)
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

// ─────────────────────────── стейджинг: накопление и порт-скан ───────────────────────────

// stagedSourceSub — провенанс staged-хоста, открытого стадией поддоменов.
const stagedSourceSub = "subdomain"

// stagedHostAccum — накопитель одного staged-хоста в ходе прогона: резолв/живость
// из стадии 2 и объединённые порты (веб от httpx + nmap -sV) из стадии 3.
type stagedHostAccum struct {
	hostname string
	isIP     bool
	ip       *string
	alive    bool
	source   string
	ports    map[int]StagedPort // union по номеру порта
}

// runFarmPorts гоняет прогрессивный nmap -sV по открытым (резолвнутым) хостам и
// объединяет найденные порты в accums. Возвращает true, если весь прогон отменён
// (caller уходит в finalizeCancelled). Каждая фаза каждого хоста — видимый RunStep
// под своим stepCtx (per-step cancel), фазы идут по очереди (быстрые вперёд), внутри
// фазы — bounded errgroup по хостам (cfg.Concurrency).
func (s *Service) runFarmPorts(ctx context.Context, runSvc *Service, cfg FarmConfig, rs reconnet.Settings, accums map[string]*stagedHostAccum, order []string, prog *progressTracker, result *FarmRunResult, wasCancelled *atomic.Bool) bool {
	scanHosts := make([]string, 0, len(order))
	for _, hn := range order {
		if accums[hn].ip != nil {
			scanHosts = append(scanHosts, hn)
		}
	}
	if len(scanHosts) > rs.PortscanMaxTargets {
		scanHosts = scanHosts[:rs.PortscanMaxTargets]
	}
	if len(scanHosts) == 0 {
		return false
	}
	scanner := runSvc.farmScanner
	if scanner == nil {
		scanner = reconnet.DefaultNmapServiceScanner(rs)
	}
	phases := reconnet.NmapPhases(rs.PortscanTopPorts == 0, rs.PortscanPorts) // scope=="all" → +фаза -p-
	limit := cfg.Concurrency
	if limit < 1 {
		limit = 1
	}
	var mu sync.Mutex
	for _, phase := range phases {
		var eg errgroup.Group
		eg.SetLimit(limit)
		for _, hn := range scanHosts {
			hn := hn
			a := accums[hn]
			phase := phase
			eg.Go(func() error {
				// Свой контекст фазы: per-step cancel рвёт только её, не весь прогон.
				stepCtx, stepCancel := context.WithCancel(ctx)
				defer stepCancel()
				id := prog.addStep(RunStep{Tool: "nmap", Args: reconnet.NmapCommand(rs.PortscanNmapBin, phase, *a.ip), Target: hn, StartedAt: time.Now()}, stepCancel)
				defer prog.removeStep(id)
				ports, e := scanner(stepCtx, *a.ip, phase)
				mu.Lock()
				for _, np := range ports {
					mergeStagedPort(a, np)
				}
				if e != "" {
					result.Errors = append(result.Errors, e)
				}
				if stepCtx.Err() != nil && ctx.Err() == nil {
					result.Errors = append(result.Errors, "процесс отменён: nmap "+hn)
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
	return false
}

// mergeStagedPort вливает порт nmap в accum: nmap уточняет state/service/version,
// а http_status (от httpx) на порту сохраняется.
func mergeStagedPort(a *stagedHostAccum, np reconnet.NmapPort) {
	cur, ok := a.ports[np.Port]
	if !ok {
		cur = StagedPort{Port: np.Port, Proto: "tcp"}
	}
	if np.Proto != "" {
		cur.Proto = np.Proto
	}
	if np.State != "" {
		cur.State = np.State
	}
	if np.Service != "" {
		svc := np.Service
		cur.Service = &svc
	}
	if np.Version != "" {
		ver := np.Version
		cur.Version = &ver
	}
	a.ports[np.Port] = cur
}

// stagedPortsSorted — порты accum списком, по возрастанию номера.
func stagedPortsSorted(m map[int]StagedPort) []StagedPort {
	out := make([]StagedPort, 0, len(m))
	for _, p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// strOrNil — пустая строка → nil (сервис без имени = null в отчёте).
func strOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
