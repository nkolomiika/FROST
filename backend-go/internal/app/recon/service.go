package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
	"github.com/nkolomiika/frost/internal/apperr"
)

// Service — use-cases рекона (порт farm/*.py + jobs.py). Персист через Store;
// сеть/парсинг — adapters/recon. detector/collector/scanner/resolverSeam — сиды
// для тестов (в проде nil → реальные бинари/резолвер).
type Service struct {
	store        Store
	settings     reconnet.Settings
	cfg          Config
	log          *slog.Logger
	detector     reconnet.Detector
	collector    reconnet.SubCollector
	scanner      reconnet.PortScanner
	resolverSeam reconnet.ForwardResolver
	// farmScanner — прогрессивный nmap-сервис-скан фермы (сид для тестов; nil → реальный).
	farmScanner reconnet.NmapServiceScanner
	// dryProber — dry-пробив стейджинга фермы (сид для тестов; nil → реальная цепочка).
	dryProber func(ctx context.Context, raw string) ([]dryHost, []string)
	// endpointScanner — вызов одного инструмента стадии эндпоинтов (katana|gau|
	// waybackurls) по хосту (сид для тестов; nil → реальный бинарь).
	endpointScanner func(ctx context.Context, tool, host string, cfg reconnet.EndpointToolConfig) ([]reconnet.EndpointHit, string)
	// jsMiner — JS-майнинг одного хоста стадии JS (сид для тестов; nil → DiscoverAndScan).
	jsMiner func(ctx context.Context, host string) ([]reconnet.ScannedFile, []string)

	// integrations — резолвер workspace-ключей (github_token и т.п.) для сканов утечек.
	integrations IntegrationResolver
	// leakSink — приёмник находок утечек (пишет в единое хранилище recon_leaks).
	leakSink LeakSink
	// githubScan — сид github-скана для тестов (nil → реальный trufflehog github).
	// Возвращает распарсенные находки по цели с (опциональным) токеном.
	githubScan func(ctx context.Context, target, token string) ([]reconnet.GithubSecret, error)
	// breachSources — сид реестра breach-источников стадии утечек (nil → реальный
	// reconnet.AllBreachSources). Возвращает ВСЕ источники; активные отбираются по
	// Enabled(keys) в runFarmLeaks, неактивные мягко самопропускаются.
	breachSources func(keys reconnet.BreachKeys) []reconnet.BreachSource
}

// AttachLeaks подключает резолвер интеграций и приёмник утечек (composition root).
// Без него github-скан вернёт понятную ошибку. Отдельный сеттер, чтобы не ломать
// сигнатуру NewService и её тестовых вызовов.
func (s *Service) AttachLeaks(resolver IntegrationResolver, sink LeakSink) {
	s.integrations = resolver
	s.leakSink = sink
}

// NewService собирает сервис рекона.
func NewService(store Store, settings reconnet.Settings, cfg Config, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	return &Service{store: store, settings: settings, cfg: cfg, log: log}
}

// ─────────────────────────── create_job (SYNC в POST) ───────────────────────────

// CreateJob разбирает вставленный список (синхронно) и ставит пробив в фон.
// Возвращает JobView для ответа 202. Диспетч create по kind.
func (s *Service) CreateJob(ctx context.Context, kind string, projectID, actorID int32, raw string) (JobView, error) {
	var view JobView
	var err error
	switch kind {
	case KindHosts:
		view, err = s.createHostsJob(ctx, projectID, actorID, raw)
	case KindIPs:
		view, err = s.createIPsJob(ctx, projectID, actorID, raw)
	case KindJS:
		view, err = s.createJSJob(ctx, projectID, actorID, raw)
	case KindSubs:
		view, err = s.createSubsJob(ctx, projectID, actorID, raw)
	case KindPorts:
		view, err = s.createPortsJob(ctx, projectID, actorID, raw)
	case KindReverse:
		view, err = s.createReverseJob(ctx, projectID, actorID, raw)
	case KindGithubScan:
		view, err = s.createGithubScanJob(ctx, projectID, actorID, raw)
	default:
		return JobView{}, apperr.Validation("Неизвестный тип задачи фермы")
	}
	if err != nil {
		return JobView{}, err
	}
	s.maybeInline(view)
	return view, nil
}

// GetJob — статус задачи (404 при чужом kind).
func (s *Service) GetJob(ctx context.Context, kind string, projectID, jobID int32) (JobView, error) {
	view, err := s.store.GetJobForProject(ctx, projectID, jobID, kind)
	if err == ErrNoRows {
		return JobView{}, apperr.NotFound(notFoundMsg(kind))
	}
	if err != nil {
		return JobView{}, err
	}
	return view, nil
}

func notFoundMsg(kind string) string {
	switch kind {
	case KindHosts, KindIPs, KindJS:
		return "Задача фермы не найдена"
	default:
		return "Задача scanner не найдена"
	}
}

// maybeInline: воркер выключен и задача pending → прогон в отдельной горутине
// после HTTP-ответа (порт enqueue_job для dev/tests). Иначе — poller подхватит.
func (s *Service) maybeInline(view JobView) {
	if view.Status != jobPending || s.cfg.WorkerEnabled {
		return
	}
	go func() {
		if err := s.RunReconJob(context.Background(), view.ID); err != nil {
			s.log.Warn("inline recon job failed", "id", view.ID, "err", err)
		}
	}()
}

func (s *Service) createHostsJob(ctx context.Context, projectID, actorID int32, raw string) (JobView, error) {
	targets, _ := reconnet.ParseTargets(raw)
	if len(targets) > s.settings.FarmMaxTargets {
		return JobView{}, apperr.Validation(fmt.Sprintf("Слишком много хостов: %d (максимум %d)", len(targets), s.settings.FarmMaxTargets))
	}
	if len(targets) == 0 {
		return JobView{}, apperr.Validation("Не удалось распознать ни одного хоста")
	}
	existing, err := s.existingHostKeys(ctx, projectID, targets)
	if err != nil {
		return JobView{}, err
	}
	newCount := int32(len(targets) - len(existing))
	skeletons := make([]SkeletonHost, 0, len(targets))
	for _, t := range targets {
		if existing[t.Hostname] {
			continue
		}
		if t.IsIP {
			ip := t.Hostname
			skeletons = append(skeletons, SkeletonHost{IPAddress: &ip})
		} else {
			hn := t.Hostname
			skeletons = append(skeletons, SkeletonHost{Hostname: &hn})
		}
	}
	if err := s.store.EnsureHostSkeletons(ctx, projectID, skeletons); err != nil {
		return JobView{}, err
	}
	job := NewJob{
		ProjectID: projectID, CreatedBy: actorID, Kind: KindHosts, Status: jobPending,
		TargetsTotal: &newCount, Raw: raw, SkippedTargets: sortedKeys(existing),
	}
	if newCount == 0 {
		res := newHostFarmResult()
		res.HostsSkipped = len(existing)
		job.Status = jobDone
		job.Result = mustJSON(res)
		job.Finished = true
	}
	return s.store.InsertJob(ctx, job)
}

func (s *Service) createIPsJob(ctx context.Context, projectID, actorID int32, raw string) (JobView, error) {
	targets, _ := reconnet.ParseIPTargets(raw)
	if len(targets) > s.settings.FarmMaxTargets {
		return JobView{}, apperr.Validation(fmt.Sprintf("Слишком много IP: %d (максимум %d)", len(targets), s.settings.FarmMaxTargets))
	}
	if len(targets) == 0 {
		return JobView{}, apperr.Validation("Не удалось распознать ни одного IP-адреса")
	}
	keys := targetKeys(targets)
	if err := s.store.DeleteHiddenIPs(ctx, projectID, keys); err != nil {
		return JobView{}, err
	}
	existingList, err := s.store.ExistingOriginIPs(ctx, projectID, keys)
	if err != nil {
		return JobView{}, err
	}
	existing := toSet(existingList)
	newCount := int32(len(targets) - len(existing))
	job := NewJob{
		ProjectID: projectID, CreatedBy: actorID, Kind: KindIPs, Status: jobPending,
		TargetsTotal: &newCount, Raw: raw, SkippedTargets: sortedKeys(existing),
	}
	if newCount == 0 {
		res := newIpFarmResult()
		res.IPsSkipped = len(existing)
		job.Status = jobDone
		job.Result = mustJSON(res)
		job.Finished = true
	}
	return s.store.InsertJob(ctx, job)
}

func (s *Service) createJSJob(ctx context.Context, projectID, actorID int32, raw string) (JobView, error) {
	domains, err := s.jsDomains(ctx, projectID, raw)
	if err != nil {
		return JobView{}, err
	}
	if len(domains) == 0 {
		return JobView{}, apperr.Validation("В проекте нет доменов для скана JS")
	}
	tt := int32(len(domains))
	return s.store.InsertJob(ctx, NewJob{
		ProjectID: projectID, CreatedBy: actorID, Kind: KindJS, Status: jobPending,
		TargetsTotal: &tt, Raw: strings.Join(domains, "\n"),
	})
}

func (s *Service) createSubsJob(ctx context.Context, projectID, actorID int32, raw string) (JobView, error) {
	roots, err := s.subsRoots(ctx, projectID, raw)
	if err != nil {
		return JobView{}, err
	}
	if len(roots) == 0 {
		return JobView{}, apperr.Validation("Не удалось распознать ни одного корневого домена")
	}
	tt := int32(len(roots))
	return s.store.InsertJob(ctx, NewJob{
		ProjectID: projectID, CreatedBy: actorID, Kind: KindSubs, Status: jobPending,
		TargetsTotal: &tt, Raw: strings.Join(roots, "\n"),
	})
}

func (s *Service) createPortsJob(ctx context.Context, projectID, actorID int32, raw string) (JobView, error) {
	targets, _ := reconnet.ParseTargets(raw)
	var keys []string
	if len(targets) > 0 {
		keys = targetKeys(targets)
	} else {
		var err error
		keys, err = s.store.ProjectScanTargets(ctx, projectID)
		if err != nil {
			return JobView{}, err
		}
		keys = dedup(keys)
	}
	if len(keys) == 0 {
		return JobView{}, apperr.Validation("Не удалось распознать ни одной цели для скана портов")
	}
	if len(keys) > s.settings.PortscanMaxTargets {
		return JobView{}, apperr.Validation(fmt.Sprintf("Слишком много целей: %d (максимум %d)", len(keys), s.settings.PortscanMaxTargets))
	}
	tt := int32(len(keys))
	return s.store.InsertJob(ctx, NewJob{
		ProjectID: projectID, CreatedBy: actorID, Kind: KindPorts, Status: jobPending,
		TargetsTotal: &tt, Raw: strings.Join(keys, "\n"),
	})
}

func (s *Service) createReverseJob(ctx context.Context, projectID, actorID int32, raw string) (JobView, error) {
	ips, err := s.reverseTargets(ctx, projectID, raw)
	if err != nil {
		return JobView{}, err
	}
	if len(ips) == 0 {
		return JobView{}, apperr.Validation("В проекте нет IP-адресов для обратного резолва")
	}
	tt := int32(len(ips))
	return s.store.InsertJob(ctx, NewJob{
		ProjectID: projectID, CreatedBy: actorID, Kind: KindReverse, Status: jobPending,
		TargetsTotal: &tt, Raw: strings.Join(ips, "\n"),
	})
}

// existingHostKeys — ключи целей, уже присутствующих в проекте (домен — по
// hostname, IP-литерал — по ip_address) (порт _existing_target_keys фермы хостов).
func (s *Service) existingHostKeys(ctx context.Context, projectID int32, targets []*reconnet.ParsedTarget) (map[string]bool, error) {
	var names, ips []string
	for _, t := range targets {
		if t.IsIP {
			ips = append(ips, t.Hostname)
		} else {
			names = append(names, t.Hostname)
		}
	}
	out := map[string]bool{}
	if len(names) > 0 {
		rows, err := s.store.ExistingHostnames(ctx, projectID, names)
		if err != nil {
			return nil, err
		}
		for _, h := range rows {
			if h != "" {
				out[h] = true
			}
		}
	}
	if len(ips) > 0 {
		rows, err := s.store.ExistingHostIPLiterals(ctx, projectID, ips)
		if err != nil {
			return nil, err
		}
		for _, h := range rows {
			if h != "" {
				out[h] = true
			}
		}
	}
	return out, nil
}

// jsDomains — домены проекта (origin=host, не IP), либо из raw (порт js domains).
func (s *Service) jsDomains(ctx context.Context, projectID int32, raw string) ([]string, error) {
	if parsed := parseRawDomains(raw); len(parsed) > 0 {
		return parsed, nil
	}
	rows, err := s.store.ProjectDomainHostnames(ctx, projectID)
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, h := range rows {
		name := strings.ToLower(strings.TrimSpace(h))
		if name != "" && !reconnet.IsIPLiteral(name) && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out, nil
}

// subsRoots — корни из raw либо доменные хосты проекта (порт subs._project_roots).
func (s *Service) subsRoots(ctx context.Context, projectID int32, raw string) ([]string, error) {
	if roots := reconnet.ParseRoots(raw); len(roots) > 0 {
		return roots, nil
	}
	rows, err := s.store.ProjectDomainHostnames(ctx, projectID)
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, h := range rows {
		name := reconnet.NormalizeRoot(h)
		if name != "" && !reconnet.IsIPLiteral(name) && strings.Contains(name, ".") && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out, nil
}

// reverseTargets — вставленные IP (только литералы) либо все origin=ip адреса.
func (s *Service) reverseTargets(ctx context.Context, projectID int32, raw string) ([]string, error) {
	parsed, _ := reconnet.ParseIPTargets(raw)
	if len(parsed) > 0 {
		return targetKeys(parsed), nil
	}
	rows, err := s.store.ProjectOriginIPs(ctx, projectID)
	if err != nil {
		return nil, err
	}
	return dedup(rows), nil
}

// parseRawDomains — построчный дедуп lower (порт js._parse_raw).
func parseRawDomains(raw string) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		name := strings.ToLower(strings.TrimSpace(line))
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// ─────────────────────────── helpers ───────────────────────────

func targetKeys(targets []*reconnet.ParsedTarget) []string {
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		out = append(out, t.Hostname)
	}
	return out
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func toSet(list []string) map[string]bool {
	out := make(map[string]bool, len(list))
	for _, v := range list {
		if v != "" {
			out[v] = true
		}
	}
	return out
}

func dedup(list []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range list {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func lowerStatus(db string) string { return strings.ToLower(db) }

func countInvalid(errs []string, substrs ...string) int {
	n := 0
	for _, e := range errs {
		for _, sub := range substrs {
			if strings.Contains(e, sub) {
				n++
				break
			}
		}
	}
	return n
}

func detailsFrom(v any, projectID int32, drop ...string) []byte {
	m := map[string]any{}
	_ = json.Unmarshal(mustJSON(v), &m)
	for _, f := range drop {
		delete(m, f)
	}
	m["project_id"] = strconv.Itoa(int(projectID))
	return mustJSON(m)
}

// detailsFromItems — как detailsFrom, но взамен выброшенного тяжёлого списка
// (dropField) кладёт компактный список имён добавленных объектов в "items", чтобы
// лента активности показывала, ЧТО именно добавила ферма. Список уже ограничен
// CapResult (ReconResultMaxItems), так что размер деталей контролируем.
func detailsFromItems(v any, projectID int32, dropField string, items []string) []byte {
	m := map[string]any{}
	_ = json.Unmarshal(mustJSON(v), &m)
	delete(m, dropField)
	m["project_id"] = strconv.Itoa(int(projectID))
	m["items"] = items
	return mustJSON(m)
}

func hostFarmNames(hs []HostResult) []string {
	out := make([]string, 0, len(hs))
	for _, h := range hs {
		if h.Hostname != nil && *h.Hostname != "" {
			out = append(out, *h.Hostname)
		} else if h.IPAddress != nil && *h.IPAddress != "" {
			out = append(out, *h.IPAddress)
		}
	}
	return out
}

func ipFarmNames(is []IPResult) []string {
	out := make([]string, 0, len(is))
	for _, i := range is {
		out = append(out, i.IPAddress)
	}
	return out
}

func jsFarmNames(fs []JSFileResult) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.URL)
	}
	return out
}

// ─────────────────────────── конфигурация фермы ───────────────────────────

// GetFarmConfig возвращает конфиг фермы проекта (дефолты, слитые с сохранённым).
func (s *Service) GetFarmConfig(ctx context.Context, projectID int32) (FarmConfig, error) {
	return s.store.GetFarmConfig(ctx, projectID)
}

// SaveFarmConfig нормализует (зажимает диапазоны) и сохраняет конфиг фермы,
// возвращая сохранённое значение.
func (s *Service) SaveFarmConfig(ctx context.Context, projectID int32, cfg FarmConfig) (FarmConfig, error) {
	cfg.Sanitize()
	if err := s.store.SaveFarmConfig(ctx, projectID, cfg); err != nil {
		return FarmConfig{}, err
	}
	return cfg, nil
}

// DeleteJSForHost удаляет JS-находки указанного хоста в проекте.
func (s *Service) DeleteJSForHost(ctx context.Context, projectID, hostID int32) error {
	return s.store.DeleteJSFilesForHost(ctx, projectID, hostID)
}

// DeleteJSFilesBulk удаляет JS-находки проекта по списку id одним запросом.
// Скоуп проекта в SQL — чужие/несуществующие id не удаляются. Пустой список —
// no-op (0). Аудита нет — зеркало DeleteJSForHost (одиночное удаление без журнала).
// Возвращает число реально удалённых.
func (s *Service) DeleteJSFilesBulk(ctx context.Context, projectID int32, ids []int32) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	deleted, err := s.store.BulkDeleteJSFiles(ctx, projectID, ids)
	if err != nil {
		return 0, err
	}
	return int(deleted), nil
}

// ─────────────────────────── полный прогон фермы ───────────────────────────

// StartFarmRun ставит задачу полного прогона фермы (kind='farm_run'). useDefaults
// — гнать с DefaultFarmConfig, иначе с сохранённым конфигом проекта. Выбранный
// конфиг сериализуется в raw задачи, чтобы раннер не зависел от гонок с сохранением.
func (s *Service) StartFarmRun(ctx context.Context, projectID, actorID int32, useDefaults bool) (JobView, error) {
	cfg := DefaultFarmConfig()
	if !useDefaults {
		saved, err := s.store.GetFarmConfig(ctx, projectID)
		if err != nil {
			return JobView{}, err
		}
		cfg = saved
	}
	cfg.Sanitize()

	roots, err := s.subsRoots(ctx, projectID, "")
	if err != nil {
		return JobView{}, err
	}
	if len(roots) == 0 {
		return JobView{}, apperr.Validation("В проекте нет корневых доменов для прогона фермы")
	}

	raw := string(mustJSON(cfg))
	tt := int32(len(roots))
	initProgress := mustJSON(RunProgress{Stage: "queued", Percent: 0, Steps: []RunStep{}, Errors: []string{}})
	view, err := s.store.InsertJob(ctx, NewJob{
		ProjectID: projectID, CreatedBy: actorID, Kind: KindFarmRun, Status: jobPending,
		TargetsTotal: &tt, Raw: raw, Progress: initProgress,
	})
	if err != nil {
		return JobView{}, err
	}
	s.maybeInline(view)
	return view, nil
}

// GetFarmRun — статус+прогресс задачи полного прогона (404 при чужом kind).
func (s *Service) GetFarmRun(ctx context.Context, projectID, jobID int32) (JobView, error) {
	view, err := s.store.GetJobForProject(ctx, projectID, jobID, KindFarmRun)
	if err == ErrNoRows {
		return JobView{}, apperr.NotFound("Задача прогона фермы не найдена")
	}
	if err != nil {
		return JobView{}, err
	}
	return view, nil
}

// ListFarmRuns — история прогонов фермы проекта (логи сканов, новые сверху). До 100.
func (s *Service) ListFarmRuns(ctx context.Context, projectID int32) ([]FarmRunListItem, error) {
	return s.store.ListFarmRuns(ctx, projectID, 100)
}

// CancelFarmRun сигналит отмену ВСЕГО прогона (cancel_requested). Валидирует, что
// задача — farm_run этого проекта (404 иначе); поллер воркера подхватит сигнал и
// оборвёт прогон. Идемпотентно: повторный вызов на уже завершённой задаче безвреден.
func (s *Service) CancelFarmRun(ctx context.Context, projectID, jobID int32) error {
	if _, err := s.GetFarmRun(ctx, projectID, jobID); err != nil {
		return err
	}
	return s.store.RequestFarmCancel(ctx, projectID, jobID)
}

// CancelFarmStep сигналит отмену ОДНОГО шага прогона по его id (добавляет в
// cancel_steps). Валидирует принадлежность задачи проекту (404 иначе).
func (s *Service) CancelFarmStep(ctx context.Context, projectID, jobID, stepID int32) error {
	if _, err := s.GetFarmRun(ctx, projectID, jobID); err != nil {
		return err
	}
	if err := s.store.RequestFarmStepCancel(ctx, projectID, jobID, stepID); err == ErrNoRows {
		return apperr.NotFound("Задача прогона фермы не найдена")
	} else if err != nil {
		return err
	}
	return nil
}

// CancelAllFarmRuns сигналит отмену ВСЕХ активных (pending|running) прогонов
// проекта; возвращает число затронутых задач.
func (s *Service) CancelAllFarmRuns(ctx context.Context, projectID int32) (int64, error) {
	return s.store.RequestFarmCancelAllActive(ctx, projectID)
}
