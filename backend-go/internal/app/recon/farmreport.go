package recon

import (
	"context"
	"net/url"
	"strings"
	"time"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
)

// Отчёт стейджинга полного прогона фермы. Прогон складывает находки в карантин
// (recon_farm_staged_hosts), а эти use-cases отдают их на ревью, импортируют
// выбранное в проект (реюзя обычный persist-путь) и чистят карантин.

// resolveReportJobID разбирает целевой job_id отчёта: явный (jobID != nil) либо
// последний прогон фермы проекта. ok=false → у проекта ещё не было прогонов.
func (s *Service) resolveReportJobID(ctx context.Context, projectID int32, jobID *int32) (int32, bool, error) {
	if jobID != nil {
		return *jobID, true, nil
	}
	return s.store.LatestFarmRunJobID(ctx, projectID)
}

// FarmReport собирает отчёт стейджинга прогона. Без jobID — по последнему прогону;
// прогонов нет → пустой отчёт (0-summary, hosts=[]), не ошибка (эндпоинт отдаёт 200).
func (s *Service) FarmReport(ctx context.Context, projectID int32, jobID *int32) (FarmReport, error) {
	rep := FarmReport{GeneratedAt: time.Now(), Hosts: []StagedHost{}, Endpoints: []StagedEndpoint{}, Js: []StagedJs{}}
	jid, ok, err := s.resolveReportJobID(ctx, projectID, jobID)
	if err != nil {
		return FarmReport{}, err
	}
	if !ok {
		return rep, nil
	}
	rep.JobID = jid

	// Статус берём из самой задачи прогона (running/done/cancelled/failed). Чужой/
	// несуществующий job_id → пустой отчёт для этого id (без 404).
	view, err := s.store.GetJobForProject(ctx, projectID, jid, KindFarmRun)
	if err == ErrNoRows {
		return rep, nil
	}
	if err != nil {
		return FarmReport{}, err
	}
	rep.Status = view.Status

	hosts, err := s.store.ListStagedHosts(ctx, projectID, jid)
	if err != nil {
		return FarmReport{}, err
	}
	if hosts == nil {
		hosts = []StagedHost{}
	}
	rep.Hosts = hosts
	for _, h := range hosts {
		rep.Summary.HostsTotal++
		if h.Alive {
			rep.Summary.Alive++
		}
		rep.Summary.PortsTotal += len(h.Ports)
		if h.Imported {
			rep.Summary.Imported++
		}
	}

	eps, err := s.store.ListStagedEndpoints(ctx, projectID, jid)
	if err != nil {
		return FarmReport{}, err
	}
	if eps == nil {
		eps = []StagedEndpoint{}
	}
	rep.Endpoints = eps
	rep.Summary.EndpointsTotal = len(eps)

	js, err := s.store.ListStagedJs(ctx, projectID, jid)
	if err != nil {
		return FarmReport{}, err
	}
	if js == nil {
		js = []StagedJs{}
	}
	rep.Js = js
	rep.Summary.JsTotal = len(js)
	return rep, nil
}

// ImportStagedHosts создаёт реальные хосты проекта (+IP +порты +сервисы) из
// выбранных staged-строк, реюзя обычный persist-путь (PersistHost) — чтобы
// импортированные хосты выглядели как добавленные вручную и их сервисы/версии
// сохранились. Идемпотентно: уже импортированные и чужие строки пропускаются.
// Возвращает число фактически импортированных.
func (s *Service) ImportStagedHosts(ctx context.Context, projectID, actorID int32, hostIDs []int32) (int, error) {
	if len(hostIDs) == 0 {
		return 0, nil
	}
	rows, err := s.store.ListStagedHostsByIDs(ctx, projectID, hostIDs)
	if err != nil {
		return 0, err
	}
	imported := make([]int32, 0, len(rows))
	for _, h := range rows {
		if h.Imported {
			continue // уже в проекте — пропускаем (идемпотентность)
		}
		in := stagedToPersistInput(projectID, h)
		if _, perr := s.store.PersistHost(ctx, in); perr != nil {
			s.log.Warn("farm import persist", "host", h.Hostname, "err", perr)
			continue
		}
		imported = append(imported, h.ID)
	}
	if len(imported) > 0 {
		if err := s.store.MarkStagedImported(ctx, projectID, imported); err != nil {
			return 0, err
		}
	}
	s.audit(ctx, actorID, "farm_import", detailsFrom(FarmReportSummary{Imported: len(imported)}, projectID))
	return len(imported), nil
}

// stagedToPersistInput переводит staged-строку в HostPersistInput обычного persist:
// статус по живости, primary IP из резолва, порты с сервисом/версией как Techs
// (чтобы replaceServices записал сервисы порта).
func stagedToPersistInput(projectID int32, h StagedHost) HostPersistInput {
	status := statusDOWN
	if h.Alive {
		status = statusUP
	}
	in := HostPersistInput{
		ProjectID: projectID,
		IsIP:      reconnet.IsIPLiteral(h.Hostname),
		TargetKey: h.Hostname,
		Status:    status,
	}
	if h.IP != nil && *h.IP != "" {
		in.IPs = []string{*h.IP}
		in.HasIP = true
	} else if in.IsIP {
		// IP-литерал без отдельного резолва: primary = сам хост.
		in.IPs = []string{h.Hostname}
		in.HasIP = true
	}
	for _, p := range h.Ports {
		state := stateFILTERED
		if strings.EqualFold(p.State, "open") {
			state = stateOPEN
		}
		pw := PortWrite{PortNumber: int32(p.Port), State: state, HTTPStatus: intPtr(p.HTTPStatus)}
		if p.Service != nil && *p.Service != "" {
			pw.Techs = []reconnet.Tech{{Name: *p.Service, Version: p.Version}}
			pw.HasTechs = true
		}
		in.Ports = append(in.Ports, pw)
	}
	return in
}

// ImportStagedReport импортирует в проект выбранные staged-строки трёх типов
// (хосты/эндпоинты/JS) — что передано, то и импортируется. Возвращает по-типовые
// счётчики импортированного.
func (s *Service) ImportStagedReport(ctx context.Context, projectID, actorID int32, hostIDs, endpointIDs, jsIDs []int32) (FarmImportResult, error) {
	var res FarmImportResult
	nh, err := s.ImportStagedHosts(ctx, projectID, actorID, hostIDs)
	if err != nil {
		return FarmImportResult{}, err
	}
	res.ImportedHosts = nh
	ne, err := s.ImportStagedEndpoints(ctx, projectID, actorID, endpointIDs)
	if err != nil {
		return FarmImportResult{}, err
	}
	res.ImportedEndpoints = ne
	nj, err := s.ImportStagedJs(ctx, projectID, actorID, jsIDs)
	if err != nil {
		return FarmImportResult{}, err
	}
	res.ImportedJs = nj
	return res, nil
}

// ImportStagedEndpoints создаёт реальные endpoints проекта из выбранных staged-строк
// эндпоинтов, привязывая их к хосту по имени. Импортируются ТОЛЬКО эндпоинты, чей
// хост уже есть в проекте; прочие пропускаются (скоуп проекта соблюдён). Дедуп на
// (host,path,method) — как обычное добавление. Возвращает число импортированных.
func (s *Service) ImportStagedEndpoints(ctx context.Context, projectID, actorID int32, ids []int32) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	rows, err := s.store.ListStagedEndpointsByIDs(ctx, projectID, ids)
	if err != nil {
		return 0, err
	}
	hostMap, err := s.store.ProjectOriginHostMap(ctx, projectID)
	if err != nil {
		return 0, err
	}
	imported := make([]int32, 0, len(rows))
	skipped := 0
	for _, e := range rows {
		if e.Imported {
			continue
		}
		hostID, ok := hostMap[strings.ToLower(e.Host)]
		if !ok {
			skipped++ // хоста нет в проекте — пропускаем
			continue
		}
		if _, perr := s.store.ImportEndpoint(ctx, EndpointImportInput{HostID: hostID, Path: endpointPathFromURL(e.URL), Method: e.Method}); perr != nil {
			s.log.Warn("farm import endpoint", "url", e.URL, "err", perr)
			continue
		}
		imported = append(imported, e.ID)
	}
	if len(imported) > 0 {
		if err := s.store.MarkStagedEndpointsImported(ctx, projectID, imported); err != nil {
			return 0, err
		}
	}
	if skipped > 0 {
		s.log.Info("farm import endpoints: some hosts not in project", "skipped", skipped)
	}
	s.audit(ctx, actorID, "farm_import_endpoints", detailsFrom(FarmReportSummary{Imported: len(imported)}, projectID))
	return len(imported), nil
}

// ImportStagedJs создаёт js_files/secrets проекта из выбранных staged-находок JS,
// реюзя обычный persist-путь (PersistJSFile). Находки группируются по (host,url):
// секреты → js_secrets, эндпоинты → js_files.endpoints. Импортируются только находки,
// чей хост уже есть в проекте. Возвращает число импортированных staged-строк.
func (s *Service) ImportStagedJs(ctx context.Context, projectID, actorID int32, ids []int32) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	rows, err := s.store.ListStagedJsByIDs(ctx, projectID, ids)
	if err != nil {
		return 0, err
	}
	hostMap, err := s.store.ProjectOriginHostMap(ctx, projectID)
	if err != nil {
		return 0, err
	}

	// Группируем по URL (в порядке появления), запоминая хост и id строк группы.
	type jsGroup struct {
		host      string
		endpoints []string
		secrets   []JSSecretInput
		ids       []int32
	}
	groups := map[string]*jsGroup{}
	var urlOrder []string
	for _, r := range rows {
		if r.Imported {
			continue
		}
		g, ok := groups[r.URL]
		if !ok {
			g = &jsGroup{host: r.Host}
			groups[r.URL] = g
			urlOrder = append(urlOrder, r.URL)
		}
		g.ids = append(g.ids, r.ID)
		switch r.Kind {
		case stagedJsEndpoint:
			g.endpoints = append(g.endpoints, r.Value)
		default: // secret
			g.secrets = append(g.secrets, JSSecretInput{Kind: stagedJsSecret, MatchPreview: r.Value, Severity: jsSeverityOr(r.Severity)})
		}
	}

	var imported []int32
	skipped := 0
	for _, u := range urlOrder {
		g := groups[u]
		hostID, ok := hostMap[strings.ToLower(g.host)]
		if !ok {
			skipped++
			continue
		}
		in := JSFileInput{
			ProjectID: projectID, HostID: hostID, URL: u, Status: "ok",
			Endpoints: orEmpty(g.endpoints), SecretCount: int32(len(g.secrets)), EndpointCount: int32(len(g.endpoints)),
			Secrets: g.secrets,
		}
		if perr := s.store.PersistJSFile(ctx, in); perr != nil {
			s.log.Warn("farm import js", "url", u, "err", perr)
			continue
		}
		imported = append(imported, g.ids...)
	}
	if len(imported) > 0 {
		if err := s.store.MarkStagedJsImported(ctx, projectID, imported); err != nil {
			return 0, err
		}
	}
	if skipped > 0 {
		s.log.Info("farm import js: some hosts not in project", "skipped_files", skipped)
	}
	s.audit(ctx, actorID, "farm_import_js", detailsFrom(FarmReportSummary{Imported: len(imported)}, projectID))
	return len(imported), nil
}

// jsSeverityOr — severity staged-секрета либо "medium" по умолчанию (как find_secrets).
func jsSeverityOr(sev *string) string {
	if sev != nil && *sev != "" {
		return *sev
	}
	return "medium"
}

// endpointPathFromURL достаёт path (+query) из URL для колонки endpoints.path. При
// ошибке парсинга возвращает сам URL (лучше сохранить как есть, чем потерять).
func endpointPathFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	return p
}

// ClearStagedReport чистит staged-строки прогона всех трёх типов (по jobID либо
// последнего). Прогонов нет → 0, не ошибка. Возвращает суммарное число удалённых строк.
func (s *Service) ClearStagedReport(ctx context.Context, projectID int32, jobID *int32) (int64, error) {
	jid, ok, err := s.resolveReportJobID(ctx, projectID, jobID)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, nil
	}
	var total int64
	n, err := s.store.ClearStagedHosts(ctx, projectID, jid)
	if err != nil {
		return 0, err
	}
	total += n
	if n, err = s.store.ClearStagedEndpoints(ctx, projectID, jid); err != nil {
		return 0, err
	}
	total += n
	if n, err = s.store.ClearStagedJs(ctx, projectID, jid); err != nil {
		return 0, err
	}
	total += n
	return total, nil
}
