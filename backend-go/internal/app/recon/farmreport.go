package recon

import (
	"context"
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
	rep := FarmReport{GeneratedAt: time.Now(), Hosts: []StagedHost{}}
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

// ClearStagedReport чистит staged-строки прогона (по jobID либо последнего).
// Прогонов нет → 0, не ошибка. Возвращает число удалённых строк.
func (s *Service) ClearStagedReport(ctx context.Context, projectID int32, jobID *int32) (int64, error) {
	jid, ok, err := s.resolveReportJobID(ctx, projectID, jobID)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, nil
	}
	return s.store.ClearStagedHosts(ctx, projectID, jid)
}
