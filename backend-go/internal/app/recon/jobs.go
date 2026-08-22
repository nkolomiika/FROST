package recon

import (
	"context"
	"encoding/json"
	"errors"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
	"github.com/nkolomiika/frost/internal/apperr"
)

// resultListFields — списки в result-блобе, обрезаемые до ResultMaxItems (порт
// _RESULT_LIST_FIELDS). Счётчики (hosts_created, …) — отдельные скаляры, целы.
var resultListFields = []string{"hosts", "ips", "files", "errors"}

// capResult обрезает детальные списки result до limit (порт _cap_result).
func capResult(payload []byte, limit int) []byte {
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		return payload
	}
	for _, key := range resultListFields {
		if val, ok := m[key].([]any); ok && len(val) > limit {
			m[key] = val[:limit]
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return payload
	}
	return out
}

// RunReconJob — прогон задачи по id (порт run_recon_job). Атомарно берёт задачу в
// работу (running + attempts++), диспетчит по kind, фиксирует done|failed.
func (s *Service) RunReconJob(ctx context.Context, id int32) error {
	claim, err := s.store.ClaimJobRunning(ctx, id)
	if err != nil {
		return err
	}
	if claim == nil {
		return nil // повторная доставка / уже done — не пробиваем дважды
	}

	var result any
	var perr error
	switch claim.Kind {
	case KindHosts:
		result, perr = s.probeHosts(ctx, claim.ProjectID, claim.CreatedBy, claim.Raw, claim.SkippedTargets, true)
	case KindIPs:
		// «Add IPs» кросс-рекон (resolve_hosts) вынесен в scanner Reverse DNS.
		result, perr = s.probeIPs(ctx, claim.ProjectID, claim.CreatedBy, claim.Raw, claim.SkippedTargets, false)
	case KindJS:
		result, perr = s.probeJS(ctx, claim.ProjectID, claim.CreatedBy, claim.Raw)
	case KindSubs:
		result, perr = s.probeSubs(ctx, claim.ProjectID, claim.CreatedBy, claim.Raw)
	case KindPorts:
		result, perr = s.probePorts(ctx, claim.ProjectID, claim.CreatedBy, claim.Raw, claim.SkippedTargets)
	case KindReverse:
		result, perr = s.probeReverse(ctx, claim.ProjectID, claim.CreatedBy, claim.Raw, claim.SkippedTargets)
	case KindGithubScan:
		result, perr = s.runGithubScan(ctx, claim)
	case KindFarmRun:
		result, perr = s.runFarm(ctx, claim)
	default:
		msg := "Неизвестный тип задачи фермы: " + claim.Kind
		return s.store.MarkJobFailed(ctx, id, msg, &msg)
	}

	// Отмена прогона фермы (cancel_requested) — это НЕ провал: фиксируем частичный
	// result и статус 'cancelled', не наращивая последующие попытки/ретраи.
	if errors.Is(perr, errFarmCancelled) {
		capped := capResult(mustJSON(result), s.cfg.ResultMaxItems)
		s.log.Info("recon farm run cancelled", "id", id)
		return s.store.MarkJobCancelled(ctx, id, capped)
	}

	if perr != nil {
		msg := truncate2000(perr.Error())
		var terminal *string
		if claim.Attempts >= s.cfg.MaxAttempts {
			terminal = &msg
		}
		s.log.Warn("recon job failed", "id", id, "kind", claim.Kind, "err", perr)
		return s.store.MarkJobFailed(ctx, id, msg, terminal)
	}

	capped := capResult(mustJSON(result), s.cfg.ResultMaxItems)
	return s.store.MarkJobDone(ctx, id, capped)
}

// Воркер разнесён на ДВЕ независимые дорожки, чтобы долгий полный прогон фермы
// (kind='farm_run', минуты) не держал обычные задачи (add-hosts/add-ips/port-scan),
// от которых зависит основное приложение:
//   - ProcessPendingRegular — все kind, КРОМЕ farm_run;
//   - ProcessPendingFarm    — только farm_run.
// Каждая крутится своим тикером в cmd/recon-worker. Реклейм тоже пофильтрован по
// kind: обычная дорожка НИКОГДА не переигрывает бегущий farm_run (иначе долгий
// прогон посчитался бы застрявшим → двойной прогон), а фермовая использует БОЛЬШОЕ
// окно stale, ведь прогон легитимно длинный.

// ProcessPendingRegular — тик обычной дорожки: реклейм застрявших (кроме farm_run)
// ДО выборки pending, затем прогон каждой обычной задачи.
func (s *Service) ProcessPendingRegular(ctx context.Context) error {
	if _, err := s.store.ReclaimStaleExcludingKind(ctx, s.cfg.StaleSeconds, s.cfg.MaxAttempts, KindFarmRun); err != nil {
		s.log.Warn("reclaim stale recon jobs (regular)", "err", err)
	}
	ids, err := s.store.SelectPendingJobIDsExcludingKind(ctx, s.cfg.MaxAttempts, 50, KindFarmRun)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.RunReconJob(ctx, id); err != nil {
			s.log.Warn("recon job run", "id", id, "err", err)
		}
	}
	return nil
}

// ProcessPendingFarm — тик фермовой дорожки: реклейм застрявших farm_run с большим
// окном stale (farmStaleSeconds), затем прогон каждого pending farm_run.
func (s *Service) ProcessPendingFarm(ctx context.Context) error {
	if _, err := s.store.ReclaimStaleForKind(ctx, s.farmStaleSeconds(), s.cfg.MaxAttempts, KindFarmRun); err != nil {
		s.log.Warn("reclaim stale recon jobs (farm)", "err", err)
	}
	ids, err := s.store.SelectPendingJobIDsForKind(ctx, s.cfg.MaxAttempts, 50, KindFarmRun)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.RunReconJob(ctx, id); err != nil {
			s.log.Warn("recon farm job run", "id", id, "err", err)
		}
	}
	return nil
}

// farmStaleSeconds — окно реклейма для farm_run. Берём FarmStaleSeconds (по умолчанию
// сильно больше обычного), с фолбэком на обычное StaleSeconds, если не задано.
func (s *Service) farmStaleSeconds() int32 {
	if s.cfg.FarmStaleSeconds > 0 {
		return s.cfg.FarmStaleSeconds
	}
	return s.cfg.StaleSeconds
}

// ListJsFiles — JS-файлы проекта с находками (порт assets.list_js_files).
func (s *Service) ListJsFiles(ctx context.Context, projectID int32) ([]JSFileView, error) {
	return s.store.ListJsFiles(ctx, projectID)
}

// BuildArchive — zip найденных .js, докачиваемых по требованию (порт download_js_archive).
func (s *Service) BuildArchive(ctx context.Context, projectID int32, hostID *int32) (string, []byte, error) {
	urls, err := s.store.JSFileURLs(ctx, projectID, hostID)
	if err != nil {
		return "", nil, err
	}
	if len(urls) == 0 {
		return "", nil, apperr.NotFound("Нет JS-файлов для скачивания")
	}
	name, blob := reconnet.BuildJSArchive(ctx, urls, hostID != nil, projectID, s.settings)
	return name, blob, nil
}

func truncate2000(s string) string {
	if len(s) > 2000 {
		return s[:2000]
	}
	return s
}
