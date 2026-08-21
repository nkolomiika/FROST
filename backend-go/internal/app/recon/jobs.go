package recon

import (
	"context"
	"encoding/json"

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
	case KindFarmRun:
		result, perr = s.runFarm(ctx, claim)
	default:
		msg := "Неизвестный тип задачи фермы: " + claim.Kind
		return s.store.MarkJobFailed(ctx, id, msg, &msg)
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

// ProcessPending — тик воркера (порт relay+consumer через DB-поллинг, как mailer).
// Реклейм застрявших ДО выборки pending (переигранные попадут в ту же выборку).
func (s *Service) ProcessPending(ctx context.Context) error {
	if _, err := s.store.ReclaimStale(ctx, s.cfg.StaleSeconds, s.cfg.MaxAttempts); err != nil {
		s.log.Warn("reclaim stale recon jobs", "err", err)
	}
	ids, err := s.store.SelectPendingJobIDs(ctx, s.cfg.MaxAttempts, 50)
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
