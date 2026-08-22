package reconrepo

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nkolomiika/frost/internal/app/recon"
)

// Реализация узкого порта recon.StagingArchiveMeta (таблица-указатель
// recon_staging_archives) поверх пула — hand-written pgx, без sqlc-генерации, чтобы
// не менять большие структуры job'ов ради опциональной архивации.

// ArchivableStagingRuns — завершённые ферм-прогоны старше olderThan, ещё не
// заархивированные и со staged-строками хотя бы в одной из трёх таблиц.
func (r *Repo) ArchivableStagingRuns(ctx context.Context, olderThan time.Duration, limit int32) ([]recon.ArchivableRun, error) {
	const q = `
SELECT j.id, j.project_id
FROM host_farm_jobs j
WHERE j.kind = 'farm_run'
  AND j.status IN ('done','failed','cancelled')
  AND j.finished_at IS NOT NULL
  AND j.finished_at < now() - ($1::bigint * interval '1 second')
  AND NOT EXISTS (SELECT 1 FROM recon_staging_archives a WHERE a.job_id = j.id)
  AND (EXISTS (SELECT 1 FROM recon_farm_staged_hosts h WHERE h.job_id = j.id)
    OR EXISTS (SELECT 1 FROM recon_farm_staged_endpoints e WHERE e.job_id = j.id)
    OR EXISTS (SELECT 1 FROM recon_farm_staged_js s WHERE s.job_id = j.id))
ORDER BY j.finished_at ASC
LIMIT $2`
	rows, err := r.pool.Query(ctx, q, int64(olderThan.Seconds()), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []recon.ArchivableRun
	for rows.Next() {
		var a recon.ArchivableRun
		if err := rows.Scan(&a.JobID, &a.ProjectID); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// StagingArchiveKey — object_key архива прогона (ok=false, если не архивирован).
func (r *Repo) StagingArchiveKey(ctx context.Context, jobID int32) (string, bool, error) {
	var key string
	err := r.pool.QueryRow(ctx, `SELECT object_key FROM recon_staging_archives WHERE job_id = $1`, jobID).Scan(&key)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}
	return key, true, nil
}

// RecordStagingArchive — записать/обновить указатель после выгрузки в MinIO.
func (r *Repo) RecordStagingArchive(ctx context.Context, a recon.ArchivableRun, key string, size int64, hosts, endpoints, js int) error {
	_, err := r.pool.Exec(ctx, `
INSERT INTO recon_staging_archives (job_id, project_id, object_key, size_bytes, hosts_count, endpoints_count, js_count)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (job_id) DO UPDATE SET
  object_key      = EXCLUDED.object_key,
  size_bytes      = EXCLUDED.size_bytes,
  hosts_count     = EXCLUDED.hosts_count,
  endpoints_count = EXCLUDED.endpoints_count,
  js_count        = EXCLUDED.js_count,
  archived_at     = now()`,
		a.JobID, a.ProjectID, key, size, hosts, endpoints, js)
	return err
}

// DeleteStagingArchive — снять указатель (после регидрации прогона обратно в БД).
func (r *Repo) DeleteStagingArchive(ctx context.Context, jobID int32) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM recon_staging_archives WHERE job_id = $1`, jobID)
	return err
}
