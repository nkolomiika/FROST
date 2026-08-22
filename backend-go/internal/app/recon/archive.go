package recon

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Автономная архивация холодного стейджинга ферм-прогонов. Мотивация: staged-строки
// (recon_farm_staged_hosts/endpoints/js) — основной объём нареконенных данных и растут
// с каждым прогоном. Для завершённых прогонов старше порога recon-worker фоново
// выгружает их в MinIO и удаляет из БД; при открытии отчёта данные прозрачно
// подтягиваются обратно (rehydrateStaging). Никаких кнопок и потери данных.

// ArchivableRun — прогон-кандидат на архивацию (id прогона + его проект).
type ArchivableRun struct {
	JobID     int32
	ProjectID int32
}

// StagingArchiveMeta — узкий порт таблицы-указателей recon_staging_archives (реализован
// reconrepo поверх пула). Отдельный от большого Store, чтобы не трогать его тестовые
// стабы: архивация — опциональная надстройка, подключается только при наличии MinIO.
type StagingArchiveMeta interface {
	// ArchivableStagingRuns — завершённые ферм-прогоны старше olderThan, ещё не
	// заархивированные и со staged-строками в БД (иначе архивировать нечего).
	ArchivableStagingRuns(ctx context.Context, olderThan time.Duration, limit int32) ([]ArchivableRun, error)
	// StagingArchiveKey — object_key архива прогона, если он заархивирован.
	StagingArchiveKey(ctx context.Context, jobID int32) (string, bool, error)
	// RecordStagingArchive — записать указатель после успешной выгрузки в MinIO.
	RecordStagingArchive(ctx context.Context, r ArchivableRun, key string, size int64, hosts, endpoints, js int) error
	// DeleteStagingArchive — удалить указатель (после регидрации назад в БД).
	DeleteStagingArchive(ctx context.Context, jobID int32) error
}

// ArchiveBlobStore — объектное хранилище архивов (реализовано storage.Minio; storage.Stub
// тоже удовлетворяет интерфейсу, но вернёт ErrStorageUnavailable — тогда архивация no-op).
type ArchiveBlobStore interface {
	Put(ctx context.Context, key string, data []byte, contentType string) error
	Get(ctx context.Context, key string) ([]byte, string, error)
	Delete(ctx context.Context, key string) error
}

// AttachArchive подключает архивацию стейджинга (composition root). Без неё
// ArchiveColdStaging и rehydrateStaging — no-op (обычное поведение без MinIO).
func (s *Service) AttachArchive(meta StagingArchiveMeta, blob ArchiveBlobStore) {
	s.archiveMeta = meta
	s.archiveBlob = blob
}

// stagingArchiveBlob — формат gzip-объекта в MinIO: полный staged-снимок прогона.
type stagingArchiveBlob struct {
	JobID     int32            `json:"job_id"`
	ProjectID int32            `json:"project_id"`
	Hosts     []StagedHost     `json:"hosts"`
	Endpoints []StagedEndpoint `json:"endpoints"`
	Js        []StagedJs       `json:"js"`
}

func stagingArchiveKey(jobID int32) string {
	return fmt.Sprintf("archives/staging-%d.json.gz", jobID)
}

// ArchiveColdStaging — один проход фонового свипа: выгружает staged холодных прогонов
// в MinIO и чистит их из БД. Возвращает число заархивированных прогонов. Порядок строго:
// Put в MinIO → запись указателя → удаление строк (если удаление сорвётся, указатель уже
// есть, а регидрация идемпотентна — сначала чистит существующие строки).
func (s *Service) ArchiveColdStaging(ctx context.Context, olderThan time.Duration, limit int32) (int, error) {
	if s.archiveMeta == nil || s.archiveBlob == nil {
		return 0, nil
	}
	runs, err := s.archiveMeta.ArchivableStagingRuns(ctx, olderThan, limit)
	if err != nil {
		return 0, err
	}
	archived := 0
	for _, r := range runs {
		hosts, err := s.store.ListStagedHosts(ctx, r.ProjectID, r.JobID)
		if err != nil {
			s.log.Warn("archive: list staged hosts", "job", r.JobID, "err", err)
			continue
		}
		eps, err := s.store.ListStagedEndpoints(ctx, r.ProjectID, r.JobID)
		if err != nil {
			s.log.Warn("archive: list staged endpoints", "job", r.JobID, "err", err)
			continue
		}
		js, err := s.store.ListStagedJs(ctx, r.ProjectID, r.JobID)
		if err != nil {
			s.log.Warn("archive: list staged js", "job", r.JobID, "err", err)
			continue
		}
		if len(hosts)+len(eps)+len(js) == 0 {
			continue // нечего архивировать (уже очищено)
		}
		data, err := gzipStagingBlob(stagingArchiveBlob{JobID: r.JobID, ProjectID: r.ProjectID, Hosts: hosts, Endpoints: eps, Js: js})
		if err != nil {
			s.log.Warn("archive: gzip", "job", r.JobID, "err", err)
			continue
		}
		key := stagingArchiveKey(r.JobID)
		if err := s.archiveBlob.Put(ctx, key, data, "application/gzip"); err != nil {
			s.log.Warn("archive: minio put", "job", r.JobID, "err", err)
			continue
		}
		if err := s.archiveMeta.RecordStagingArchive(ctx, r, key, int64(len(data)), len(hosts), len(eps), len(js)); err != nil {
			s.log.Warn("archive: record", "job", r.JobID, "err", err)
			_ = s.archiveBlob.Delete(ctx, key) // откат: без указателя объект не нужен
			continue
		}
		// Строки больше не нужны — они в MinIO. Ошибку чистки логируем: указатель уже
		// стоит, регидрация всё равно сработает (она идемпотентна).
		if _, err := s.store.ClearStagedHosts(ctx, r.ProjectID, r.JobID); err != nil {
			s.log.Warn("archive: clear hosts", "job", r.JobID, "err", err)
		}
		if _, err := s.store.ClearStagedEndpoints(ctx, r.ProjectID, r.JobID); err != nil {
			s.log.Warn("archive: clear endpoints", "job", r.JobID, "err", err)
		}
		if _, err := s.store.ClearStagedJs(ctx, r.ProjectID, r.JobID); err != nil {
			s.log.Warn("archive: clear js", "job", r.JobID, "err", err)
		}
		archived++
	}
	return archived, nil
}

// rehydrateStaging возвращает заархивированный стейджинг прогона обратно в БД (если он
// был заархивирован) — вызывается на входе в отчёт, «при необходимости данных». После
// восстановления указатель и объект удаляются: прогон снова «горячий» (позже свип
// заархивирует его опять, если он остынет). Идемпотентно: сначала чистит существующие
// staged-строки прогона, чтобы повторный вызов не задваивал.
func (s *Service) rehydrateStaging(ctx context.Context, projectID, jobID int32) {
	if s.archiveMeta == nil || s.archiveBlob == nil {
		return
	}
	key, ok, err := s.archiveMeta.StagingArchiveKey(ctx, jobID)
	if err != nil {
		s.log.Warn("rehydrate: lookup", "job", jobID, "err", err)
		return
	}
	if !ok {
		return
	}
	data, _, err := s.archiveBlob.Get(ctx, key)
	if err != nil {
		s.log.Warn("rehydrate: minio get", "job", jobID, "err", err)
		return
	}
	blob, err := gunzipStagingBlob(data)
	if err != nil {
		s.log.Warn("rehydrate: gunzip", "job", jobID, "err", err)
		return
	}
	// Идемпотентность: убираем возможные остатки, затем восстанавливаем из снимка.
	_, _ = s.store.ClearStagedHosts(ctx, projectID, jobID)
	_, _ = s.store.ClearStagedEndpoints(ctx, projectID, jobID)
	_, _ = s.store.ClearStagedJs(ctx, projectID, jobID)

	if hosts := stagedHostsToInputs(projectID, jobID, blob.Hosts); len(hosts) > 0 {
		if err := s.store.InsertStagedHosts(ctx, hosts); err != nil {
			s.log.Warn("rehydrate: insert hosts", "job", jobID, "err", err)
			return
		}
	}
	if eps := stagedEndpointsToInputs(projectID, jobID, blob.Endpoints); len(eps) > 0 {
		if err := s.store.InsertStagedEndpoints(ctx, eps); err != nil {
			s.log.Warn("rehydrate: insert endpoints", "job", jobID, "err", err)
			return
		}
	}
	if js := stagedJsToInputs(projectID, jobID, blob.Js); len(js) > 0 {
		if err := s.store.InsertStagedJs(ctx, js); err != nil {
			s.log.Warn("rehydrate: insert js", "job", jobID, "err", err)
			return
		}
	}
	// Прогон снова горячий — снимаем указатель и удаляем объект.
	if err := s.archiveMeta.DeleteStagingArchive(ctx, jobID); err != nil {
		s.log.Warn("rehydrate: delete archive record", "job", jobID, "err", err)
		return
	}
	_ = s.archiveBlob.Delete(ctx, key)
}

func stagedHostsToInputs(projectID, jobID int32, rows []StagedHost) []StagedHostInput {
	out := make([]StagedHostInput, 0, len(rows))
	for _, h := range rows {
		out = append(out, StagedHostInput{ProjectID: projectID, JobID: jobID, Hostname: h.Hostname, IP: h.IP, Alive: h.Alive, Source: h.Source, Ports: h.Ports})
	}
	return out
}

func stagedEndpointsToInputs(projectID, jobID int32, rows []StagedEndpoint) []StagedEndpointInput {
	out := make([]StagedEndpointInput, 0, len(rows))
	for _, e := range rows {
		out = append(out, StagedEndpointInput{ProjectID: projectID, JobID: jobID, Host: e.Host, URL: e.URL, Method: e.Method, Source: e.Source})
	}
	return out
}

func stagedJsToInputs(projectID, jobID int32, rows []StagedJs) []StagedJsInput {
	out := make([]StagedJsInput, 0, len(rows))
	for _, j := range rows {
		out = append(out, StagedJsInput{ProjectID: projectID, JobID: jobID, Host: j.Host, URL: j.URL, Kind: j.Kind, Value: j.Value, Severity: j.Severity})
	}
	return out
}

func gzipStagingBlob(b stagingArchiveBlob) ([]byte, error) {
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func gunzipStagingBlob(data []byte) (stagingArchiveBlob, error) {
	var b stagingArchiveBlob
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return b, err
	}
	defer zr.Close()
	raw, err := io.ReadAll(zr)
	if err != nil {
		return b, err
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return b, err
	}
	return b, nil
}
