package recon

import (
	"context"
	"errors"
)

// ErrNoRows — репозиторий не нашёл строку (задача/файл).
var ErrNoRows = errors.New("no rows")

// Store — порт хранилища рекона (реализуется reconrepo поверх sqlc + pgxpool).
// Persist-методы компаундны и атомарны внутри адаптера (транзакция на элемент —
// зеркало похостного commit Python-версии).
type Store interface {
	// ─── очередь задач ───
	InsertJob(ctx context.Context, j NewJob) (JobView, error)
	GetJobForProject(ctx context.Context, projectID, jobID int32, kind string) (JobView, error)
	ClaimJobRunning(ctx context.Context, id int32) (*JobClaim, error)
	UpdateJobProgress(ctx context.Context, id int32, progress []byte) error
	MarkJobDone(ctx context.Context, id int32, result []byte) error
	MarkJobFailed(ctx context.Context, id int32, lastErr string, terminalErr *string) error
	// MarkJobCancelled — прогон остановлен по запросу (status='cancelled',
	// finished_at=now(), частичный result). Отмена ≠ провал.
	MarkJobCancelled(ctx context.Context, id int32, result []byte) error
	// Выборка/реклейм с фильтром по kind — воркер гоняет две независимые дорожки
	// (обычная = все kind кроме farm_run; фермовая = только farm_run), чтобы долгий
	// прогон фермы не блокировал add-hosts/add-ips/port-scan.
	SelectPendingJobIDsExcludingKind(ctx context.Context, maxAttempts, limit int32, kind string) ([]int32, error)
	SelectPendingJobIDsForKind(ctx context.Context, maxAttempts, limit int32, kind string) ([]int32, error)
	ReclaimStaleExcludingKind(ctx context.Context, staleSeconds, maxAttempts int32, kind string) (int64, error)
	ReclaimStaleForKind(ctx context.Context, staleSeconds, maxAttempts int32, kind string) (int64, error)

	// ─── сигналы отмены прогона фермы (пишет HTTP, читает поллер воркера) ───
	// RequestFarmCancel — отмена всего прогона (cancel_requested=true) для farm_run
	// задачи проекта.
	RequestFarmCancel(ctx context.Context, projectID, jobID int32) error
	// RequestFarmStepCancel — добавляет id шага в cancel_steps (дедуп, создаёт
	// массив при null) для farm_run задачи проекта.
	RequestFarmStepCancel(ctx context.Context, projectID, jobID, stepID int32) error
	// RequestFarmCancelAllActive — отмена всех активных (pending|running) farm_run
	// задач проекта; возвращает число затронутых.
	RequestFarmCancelAllActive(ctx context.Context, projectID int32) (int64, error)
	// GetFarmCancelState — снимок управляющих колонок отмены (для поллера).
	GetFarmCancelState(ctx context.Context, jobID int32) (cancelRequested bool, cancelSteps []int32, err error)

	// ─── create_job: уже добавленные цели + заготовки + снятие скрытия ───
	ExistingHostnames(ctx context.Context, projectID int32, names []string) ([]string, error)
	ExistingHostIPLiterals(ctx context.Context, projectID int32, addrs []string) ([]string, error)
	ExistingOriginIPs(ctx context.Context, projectID int32, addrs []string) ([]string, error)
	EnsureHostSkeletons(ctx context.Context, projectID int32, hosts []SkeletonHost) error
	DeleteHiddenIPs(ctx context.Context, projectID int32, addrs []string) error

	// ─── persist (по элементу, в транзакции) ───
	PersistHost(ctx context.Context, in HostPersistInput) (HostPersistOutcome, error)
	PersistIP(ctx context.Context, in IPPersistInput) (IPPersistOutcome, error)
	PersistScanHost(ctx context.Context, in ScanHostInput) (ScanHostOutcome, error)
	PersistJSFile(ctx context.Context, in JSFileInput) error

	// ─── выбор целей по проекту ───
	ProjectDomainHostnames(ctx context.Context, projectID int32) ([]string, error)
	ProjectAllHostnames(ctx context.Context, projectID int32) ([]string, error)
	ProjectOriginIPs(ctx context.Context, projectID int32) ([]string, error)
	ProjectScanTargets(ctx context.Context, projectID int32) ([]string, error)
	ProjectOriginHostMap(ctx context.Context, projectID int32) (map[string]int32, error)

	// ─── стейджинг полного прогона фермы (карантин, не проект) ───
	// InsertStagedHosts вставляет staged-строки прогона (по строке на открытый хост).
	InsertStagedHosts(ctx context.Context, hosts []StagedHostInput) error
	// ListStagedHosts — все staged-строки одного прогона (для отчёта).
	ListStagedHosts(ctx context.Context, projectID, jobID int32) ([]StagedHost, error)
	// ListStagedHostsByIDs — выбранные staged-строки проекта по id (для импорта).
	ListStagedHostsByIDs(ctx context.Context, projectID int32, ids []int32) ([]StagedHost, error)
	// LatestFarmRunJobID — id последнего прогона фермы проекта (отчёт без job_id).
	LatestFarmRunJobID(ctx context.Context, projectID int32) (int32, bool, error)
	// ListFarmRuns — история прогонов фермы проекта (новые сверху, до limit).
	ListFarmRuns(ctx context.Context, projectID, limit int32) ([]FarmRunListItem, error)
	// DeleteFarmRunJob удаляет строку прогона (kind='farm_run') проекта из истории.
	DeleteFarmRunJob(ctx context.Context, projectID, jobID int32) error
	// MarkStagedImported помечает выбранные staged-строки импортированными.
	MarkStagedImported(ctx context.Context, projectID int32, ids []int32) error
	// ClearStagedHosts удаляет staged-строки одного прогона; возвращает число удалённых.
	ClearStagedHosts(ctx context.Context, projectID, jobID int32) (int64, error)

	// ─── стейджинг эндпоинтов прогона (recon_farm_staged_endpoints) ───
	// InsertStagedEndpoints вставляет staged-эндпоинты прогона (по строке на URL).
	InsertStagedEndpoints(ctx context.Context, eps []StagedEndpointInput) error
	// ListStagedEndpoints — все staged-эндпоинты одного прогона (для отчёта).
	ListStagedEndpoints(ctx context.Context, projectID, jobID int32) ([]StagedEndpoint, error)
	// ListStagedEndpointsByIDs — выбранные staged-эндпоинты проекта по id (для импорта).
	ListStagedEndpointsByIDs(ctx context.Context, projectID int32, ids []int32) ([]StagedEndpoint, error)
	// MarkStagedEndpointsImported помечает выбранные staged-эндпоинты импортированными.
	MarkStagedEndpointsImported(ctx context.Context, projectID int32, ids []int32) error
	// ClearStagedEndpoints удаляет staged-эндпоинты одного прогона; возвращает число удалённых.
	ClearStagedEndpoints(ctx context.Context, projectID, jobID int32) (int64, error)
	// ImportEndpoint создаёт реальный endpoint проекта (дедуп на host_id/path/method,
	// как обычное добавление). created=false → уже существовал (идемпотентно).
	ImportEndpoint(ctx context.Context, in EndpointImportInput) (created bool, err error)

	// ─── стейджинг JS-майнинга прогона (recon_farm_staged_js) ───
	// InsertStagedJs вставляет staged-находки JS прогона (по строке на секрет/эндпоинт).
	InsertStagedJs(ctx context.Context, rows []StagedJsInput) error
	// ListStagedJs — все staged-находки JS одного прогона (для отчёта).
	ListStagedJs(ctx context.Context, projectID, jobID int32) ([]StagedJs, error)
	// ListStagedJsByIDs — выбранные staged-находки JS проекта по id (для импорта).
	ListStagedJsByIDs(ctx context.Context, projectID int32, ids []int32) ([]StagedJs, error)
	// MarkStagedJsImported помечает выбранные staged-находки JS импортированными.
	MarkStagedJsImported(ctx context.Context, projectID int32, ids []int32) error
	// ClearStagedJs удаляет staged-находки JS одного прогона; возвращает число удалённых.
	ClearStagedJs(ctx context.Context, projectID, jobID int32) (int64, error)

	// ─── js-файлы (эндпоинты списка/архива) ───
	ListJsFiles(ctx context.Context, projectID int32) ([]JSFileView, error)
	JSFileURLs(ctx context.Context, projectID int32, hostID *int32) ([]string, error)
	DeleteJSFilesForHost(ctx context.Context, projectID, hostID int32) error
	// BulkDeleteJSFiles удаляет JS-находки проекта по списку id одним DELETE;
	// возвращает число реально удалённых (чужие/несуществующие id не считаются).
	BulkDeleteJSFiles(ctx context.Context, projectID int32, ids []int32) (int64, error)

	// ─── конфигурация фермы (пер-проектный JSONB-блоб) ───
	GetFarmConfig(ctx context.Context, projectID int32) (FarmConfig, error)
	SaveFarmConfig(ctx context.Context, projectID int32, cfg FarmConfig) error

	// ─── аудит ───
	InsertAudit(ctx context.Context, e AuditEntry) error
}
