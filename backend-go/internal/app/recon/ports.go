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
	MarkJobDone(ctx context.Context, id int32, result []byte) error
	MarkJobFailed(ctx context.Context, id int32, lastErr string, terminalErr *string) error
	SelectPendingJobIDs(ctx context.Context, maxAttempts, limit int32) ([]int32, error)
	ReclaimStale(ctx context.Context, staleSeconds, maxAttempts int32) (int64, error)

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

	// ─── js-файлы (эндпоинты списка/архива) ───
	ListJsFiles(ctx context.Context, projectID int32) ([]JSFileView, error)
	JSFileURLs(ctx context.Context, projectID int32, hostID *int32) ([]string, error)

	// ─── конфигурация фермы (пер-проектный JSONB-блоб) ───
	GetFarmConfig(ctx context.Context, projectID int32) (FarmConfig, error)
	SaveFarmConfig(ctx context.Context, projectID int32, cfg FarmConfig) error

	// ─── аудит ───
	InsertAudit(ctx context.Context, e AuditEntry) error
}
