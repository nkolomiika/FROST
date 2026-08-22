package recon

import (
	"context"
	"log/slog"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
)

// stubStore — конфигурируемый фейк Store для порт-тестов фермы. Встраивает
// интерфейс Store: методы без переопределения паникуют при вызове (тест их не
// трогает). Нужные методы задаются функциональными полями.
type stubStore struct {
	Store

	existingHostnames  func([]string) []string
	existingIPLiterals func([]string) []string
	existingOriginIPs  func([]string) []string
	domainHostnames    []string
	originHostMap      map[string]int32
	jsFileURLs         []string

	persistHostFn    func(HostPersistInput) (HostPersistOutcome, error)
	persistIPFn      func(IPPersistInput) (IPPersistOutcome, error)
	persistHostCalls int
	reclaimN         int64

	// стейджинг прогона фермы
	stagedInserts  []StagedHostInput      // захват InsertStagedHosts
	stagedByJob    map[int32][]StagedHost // ListStagedHosts(project, job)
	stagedByID     map[int32]StagedHost   // ListStagedHostsByIDs
	latestFarmJob  func() (int32, bool)   // LatestFarmRunJobID
	markedImported []int32                // захват MarkStagedImported
	clearedStaged  [][2]int32             // (project, job) очистки
	clearStagedN   int64

	// захваты
	captured       *NewJob
	jsFiles        []JSFileInput
	auditCount     int
	callOrder      []string
	pendingIDs     []int32
	pendingFarmIDs []int32
	claimByID      map[int32]*JobClaim
	doneResults    map[int32][]byte
	lastProgress   []byte

	// захваты фильтров дорожек воркера
	reclaimExclKind string
	reclaimForKind  string
	reclaimForStale int32
	selectExclKind  string
	selectForKind   string

	// цели/хосты проекта (для runFarm end-to-end)
	allHostnames []string
	scanTargets  []string

	// отмена прогона фермы
	cancelState      func(jobID int32) (bool, []int32) // снимок для поллера
	jobForProject    func(projectID, jobID int32, kind string) (JobView, error)
	cancelledResults map[int32][]byte
	farmCancelReqs   []int32 // jobID'ы с RequestFarmCancel
	farmStepReqs     [][2]int32
	cancelAllN       int64
	cancelAllCalled  int
}

func (s *stubStore) note(m string) { s.callOrder = append(s.callOrder, m) }

func (s *stubStore) InsertJob(_ context.Context, j NewJob) (JobView, error) {
	s.captured = &j
	return JobView{ID: 1, ProjectID: j.ProjectID, Kind: j.Kind, Status: j.Status, TargetsTotal: j.TargetsTotal, Result: j.Result}, nil
}

func (s *stubStore) ExistingHostnames(_ context.Context, _ int32, names []string) ([]string, error) {
	if s.existingHostnames != nil {
		return s.existingHostnames(names), nil
	}
	return nil, nil
}

func (s *stubStore) ExistingHostIPLiterals(_ context.Context, _ int32, addrs []string) ([]string, error) {
	if s.existingIPLiterals != nil {
		return s.existingIPLiterals(addrs), nil
	}
	return nil, nil
}

func (s *stubStore) ExistingOriginIPs(_ context.Context, _ int32, addrs []string) ([]string, error) {
	if s.existingOriginIPs != nil {
		return s.existingOriginIPs(addrs), nil
	}
	return nil, nil
}

func (s *stubStore) EnsureHostSkeletons(context.Context, int32, []SkeletonHost) error { return nil }
func (s *stubStore) DeleteHiddenIPs(context.Context, int32, []string) error           { return nil }

func (s *stubStore) ProjectDomainHostnames(context.Context, int32) ([]string, error) {
	return s.domainHostnames, nil
}
func (s *stubStore) ProjectOriginHostMap(context.Context, int32) (map[string]int32, error) {
	return s.originHostMap, nil
}
func (s *stubStore) JSFileURLs(context.Context, int32, *int32) ([]string, error) {
	return s.jsFileURLs, nil
}

func (s *stubStore) PersistHost(_ context.Context, in HostPersistInput) (HostPersistOutcome, error) {
	s.persistHostCalls++
	if s.persistHostFn != nil {
		return s.persistHostFn(in)
	}
	return defaultPersistHost(in), nil
}

// ─── стейджинг прогона фермы ───

func (s *stubStore) InsertStagedHosts(_ context.Context, hosts []StagedHostInput) error {
	s.stagedInserts = append(s.stagedInserts, hosts...)
	return nil
}
func (s *stubStore) ListStagedHosts(_ context.Context, _ int32, jobID int32) ([]StagedHost, error) {
	if s.stagedByJob != nil {
		return s.stagedByJob[jobID], nil
	}
	return []StagedHost{}, nil
}
func (s *stubStore) ListStagedHostsByIDs(_ context.Context, _ int32, ids []int32) ([]StagedHost, error) {
	out := make([]StagedHost, 0, len(ids))
	for _, id := range ids {
		if h, ok := s.stagedByID[id]; ok {
			out = append(out, h)
		}
	}
	return out, nil
}
func (s *stubStore) LatestFarmRunJobID(_ context.Context, _ int32) (int32, bool, error) {
	if s.latestFarmJob != nil {
		id, ok := s.latestFarmJob()
		return id, ok, nil
	}
	return 0, false, nil
}
func (s *stubStore) MarkStagedImported(_ context.Context, _ int32, ids []int32) error {
	s.markedImported = append(s.markedImported, ids...)
	return nil
}
func (s *stubStore) ClearStagedHosts(_ context.Context, projectID, jobID int32) (int64, error) {
	s.clearedStaged = append(s.clearedStaged, [2]int32{projectID, jobID})
	return s.clearStagedN, nil
}
func (s *stubStore) PersistIP(_ context.Context, in IPPersistInput) (IPPersistOutcome, error) {
	if s.persistIPFn != nil {
		return s.persistIPFn(in)
	}
	return IPPersistOutcome{PortsCreated: len(in.Ports)}, nil
}
func (s *stubStore) PersistJSFile(_ context.Context, in JSFileInput) error {
	s.jsFiles = append(s.jsFiles, in)
	return nil
}

func (s *stubStore) ReclaimStaleExcludingKind(_ context.Context, _ int32, _ int32, kind string) (int64, error) {
	s.note("reclaim")
	s.reclaimExclKind = kind
	return s.reclaimN, nil
}
func (s *stubStore) ReclaimStaleForKind(_ context.Context, staleSeconds int32, _ int32, kind string) (int64, error) {
	s.note("reclaim-farm")
	s.reclaimForKind = kind
	s.reclaimForStale = staleSeconds
	return s.reclaimN, nil
}
func (s *stubStore) SelectPendingJobIDsExcludingKind(_ context.Context, _ int32, _ int32, kind string) ([]int32, error) {
	s.note("select")
	s.selectExclKind = kind
	return s.pendingIDs, nil
}
func (s *stubStore) SelectPendingJobIDsForKind(_ context.Context, _ int32, _ int32, kind string) ([]int32, error) {
	s.note("select-farm")
	s.selectForKind = kind
	return s.pendingFarmIDs, nil
}
func (s *stubStore) ClaimJobRunning(_ context.Context, id int32) (*JobClaim, error) {
	return s.claimByID[id], nil
}
func (s *stubStore) UpdateJobProgress(_ context.Context, _ int32, progress []byte) error {
	s.lastProgress = progress
	return nil
}
func (s *stubStore) MarkJobDone(_ context.Context, id int32, result []byte) error {
	if s.doneResults == nil {
		s.doneResults = map[int32][]byte{}
	}
	s.doneResults[id] = result
	return nil
}
func (s *stubStore) MarkJobFailed(context.Context, int32, string, *string) error { return nil }

func (s *stubStore) MarkJobCancelled(_ context.Context, id int32, result []byte) error {
	if s.cancelledResults == nil {
		s.cancelledResults = map[int32][]byte{}
	}
	s.cancelledResults[id] = result
	return nil
}

func (s *stubStore) ProjectAllHostnames(context.Context, int32) ([]string, error) {
	return s.allHostnames, nil
}
func (s *stubStore) ProjectScanTargets(context.Context, int32) ([]string, error) {
	return s.scanTargets, nil
}

func (s *stubStore) GetJobForProject(_ context.Context, projectID, jobID int32, kind string) (JobView, error) {
	if s.jobForProject != nil {
		return s.jobForProject(projectID, jobID, kind)
	}
	return JobView{ID: jobID, ProjectID: projectID, Kind: kind, Status: "running"}, nil
}

func (s *stubStore) RequestFarmCancel(_ context.Context, _ int32, jobID int32) error {
	s.farmCancelReqs = append(s.farmCancelReqs, jobID)
	return nil
}
func (s *stubStore) RequestFarmStepCancel(_ context.Context, _ int32, jobID, stepID int32) error {
	s.farmStepReqs = append(s.farmStepReqs, [2]int32{jobID, stepID})
	return nil
}
func (s *stubStore) RequestFarmCancelAllActive(context.Context, int32) (int64, error) {
	s.cancelAllCalled++
	return s.cancelAllN, nil
}
func (s *stubStore) GetFarmCancelState(_ context.Context, jobID int32) (bool, []int32, error) {
	if s.cancelState != nil {
		cr, steps := s.cancelState(jobID)
		return cr, steps, nil
	}
	return false, nil, nil
}

func (s *stubStore) InsertAudit(context.Context, AuditEntry) error {
	s.auditCount++
	return nil
}

// defaultPersistHost — «хост создан, порты записаны как есть» (счётчик = число
// записей, пришедших из buildPorts). Зеркалит основной путь reconrepo.
func defaultPersistHost(in HostPersistInput) HostPersistOutcome {
	out := HostPersistOutcome{Created: true, PortsCreated: len(in.Ports)}
	if in.IsIP {
		ip := in.TargetKey
		out.FinalIPAddress = &ip
	} else {
		hn := in.TargetKey
		out.FinalHostname = &hn
	}
	return out
}

// stubService собирает Service поверх stubStore с настраиваемыми Settings/Config.
func stubService(store Store, s reconnet.Settings, cfg Config) *Service {
	return NewService(store, s, cfg, slog.New(slog.NewTextHandler(discard{}, nil)))
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func boolPtr(b bool) *bool { return &b }

func (s *stubStore) DeleteJSFilesForHost(context.Context, int32, int32) error { return nil }
func (s *stubStore) BulkDeleteJSFiles(context.Context, int32, []int32) (int64, error) {
	return 0, nil
}
