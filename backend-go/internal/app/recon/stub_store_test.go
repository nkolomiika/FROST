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

	persistHostFn func(HostPersistInput) (HostPersistOutcome, error)
	persistIPFn   func(IPPersistInput) (IPPersistOutcome, error)
	reclaimN      int64

	// захваты
	captured     *NewJob
	jsFiles      []JSFileInput
	auditCount   int
	callOrder    []string
	pendingIDs   []int32
	claimByID    map[int32]*JobClaim
	doneResults  map[int32][]byte
	lastProgress []byte
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
	if s.persistHostFn != nil {
		return s.persistHostFn(in)
	}
	return defaultPersistHost(in), nil
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

func (s *stubStore) ReclaimStale(context.Context, int32, int32) (int64, error) {
	s.note("reclaim")
	return s.reclaimN, nil
}
func (s *stubStore) SelectPendingJobIDs(context.Context, int32, int32) ([]int32, error) {
	s.note("select")
	return s.pendingIDs, nil
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
