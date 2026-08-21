package recon

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
)

// fakeStore реализует Store: методы, не нужные тесту, — заглушки.
type fakeStore struct {
	existingNames map[string]bool
	captured      *NewJob
}

func (f *fakeStore) InsertJob(_ context.Context, j NewJob) (JobView, error) {
	f.captured = &j
	return JobView{ID: 1, ProjectID: j.ProjectID, Kind: j.Kind, Status: j.Status, TargetsTotal: j.TargetsTotal, Result: j.Result}, nil
}
func (f *fakeStore) ExistingHostnames(_ context.Context, _ int32, names []string) ([]string, error) {
	var out []string
	for _, n := range names {
		if f.existingNames[n] {
			out = append(out, n)
		}
	}
	return out, nil
}
func (f *fakeStore) GetJobForProject(context.Context, int32, int32, string) (JobView, error) {
	return JobView{}, ErrNoRows
}
func (f *fakeStore) ClaimJobRunning(context.Context, int32) (*JobClaim, error)   { return nil, nil }
func (f *fakeStore) UpdateJobProgress(context.Context, int32, []byte) error      { return nil }
func (f *fakeStore) MarkJobDone(context.Context, int32, []byte) error            { return nil }
func (f *fakeStore) MarkJobFailed(context.Context, int32, string, *string) error { return nil }
func (f *fakeStore) SelectPendingJobIDs(context.Context, int32, int32) ([]int32, error) {
	return nil, nil
}
func (f *fakeStore) ReclaimStale(context.Context, int32, int32) (int64, error) { return 0, nil }
func (f *fakeStore) ExistingHostIPLiterals(context.Context, int32, []string) ([]string, error) {
	return nil, nil
}
func (f *fakeStore) ExistingOriginIPs(context.Context, int32, []string) ([]string, error) {
	return nil, nil
}
func (f *fakeStore) EnsureHostSkeletons(context.Context, int32, []SkeletonHost) error { return nil }
func (f *fakeStore) DeleteHiddenIPs(context.Context, int32, []string) error           { return nil }
func (f *fakeStore) PersistHost(context.Context, HostPersistInput) (HostPersistOutcome, error) {
	return HostPersistOutcome{}, nil
}
func (f *fakeStore) PersistIP(context.Context, IPPersistInput) (IPPersistOutcome, error) {
	return IPPersistOutcome{}, nil
}
func (f *fakeStore) PersistScanHost(context.Context, ScanHostInput) (ScanHostOutcome, error) {
	return ScanHostOutcome{}, nil
}
func (f *fakeStore) PersistJSFile(context.Context, JSFileInput) error { return nil }
func (f *fakeStore) ProjectDomainHostnames(context.Context, int32) ([]string, error) {
	return nil, nil
}
func (f *fakeStore) ProjectAllHostnames(context.Context, int32) ([]string, error) { return nil, nil }
func (f *fakeStore) ProjectOriginIPs(context.Context, int32) ([]string, error)    { return nil, nil }
func (f *fakeStore) ProjectScanTargets(context.Context, int32) ([]string, error)  { return nil, nil }
func (f *fakeStore) ProjectOriginHostMap(context.Context, int32) (map[string]int32, error) {
	return nil, nil
}
func (f *fakeStore) ListJsFiles(context.Context, int32) ([]JSFileView, error) { return nil, nil }
func (f *fakeStore) JSFileURLs(context.Context, int32, *int32) ([]string, error) {
	return nil, nil
}
func (f *fakeStore) InsertAudit(context.Context, AuditEntry) error { return nil }
func (f *fakeStore) GetFarmConfig(context.Context, int32) (FarmConfig, error) {
	return DefaultFarmConfig(), nil
}
func (f *fakeStore) SaveFarmConfig(context.Context, int32, FarmConfig) error { return nil }

func testService(store Store) *Service {
	return NewService(store, reconnet.Settings{FarmMaxTargets: 256, PortscanMaxTargets: 64}, Config{WorkerEnabled: true, MaxAttempts: 3}, nil)
}

func TestCreateHostsJob_shortCircuit(t *testing.T) {
	store := &fakeStore{existingNames: map[string]bool{"a.com": true, "b.com": true}}
	svc := testService(store)
	view, err := svc.CreateJob(context.Background(), KindHosts, 7, 42, "a.com\nb.com")
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if view.Status != jobDone {
		t.Errorf("status = %q, want done", view.Status)
	}
	j := store.captured
	if j == nil {
		t.Fatal("no job captured")
	}
	if j.TargetsTotal == nil || *j.TargetsTotal != 0 {
		t.Errorf("targets_total = %v, want 0", j.TargetsTotal)
	}
	if !reflect.DeepEqual(j.SkippedTargets, []string{"a.com", "b.com"}) {
		t.Errorf("skipped_targets = %v, want [a.com b.com]", j.SkippedTargets)
	}
	var res map[string]any
	if err := json.Unmarshal(j.Result, &res); err != nil {
		t.Fatalf("result not JSON: %v", err)
	}
	if res["hosts_skipped"] != float64(2) {
		t.Errorf("hosts_skipped = %v, want 2", res["hosts_skipped"])
	}
}

func TestCreateHostsJob_skippedTargets(t *testing.T) {
	store := &fakeStore{existingNames: map[string]bool{"a.com": true}}
	svc := testService(store)
	_, err := svc.CreateJob(context.Background(), KindHosts, 7, 42, "a.com\nb.com\nc.com")
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	j := store.captured
	if j.Status != jobPending {
		t.Errorf("status = %q, want pending", j.Status)
	}
	if j.TargetsTotal == nil || *j.TargetsTotal != 2 {
		t.Errorf("targets_total = %v, want 2", j.TargetsTotal)
	}
	if !reflect.DeepEqual(j.SkippedTargets, []string{"a.com"}) {
		t.Errorf("skipped_targets = %v, want [a.com]", j.SkippedTargets)
	}
	if j.Result != nil {
		t.Errorf("pending job should have nil result, got %s", j.Result)
	}
}

func TestCreateHostsJob_emptyRejected(t *testing.T) {
	svc := testService(&fakeStore{})
	if _, err := svc.CreateJob(context.Background(), KindHosts, 1, 1, "# only a comment"); err == nil {
		t.Error("expected validation error for empty target list")
	}
}

func TestCapResult(t *testing.T) {
	res := newHostFarmResult()
	res.HostsCreated = 5
	for i := 0; i < 5; i++ {
		res.Hosts = append(res.Hosts, HostResult{Status: "up", Ports: []PortResult{}})
	}
	res.Errors = []string{"e1", "e2", "e3"}
	capped := capResult(mustJSON(res), 2)
	var m map[string]any
	if err := json.Unmarshal(capped, &m); err != nil {
		t.Fatalf("capped not JSON: %v", err)
	}
	if got := len(m["hosts"].([]any)); got != 2 {
		t.Errorf("hosts capped to %d, want 2", got)
	}
	if got := len(m["errors"].([]any)); got != 2 {
		t.Errorf("errors capped to %d, want 2", got)
	}
	if m["hosts_created"] != float64(5) {
		t.Errorf("hosts_created = %v, want 5 (counters untouched)", m["hosts_created"])
	}
}

func (f *fakeStore) DeleteJSFilesForHost(context.Context, int32, int32) error { return nil }
