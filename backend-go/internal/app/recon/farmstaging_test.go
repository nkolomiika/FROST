package recon

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
)

func strp(s string) *string { return &s }

// Полный прогон фермы кладёт находки в СТЕЙДИНГ и НЕ пишет в проект: PersistHost
// не зовётся, а staged-строки содержат веб-порт (httpx) и порт nmap -sV с сервисом.
func TestRunFarm_DryRun_StagesAndDoesNotPersist(t *testing.T) {
	withFastPoll(t)
	store := &stubStore{
		domainHostnames: []string{"example.com"},
		claimByID:       map[int32]*JobClaim{1: farmClaim(1, 7)}, // raw {"mode":"passive"}
	}
	svc := stubService(store, reconnet.Settings{FarmMaxConcurrency: 2, SubsMaxResults: 100, FarmMaxTargets: 64, PortscanMaxTargets: 64}, Config{WorkerEnabled: true, MaxAttempts: 3, ResultMaxItems: 200})
	svc.collector = func(_ context.Context, roots []string) (map[string]bool, []string, []string) {
		return map[string]bool{"api.example.com": true}, []string{"subfinder"}, nil
	}
	// dry-пробив (резолв+liveness) без сети: один живой хост, веб-порт 80.
	svc.dryProber = func(_ context.Context, _ string) ([]dryHost, []string) {
		return []dryHost{{
			hostname: "api.example.com",
			ip:       strp("93.184.216.34"),
			alive:    true,
			ports:    []dryPort{{port: 80, state: stateOPEN, httpStatus: intp(200)}},
		}}, nil
	}
	// прогрессивный nmap -sV: 9100/tcp с опознанным сервисом.
	svc.farmScanner = func(_ context.Context, _ string, _ reconnet.NmapPhase) ([]reconnet.NmapPort, string) {
		return []reconnet.NmapPort{{Port: 9100, Proto: "tcp", State: "open", Service: "jetdirect", Version: "HP"}}, ""
	}

	if err := svc.RunReconJob(context.Background(), 1); err != nil {
		t.Fatalf("RunReconJob: %v", err)
	}

	if store.persistHostCalls != 0 {
		t.Fatalf("farm run must NOT persist project hosts, got %d PersistHost calls", store.persistHostCalls)
	}
	if len(store.stagedInserts) != 1 {
		t.Fatalf("want 1 staged host, got %d", len(store.stagedInserts))
	}
	sh := store.stagedInserts[0]
	if sh.Hostname != "api.example.com" || sh.JobID != 1 || sh.ProjectID != 7 || !sh.Alive {
		t.Fatalf("staged host wrong: %+v", sh)
	}
	byPort := map[int]StagedPort{}
	for _, p := range sh.Ports {
		byPort[p.Port] = p
	}
	if _, ok := byPort[80]; !ok {
		t.Fatalf("web port 80 not staged: %+v", sh.Ports)
	}
	if byPort[80].HTTPStatus == nil || *byPort[80].HTTPStatus != 200 {
		t.Fatalf("http_status not staged on 80: %+v", byPort[80])
	}
	p9100, ok := byPort[9100]
	if !ok {
		t.Fatalf("nmap port 9100 not staged: %+v", sh.Ports)
	}
	if p9100.Service == nil || *p9100.Service != "jetdirect" {
		t.Fatalf("service not filled from -sV: %+v", p9100)
	}
	if p9100.Version == nil || *p9100.Version != "HP" {
		t.Fatalf("version not filled from -sV: %+v", p9100)
	}

	// result-счётчики отражают staged-объём.
	var res FarmRunResult
	if err := json.Unmarshal(store.doneResults[1], &res); err != nil {
		t.Fatalf("result JSON: %v", err)
	}
	if res.HostsCreated != 1 || res.HostsOnline != 1 || res.PortsFound != 2 {
		t.Fatalf("result counters = %+v, want hosts=1 online=1 ports=2", res)
	}
}

// FarmReport по явному job_id собирает summary и список staged-хостов.
func TestFarmReport_ShapeAndSummary(t *testing.T) {
	store := &stubStore{
		stagedByJob: map[int32][]StagedHost{
			5: {
				{ID: 1, Hostname: "a.com", IP: strp("1.1.1.1"), Alive: true, Ports: []StagedPort{{Port: 80, Proto: "tcp", State: "open"}, {Port: 9100, Proto: "tcp", State: "open", Service: strp("jetdirect")}}},
				{ID: 2, Hostname: "b.com", Alive: false, Imported: true, Ports: []StagedPort{}},
			},
		},
		jobForProject: func(_, jobID int32, _ string) (JobView, error) {
			return JobView{ID: jobID, Status: "done"}, nil
		},
	}
	svc := stubService(store, reconnet.Settings{}, Config{})
	jid := int32(5)
	rep, err := svc.FarmReport(context.Background(), 7, &jid)
	if err != nil {
		t.Fatalf("FarmReport: %v", err)
	}
	if rep.JobID != 5 || rep.Status != "done" {
		t.Fatalf("report head = %+v, want job=5 status=done", rep)
	}
	if rep.Summary.HostsTotal != 2 || rep.Summary.Alive != 1 || rep.Summary.PortsTotal != 2 || rep.Summary.Imported != 1 {
		t.Fatalf("summary = %+v, want hosts=2 alive=1 ports=2 imported=1", rep.Summary)
	}
	if len(rep.Hosts) != 2 {
		t.Fatalf("want 2 hosts, got %d", len(rep.Hosts))
	}
	if rep.GeneratedAt.IsZero() || rep.GeneratedAt.After(time.Now().Add(time.Minute)) {
		t.Fatalf("generated_at wrong: %v", rep.GeneratedAt)
	}
}

// Отчёт без job_id и без прошлых прогонов → пустой отчёт (не 404/ошибка).
func TestFarmReport_NoRuns_EmptyReport(t *testing.T) {
	store := &stubStore{} // latestFarmJob nil → (0,false)
	svc := stubService(store, reconnet.Settings{}, Config{})
	rep, err := svc.FarmReport(context.Background(), 7, nil)
	if err != nil {
		t.Fatalf("FarmReport: %v", err)
	}
	if rep.JobID != 0 || len(rep.Hosts) != 0 || rep.Summary.HostsTotal != 0 {
		t.Fatalf("want empty report, got %+v", rep)
	}
}

// Импорт выбранных staged-строк: создаёт хост (с сервисом/версией через Techs),
// помечает imported, идемпотентно пропускает уже импортированные.
func TestImportStagedHosts_CreatesAndMarks(t *testing.T) {
	var captured *HostPersistInput
	store := &stubStore{
		stagedByID: map[int32]StagedHost{
			1: {ID: 1, Hostname: "a.com", IP: strp("1.2.3.4"), Alive: true, Ports: []StagedPort{{Port: 9100, State: "open", Service: strp("jetdirect"), Version: strp("HP")}}},
			2: {ID: 2, Hostname: "b.com", Imported: true}, // уже импортирован → скип
		},
		persistHostFn: func(in HostPersistInput) (HostPersistOutcome, error) {
			cp := in
			captured = &cp
			return defaultPersistHost(in), nil
		},
	}
	svc := stubService(store, reconnet.Settings{}, Config{})
	n, err := svc.ImportStagedHosts(context.Background(), 7, 99, []int32{1, 2})
	if err != nil {
		t.Fatalf("ImportStagedHosts: %v", err)
	}
	if n != 1 {
		t.Fatalf("imported = %d, want 1 (id=2 already imported)", n)
	}
	if store.persistHostCalls != 1 {
		t.Fatalf("PersistHost calls = %d, want 1", store.persistHostCalls)
	}
	if len(store.markedImported) != 1 || store.markedImported[0] != 1 {
		t.Fatalf("markedImported = %v, want [1]", store.markedImported)
	}
	if captured == nil {
		t.Fatal("PersistHost input not captured")
	}
	if captured.TargetKey != "a.com" || captured.Status != statusUP || !captured.HasIP || len(captured.IPs) != 1 {
		t.Fatalf("persist input head wrong: %+v", captured)
	}
	if len(captured.Ports) != 1 || !captured.Ports[0].HasTechs || len(captured.Ports[0].Techs) != 1 {
		t.Fatalf("port techs not carried: %+v", captured.Ports)
	}
	if captured.Ports[0].Techs[0].Name != "jetdirect" {
		t.Fatalf("service name lost on import: %+v", captured.Ports[0].Techs[0])
	}
}

// Очистка отчёта делегирует в стор с целевым job_id и отдаёт число удалённых.
func TestClearStagedReport_Delegates(t *testing.T) {
	store := &stubStore{clearStagedN: 4}
	svc := stubService(store, reconnet.Settings{}, Config{})
	jid := int32(9)
	n, err := svc.ClearStagedReport(context.Background(), 7, &jid)
	if err != nil {
		t.Fatalf("ClearStagedReport: %v", err)
	}
	if n != 4 {
		t.Fatalf("cleared = %d, want 4", n)
	}
	if len(store.clearedStaged) != 1 || store.clearedStaged[0] != [2]int32{7, 9} {
		t.Fatalf("clear delegated wrong: %v", store.clearedStaged)
	}
}
