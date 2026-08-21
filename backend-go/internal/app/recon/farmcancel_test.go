package recon

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
)

// Тесты кооперативной отмены полного прогона фермы. Поллер отмены ходит в БД;
// снижаем период опроса, чтобы не ждать реальные 2с.
func withFastPoll(t *testing.T) {
	t.Helper()
	old := farmCancelPollInterval
	farmCancelPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { farmCancelPollInterval = old })
}

// blockingCollector — пассивный сборщик, который «работает», пока не оборвут его
// контекст (per-step или общий cancel). Зеркалит внешний инструмент под ctx.
func blockingCollector(ctx context.Context, _ []string) (map[string]bool, []string, []string) {
	<-ctx.Done()
	return map[string]bool{}, []string{"subfinder"}, nil
}

func farmClaim(id, projectID int32) *JobClaim {
	return &JobClaim{ID: id, ProjectID: projectID, Kind: KindFarmRun, Raw: `{"mode":"passive"}`}
}

// Отмена всего прогона на лету → задача помечается cancelled (НЕ failed), прогон
// останавливается рано, финальный снимок stage="cancelled".
func TestRunFarm_WholeRunCancel_MarksCancelledNotFailed(t *testing.T) {
	withFastPoll(t)
	store := &stubStore{
		domainHostnames: []string{"example.com"},
		claimByID:       map[int32]*JobClaim{1: farmClaim(1, 7)},
		cancelState:     func(int32) (bool, []int32) { return true, nil }, // cancel_requested
	}
	svc := stubService(store, reconnet.Settings{FarmMaxConcurrency: 2, SubsMaxResults: 100, FarmMaxTargets: 64, PortscanMaxTargets: 64}, Config{WorkerEnabled: true, MaxAttempts: 3, ResultMaxItems: 200})
	svc.collector = blockingCollector

	done := make(chan error, 1)
	go func() { done <- svc.RunReconJob(context.Background(), 1) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunReconJob returned error (cancel should be swallowed as cancelled): %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunReconJob did not stop promptly after cancel")
	}

	if _, ok := store.cancelledResults[1]; !ok {
		t.Fatalf("job not marked cancelled; done=%v", store.doneResults)
	}
	if _, ok := store.doneResults[1]; ok {
		t.Fatalf("cancelled run must NOT be marked done")
	}
	var snap RunProgress
	if err := json.Unmarshal(store.lastProgress, &snap); err != nil {
		t.Fatalf("progress not JSON: %v", err)
	}
	if snap.Stage != "cancelled" || !snap.Done {
		t.Fatalf("final progress = %+v, want stage=cancelled done=true", snap)
	}
}

// Per-step cancel: отменённый шаг убирается, помечается мягкой ошибкой, а прогон
// доводится до done (не cancelled, не failed).
func TestRunFarm_PerStepCancel_RemovesStepRunCompletes(t *testing.T) {
	withFastPoll(t)
	// Первый (и единственный) пассивный шаг получает id=1.
	store := &stubStore{
		domainHostnames: []string{"example.com"},
		claimByID:       map[int32]*JobClaim{1: farmClaim(1, 7)},
		cancelState:     func(int32) (bool, []int32) { return false, []int32{1} }, // отмена шага 1
	}
	svc := stubService(store, reconnet.Settings{FarmMaxConcurrency: 2, SubsMaxResults: 100, FarmMaxTargets: 64, PortscanMaxTargets: 64}, Config{WorkerEnabled: true, MaxAttempts: 3, ResultMaxItems: 200})
	svc.collector = blockingCollector

	done := make(chan error, 1)
	go func() { done <- svc.RunReconJob(context.Background(), 1) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunReconJob error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run did not complete after per-step cancel")
	}

	if _, ok := store.doneResults[1]; !ok {
		t.Fatalf("per-step cancel must still finish the run as done; cancelled=%v", store.cancelledResults)
	}
	if _, ok := store.cancelledResults[1]; ok {
		t.Fatalf("per-step cancel must NOT mark the whole run cancelled")
	}
	var res FarmRunResult
	if err := json.Unmarshal(store.doneResults[1], &res); err != nil {
		t.Fatalf("result not JSON: %v", err)
	}
	if !containsSubstr(res.Errors, "процесс отменён") {
		t.Fatalf("expected soft cancel note in errors, got %v", res.Errors)
	}
}

// RunStep сериализуется со стабильным id (фронт шлёт его в per-step cancel).
func TestRunStep_SerializesID(t *testing.T) {
	tr := newProgressTracker(nil)
	id := tr.addStep(RunStep{Tool: "subfinder", Target: "x"}, nil)
	blob, err := json.Marshal(tr.p.Steps[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	_ = json.Unmarshal(blob, &m)
	if _, ok := m["id"]; !ok {
		t.Fatalf("RunStep JSON missing id: %s", blob)
	}
	if got := int(m["id"].(float64)); got != id {
		t.Fatalf("serialized id=%d, want %d", got, id)
	}
}

// Сервисный слой: CancelAllFarmRuns делегирует в стор и отдаёт число задач.
func TestCancelAllFarmRuns_DelegatesCount(t *testing.T) {
	store := &stubStore{cancelAllN: 3}
	svc := stubService(store, reconnet.Settings{}, Config{})
	n, err := svc.CancelAllFarmRuns(context.Background(), 7)
	if err != nil {
		t.Fatalf("CancelAllFarmRuns: %v", err)
	}
	if n != 3 || store.cancelAllCalled != 1 {
		t.Fatalf("n=%d calls=%d, want 3/1", n, store.cancelAllCalled)
	}
}

// CancelFarmRun на чужой/несуществующей задаче → 404 (валидация через GetJobForProject).
func TestCancelFarmRun_UnknownJob404(t *testing.T) {
	store := &stubStore{
		jobForProject: func(int32, int32, string) (JobView, error) { return JobView{}, ErrNoRows },
	}
	svc := stubService(store, reconnet.Settings{}, Config{})
	err := svc.CancelFarmRun(context.Background(), 7, 999)
	if err == nil {
		t.Fatal("want NotFound for unknown job, got nil")
	}
	if len(store.farmCancelReqs) != 0 {
		t.Fatalf("must not signal cancel for unknown job: %v", store.farmCancelReqs)
	}
}

// CancelFarmRun на валидной задаче сигналит отмену.
func TestCancelFarmRun_SignalsCancel(t *testing.T) {
	store := &stubStore{} // jobForProject nil → возвращает валидный farm_run view
	svc := stubService(store, reconnet.Settings{}, Config{})
	if err := svc.CancelFarmRun(context.Background(), 7, 42); err != nil {
		t.Fatalf("CancelFarmRun: %v", err)
	}
	if len(store.farmCancelReqs) != 1 || store.farmCancelReqs[0] != 42 {
		t.Fatalf("cancel not signalled for job 42: %v", store.farmCancelReqs)
	}
}
