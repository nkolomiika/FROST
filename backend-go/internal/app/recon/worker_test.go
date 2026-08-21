package recon

import (
	"context"
	"testing"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
)

// Порт backend/tests/test_recon_worker.py — реклейм застрявших задач.
//
// PORTING GAP: сама логика реклейма (перевод running/queued → pending, инкремент
// attempts, commit только при наличии застрявших) в Go живёт в SQL-запросе
// адаптера reconrepo (пакет adapters/postgres/reconrepo), вне scope этого пакета.
// На уровне app/recon реклейм — непрозрачный вызов store.ReclaimStale*, возвращающий
// число затронутых строк. Проверяем оркестрацию: дорожка вызывает реклейм ДО выборки
// pending (переигранные попадают в ту же выборку), что зеркалит порядок в воркере.

func TestProcessPendingRegular_reclaimsBeforeSelecting(t *testing.T) {
	store := &stubStore{reclaimN: 2, pendingIDs: nil}
	svc := stubService(store, reconnet.Settings{}, Config{MaxAttempts: 3, StaleSeconds: 1800})

	if err := svc.ProcessPendingRegular(context.Background()); err != nil {
		t.Fatalf("ProcessPendingRegular: %v", err)
	}
	if len(store.callOrder) < 2 || store.callOrder[0] != "reclaim" || store.callOrder[1] != "select" {
		t.Errorf("call order = %v, want [reclaim select ...]", store.callOrder)
	}
	// Обычная дорожка фильтрует farm_run из выборки И реклейма.
	if store.selectExclKind != KindFarmRun || store.reclaimExclKind != KindFarmRun {
		t.Errorf("regular lane must exclude farm_run (select=%q reclaim=%q)", store.selectExclKind, store.reclaimExclKind)
	}
}

// Обычная дорожка забирает обычную (host) задачу, даже когда farm_run «running» —
// farm_run не попадает в её выборку (SelectExcludingKind), поэтому не блокирует.
func TestProcessPendingRegular_picksRegularJobWhileFarmRunning(t *testing.T) {
	hostClaim := &JobClaim{ID: 10, ProjectID: 7, Kind: KindHosts, Raw: ""}
	store := &stubStore{
		pendingIDs: []int32{10}, // обычная задача pending; running farm_run сюда НЕ входит
		claimByID:  map[int32]*JobClaim{10: hostClaim},
	}
	svc := stubService(store, reconnet.Settings{FarmMaxTargets: 64}, Config{MaxAttempts: 3, StaleSeconds: 1800, ResultMaxItems: 200})

	if err := svc.ProcessPendingRegular(context.Background()); err != nil {
		t.Fatalf("ProcessPendingRegular: %v", err)
	}
	if _, ok := store.doneResults[10]; !ok {
		t.Fatalf("regular host job 10 was not processed (blocked by farm?): done=%v", store.doneResults)
	}
}

// Фермовая дорожка берёт ТОЛЬКО farm_run и с большим окном реклейма.
func TestProcessPendingFarm_selectsOnlyFarmWithLargeStale(t *testing.T) {
	store := &stubStore{pendingFarmIDs: nil}
	svc := stubService(store, reconnet.Settings{}, Config{MaxAttempts: 3, StaleSeconds: 1800, FarmStaleSeconds: 7200})

	if err := svc.ProcessPendingFarm(context.Background()); err != nil {
		t.Fatalf("ProcessPendingFarm: %v", err)
	}
	if store.selectForKind != KindFarmRun || store.reclaimForKind != KindFarmRun {
		t.Errorf("farm lane must target farm_run only (select=%q reclaim=%q)", store.selectForKind, store.reclaimForKind)
	}
	if store.reclaimForStale != 7200 {
		t.Errorf("farm reclaim stale window = %d, want 7200 (large)", store.reclaimForStale)
	}
}
