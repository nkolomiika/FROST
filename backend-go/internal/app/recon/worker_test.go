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
// адаптера reconrepo.ReclaimStale (пакет adapters/postgres/reconrepo), вне scope
// этого пакета. На уровне app/recon реклейм — непрозрачный вызов store.ReclaimStale,
// возвращающий число затронутых строк. Проверяем оркестрацию: ProcessPending
// вызывает реклейм ДО выборки pending (переигранные попадают в ту же выборку),
// что зеркалит порядок в Python-воркере.

func TestProcessPending_reclaimsBeforeSelecting(t *testing.T) {
	store := &stubStore{reclaimN: 2, pendingIDs: nil}
	svc := stubService(store, reconnet.Settings{}, Config{MaxAttempts: 3, StaleSeconds: 1800})

	if err := svc.ProcessPending(context.Background()); err != nil {
		t.Fatalf("ProcessPending: %v", err)
	}
	if len(store.callOrder) < 2 || store.callOrder[0] != "reclaim" || store.callOrder[1] != "select" {
		t.Errorf("call order = %v, want [reclaim select ...]", store.callOrder)
	}
}
