package http

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nkolomiika/frost/config"
	"github.com/nkolomiika/frost/internal/adapters/postgres/reconrepo"
	"github.com/nkolomiika/frost/internal/adapters/postgres/sqlc"
	"github.com/nkolomiika/frost/internal/adapters/security"
	"github.com/nkolomiika/frost/internal/app/recon"
)

// Service-level DB test of the recon job lifecycle. Uses a PRIVATE IP target,
// which netguard blocks (FARM_ALLOW_PRIVATE_TARGETS=false) — no outbound network:
// create job (pending) -> ProcessPendingRegular -> terminal 'done' (host persisted, status unknown).
func TestE2EReconJobLifecycle(t *testing.T) {
	dsn := os.Getenv("FROST_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set FROST_TEST_DATABASE_URL to run the DB-backed e2e test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	applyBaseline(t, ctx, pool)

	q := sqlc.New(pool)
	hash, _ := security.HashPassword("pw")
	admin, err := q.CreateUser(ctx, sqlc.CreateUserParams{
		Username: "admin", Email: "a@x.io", PasswordHash: hash,
		Role: sqlc.UserRoleADMIN, ProjectRole: sqlc.ProjectRolePENTESTER, IsActive: true,
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	proj, err := q.InsertProject(ctx, sqlc.InsertProjectParams{Name: "P", Status: sqlc.ProjectStatusACTIVE, CreatedBy: admin.ID})
	if err != nil {
		t.Fatalf("seed project: %v", err)
	}

	// build recon service via env-loaded config (defaults: worker_enabled=true, private blocked)
	os.Setenv("DATABASE_URL", dsn)
	os.Setenv("JWT_SECRET_KEY", "e2e-secret-key-at-least-32-chars-long!!")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := recon.NewService(reconrepo.New(pool), recon.SettingsFromConfig(cfg), recon.ConfigFromConfig(cfg), logger)

	// create a hosts job for a private IP target (blocked by netguard -> no network)
	job, err := svc.CreateJob(ctx, "hosts", proj.ID, admin.ID, "10.255.255.1")
	if err != nil {
		t.Fatalf("create job: %v", err)
	}
	if job.ID == 0 || (job.Status != "pending" && job.Status != "done") {
		t.Fatalf("unexpected job: %+v", job)
	}

	// drive the worker synchronously
	if err := svc.ProcessPendingRegular(ctx); err != nil {
		t.Fatalf("process pending: %v", err)
	}

	// job must be terminal (done) and a host row must exist for the project
	got, err := svc.GetJob(ctx, "hosts", proj.ID, job.ID)
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if got.Status != "done" {
		t.Fatalf("expected job done, got %q (err=%v)", got.Status, got.Error)
	}
	n, err := q.CountHosts(ctx, sqlc.CountHostsParams{ProjectID: proj.ID})
	if err != nil {
		t.Fatalf("count hosts: %v", err)
	}
	if n == 0 {
		t.Fatalf("expected a host row persisted for the blocked target")
	}
}
