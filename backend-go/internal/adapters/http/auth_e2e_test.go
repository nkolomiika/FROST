package http

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nkolomiika/frost/internal/adapters/postgres/agenttokenrepo"
	"github.com/nkolomiika/frost/internal/adapters/postgres/auditrepo"
	"github.com/nkolomiika/frost/internal/adapters/postgres/authrepo"
	"github.com/nkolomiika/frost/internal/adapters/postgres/inventoryrepo"
	"github.com/nkolomiika/frost/internal/adapters/postgres/projectsrepo"
	"github.com/nkolomiika/frost/internal/adapters/postgres/sqlc"
	"github.com/nkolomiika/frost/internal/adapters/postgres/usersrepo"
	"github.com/nkolomiika/frost/internal/adapters/postgres/vulnsrepo"
	"github.com/nkolomiika/frost/internal/adapters/security"
	"github.com/nkolomiika/frost/internal/adapters/storage"
	"github.com/nkolomiika/frost/internal/app/agenttokens"
	"github.com/nkolomiika/frost/internal/app/audit"
	"github.com/nkolomiika/frost/internal/app/auth"
	"github.com/nkolomiika/frost/internal/app/inventory"
	"github.com/nkolomiika/frost/internal/app/projects"
	"github.com/nkolomiika/frost/internal/app/users"
	"github.com/nkolomiika/frost/internal/app/vulns"
)

// E2E-тест сквозного пути auth: baseline → sqlc → repo → use-cases → HTTP.
// Запускается только когда задан FROST_TEST_DATABASE_URL (иначе пропускается):
//
//	docker run -d --name pg -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=frost -p 55432:5432 postgres:16-alpine
//	FROST_TEST_DATABASE_URL='postgres://postgres:pw@127.0.0.1:55432/frost' go test ./internal/adapters/http/ -run E2E
const testOrigin = "http://frost.test"

func applyBaseline(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	raw, err := os.ReadFile("../../../db/migrations/00001_baseline.sql")
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}
	sql := string(raw)
	up := section(sql, "-- +goose Up", "-- +goose Down")
	down := section(sql, "-- +goose Down", "")
	// idempotent: снести прошлую схему, затем создать заново (Exec без args → simple protocol, много стейтментов).
	_, _ = pool.Exec(ctx, strip(down))
	if _, err := pool.Exec(ctx, strip(up)); err != nil {
		t.Fatalf("apply baseline: %v", err)
	}
}

// section вырезает текст между маркерами (from..to); пустой to — до конца.
func section(s, from, to string) string {
	i := strings.Index(s, from)
	if i < 0 {
		return ""
	}
	s = s[i+len(from):]
	if to == "" {
		return s
	}
	if j := strings.Index(s, to); j >= 0 {
		return s[:j]
	}
	return s
}

// strip убирает goose-аннотации StatementBegin/End (комментарии psql игнорирует, но чистим).
func strip(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "-- +goose") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func newE2EServer(t *testing.T, pool *pgxpool.Pool) *httptest.Server {
	t.Helper()
	const secret = "e2e-secret-key-at-least-32-chars-long!!"
	cipher, err := security.NewSecretCipher(secret)
	if err != nil {
		t.Fatal(err)
	}
	svc := auth.NewService(
		authrepo.New(pool),
		security.NewJWTManager(secret, 30, 30),
		cipher,
		auth.Config{RefreshTokenTTL: 30 * 24 * time.Hour, PasswordResetTTL: 2 * time.Hour, AppBaseURL: "https://app", MailEnabled: true},
		nil,
	)
	cookies := CookieConfig{Secure: false, SameSite: http.SameSiteLaxMode, AccessMaxAge: 1800, RefreshMaxAge: 2592000, TwoFAMaxAge: 300}
	handler := NewAuthHandler(svc, cookies, []string{testOrigin})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	projectsSvc := projects.NewService(projectsrepo.New(pool), cipher, nil)
	projectsH := NewProjectsHandler(projectsSvc, svc, []string{testOrigin})
	auditH := NewAuditHandler(audit.NewService(auditrepo.New(pool)), svc)
	inventorySvc := inventory.NewService(inventoryrepo.New(pool), nil)
	inventoryH := NewInventoryHandler(inventorySvc, projectsSvc, svc, []string{testOrigin})
	vulnsSvc := vulns.NewService(vulnsrepo.New(pool), storage.Stub{}, "frost")
	vulnsH := NewVulnsHandler(vulnsSvc, projectsSvc, svc, []string{testOrigin})
	agentSvc := agenttokens.NewService(agenttokenrepo.New(pool), nil)
	agentTokH := NewAgentTokenHandler(agentSvc, svc, []string{testOrigin})
	agentV2H := NewAgentV2Handler(agentSvc, projectsSvc, inventorySvc, vulnsSvc)
	usersH := NewUsersHandler(users.NewService(usersrepo.New(pool), cipher, storage.Stub{}, users.Config{
		AppBaseURL: "https://app", MailEnabled: true, Brand: "FROST", MinioBucketName: "frost",
		InviteTokenExpireHours: 168, ReactivationExpireHours: 24,
	}, nil), svc, []string{testOrigin})
	return httptest.NewServer(NewRouter(Deps{
		Logger: logger, Auth: handler, Projects: projectsH, Audit: auditH,
		Inventory: inventoryH, Vulns: vulnsH, Users: usersH,
		AgentTokens: agentTokH, AgentV2: agentV2H,
	}))
}

func TestE2EAuthLoginRefreshLogout(t *testing.T) {
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

	// seed a user directly via sqlc
	q := sqlc.New(pool)
	hash, _ := security.HashPassword("s3cret-pw")
	if _, err := q.CreateUser(ctx, sqlc.CreateUserParams{
		Username: "alice", Email: "alice@x.io", PasswordHash: hash,
		Role: sqlc.UserRoleADMIN, ProjectRole: sqlc.ProjectRolePENTESTER, IsActive: true,
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	srv := newE2EServer(t, pool)
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	post := func(path, body string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", testOrigin)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		return resp
	}

	// 1. login
	resp := post("/api/v1/auth/login", `{"username":"alice","password":"s3cret-pw"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d", resp.StatusCode)
	}
	resp.Body.Close()

	// 2. CSRF: missing Origin -> 403
	{
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/auth/refresh", nil)
		r2, _ := client.Do(req)
		if r2.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 without Origin, got %d", r2.StatusCode)
		}
		r2.Body.Close()
	}

	// 3. refresh (rotates)
	resp = post("/api/v1/auth/refresh", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh status=%d", resp.StatusCode)
	}
	resp.Body.Close()

	// 4. logout
	resp = post("/api/v1/auth/logout", "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status=%d", resp.StatusCode)
	}
	resp.Body.Close()

	// 5. wrong password -> 401
	resp = post("/api/v1/auth/login", `{"username":"alice","password":"nope"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong password, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}
