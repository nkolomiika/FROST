package http

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nkolomiika/frost/internal/adapters/postgres/sqlc"
	"github.com/nkolomiika/frost/internal/adapters/security"
)

// DB-backed smoke test for the projects context (exercises real SQL/repo).
func TestE2EProjectsFlow(t *testing.T) {
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
	hash, _ := security.HashPassword("s3cret-pw")
	if _, err := q.CreateUser(ctx, sqlc.CreateUserParams{
		Username: "admin", Email: "admin@x.io", PasswordHash: hash,
		Role: sqlc.UserRoleADMIN, ProjectRole: sqlc.ProjectRolePENTESTER, IsActive: true,
	}); err != nil {
		t.Fatalf("seed admin: %v", err)
	}

	srv := newE2EServer(t, pool)
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	do := func(method, path, body string) (*http.Response, []byte) {
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, srv.URL+path, rdr)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", testOrigin)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, b
	}

	// login
	if r, _ := do(http.MethodPost, "/api/v1/auth/login", `{"username":"admin","password":"s3cret-pw"}`); r.StatusCode != 200 {
		t.Fatalf("login %d", r.StatusCode)
	}

	// create project (admin, 201)
	r, b := do(http.MethodPost, "/api/v1/projects", `{"name":"Alpha","description":"d"}`)
	if r.StatusCode != 201 {
		t.Fatalf("create project %d: %s", r.StatusCode, b)
	}
	var proj struct {
		Id     int    `json:"id"`
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	json.Unmarshal(b, &proj)
	if proj.Id == 0 || proj.Name != "Alpha" || proj.Status != "active" {
		t.Fatalf("unexpected project: %s", b)
	}
	pid := strconv.Itoa(proj.Id)

	// get project
	if r, _ := do(http.MethodGet, "/api/v1/projects/"+pid, ""); r.StatusCode != 200 {
		t.Fatalf("get project %d", r.StatusCode)
	}

	// list projects (paginated envelope)
	r, b = do(http.MethodGet, "/api/v1/projects", "")
	if r.StatusCode != 200 {
		t.Fatalf("list %d", r.StatusCode)
	}
	var page struct {
		Total int `json:"total"`
		Pages int `json:"pages"`
	}
	json.Unmarshal(b, &page)
	if page.Total != 1 || page.Pages != 1 {
		t.Fatalf("list envelope: %s", b)
	}

	// create note
	r, b = do(http.MethodPost, "/api/v1/projects/"+pid+"/notes", `{"title":"Root note","content":"c"}`)
	if r.StatusCode != 201 {
		t.Fatalf("create note %d: %s", r.StatusCode, b)
	}
	// duplicate sibling title -> 409
	if r, _ := do(http.MethodPost, "/api/v1/projects/"+pid+"/notes", `{"title":"Root note"}`); r.StatusCode != 409 {
		t.Fatalf("expected 409 dup note title, got %d", r.StatusCode)
	}

	// credential create+list (Fernet round-trip)
	if r, _ := do(http.MethodPost, "/api/v1/projects/"+pid+"/credentials", `{"username":"u","password":"p@ss","host":"h"}`); r.StatusCode != 201 {
		t.Fatalf("create cred %d", r.StatusCode)
	}
	r, b = do(http.MethodGet, "/api/v1/projects/"+pid+"/credentials", "")
	if r.StatusCode != 200 || !strings.Contains(string(b), `"p@ss"`) {
		t.Fatalf("cred list should return decrypted password: %s", b)
	}

	// update status -> archived (lowercase on the wire, uppercase in DB)
	r, b = do(http.MethodPut, "/api/v1/projects/"+pid, `{"status":"archived"}`)
	if r.StatusCode != 200 {
		t.Fatalf("update status %d: %s", r.StatusCode, b)
	}
	json.Unmarshal(b, &proj)
	if proj.Status != "archived" {
		t.Fatalf("status not archived: %s", b)
	}

	// status filter round-trips through enum mapping
	r, b = do(http.MethodGet, "/api/v1/projects?status=archived", "")
	json.Unmarshal(b, &page)
	if r.StatusCode != 200 || page.Total != 1 {
		t.Fatalf("status filter: %s", b)
	}

	// delete project (204)
	if r, _ := do(http.MethodDelete, "/api/v1/projects/"+pid, ""); r.StatusCode != 204 {
		t.Fatalf("delete project %d", r.StatusCode)
	}
}
