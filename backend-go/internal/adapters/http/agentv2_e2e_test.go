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

func TestE2EAgentV2Flow(t *testing.T) {
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
		t.Fatalf("seed: %v", err)
	}
	srv := newE2EServer(t, pool)
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	req := func(method, path, body, bearer string) (*http.Response, []byte) {
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		r, _ := http.NewRequest(method, srv.URL+path, rdr)
		r.Header.Set("Content-Type", "application/json")
		if bearer == "" {
			r.Header.Set("Origin", testOrigin) // cookie flow
		} else {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := client.Do(r)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, b
	}

	// login (cookie) as admin
	if r, _ := req(http.MethodPost, "/api/v1/auth/login", `{"username":"admin","password":"s3cret-pw"}`, ""); r.StatusCode != 200 {
		t.Fatalf("login %d", r.StatusCode)
	}
	// create a project (v1, admin)
	r, b := req(http.MethodPost, "/api/v1/projects", `{"name":"AgentProj"}`, "")
	var proj struct {
		Id int `json:"id"`
	}
	json.Unmarshal(b, &proj)
	if r.StatusCode != 201 || proj.Id == 0 {
		t.Fatalf("create project: %d %s", r.StatusCode, b)
	}
	pid := strconv.Itoa(proj.Id)
	// create agent token (v1, all_projects admin)
	r, b = req(http.MethodPost, "/api/v1/agent-tokens", `{"name":"ci","all_projects":true,"scopes":["projects:read","notes:read","notes:write"]}`, "")
	if r.StatusCode != 201 {
		t.Fatalf("create token: %d %s", r.StatusCode, b)
	}
	var tok struct {
		Token string `json:"token"`
	}
	json.Unmarshal(b, &tok)
	if !strings.HasPrefix(tok.Token, "frost_") {
		t.Fatalf("token format: %s", b)
	}

	// --- v2 bearer ---
	// no bearer -> 401
	if r, _ := req(http.MethodGet, "/api/v2/projects", "", "nope-not-a-token"); r.StatusCode != 401 {
		t.Fatalf("expected 401 bad bearer, got %d", r.StatusCode)
	}
	// list projects
	r, b = req(http.MethodGet, "/api/v2/projects", "", tok.Token)
	if r.StatusCode != 200 || !strings.Contains(string(b), `"AgentProj"`) {
		t.Fatalf("v2 list projects: %d %s", r.StatusCode, b)
	}
	// get project
	if r, _ := req(http.MethodGet, "/api/v2/projects/"+pid, "", tok.Token); r.StatusCode != 200 {
		t.Fatalf("v2 get project %d", r.StatusCode)
	}
	// scope enforcement: assets:read not granted -> 403
	if r, _ := req(http.MethodGet, "/api/v2/projects/"+pid+"/hosts", "", tok.Token); r.StatusCode != 403 {
		t.Fatalf("expected 403 missing scope, got %d", r.StatusCode)
	}
	// create note via v2 (notes:write), author = token creator (admin)
	r, b = req(http.MethodPost, "/api/v2/projects/"+pid+"/notes", `{"title":"Agent note","content":"c"}`, tok.Token)
	if r.StatusCode != 201 {
		t.Fatalf("v2 create note: %d %s", r.StatusCode, b)
	}
	var note struct {
		CreatedBy int    `json:"created_by"`
		Title     string `json:"title"`
	}
	json.Unmarshal(b, &note)
	if note.Title != "Agent note" || note.CreatedBy == 0 {
		t.Fatalf("v2 note: %s", b)
	}
	// list notes via v2
	if r, nb := req(http.MethodGet, "/api/v2/projects/"+pid+"/notes", "", tok.Token); r.StatusCode != 200 || !strings.Contains(string(nb), "Agent note") {
		t.Fatalf("v2 list notes: %d %s", r.StatusCode, nb)
	}
}
