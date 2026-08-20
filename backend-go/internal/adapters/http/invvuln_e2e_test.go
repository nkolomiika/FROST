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

// DB-backed smoke for inventory + vulns (+ CVSS) against real Postgres.
func TestE2EInventoryVulnsFlow(t *testing.T) {
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

	if r, _ := do(http.MethodPost, "/api/v1/auth/login", `{"username":"admin","password":"s3cret-pw"}`); r.StatusCode != 200 {
		t.Fatalf("login %d", r.StatusCode)
	}
	r, b := do(http.MethodPost, "/api/v1/projects", `{"name":"Inv"}`)
	if r.StatusCode != 201 {
		t.Fatalf("create project %d: %s", r.StatusCode, b)
	}
	var proj struct {
		Id int `json:"id"`
	}
	json.Unmarshal(b, &proj)
	pid := strconv.Itoa(proj.Id)

	// create host
	r, b = do(http.MethodPost, "/api/v1/projects/"+pid+"/hosts", `{"hostname":"h.example.com"}`)
	if r.StatusCode != 201 {
		t.Fatalf("create host %d: %s", r.StatusCode, b)
	}
	var host struct {
		Id       int    `json:"id"`
		Hostname string `json:"hostname"`
		Origin   string `json:"origin"`
	}
	json.Unmarshal(b, &host)
	if host.Id == 0 || host.Hostname != "h.example.com" {
		t.Fatalf("host: %s", b)
	}
	hid := strconv.Itoa(host.Id)

	// list hosts (paginated envelope with default origin=host)
	r, b = do(http.MethodGet, "/api/v1/projects/"+pid+"/hosts", "")
	var page struct {
		Total int `json:"total"`
	}
	json.Unmarshal(b, &page)
	if r.StatusCode != 200 || page.Total != 1 {
		t.Fatalf("list hosts: %d %s", r.StatusCode, b)
	}

	// create vuln with a CVSS 4.0 vector -> score 10.0, severity critical
	body := `{"host_id":` + hid + `,"title":"RCE","cvss_version":"4.0","cvss_vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"}`
	r, b = do(http.MethodPost, "/api/v1/projects/"+pid+"/vulnerabilities", body)
	if r.StatusCode != 201 {
		t.Fatalf("create vuln %d: %s", r.StatusCode, b)
	}
	var vuln struct {
		Id       int      `json:"id"`
		Severity string   `json:"severity"`
		Score    *float64 `json:"cvss_score"`
		Version  *string  `json:"cvss_version"`
	}
	json.Unmarshal(b, &vuln)
	if vuln.Id == 0 {
		t.Fatalf("vuln id: %s", b)
	}
	if vuln.Score == nil || *vuln.Score != 10.0 {
		t.Fatalf("expected cvss_score 10.0, got %s", b)
	}
	if vuln.Severity != "critical" {
		t.Fatalf("expected severity critical, got %q (%s)", vuln.Severity, b)
	}
	if vuln.Version == nil || *vuln.Version != "4.0" {
		t.Fatalf("expected cvss_version 4.0, got %s", b)
	}
	vid := strconv.Itoa(vuln.Id)

	// get vuln (composite: assets injected, at least the auto HOST link)
	r, b = do(http.MethodGet, "/api/v1/projects/"+pid+"/vulnerabilities/"+vid, "")
	if r.StatusCode != 200 || !strings.Contains(string(b), `"assets"`) {
		t.Fatalf("get vuln composite: %d %s", r.StatusCode, b)
	}

	// list vulns
	r, b = do(http.MethodGet, "/api/v1/projects/"+pid+"/vulnerabilities", "")
	json.Unmarshal(b, &page)
	if r.StatusCode != 200 || page.Total != 1 {
		t.Fatalf("list vulns: %d %s", r.StatusCode, b)
	}

	// add a comment
	if r, cb := do(http.MethodPost, "/api/v1/projects/"+pid+"/vulnerabilities/"+vid+"/comments", `{"content":"looks bad"}`); r.StatusCode != 201 {
		t.Fatalf("create comment %d: %s", r.StatusCode, cb)
	}

	// patch status -> fixed
	r, b = do(http.MethodPatch, "/api/v1/projects/"+pid+"/vulnerabilities/"+vid+"/status", `{"status":"fixed"}`)
	if r.StatusCode != 200 {
		t.Fatalf("patch status %d: %s", r.StatusCode, b)
	}
}
