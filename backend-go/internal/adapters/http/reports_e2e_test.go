package http

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nkolomiika/frost/internal/adapters/postgres/sqlc"
	"github.com/nkolomiika/frost/internal/adapters/security"
)

// End-to-end reports test: Go handler -> Python sidecar -> .docx. Requires BOTH
// FROST_TEST_DATABASE_URL and FROST_TEST_SIDECAR_URL (a running report_sidecar).
func TestE2EReportsSidecar(t *testing.T) {
	dsn := os.Getenv("FROST_TEST_DATABASE_URL")
	if dsn == "" || os.Getenv("FROST_TEST_SIDECAR_URL") == "" {
		t.Skip("set FROST_TEST_DATABASE_URL and FROST_TEST_SIDECAR_URL to run the reports e2e")
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
	admin, _ := q.CreateUser(ctx, sqlc.CreateUserParams{Username: "admin", Email: "a@x.io", PasswordHash: hash, Role: sqlc.UserRoleADMIN, ProjectRole: sqlc.ProjectRolePENTESTER, IsActive: true})
	proj, _ := q.InsertProject(ctx, sqlc.InsertProjectParams{Name: "Отчётный Проект", Status: sqlc.ProjectStatusACTIVE, CreatedBy: admin.ID})
	host, _ := q.InsertHost(ctx, sqlc.InsertHostParams{ProjectID: proj.ID, Hostname: pgtype.Text{String: "app.example.com", Valid: true}, Status: sqlc.HostStatusUNKNOWN, OsType: sqlc.HostOsTypeUNKNOWN, Origin: "host"})
	score := 8.7
	vuln, _ := q.InsertVuln(ctx, sqlc.InsertVulnParams{
		ProjectID: proj.ID, Title: "SQLi", Severity: sqlc.VulnSeverityHIGH, Status: sqlc.VulnStatusOPEN,
		CvssVersion: sqlc.NullCvssVersion{CvssVersion: sqlc.CvssVersionV40, Valid: true},
		CvssScore:   &score, CvssVector: pgtype.Text{String: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", Valid: true},
		Description: pgtype.Text{String: "desc", Valid: true}, CreatedBy: admin.ID,
	})
	q.InsertVulnAsset(ctx, sqlc.InsertVulnAssetParams{VulnerabilityID: vuln.ID, AssetType: sqlc.AssetTypeHOST, AssetID: host.ID})

	srv := newE2EServer(t, pool)
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	login := func() {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"pw"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", testOrigin)
		r, _ := client.Do(req)
		if r.StatusCode != 200 {
			t.Fatalf("login %d", r.StatusCode)
		}
		r.Body.Close()
	}
	login()
	pid := strconv.Itoa(int(proj.ID))
	for _, kind := range []string{"szi", "pp"} {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/projects/"+pid+"/reports/"+kind, nil)
		req.Header.Set("Origin", testOrigin)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s status %d: %s", kind, resp.StatusCode, body)
		}
		if !bytes.HasPrefix(body, []byte("PK")) || len(body) < 50000 {
			t.Fatalf("%s: not a .docx (len=%d)", kind, len(body))
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "wordprocessingml") {
			t.Fatalf("%s content-type: %s", kind, ct)
		}
		if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "filename*=UTF-8''") {
			t.Fatalf("%s content-disposition: %s", kind, cd)
		}
	}
}
