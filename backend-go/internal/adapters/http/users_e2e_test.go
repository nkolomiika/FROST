package http

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nkolomiika/frost/internal/adapters/postgres/sqlc"
	"github.com/nkolomiika/frost/internal/adapters/security"
)

func TestE2EUsersFlow(t *testing.T) {
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
	// GET /me
	r, b := do(http.MethodGet, "/api/v1/users/me", "")
	var me struct {
		Id       int    `json:"id"`
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	json.Unmarshal(b, &me)
	if r.StatusCode != 200 || me.Username != "admin" || me.Role != "admin" {
		t.Fatalf("me: %d %s", r.StatusCode, b)
	}
	// list users (admin, paginated)
	r, b = do(http.MethodGet, "/api/v1/users", "")
	var page struct {
		Total int `json:"total"`
	}
	json.Unmarshal(b, &page)
	if r.StatusCode != 200 || page.Total != 1 {
		t.Fatalf("list users: %d %s", r.StatusCode, b)
	}
	// 2FA setup returns secret + qr
	r, b = do(http.MethodPost, "/api/v1/users/me/2fa/setup", "")
	if r.StatusCode != 200 || !strings.Contains(string(b), `"secret"`) || !strings.Contains(string(b), "data:image/png;base64,") {
		t.Fatalf("2fa setup: %d %s", r.StatusCode, b)
	}
	// change own password (revokes sessions)
	if r, _ := do(http.MethodPatch, "/api/v1/users/me/password", `{"current_password":"s3cret-pw","new_password":"newpassw0rd"}`); r.StatusCode != 200 {
		t.Fatalf("change pw %d", r.StatusCode)
	}
	// create invitation (admin) -> 201
	r, b = do(http.MethodPost, "/api/v1/users/invitations", `{"email":"new@x.io"}`)
	if r.StatusCode != 201 {
		t.Fatalf("invite %d: %s", r.StatusCode, b)
	}
	// duplicate active invite -> 409
	if r, _ := do(http.MethodPost, "/api/v1/users/invitations", `{"email":"new@x.io"}`); r.StatusCode != 409 {
		t.Fatalf("expected 409 dup invite, got %d", r.StatusCode)
	}
}
