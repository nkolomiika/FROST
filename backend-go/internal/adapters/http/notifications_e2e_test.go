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

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nkolomiika/frost/internal/adapters/postgres/sqlc"
	"github.com/nkolomiika/frost/internal/adapters/security"
)

func TestE2ENotificationsFlow(t *testing.T) {
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
	admin, err := q.CreateUser(ctx, sqlc.CreateUserParams{
		Username: "admin", Email: "admin@x.io", PasswordHash: hash,
		Role: sqlc.UserRoleADMIN, ProjectRole: sqlc.ProjectRolePENTESTER, IsActive: true,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	proj, err := q.InsertProject(ctx, sqlc.InsertProjectParams{Name: "P", Status: sqlc.ProjectStatusACTIVE, CreatedBy: admin.ID})
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	// seed a notification for admin (project_status_changed carries project_id + status)
	if err := q.InsertNotification(ctx, sqlc.InsertNotificationParams{
		UserID: admin.ID, Type: sqlc.NotificationTypePROJECTSTATUSCHANGED,
		ProjectID: pgtype.Int4{Int32: proj.ID, Valid: true},
		ActorID:   pgtype.Int4{Int32: admin.ID, Valid: true},
		Status:    pgtype.Text{String: "archived", Valid: true},
	}); err != nil {
		t.Fatalf("notif: %v", err)
	}

	srv := newE2EServer(t, pool)
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	do := func(method, path string) (*http.Response, []byte) {
		req, _ := http.NewRequest(method, srv.URL+path, nil)
		req.Header.Set("Origin", testOrigin)
		resp, _ := client.Do(req)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, b
	}
	// login
	{
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"s3cret-pw"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", testOrigin)
		r, _ := client.Do(req)
		if r.StatusCode != 200 {
			t.Fatalf("login %d", r.StatusCode)
		}
		r.Body.Close()
	}

	// list -> total 1, type lowercase, context.project_name resolved
	r, b := do(http.MethodGet, "/api/v1/notifications")
	var page struct {
		Total int `json:"total"`
		Items []struct {
			Id      int    `json:"id"`
			Type    string `json:"type"`
			Context *struct {
				ProjectName *string `json:"project_name"`
				Status      *string `json:"status"`
			} `json:"context"`
		} `json:"items"`
	}
	json.Unmarshal(b, &page)
	if r.StatusCode != 200 || page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("list: %d %s", r.StatusCode, b)
	}
	if page.Items[0].Type != "project_status_changed" {
		t.Fatalf("type should be lowercase: %s", b)
	}
	if page.Items[0].Context == nil || page.Items[0].Context.ProjectName == nil || *page.Items[0].Context.ProjectName != "P" {
		t.Fatalf("context.project_name should resolve to P: %s", b)
	}
	nid := strconv.Itoa(page.Items[0].Id)

	// unread-count -> 1
	r, b = do(http.MethodGet, "/api/v1/notifications/unread-count")
	if r.StatusCode != 200 || !strings.Contains(string(b), `"count":1`) {
		t.Fatalf("unread: %d %s", r.StatusCode, b)
	}
	// mark read -> 200, context null
	r, b = do(http.MethodPatch, "/api/v1/notifications/"+nid+"/read")
	if r.StatusCode != 200 || !strings.Contains(string(b), `"is_read":true`) {
		t.Fatalf("mark read: %d %s", r.StatusCode, b)
	}
	// unread now 0
	if _, b := do(http.MethodGet, "/api/v1/notifications/unread-count"); !strings.Contains(string(b), `"count":0`) {
		t.Fatalf("unread after read: %s", b)
	}
	// mark-all -> 204
	if r, _ := do(http.MethodPatch, "/api/v1/notifications/read-all"); r.StatusCode != 204 {
		t.Fatalf("mark-all: %d", r.StatusCode)
	}
	// mark read on missing -> 404
	if r, _ := do(http.MethodPatch, "/api/v1/notifications/99999/read"); r.StatusCode != 404 {
		t.Fatalf("expected 404 for missing notif, got %d", r.StatusCode)
	}
}
