package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/nkolomiika/frost/internal/app/auth"
	"github.com/nkolomiika/frost/internal/app/projects"
	"github.com/nkolomiika/frost/internal/apperr"
)

// Порт test_dependencies.py: enforce_csrf → enforceCSRF, require_project_access →
// requireProjectAccessFor, плюс чистые помощники actorFrom / pathInt32.

// detailOf вытаскивает {"detail": "..."} из ответа writeError.
func detailOf(t *testing.T, body []byte) string {
	t.Helper()
	var payload struct {
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("unmarshal error body %q: %v", body, err)
	}
	return payload.Detail
}

// okHandler — терминальный хендлер, отмечающий, что цепочка дошла до конца.
func okHandler(reached *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusOK)
	})
}

// ─────────────────────────── enforce_csrf ───────────────────────────

// GET пропускается без Origin. (test_enforce_csrf_skips_get_requests)
func TestEnforceCSRFSkipsSafeMethods(t *testing.T) {
	reached := false
	mw := enforceCSRF([]string{"http://localhost:3000"})(okHandler(&reached))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if !reached || rec.Code != http.StatusOK {
		t.Fatalf("GET without Origin blocked: reached=%v code=%d", reached, rec.Code)
	}
}

// POST без Origin → 403 «Отсутствует заголовок Origin».
// (test_enforce_csrf_requires_origin_on_post_tc_auth_005)
func TestEnforceCSRFRequiresOriginOnPost(t *testing.T) {
	reached := false
	mw := enforceCSRF([]string{"http://localhost:3000"})(okHandler(&reached))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))

	if reached {
		t.Fatal("handler reached despite missing Origin")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rec.Code)
	}
	if d := detailOf(t, rec.Body.Bytes()); d != "Отсутствует заголовок Origin" {
		t.Fatalf("detail = %q", d)
	}
}

// Неизвестный Origin на мутирующем методе → 403 «Недопустимый Origin».
// (test_enforce_csrf_rejects_unknown_origin_tc_sec_005)
func TestEnforceCSRFRejectsUnknownOrigin(t *testing.T) {
	reached := false
	mw := enforceCSRF([]string{"http://localhost:3000"})(okHandler(&reached))
	req := httptest.NewRequest(http.MethodPatch, "/", nil)
	req.Header.Set("Origin", "http://evil.local")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if reached {
		t.Fatal("handler reached despite unknown Origin")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rec.Code)
	}
	if d := detailOf(t, rec.Body.Bytes()); d != "Недопустимый Origin" {
		t.Fatalf("detail = %q", d)
	}
}

// Разрешённый Origin пропускается. (test_enforce_csrf_accepts_allowed_origin)
func TestEnforceCSRFAcceptsAllowedOrigin(t *testing.T) {
	reached := false
	mw := enforceCSRF([]string{"http://localhost:3000"})(okHandler(&reached))
	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if !reached || rec.Code != http.StatusOK {
		t.Fatalf("allowed Origin blocked: reached=%v code=%d", reached, rec.Code)
	}
}

// ─────────────────────────── actorFrom / pathInt32 ───────────────────────────

func TestActorFromUser(t *testing.T) {
	u := &auth.User{ID: 42, Username: "lead", Role: "ADMIN", ProjectRole: "LEAD"}
	ctx := context.WithValue(context.Background(), userCtxKey, u)
	r := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)

	actor := actorFrom(r)
	want := projects.Actor{ID: 42, Username: "lead", Role: "ADMIN", ProjectRole: "LEAD"}
	if actor != want {
		t.Fatalf("actorFrom = %+v, want %+v", actor, want)
	}
}

func TestActorFromNoUser(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if actor := actorFrom(r); actor != (projects.Actor{}) {
		t.Fatalf("actorFrom without user = %+v, want zero", actor)
	}
}

// pathInt32 читает {project_id} из chi-контекста; нечисловое значение → 422.
func TestPathInt32(t *testing.T) {
	mkReq := func(val string) *http.Request {
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("project_id", val)
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	}

	got, err := pathInt32(mkReq("7"), "project_id")
	if err != nil || got != 7 {
		t.Fatalf("pathInt32(\"7\") = %d, %v; want 7, nil", got, err)
	}

	if _, err := pathInt32(mkReq("nope"), "project_id"); err == nil {
		t.Fatal("pathInt32(\"nope\") expected validation error")
	} else if apperr.HTTPStatus(err) != http.StatusUnprocessableEntity {
		t.Fatalf("pathInt32(\"nope\") status = %d, want 422", apperr.HTTPStatus(err))
	}
}

// ─────────────────────────── require_project_access ───────────────────────────

// fakeAuthorizer — заглушка projectAuthorizer: возвращает заранее заданный
// проект или ошибку и запоминает переданного actor.
type fakeAuthorizer struct {
	project   *projects.Project
	err       error
	gotActor  projects.Actor
	gotProjID int32
}

func (f *fakeAuthorizer) AuthorizeAccess(ctx context.Context, projectID int32, actor projects.Actor) (*projects.Project, error) {
	f.gotProjID = projectID
	f.gotActor = actor
	return f.project, f.err
}

func projReq(projectID string, user *auth.User) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("project_id", projectID)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rctx)
	if user != nil {
		ctx = context.WithValue(ctx, userCtxKey, user)
	}
	return r.WithContext(ctx)
}

// Доступ разрешён (напр. админ или участник): проект кладётся в контекст, цепочка
// доходит до хендлера, а authz получает корректный project_id и actor.
// (test_require_project_access_admin_without_membership — доменное правило «админ
// проходит без членства» проверяется в internal/app/projects; здесь — обвязка
// middleware поверх результата AuthorizeAccess.)
func TestRequireProjectAccessAllows(t *testing.T) {
	proj := &projects.Project{ID: 7, Name: "Project without the admin"}
	authz := &fakeAuthorizer{project: proj}
	admin := &auth.User{ID: 1, Username: "admin", Role: "ADMIN", ProjectRole: "PENTESTER"}

	var seen *projects.Project
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = projectFromContext(r.Context())
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	requireProjectAccessFor(authz)(next).ServeHTTP(rec, projReq("7", admin))

	if !reached || rec.Code != http.StatusOK {
		t.Fatalf("access allowed but chain stopped: reached=%v code=%d", reached, rec.Code)
	}
	if seen != proj {
		t.Fatalf("project not placed in context: %+v", seen)
	}
	if authz.gotProjID != 7 {
		t.Errorf("authz got project_id %d, want 7", authz.gotProjID)
	}
	if authz.gotActor.ID != 1 || authz.gotActor.Role != "ADMIN" {
		t.Errorf("authz got actor %+v", authz.gotActor)
	}
}

// Доступ отклонён (не-участник): AuthorizeAccess → Forbidden, middleware отдаёт 403
// и до хендлера дело не доходит.
// (test_require_project_access_rejects_non_member_pentester)
func TestRequireProjectAccessRejects(t *testing.T) {
	authz := &fakeAuthorizer{err: apperr.Forbidden("Нет доступа к проекту")}
	user := &auth.User{ID: 2, Username: "pentester", Role: "PENTESTER", ProjectRole: "PENTESTER"}

	reached := false
	rec := httptest.NewRecorder()
	requireProjectAccessFor(authz)(okHandler(&reached)).ServeHTTP(rec, projReq("7", user))

	if reached {
		t.Fatal("handler reached despite forbidden access")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rec.Code)
	}
	if d := detailOf(t, rec.Body.Bytes()); d != "Нет доступа к проекту" {
		t.Fatalf("detail = %q", d)
	}
}
