package projects

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nkolomiika/frost/internal/apperr"
)

// isForbidden — ошибка домена уровня Forbidden с подстрокой в сообщении.
func isForbidden(err error, substr string) bool {
	var e *apperr.Error
	if errors.As(err, &e) {
		return e.Kind == apperr.KindForbidden && strings.Contains(e.Message, substr)
	}
	return false
}

// ─── list_projects: admin vs pentester (SQL-детали → параметры Store) ───
// Python-тесты проверяли текст SQL (наличие/отсутствие JOIN project_members и
// фильтра projects.status). В Go SQL строится в repo-адаптере; на уровне сервиса
// эквивалент — параметры ProjectListParams, передаваемые в Store. Проверяем их.

func TestListProjectsAdminAppliesStatusFilterNoMembership(t *testing.T) {
	f := newFakeStore()
	item := Project{ID: 1, Name: "Project A"}
	f.listResult = []Project{item}
	f.listTotal = 1
	svc := NewService(f, noopCipher{}, fixedNow)

	admin := Actor{ID: 100, Role: "ADMIN"}
	items, total, err := svc.ListProjects(context.Background(), admin, 1, 20, "active")
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].ID != 1 {
		t.Fatalf("items=%v total=%d", items, total)
	}
	if f.listParams == nil {
		t.Fatal("ListProjects params not captured")
	}
	if !f.listParams.IsAdmin {
		t.Fatalf("IsAdmin = false, want true (admin ⇒ без JOIN project_members)")
	}
	if f.listParams.Status != "ACTIVE" {
		t.Fatalf("Status = %q, want ACTIVE", f.listParams.Status)
	}
}

func TestListProjectsAdminIgnoresMembership(t *testing.T) {
	f := newFakeStore()
	f.listResult = []Project{{ID: 2, Name: "Project without the admin"}}
	f.listTotal = 1
	svc := NewService(f, noopCipher{}, fixedNow)

	admin := Actor{ID: 100, Role: "ADMIN"}
	items, total, err := svc.ListProjects(context.Background(), admin, 1, 20, "")
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("items=%v total=%d", items, total)
	}
	if !f.listParams.IsAdmin {
		t.Fatal("IsAdmin = false, want true (членство админа не влияет на выдачу)")
	}
	if f.listParams.Status != "" {
		t.Fatalf("Status = %q, want empty", f.listParams.Status)
	}
}

func TestListProjectsPentesterLimitedToMembership(t *testing.T) {
	f := newFakeStore()
	f.listResult = []Project{{ID: 3, Name: "Project B"}}
	f.listTotal = 1
	svc := NewService(f, noopCipher{}, fixedNow)

	pentester := Actor{ID: 55, Role: "PENTESTER"}
	// page=2, size=10 ⇒ offset=10, limit=10.
	_, _, err := svc.ListProjects(context.Background(), pentester, 2, 10, "")
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if f.listParams.IsAdmin {
		t.Fatal("IsAdmin = true, want false (не-админ ⇒ JOIN project_members по user_id)")
	}
	if f.listParams.UserID != 55 {
		t.Fatalf("UserID = %d, want 55", f.listParams.UserID)
	}
	if f.listParams.Offset != 10 || f.listParams.Limit != 10 {
		t.Fatalf("offset=%d limit=%d, want 10/10", f.listParams.Offset, f.listParams.Limit)
	}
}

// ─── delete_project: удаляет сущность и пишет аудит ───
func TestDeleteProjectRemovesEntityAndWritesAudit(t *testing.T) {
	f := newFakeStore()
	f.project = &Project{ID: 77}
	svc := NewService(f, noopCipher{}, fixedNow)

	if err := svc.DeleteProject(context.Background(), 77, 9, "127.0.0.1"); err != nil {
		t.Fatalf("DeleteProject: %v", err)
	}
	if f.deletedProjectID == nil || *f.deletedProjectID != 77 {
		t.Fatalf("DeleteProject called with %v, want 77", f.deletedProjectID)
	}
	if len(f.audits) != 1 {
		t.Fatalf("audits = %d, want 1", len(f.audits))
	}
	a := f.audits[0]
	if a.Action != "DELETE" || a.EntityType != "project" || a.EntityID == nil || *a.EntityID != 77 ||
		a.UserID == nil || *a.UserID != 9 || a.IPAddress != "127.0.0.1" {
		t.Fatalf("bad audit: %+v", a)
	}
}

// ─── update_project: логика timeline_frozen_at по ветвям смены статуса ───

func TestUpdateProjectFreezesTimelineOnFirstNonActiveStatus(t *testing.T) {
	f := newFakeStore()
	f.project = &Project{ID: 1, Status: StatusActive}
	svc := NewService(f, noopCipher{}, fixedNow)

	next := StatusHandoverToDevelopment
	updated, err := svc.UpdateProject(context.Background(), 1, UpdateInput{Status: &next}, 5, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpdateProject: %v", err)
	}
	if updated.Status != StatusHandoverToDevelopment {
		t.Fatalf("status = %q", updated.Status)
	}
	if f.updated.TimelineFrozenAt == nil || !f.updated.TimelineFrozenAt.Equal(fixedNow()) {
		t.Fatalf("timeline_frozen_at = %v, want %v", f.updated.TimelineFrozenAt, fixedNow())
	}
}

func TestUpdateProjectKeepsExistingFrozenTimestampForNonActiveTransitions(t *testing.T) {
	f := newFakeStore()
	frozen := fixedNow().AddDate(0, 0, -3)
	f.project = &Project{ID: 1, Status: StatusHandoverToDevelopment, TimelineFrozenAt: &frozen}
	svc := NewService(f, noopCipher{}, fixedNow)

	next := StatusVulnerabilityRecheck
	updated, err := svc.UpdateProject(context.Background(), 1, UpdateInput{Status: &next}, 5, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpdateProject: %v", err)
	}
	if updated.Status != StatusVulnerabilityRecheck {
		t.Fatalf("status = %q", updated.Status)
	}
	if f.updated.TimelineFrozenAt == nil || !f.updated.TimelineFrozenAt.Equal(frozen) {
		t.Fatalf("timeline_frozen_at = %v, want unchanged %v", f.updated.TimelineFrozenAt, frozen)
	}
}

func TestUpdateProjectUnfreezesTimelineWhenReactivated(t *testing.T) {
	f := newFakeStore()
	frozen := fixedNow()
	f.project = &Project{ID: 1, Status: StatusVulnerabilityRecheck, TimelineFrozenAt: &frozen}
	svc := NewService(f, noopCipher{}, fixedNow)

	next := StatusActive
	updated, err := svc.UpdateProject(context.Background(), 1, UpdateInput{Status: &next}, 5, "127.0.0.1")
	if err != nil {
		t.Fatalf("UpdateProject: %v", err)
	}
	if updated.Status != StatusActive {
		t.Fatalf("status = %q", updated.Status)
	}
	if f.updated.TimelineFrozenAt != nil {
		t.Fatalf("timeline_frozen_at = %v, want nil", f.updated.TimelineFrozenAt)
	}
}

func TestUpdateProjectWithoutStatusChangeNotifiesNobody(t *testing.T) {
	f := newFakeStore()
	f.project = &Project{ID: 1, Name: "old", Status: StatusActive}
	f.memberIDs = []int32{1, 2, 3}
	svc := NewService(f, noopCipher{}, fixedNow)

	newName := "new"
	if _, err := svc.UpdateProject(context.Background(), 1, UpdateInput{Name: &newName}, 1, "127.0.0.1"); err != nil {
		t.Fatalf("UpdateProject: %v", err)
	}
	if len(f.notifications) != 0 {
		t.Fatalf("notifications = %d, want 0 (переименование не уведомляет)", len(f.notifications))
	}
}

// ─── ensure_can_edit_project: админ / создатель / лид-участник ───

func TestEnsureCanEditProjectAllowsAdminNonMember(t *testing.T) {
	f := newFakeStore()
	f.project = &Project{ID: 1, CreatedBy: 999}
	f.isMember = false
	svc := NewService(f, noopCipher{}, fixedNow)

	admin := Actor{ID: 1, Role: "ADMIN", ProjectRole: "PENTESTER"}
	p, err := svc.EnsureCanEditProject(context.Background(), 1, admin)
	if err != nil {
		t.Fatalf("EnsureCanEditProject: %v", err)
	}
	if p.ID != 1 {
		t.Fatalf("project = %+v", p)
	}
}

func TestEnsureCanEditProjectAllowsCreator(t *testing.T) {
	f := newFakeStore()
	f.project = &Project{ID: 1, CreatedBy: 42}
	svc := NewService(f, noopCipher{}, fixedNow)

	creator := Actor{ID: 42, Role: "PENTESTER", ProjectRole: "PENTESTER"}
	if _, err := svc.EnsureCanEditProject(context.Background(), 1, creator); err != nil {
		t.Fatalf("EnsureCanEditProject: %v", err)
	}
}

func TestEnsureCanEditProjectAllowsLeadMember(t *testing.T) {
	f := newFakeStore()
	f.project = &Project{ID: 1, CreatedBy: 999}
	f.isMember = true
	svc := NewService(f, noopCipher{}, fixedNow)

	lead := Actor{ID: 42, Role: "PENTESTER", ProjectRole: "LEAD"}
	if _, err := svc.EnsureCanEditProject(context.Background(), 1, lead); err != nil {
		t.Fatalf("EnsureCanEditProject: %v", err)
	}
}

func TestEnsureCanEditProjectRejectsLeadWithoutMembership(t *testing.T) {
	f := newFakeStore()
	f.project = &Project{ID: 1, CreatedBy: 999}
	f.isMember = false
	svc := NewService(f, noopCipher{}, fixedNow)

	outsiderLead := Actor{ID: 42, Role: "PENTESTER", ProjectRole: "LEAD"}
	_, err := svc.EnsureCanEditProject(context.Background(), 1, outsiderLead)
	if !isForbidden(err, "Изменять проект") {
		t.Fatalf("want Forbidden 'Изменять проект', got %v", err)
	}
}

func TestEnsureCanEditProjectRejectsPlainMember(t *testing.T) {
	f := newFakeStore()
	f.project = &Project{ID: 1, CreatedBy: 999}
	f.isMember = true
	svc := NewService(f, noopCipher{}, fixedNow)

	member := Actor{ID: 42, Role: "PENTESTER", ProjectRole: "PENTESTER"}
	_, err := svc.EnsureCanEditProject(context.Background(), 1, member)
	if !isForbidden(err, "Изменять проект") {
		t.Fatalf("want Forbidden 'Изменять проект', got %v", err)
	}
}

// ─── add_member: уведомление добавленному (и не себе) ───

func TestAddMemberNotifiesTheAddedUser(t *testing.T) {
	f := newFakeStore()
	f.project = &Project{ID: 1}
	f.userBrief = &UserBrief{ID: 42, Username: "bob", ProjectRole: "PENTESTER"}
	f.memberExists = false
	f.insertedMemberID = 300
	svc := NewService(f, noopCipher{}, fixedNow)

	if _, err := svc.AddMember(context.Background(), 1, 42, 1, "127.0.0.1"); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if len(f.notifications) != 1 {
		t.Fatalf("notifications = %d, want 1", len(f.notifications))
	}
	n := f.notifications[0]
	if n.UserID != 42 || n.Type != NotificationProjectMemberAdded || n.ProjectID == nil || *n.ProjectID != 1 {
		t.Fatalf("bad notification: %+v", n)
	}
}

func TestAddMemberDoesNotNotifyYourself(t *testing.T) {
	f := newFakeStore()
	f.project = &Project{ID: 1}
	f.userBrief = &UserBrief{ID: 1, Username: "admin", ProjectRole: "LEAD"}
	f.memberExists = false
	f.insertedMemberID = 300
	svc := NewService(f, noopCipher{}, fixedNow)

	if _, err := svc.AddMember(context.Background(), 1, 1, 1, "127.0.0.1"); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if len(f.notifications) != 0 {
		t.Fatalf("notifications = %d, want 0 (добавил себя — уведомлять некого)", len(f.notifications))
	}
}
