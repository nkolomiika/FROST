package projects

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nkolomiika/frost/internal/apperr"
)

// fakeStore — in-memory реализация Store для проверки чистой логики сервиса.
type fakeStore struct {
	project       *Project
	folders       map[int32]*Folder
	folderOrder   []int32
	projects      map[int32]*Project
	notes         map[int32]*Note
	memberIDs     []int32
	usersByName   map[string]UserBrief
	notifications []Notification
	audits        []AuditEntry
	updated       *ProjectUpdate
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		folders:     map[int32]*Folder{},
		projects:    map[int32]*Project{},
		notes:       map[int32]*Note{},
		usersByName: map[string]UserBrief{},
	}
}

// noopCipher — тривиальный шифр (для кред-тестов не используется здесь).
type noopCipher struct{}

func (noopCipher) Encrypt(v string) (string, error) { return "enc:" + v, nil }
func (noopCipher) Decrypt(t string) (string, error) { return t, nil }

// ─── реализованные для тестов методы ───

func (f *fakeStore) GetProject(_ context.Context, id int32) (*Project, error) {
	if f.project != nil && f.project.ID == id {
		return cloneProject(f.project), nil
	}
	if p, ok := f.projects[id]; ok {
		return cloneProject(p), nil
	}
	return nil, ErrNoRows
}

func (f *fakeStore) ProjectsByIDs(_ context.Context, ids []int32) ([]Project, error) {
	var out []Project
	for _, id := range ids {
		if p, ok := f.projects[id]; ok {
			out = append(out, *cloneProject(p))
		}
	}
	return out, nil
}

func (f *fakeStore) AllProjectIDs(_ context.Context) ([]int32, error) {
	out := make([]int32, 0, len(f.projects))
	for id := range f.projects {
		out = append(out, id)
	}
	return out, nil
}

func (f *fakeStore) UpdateProject(_ context.Context, up ProjectUpdate) (*Project, error) {
	f.updated = &up
	p := &Project{
		ID: up.ID, Name: up.Name, Folder: up.Folder, Description: up.Description,
		StartDate: up.StartDate, EndDate: up.EndDate, Status: up.Status, TimelineFrozenAt: up.TimelineFrozenAt,
	}
	f.project = p
	return cloneProject(p), nil
}

func (f *fakeStore) ListProjectMemberIDs(_ context.Context, _ int32) ([]int32, error) {
	return f.memberIDs, nil
}
func (f *fakeStore) InsertNotification(_ context.Context, n Notification) error {
	f.notifications = append(f.notifications, n)
	return nil
}
func (f *fakeStore) InsertAudit(_ context.Context, e AuditEntry) error {
	f.audits = append(f.audits, e)
	return nil
}

func (f *fakeStore) GetFolderByID(_ context.Context, id int32) (*Folder, error) {
	if fol, ok := f.folders[id]; ok {
		c := *fol
		return &c, nil
	}
	return nil, ErrNoRows
}
func (f *fakeStore) FindSiblingFolder(_ context.Context, _ *int32, _ string, _ int32) (bool, error) {
	return false, nil
}
func (f *fakeStore) ListSubtreeFolders(_ context.Context, path string) ([]Folder, error) {
	var out []Folder
	for _, id := range f.folderOrder {
		fol := f.folders[id]
		if fol.Path == path || len(fol.Path) > len(path) && fol.Path[:len(path)+1] == path+"/" {
			out = append(out, *fol)
		}
	}
	return out, nil
}
func (f *fakeStore) ListSubtreeProjects(_ context.Context, folder string) ([]Project, error) {
	var out []Project
	for _, p := range f.projects {
		if p.Folder == folder || len(p.Folder) > len(folder) && p.Folder[:len(folder)+1] == folder+"/" {
			out = append(out, *p)
		}
	}
	return out, nil
}
func (f *fakeStore) ApplyFolderMove(_ context.Context, plan FolderMovePlan) error {
	for _, fu := range plan.FolderUpdates {
		fol := f.folders[fu.ID]
		fol.Path = fu.Path
		if fu.IsRoot {
			fol.ParentID = fu.ParentID
		}
	}
	for _, pm := range plan.ProjectMoves {
		f.projects[pm.ID].Folder = pm.Folder
	}
	return nil
}

func (f *fakeStore) GetNote(_ context.Context, projectID, noteID int32) (*Note, error) {
	if n, ok := f.notes[noteID]; ok && n.ProjectID == projectID {
		c := *n
		return &c, nil
	}
	return nil, ErrNoRows
}
func (f *fakeStore) GetNoteParentID(_ context.Context, projectID, noteID int32) (*int32, error) {
	if n, ok := f.notes[noteID]; ok && n.ProjectID == projectID {
		return n.ParentID, nil
	}
	return nil, nil
}
func (f *fakeStore) SiblingTitleExists(_ context.Context, _ int32, _ *int32, _ string, _ int32) (bool, error) {
	return false, nil
}
func (f *fakeStore) MaxSiblingSortOrder(_ context.Context, _ int32, _ *int32) (int32, error) {
	return -1, nil
}
func (f *fakeStore) MoveNote(_ context.Context, id int32, parentID *int32, sortOrder, _ int32) error {
	n := f.notes[id]
	n.ParentID = parentID
	n.SortOrder = sortOrder
	return nil
}

func (f *fakeStore) InsertNoteComment(_ context.Context, projectID, noteID, userID int32, content string) (*NoteComment, error) {
	return &NoteComment{ID: 500, ProjectID: projectID, NoteID: noteID, UserID: userID, Content: content}, nil
}
func (f *fakeStore) ResolveMentionUsers(_ context.Context, _ int32, usernames []string) ([]UserBrief, error) {
	var out []UserBrief
	for _, name := range usernames {
		if u, ok := f.usersByName[name]; ok {
			out = append(out, u)
		}
	}
	return out, nil
}

func cloneProject(p *Project) *Project { c := *p; return &c }

// ─── незадействованные в тестах методы (заглушки) ───

func (f *fakeStore) ListProjects(context.Context, ProjectListParams) ([]Project, int64, error) {
	return nil, 0, nil
}
func (f *fakeStore) InsertProject(context.Context, NewProject) (*Project, error) { return nil, nil }
func (f *fakeStore) DeleteProject(context.Context, int32) error                  { return nil }
func (f *fakeStore) IsProjectMember(context.Context, int32, int32) (bool, error) { return false, nil }
func (f *fakeStore) ProjectStats(context.Context, int32, bool) ([]ProjectStat, error) {
	return nil, nil
}
func (f *fakeStore) GetUserBrief(context.Context, int32) (*UserBrief, error)    { return nil, ErrNoRows }
func (f *fakeStore) ListMembers(context.Context, int32) ([]MemberDetail, error) { return nil, nil }
func (f *fakeStore) GetMember(context.Context, int32, int32) (int32, bool, error) {
	return 0, false, nil
}
func (f *fakeStore) InsertMember(context.Context, int32, int32) (int32, time.Time, error) {
	return 0, time.Time{}, nil
}
func (f *fakeStore) DeleteMember(context.Context, int32, int32) error         { return nil }
func (f *fakeStore) ListFolders(context.Context) ([]Folder, error)            { return nil, nil }
func (f *fakeStore) GetFolderByPath(context.Context, string) (*Folder, error) { return nil, ErrNoRows }
func (f *fakeStore) InsertFolder(context.Context, string, string, *int32, int32) (*Folder, error) {
	return nil, nil
}
func (f *fakeStore) DeleteFolderCascade(context.Context, string) (int, int, error) { return 0, 0, nil }
func (f *fakeStore) ListNotes(context.Context, int32) ([]Note, error)              { return nil, nil }
func (f *fakeStore) ListSiblingNotes(context.Context, int32, *int32) ([]Note, error) {
	return nil, nil
}
func (f *fakeStore) InsertNote(context.Context, NewNote) (*Note, error)              { return nil, nil }
func (f *fakeStore) UpdateNote(context.Context, int32, string, *string, int32) error { return nil }
func (f *fakeStore) ReorderNotes(context.Context, []ReorderItem, int32) error        { return nil }
func (f *fakeStore) DeleteNote(context.Context, int32) error                         { return nil }
func (f *fakeStore) CountNoteComments(context.Context, int32, int32) (int64, error)  { return 0, nil }
func (f *fakeStore) ListNoteComments(context.Context, int32, int32, int32, int32) ([]NoteComment, error) {
	return nil, nil
}
func (f *fakeStore) GetNoteComment(context.Context, int32, int32, int32) (*NoteComment, error) {
	return nil, ErrNoRows
}
func (f *fakeStore) UpdateNoteComment(context.Context, int32, string) error       { return nil }
func (f *fakeStore) DeleteNoteComment(context.Context, int32) error               { return nil }
func (f *fakeStore) ListCredentials(context.Context, int32) ([]Credential, error) { return nil, nil }
func (f *fakeStore) GetCredential(context.Context, int32, int32) (*Credential, error) {
	return nil, ErrNoRows
}
func (f *fakeStore) InsertCredential(context.Context, NewCredential) (int32, error) { return 0, nil }
func (f *fakeStore) UpdateCredential(context.Context, int32, *string, string, *string) error {
	return nil
}
func (f *fakeStore) DeleteCredential(context.Context, int32) error          { return nil }
func (f *fakeStore) ListHiddenIPs(context.Context, int32) ([]string, error) { return nil, nil }
func (f *fakeStore) HideIP(context.Context, int32, string, int32) error     { return nil }
func (f *fakeStore) UnhideIP(context.Context, int32, string) error          { return nil }
func (f *fakeStore) ListProjectActivity(context.Context, int32, int32) ([]ActivityItem, error) {
	return nil, nil
}
func (f *fakeStore) VulnsByIDs(context.Context, []int32) ([]VulnBrief, error) { return nil, nil }
func (f *fakeStore) ListNotesActivity(context.Context, int32, int32) ([]NotesActivityItem, error) {
	return nil, nil
}

// ─────────────────────────── tests ───────────────────────────

func fixedNow() time.Time { return time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC) }

func i32(v int32) *int32 { return &v }

// 1. Перемещение папки пересчитывает пути поддерева (папок и проектов).
func TestMoveFolderRewritesSubtreePaths(t *testing.T) {
	f := newFakeStore()
	// a (root), a/b (child of a), target (root). Проект в a/b.
	f.folders[1] = &Folder{ID: 1, Name: "a", Path: "a"}
	f.folders[2] = &Folder{ID: 2, Name: "b", Path: "a/b", ParentID: i32(1)}
	f.folders[3] = &Folder{ID: 3, Name: "target", Path: "target"}
	f.folderOrder = []int32{1, 2, 3}
	f.projects[10] = &Project{ID: 10, Folder: "a/b"}

	svc := NewService(f, noopCipher{}, fixedNow)
	// Переносим папку a под target → target/a, ребёнок → target/a/b, проект → target/a/b.
	got, err := svc.MoveFolder(context.Background(), 1, i32(3), 99, "")
	if err != nil {
		t.Fatalf("MoveFolder: %v", err)
	}
	if got.Path != "target/a" {
		t.Fatalf("root path = %q, want target/a", got.Path)
	}
	if f.folders[2].Path != "target/a/b" {
		t.Fatalf("child path = %q, want target/a/b", f.folders[2].Path)
	}
	if f.projects[10].Folder != "target/a/b" {
		t.Fatalf("project folder = %q, want target/a/b", f.projects[10].Folder)
	}
	if f.folders[1].ParentID == nil || *f.folders[1].ParentID != 3 {
		t.Fatalf("root parent = %v, want 3", f.folders[1].ParentID)
	}
}

// 2. Перенос заметки в собственного потомка / в себя отклоняется (422).
func TestMoveNoteValidation(t *testing.T) {
	f := newFakeStore()
	f.notes[1] = &Note{ID: 1, ProjectID: 7, Title: "root"}
	f.notes[2] = &Note{ID: 2, ProjectID: 7, Title: "child", ParentID: i32(1)}
	svc := NewService(f, noopCipher{}, fixedNow)

	// В саму себя.
	if _, err := svc.MoveNote(context.Background(), 7, 1, i32(1), 99); !isValidation(err) {
		t.Fatalf("move into self: want validation, got %v", err)
	}
	// В собственного потомка (1 → под 2, а 2 — ребёнок 1).
	if _, err := svc.MoveNote(context.Background(), 7, 1, i32(2), 99); !isValidation(err) {
		t.Fatalf("move into descendant: want validation, got %v", err)
	}
}

// 3. Логика timeline_frozen_at при смене статуса + уведомления участникам (кроме актора).
func TestUpdateProjectStatusTimeline(t *testing.T) {
	f := newFakeStore()
	f.project = &Project{ID: 5, Name: "p", Status: StatusActive}
	f.memberIDs = []int32{1, 10, 11} // актор = 1
	svc := NewService(f, noopCipher{}, fixedNow)

	// ACTIVE → FREEZE: замораживаем таймлайн «сейчас».
	freeze := StatusFreeze
	_, err := svc.UpdateProject(context.Background(), 5, UpdateInput{Status: &freeze}, 1, "")
	if err != nil {
		t.Fatalf("update→freeze: %v", err)
	}
	if f.updated.TimelineFrozenAt == nil || !f.updated.TimelineFrozenAt.Equal(fixedNow()) {
		t.Fatalf("timeline_frozen_at = %v, want %v", f.updated.TimelineFrozenAt, fixedNow())
	}
	// Уведомления: участникам 10 и 11 (не актору 1).
	if len(f.notifications) != 2 {
		t.Fatalf("notifications = %d, want 2", len(f.notifications))
	}
	for _, n := range f.notifications {
		if n.Type != NotificationProjectStatusChanged || n.Status != "freeze" || n.UserID == 1 {
			t.Fatalf("bad notification: %+v", n)
		}
	}

	// FREEZE → ACTIVE: таймлайн очищается.
	f.notifications = nil
	active := StatusActive
	if _, err := svc.UpdateProject(context.Background(), 5, UpdateInput{Status: &active}, 1, ""); err != nil {
		t.Fatalf("update→active: %v", err)
	}
	if f.updated.TimelineFrozenAt != nil {
		t.Fatalf("timeline_frozen_at = %v, want nil", f.updated.TimelineFrozenAt)
	}
}

// 4. Извлечение @упоминаний дедуплицируется; self исключается из уведомлений.
func TestMentionDedupeAndSelfExclusion(t *testing.T) {
	if got := extractMentions("hi @alice @bob @alice, ping @bob!"); len(got) != 2 {
		t.Fatalf("extractMentions = %v, want 2 unique", got)
	}

	f := newFakeStore()
	f.notes[3] = &Note{ID: 3, ProjectID: 8, Title: "note"}
	f.usersByName["alice"] = UserBrief{ID: 1, Username: "alice"}
	f.usersByName["bob"] = UserBrief{ID: 2, Username: "bob"}
	svc := NewService(f, noopCipher{}, fixedNow)

	actor := Actor{ID: 1, Username: "alice", Role: "PENTESTER"}
	if _, err := svc.CreateNoteComment(context.Background(), 8, 3, "@alice @bob @alice", actor); err != nil {
		t.Fatalf("CreateNoteComment: %v", err)
	}
	// Только bob (2) получает MENTION; alice (автор) — нет.
	if len(f.notifications) != 1 {
		t.Fatalf("notifications = %d, want 1", len(f.notifications))
	}
	n := f.notifications[0]
	if n.UserID != 2 || n.Type != NotificationMention || n.NoteCommentID == nil || *n.NoteCommentID != 500 {
		t.Fatalf("bad mention notification: %+v", n)
	}
}

func isValidation(err error) bool {
	var e *apperr.Error
	if errors.As(err, &e) {
		return e.Kind == apperr.KindValidation
	}
	return false
}
