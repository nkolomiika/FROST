package projects

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nkolomiika/frost/internal/apperr"
)

// mentionRe — распознаёт @упоминания (порт MENTION_RE).
var mentionRe = regexp.MustCompile(`@([a-zA-Z0-9_.-]{1,100})`)

// Actor — аутентифицированный пользователь в терминах контекста projects.
type Actor struct {
	ID          int32
	Username    string
	Role        string // "ADMIN" | "PENTESTER"
	ProjectRole string // "LEAD" | "PENTESTER"
}

// IsAdmin — сокращение проверки роли.
func (a Actor) IsAdmin() bool { return a.Role == "ADMIN" }

// Service — use-cases контекста projects. Зависит только от портов.
type Service struct {
	store  Store
	cipher Cipher
	now    func() time.Time
}

// NewService собирает сервис. now можно подменить в тестах.
func NewService(store Store, cipher Cipher, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{store: store, cipher: cipher, now: now}
}

// ─────────────────────────── доступ ───────────────────────────

// AuthorizeAccess — порт require_project_access: грузит проект, отсутствие → 403
// (не 404), админ проходит, иначе требуется членство.
func (s *Service) AuthorizeAccess(ctx context.Context, projectID int32, actor Actor) (*Project, error) {
	project, err := s.store.GetProject(ctx, projectID)
	if errors.Is(err, ErrNoRows) {
		return nil, apperr.Forbidden("Проект не найден или недоступен")
	}
	if err != nil {
		return nil, err
	}
	if actor.IsAdmin() {
		return project, nil
	}
	ok, err := s.store.IsProjectMember(ctx, projectID, actor.ID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, apperr.Forbidden("Нет доступа к проекту")
	}
	return project, nil
}

func (s *Service) getProject(ctx context.Context, projectID int32) (*Project, error) {
	project, err := s.store.GetProject(ctx, projectID)
	if errors.Is(err, ErrNoRows) {
		return nil, apperr.NotFound("Проект не найден")
	}
	if err != nil {
		return nil, err
	}
	return project, nil
}

// GetProject — проект по ID (для GET /{project_id}).
func (s *Service) GetProject(ctx context.Context, projectID int32) (*Project, error) {
	return s.getProject(ctx, projectID)
}

func (s *Service) isProjectManager(ctx context.Context, project *Project, actor Actor) (bool, error) {
	if actor.IsAdmin() || project.CreatedBy == actor.ID {
		return true, nil
	}
	if actor.ProjectRole == "LEAD" {
		return s.store.IsProjectMember(ctx, project.ID, actor.ID)
	}
	return false, nil
}

// EnsureCanManageMembers — составом команды управляют админ, создатель или лид-участник.
func (s *Service) EnsureCanManageMembers(ctx context.Context, projectID int32, actor Actor) (*Project, error) {
	project, err := s.getProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	ok, err := s.isProjectManager(ctx, project, actor)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, apperr.Forbidden("Управлять участниками может админ, лид проекта или его создатель")
	}
	return project, nil
}

// EnsureCanEditProject — карточку проекта правят те же роли, что и состав команды.
func (s *Service) EnsureCanEditProject(ctx context.Context, projectID int32, actor Actor) (*Project, error) {
	project, err := s.getProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	ok, err := s.isProjectManager(ctx, project, actor)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, apperr.Forbidden("Изменять проект может админ, лид проекта или его создатель")
	}
	return project, nil
}

// ─────────────────────────── projects ───────────────────────────

// ListProjects — список проектов с учётом доступа и опционального фильтра статуса.
// statusFilter приходит с http в нижнем регистре; приводим к БД-регистру.
// ProjectsByIDs возвращает проекты по набору id (для agent /api/v2).
func (s *Service) ProjectsByIDs(ctx context.Context, ids []int32) ([]Project, error) {
	if len(ids) == 0 {
		return []Project{}, nil
	}
	return s.store.ProjectsByIDs(ctx, ids)
}

// AllProjectIDs возвращает id всех проектов (для agent /api/v2 all_projects+admin).
func (s *Service) AllProjectIDs(ctx context.Context) ([]int32, error) {
	return s.store.AllProjectIDs(ctx)
}

func (s *Service) ListProjects(ctx context.Context, actor Actor, page, size int, statusFilter string) ([]Project, int64, error) {
	status := ""
	if statusFilter != "" {
		status = strings.ToUpper(statusFilter)
		if !validStatuses[status] {
			// Неизвестный статус: как в Python (== по несуществующему значению) — пусто.
			return []Project{}, 0, nil
		}
	}
	return s.store.ListProjects(ctx, ProjectListParams{
		UserID:  actor.ID,
		IsAdmin: actor.IsAdmin(),
		Status:  status,
		Offset:  int32((page - 1) * size),
		Limit:   int32(size),
	})
}

// CreateProject создаёт проект (статус по умолчанию ACTIVE).
func (s *Service) CreateProject(ctx context.Context, in NewProject, actorID int32, ip string) (*Project, error) {
	if err := validateProjectDates(in.StartDate, in.EndDate); err != nil {
		return nil, err
	}
	in.Folder = strings.TrimSpace(in.Folder)
	in.Status = StatusActive
	in.CreatedBy = actorID
	project, err := s.store.InsertProject(ctx, in)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "CREATE", EntityType: "project", EntityID: &project.ID, IPAddress: ip})
	// TODO(phase2): ws broadcast projects index (created)
	return project, nil
}

// UpdateProject обновляет карточку проекта (partial), с логикой timeline_frozen_at и
// уведомлениями при смене статуса.
func (s *Service) UpdateProject(ctx context.Context, projectID int32, in UpdateInput, actorID int32, ip string) (*Project, error) {
	project, err := s.getProject(ctx, projectID)
	if err != nil {
		return nil, err
	}

	up := ProjectUpdate{
		ID:               project.ID,
		Name:             project.Name,
		Folder:           project.Folder,
		Description:      project.Description,
		StartDate:        project.StartDate,
		EndDate:          project.EndDate,
		Status:           project.Status,
		TimelineFrozenAt: project.TimelineFrozenAt,
	}
	if in.Name != nil {
		up.Name = *in.Name
	}
	if in.Folder != nil {
		up.Folder = strings.TrimSpace(*in.Folder)
	}
	if in.Description != nil {
		up.Description = in.Description
	}
	if in.StartDate != nil {
		up.StartDate = in.StartDate
	}
	if in.EndDate != nil {
		up.EndDate = in.EndDate
	}
	if err := validateProjectDates(up.StartDate, up.EndDate); err != nil {
		return nil, err
	}

	oldStatus := project.Status
	statusChanged := false
	if in.Status != nil {
		next := *in.Status
		up.Status = next
		statusChanged = next != oldStatus
		switch {
		case next == StatusActive:
			up.TimelineFrozenAt = nil
		case oldStatus == StatusActive:
			now := s.now().UTC()
			up.TimelineFrozenAt = &now
		default:
			up.TimelineFrozenAt = project.TimelineFrozenAt
		}
	}

	updated, err := s.store.UpdateProject(ctx, up)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "UPDATE", EntityType: "project", EntityID: &updated.ID, IPAddress: ip})
	// TODO(phase2): ws broadcast (project + projects index, updated)

	if statusChanged {
		s.audit(ctx, AuditEntry{
			UserID:     &actorID,
			Action:     "STATUS_CHANGE",
			EntityType: "project",
			EntityID:   &updated.ID,
			Details:    mustJSON(map[string]any{"old_status": strings.ToLower(oldStatus), "new_status": strings.ToLower(updated.Status)}),
			IPAddress:  ip,
		})
		if err := s.notifyProjectStatusChanged(ctx, updated, actorID); err != nil {
			return nil, err
		}
	}
	return updated, nil
}

// notifyProjectStatusChanged — повод №4: статус проекта изменился (участникам, кроме актора).
func (s *Service) notifyProjectStatusChanged(ctx context.Context, project *Project, actorID int32) error {
	memberIDs, err := s.store.ListProjectMemberIDs(ctx, project.ID)
	if err != nil {
		return err
	}
	statusValue := strings.ToLower(project.Status)
	pid := project.ID
	aid := actorID
	for _, uid := range memberIDs {
		if uid == actorID {
			continue
		}
		if err := s.store.InsertNotification(ctx, Notification{
			UserID:    uid,
			Type:      NotificationProjectStatusChanged,
			ProjectID: &pid,
			ActorID:   &aid,
			Status:    statusValue,
		}); err != nil {
			return err
		}
		// TODO(phase2): ws notify_user (notification)
	}
	return nil
}

// DeleteProject удаляет проект (только админ — проверяется в http).
func (s *Service) DeleteProject(ctx context.Context, projectID, actorID int32, ip string) error {
	project, err := s.getProject(ctx, projectID)
	if err != nil {
		return err
	}
	if err := s.store.DeleteProject(ctx, project.ID); err != nil {
		return err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "DELETE", EntityType: "project", EntityID: &projectID, IPAddress: ip})
	// TODO(phase2): ws broadcast (project + projects index, deleted)
	return nil
}

// ProjectStats — счётчики по каждому доступному проекту.
func (s *Service) ProjectStats(ctx context.Context, actor Actor) ([]ProjectStat, error) {
	return s.store.ProjectStats(ctx, actor.ID, actor.IsAdmin())
}

// ─────────────────────────── members ───────────────────────────

// ListMembers — участники проекта.
func (s *Service) ListMembers(ctx context.Context, projectID int32) ([]MemberDetail, error) {
	return s.store.ListMembers(ctx, projectID)
}

// AddMember добавляет участника (повод №2 — уведомление добавленному).
func (s *Service) AddMember(ctx context.Context, projectID, userID, actorID int32, ip string) (*AddMemberResult, error) {
	if _, err := s.getProject(ctx, projectID); err != nil {
		return nil, err
	}
	user, err := s.store.GetUserBrief(ctx, userID)
	if errors.Is(err, ErrNoRows) {
		return nil, apperr.NotFound("User not found")
	}
	if err != nil {
		return nil, err
	}
	if _, found, err := s.store.GetMember(ctx, projectID, userID); err != nil {
		return nil, err
	} else if found {
		return nil, apperr.Conflict("Пользователь уже участник проекта")
	}
	memberID, addedAt, err := s.store.InsertMember(ctx, projectID, userID)
	if err != nil {
		return nil, err
	}
	if userID != actorID {
		pid := projectID
		aid := actorID
		if err := s.store.InsertNotification(ctx, Notification{
			UserID:    userID,
			Type:      NotificationProjectMemberAdded,
			ProjectID: &pid,
			ActorID:   &aid,
		}); err != nil {
			return nil, err
		}
		// TODO(phase2): ws notify_user (notification)
	}
	s.audit(ctx, AuditEntry{
		UserID:     &actorID,
		Action:     "CREATE",
		EntityType: "project_member",
		EntityID:   &memberID,
		Details:    mustJSON(map[string]any{"project_id": strconv.Itoa(int(projectID)), "username": user.Username}),
		IPAddress:  ip,
	})
	return &AddMemberResult{
		UserID:      user.ID,
		Username:    user.Username,
		ProjectRole: user.ProjectRole,
		AddedAt:     addedAt,
	}, nil
}

// RemoveMember удаляет участника.
func (s *Service) RemoveMember(ctx context.Context, projectID, userID, actorID int32, ip string) error {
	memberID, found, err := s.store.GetMember(ctx, projectID, userID)
	if err != nil {
		return err
	}
	if !found {
		return apperr.NotFound("Участник не найден")
	}
	// Имя забираем до удаления — иначе в журнале осталось бы «удалил участника #N».
	var username *string
	if user, err := s.store.GetUserBrief(ctx, userID); err == nil {
		username = &user.Username
	} else if !errors.Is(err, ErrNoRows) {
		return err
	}
	if err := s.store.DeleteMember(ctx, projectID, userID); err != nil {
		return err
	}
	s.audit(ctx, AuditEntry{
		UserID:     &actorID,
		Action:     "DELETE",
		EntityType: "project_member",
		EntityID:   &memberID,
		Details: mustJSON(map[string]any{
			"project_id": strconv.Itoa(int(projectID)),
			"user_id":    strconv.Itoa(int(userID)),
			"username":   username,
		}),
		IPAddress: ip,
	})
	return nil
}

// ─────────────────────────── folders ───────────────────────────

// ListFolders — плоский список папок каталога.
func (s *Service) ListFolders(ctx context.Context) ([]Folder, error) {
	return s.store.ListFolders(ctx)
}

// CreateFolder создаёт папку (в т.ч. вложенную).
func (s *Service) CreateFolder(ctx context.Context, name string, parentID *int32, actorID int32, ip string) (*Folder, error) {
	segment, err := normalizeFolderSegment(name)
	if err != nil {
		return nil, err
	}
	if parentID != nil && *parentID == 0 {
		parentID = nil
	}
	var parent *Folder
	if parentID != nil {
		parent, err = s.store.GetFolderByID(ctx, *parentID)
		if errors.Is(err, ErrNoRows) {
			return nil, apperr.NotFound("Родительская папка не найдена")
		}
		if err != nil {
			return nil, err
		}
	}
	path := segment
	if parent != nil {
		path = parent.Path + "/" + segment
	}
	if _, err := s.store.GetFolderByPath(ctx, path); err == nil {
		return nil, apperr.Conflict("Папка с таким путём уже существует")
	} else if !errors.Is(err, ErrNoRows) {
		return nil, err
	}
	folder, err := s.store.InsertFolder(ctx, segment, path, parentID, actorID)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "CREATE", EntityType: "project_folder", EntityID: &folder.ID, IPAddress: ip})
	// TODO(phase2): ws broadcast projects index (folder created)
	return folder, nil
}

// MoveFolder перемещает папку и пересчитывает пути дочерних папок и проектов.
func (s *Service) MoveFolder(ctx context.Context, folderID int32, newParentID *int32, actorID int32, ip string) (*Folder, error) {
	if newParentID != nil && *newParentID == 0 {
		newParentID = nil
	}
	folder, err := s.store.GetFolderByID(ctx, folderID)
	if errors.Is(err, ErrNoRows) {
		return nil, apperr.NotFound("Папка не найдена")
	}
	if err != nil {
		return nil, err
	}
	if newParentID != nil && *newParentID == folder.ID {
		return nil, apperr.Validation("Нельзя переместить папку в саму себя")
	}
	var newParent *Folder
	if newParentID != nil {
		newParent, err = s.store.GetFolderByID(ctx, *newParentID)
		if errors.Is(err, ErrNoRows) {
			return nil, apperr.NotFound("Родительская папка не найдена")
		}
		if err != nil {
			return nil, err
		}
		if newParent.Path == folder.Path || strings.HasPrefix(newParent.Path, folder.Path+"/") {
			return nil, apperr.Validation("Нельзя переместить папку в её дочернюю папку")
		}
	}
	if dup, err := s.store.FindSiblingFolder(ctx, newParentID, folder.Name, folder.ID); err != nil {
		return nil, err
	} else if dup {
		return nil, apperr.Conflict("В целевой папке уже есть папка с таким именем")
	}

	oldPath := folder.Path
	newPath := folder.Name
	if newParent != nil {
		newPath = newParent.Path + "/" + folder.Name
	}
	if newPath == oldPath && eqInt32Ptr(folder.ParentID, newParentID) {
		return folder, nil
	}

	subFolders, err := s.store.ListSubtreeFolders(ctx, oldPath)
	if err != nil {
		return nil, err
	}
	subProjects, err := s.store.ListSubtreeProjects(ctx, oldPath)
	if err != nil {
		return nil, err
	}
	plan := buildFolderMovePlan(folder, newParentID, oldPath, newPath, subFolders, subProjects)
	if err := s.store.ApplyFolderMove(ctx, plan); err != nil {
		return nil, err
	}
	updated, err := s.store.GetFolderByID(ctx, folderID)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{
		UserID:     &actorID,
		Action:     "UPDATE",
		EntityType: "project_folder",
		EntityID:   &folder.ID,
		Details:    mustJSON(map[string]any{"from": oldPath, "to": newPath}),
		IPAddress:  ip,
	})
	// TODO(phase2): ws broadcast projects index (folder updated)
	return updated, nil
}

// buildFolderMovePlan — чистая логика пересчёта путей поддерева (тестируется напрямую).
func buildFolderMovePlan(folder *Folder, newParentID *int32, oldPath, newPath string, subFolders []Folder, subProjects []Project) FolderMovePlan {
	plan := FolderMovePlan{FolderID: folder.ID, NewParentID: newParentID}
	for _, sf := range subFolders {
		suffix := sf.Path[len(oldPath):]
		upd := FolderPathUpdate{ID: sf.ID, Path: newPath + suffix}
		if sf.ID == folder.ID {
			upd.IsRoot = true
			upd.ParentID = newParentID
		}
		plan.FolderUpdates = append(plan.FolderUpdates, upd)
	}
	for _, pr := range subProjects {
		suffix := pr.Folder[len(oldPath):]
		plan.ProjectMoves = append(plan.ProjectMoves, ProjectFolderMove{ID: pr.ID, Folder: newPath + suffix})
	}
	return plan
}

// DeleteFolder каскадно удаляет папку, подпапки и проекты внутри.
func (s *Service) DeleteFolder(ctx context.Context, folderID, actorID int32, ip string) (*FolderDeleteSummary, error) {
	folder, err := s.store.GetFolderByID(ctx, folderID)
	if errors.Is(err, ErrNoRows) {
		return nil, apperr.NotFound("Папка не найдена")
	}
	if err != nil {
		return nil, err
	}
	df, dp, err := s.store.DeleteFolderCascade(ctx, folder.Path)
	if err != nil {
		return nil, err
	}
	summary := &FolderDeleteSummary{Path: folder.Path, DeletedFolders: df, DeletedProjects: dp}
	s.audit(ctx, AuditEntry{
		UserID:     &actorID,
		Action:     "DELETE",
		EntityType: "project_folder",
		EntityID:   &folderID,
		Details:    mustJSON(map[string]any{"path": summary.Path, "deleted_folders": df, "deleted_projects": dp}),
		IPAddress:  ip,
	})
	// TODO(phase2): ws broadcast projects index (folder deleted)
	return summary, nil
}

// ─────────────────────────── notes ───────────────────────────

// ListNotes — дерево заметок (плоским списком).
func (s *Service) ListNotes(ctx context.Context, projectID int32) ([]Note, error) {
	if _, err := s.ensureProjectNote(ctx, projectID); err != nil {
		return nil, err
	}
	return s.store.ListNotes(ctx, projectID)
}

func (s *Service) ensureProjectNote(ctx context.Context, projectID int32) (*Project, error) {
	// Заметки/креды используют текст ошибки "Проект не найден" (как в services.py).
	return s.getProject(ctx, projectID)
}

func (s *Service) getNote(ctx context.Context, projectID, noteID int32) (*Note, error) {
	note, err := s.store.GetNote(ctx, projectID, noteID)
	if errors.Is(err, ErrNoRows) {
		return nil, apperr.NotFound("Страница заметки не найдена")
	}
	if err != nil {
		return nil, err
	}
	return note, nil
}

// GetNote — страница заметки.
func (s *Service) GetNote(ctx context.Context, projectID, noteID int32) (*Note, error) {
	return s.getNote(ctx, projectID, noteID)
}

func (s *Service) ensureParent(ctx context.Context, projectID int32, parentID *int32) error {
	if parentID == nil || *parentID == 0 {
		return nil
	}
	_, err := s.store.GetNote(ctx, projectID, *parentID)
	if errors.Is(err, ErrNoRows) {
		return apperr.NotFound("Родительская страница не найдена")
	}
	return err
}

func (s *Service) ensureUniqueTitle(ctx context.Context, projectID int32, parentID *int32, title string, excludeID int32) error {
	exists, err := s.store.SiblingTitleExists(ctx, projectID, parentID, title, excludeID)
	if err != nil {
		return err
	}
	if exists {
		return apperr.Conflict("В этом разделе уже есть страница с таким названием")
	}
	return nil
}

func (s *Service) nextSortOrder(ctx context.Context, projectID int32, parentID *int32) (int32, error) {
	max, err := s.store.MaxSiblingSortOrder(ctx, projectID, parentID)
	if err != nil {
		return 0, err
	}
	if max < 0 {
		max = 0
	}
	return max + 1, nil
}

// CreateNote создаёт страницу заметки.
func (s *Service) CreateNote(ctx context.Context, projectID int32, title string, parentID *int32, content *string, actorID int32) (*Note, error) {
	if _, err := s.ensureProjectNote(ctx, projectID); err != nil {
		return nil, err
	}
	title = strings.TrimSpace(title)
	if parentID != nil && *parentID == 0 {
		parentID = nil
	}
	if err := s.ensureParent(ctx, projectID, parentID); err != nil {
		return nil, err
	}
	if err := s.ensureUniqueTitle(ctx, projectID, parentID, title, 0); err != nil {
		return nil, err
	}
	sort, err := s.nextSortOrder(ctx, projectID, parentID)
	if err != nil {
		return nil, err
	}
	inserted, err := s.store.InsertNote(ctx, NewNote{
		ProjectID: projectID,
		ParentID:  parentID,
		Title:     title,
		Content:   content,
		SortOrder: sort,
		CreatedBy: actorID,
	})
	if err != nil {
		return nil, err
	}
	// Перечитываем с JOIN — чтобы вернуть created_by_username (как list/get).
	note, err := s.getNote(ctx, projectID, inserted.ID)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{
		UserID:     &actorID,
		Action:     "CREATE",
		EntityType: "project_note",
		EntityID:   &note.ID,
		Details:    mustJSON(map[string]any{"project_id": strconv.Itoa(int(projectID)), "title": note.Title}),
	})
	// TODO(phase2): ws broadcast (project_note created)
	return note, nil
}

// UpdateNote обновляет заголовок/содержимое заметки.
func (s *Service) UpdateNote(ctx context.Context, projectID, noteID int32, title, content *string, actorID int32) (*Note, error) {
	note, err := s.getNote(ctx, projectID, noteID)
	if err != nil {
		return nil, err
	}
	finalTitle := note.Title
	if title != nil {
		normalized := strings.TrimSpace(*title)
		if normalized != note.Title {
			if err := s.ensureUniqueTitle(ctx, projectID, note.ParentID, normalized, note.ID); err != nil {
				return nil, err
			}
			finalTitle = normalized
		}
	}
	finalContent := note.Content
	if content != nil {
		finalContent = content
	}
	if err := s.store.UpdateNote(ctx, note.ID, finalTitle, finalContent, actorID); err != nil {
		return nil, err
	}
	updated, err := s.getNote(ctx, projectID, noteID)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{
		UserID:     &actorID,
		Action:     "UPDATE",
		EntityType: "project_note",
		EntityID:   &updated.ID,
		Details:    mustJSON(map[string]any{"project_id": strconv.Itoa(int(projectID)), "title": updated.Title}),
	})
	// TODO(phase2): ws broadcast (project_note updated)
	return updated, nil
}

// MoveNote переносит заметку под другого родителя (с защитой от циклов/потомков).
func (s *Service) MoveNote(ctx context.Context, projectID, noteID int32, parentID *int32, actorID int32) (*Note, error) {
	note, err := s.getNote(ctx, projectID, noteID)
	if err != nil {
		return nil, err
	}
	if parentID != nil && *parentID == 0 {
		parentID = nil
	}
	if parentID != nil && *parentID == note.ID {
		return nil, apperr.Validation("Нельзя переместить страницу в саму себя")
	}
	if err := s.ensureParent(ctx, projectID, parentID); err != nil {
		return nil, err
	}
	if err := s.ensureNotDescendantMove(ctx, projectID, note.ID, parentID); err != nil {
		return nil, err
	}
	if err := s.ensureUniqueTitle(ctx, projectID, parentID, note.Title, note.ID); err != nil {
		return nil, err
	}
	sort, err := s.nextSortOrder(ctx, projectID, parentID)
	if err != nil {
		return nil, err
	}
	if err := s.store.MoveNote(ctx, note.ID, parentID, sort, actorID); err != nil {
		return nil, err
	}
	updated, err := s.getNote(ctx, projectID, noteID)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{
		UserID:     &actorID,
		Action:     "UPDATE",
		EntityType: "project_note",
		EntityID:   &updated.ID,
		Details:    mustJSON(map[string]any{"action": "move"}),
	})
	// TODO(phase2): ws broadcast (project_note updated)
	return updated, nil
}

// ensureNotDescendantMove — запрет переноса в собственного потомка/цикл (порт _ensure_not_descendant_move).
func (s *Service) ensureNotDescendantMove(ctx context.Context, projectID, noteID int32, newParentID *int32) error {
	cursor := newParentID
	visited := map[int32]bool{}
	for cursor != nil {
		if *cursor == noteID {
			return apperr.Validation("Нельзя переместить страницу в её дочернюю страницу")
		}
		if visited[*cursor] {
			return apperr.Validation("Обнаружен цикл в дереве заметок")
		}
		visited[*cursor] = true
		parent, err := s.store.GetNoteParentID(ctx, projectID, *cursor)
		if err != nil {
			return err
		}
		cursor = parent
	}
	return nil
}

// ReorderNotes задаёт ручной порядок sibling-страниц (нужен полный набор).
func (s *Service) ReorderNotes(ctx context.Context, projectID int32, parentID *int32, items []ReorderItem, actorID int32) ([]Note, error) {
	if parentID != nil && *parentID == 0 {
		parentID = nil
	}
	if err := s.ensureParent(ctx, projectID, parentID); err != nil {
		return nil, err
	}
	siblings, err := s.store.ListSiblingNotes(ctx, projectID, parentID)
	if err != nil {
		return nil, err
	}
	siblingIDs := map[int32]bool{}
	for _, sib := range siblings {
		siblingIDs[sib.ID] = true
	}
	if len(items) != len(siblingIDs) {
		return nil, apperr.Validation("Для ручной сортировки нужно передать полный набор sibling-страниц")
	}
	itemIDs := map[int32]bool{}
	for _, it := range items {
		itemIDs[it.ID] = true
	}
	for id := range siblingIDs {
		if !itemIDs[id] {
			return nil, apperr.Validation("Для ручной сортировки нужно передать полный набор sibling-страниц")
		}
	}
	if err := s.store.ReorderNotes(ctx, items, actorID); err != nil {
		return nil, err
	}
	var parentStr *string
	if parentID != nil {
		v := strconv.Itoa(int(*parentID))
		parentStr = &v
	}
	s.audit(ctx, AuditEntry{
		UserID:     &actorID,
		Action:     "UPDATE",
		EntityType: "project_note",
		Details:    mustJSON(map[string]any{"action": "reorder", "parent_id": parentStr}),
	})
	// TODO(phase2): ws broadcast (project_note updated)
	return s.store.ListSiblingNotes(ctx, projectID, parentID)
}

// DeleteNote удаляет страницу заметки.
func (s *Service) DeleteNote(ctx context.Context, projectID, noteID, actorID int32) error {
	note, err := s.getNote(ctx, projectID, noteID)
	if err != nil {
		return err
	}
	deletedTitle := note.Title
	if err := s.store.DeleteNote(ctx, note.ID); err != nil {
		return err
	}
	s.audit(ctx, AuditEntry{
		UserID:     &actorID,
		Action:     "DELETE",
		EntityType: "project_note",
		EntityID:   &noteID,
		Details:    mustJSON(map[string]any{"project_id": strconv.Itoa(int(projectID)), "title": deletedTitle}),
	})
	// TODO(phase2): ws broadcast (project_note deleted)
	return nil
}

// ─────────────────────────── note comments ───────────────────────────

// ListNoteComments — комментарии заметки (пагинация).
func (s *Service) ListNoteComments(ctx context.Context, projectID, noteID int32, page, size int) ([]NoteComment, int64, error) {
	if _, err := s.getNote(ctx, projectID, noteID); err != nil {
		return nil, 0, err
	}
	total, err := s.store.CountNoteComments(ctx, projectID, noteID)
	if err != nil {
		return nil, 0, err
	}
	items, err := s.store.ListNoteComments(ctx, projectID, noteID, int32((page-1)*size), int32(size))
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

func (s *Service) getNoteComment(ctx context.Context, projectID, noteID, commentID int32) (*NoteComment, error) {
	c, err := s.store.GetNoteComment(ctx, projectID, noteID, commentID)
	if errors.Is(err, ErrNoRows) {
		return nil, apperr.NotFound("Комментарий не найден")
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// CreateNoteComment добавляет комментарий и создаёт MENTION-уведомления (кроме себя).
func (s *Service) CreateNoteComment(ctx context.Context, projectID, noteID int32, content string, actor Actor) (*NoteComment, error) {
	note, err := s.getNote(ctx, projectID, noteID)
	if err != nil {
		return nil, err
	}
	comment, err := s.store.InsertNoteComment(ctx, projectID, note.ID, actor.ID, content)
	if err != nil {
		return nil, err
	}
	mentioned, err := s.resolveMentions(ctx, projectID, content, actor.ID)
	if err != nil {
		return nil, err
	}
	cid := comment.ID
	aid := actor.ID
	for _, u := range mentioned {
		if err := s.store.InsertNotification(ctx, Notification{
			UserID:        u.ID,
			Type:          NotificationMention,
			NoteCommentID: &cid,
			ActorID:       &aid,
		}); err != nil {
			return nil, err
		}
		// TODO(phase2): ws notify_user (notification)
	}
	s.audit(ctx, AuditEntry{UserID: &actor.ID, Action: "CREATE", EntityType: "project_note_comment", EntityID: &comment.ID})
	// TODO(phase2): ws broadcast (project_note_comment created)
	comment.Username = actor.Username
	return comment, nil
}

// resolveMentions извлекает @упоминания и резолвит их в пользователей (кроме автора).
func (s *Service) resolveMentions(ctx context.Context, projectID int32, content string, actorID int32) ([]UserBrief, error) {
	usernames := extractMentions(content)
	if len(usernames) == 0 {
		return nil, nil
	}
	users, err := s.store.ResolveMentionUsers(ctx, projectID, usernames)
	if err != nil {
		return nil, err
	}
	out := make([]UserBrief, 0, len(users))
	for _, u := range users {
		if u.ID != actorID {
			out = append(out, u)
		}
	}
	return out, nil
}

// extractMentions — уникальные username из @упоминаний (порт set(MENTION_RE.findall)).
func extractMentions(content string) []string {
	matches := mentionRe.FindAllStringSubmatch(content, -1)
	seen := map[string]bool{}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		name := m[1]
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// UpdateNoteComment редактирует свой комментарий.
func (s *Service) UpdateNoteComment(ctx context.Context, projectID, noteID, commentID int32, content string, actor Actor) (*NoteComment, error) {
	comment, err := s.getNoteComment(ctx, projectID, noteID, commentID)
	if err != nil {
		return nil, err
	}
	if comment.UserID != actor.ID {
		return nil, apperr.Forbidden("Можно редактировать только свой комментарий")
	}
	if err := s.store.UpdateNoteComment(ctx, comment.ID, content); err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &actor.ID, Action: "UPDATE", EntityType: "project_note_comment", EntityID: &comment.ID})
	// TODO(phase2): ws broadcast (project_note_comment updated)
	comment.Content = content
	comment.Username = actor.Username
	return comment, nil
}

// DeleteNoteComment удаляет свой комментарий.
func (s *Service) DeleteNoteComment(ctx context.Context, projectID, noteID, commentID int32, actor Actor) error {
	comment, err := s.getNoteComment(ctx, projectID, noteID, commentID)
	if err != nil {
		return err
	}
	if comment.UserID != actor.ID {
		return apperr.Forbidden("Можно удалить только свой комментарий")
	}
	if err := s.store.DeleteNoteComment(ctx, comment.ID); err != nil {
		return err
	}
	s.audit(ctx, AuditEntry{UserID: &actor.ID, Action: "DELETE", EntityType: "project_note_comment", EntityID: &comment.ID})
	// TODO(phase2): ws broadcast (project_note_comment deleted)
	return nil
}

// ─────────────────────────── credentials ───────────────────────────

// ListCredentials — учётные данные проекта (с расшифрованным паролем).
func (s *Service) ListCredentials(ctx context.Context, projectID int32) ([]Credential, error) {
	if _, err := s.ensureProjectNote(ctx, projectID); err != nil {
		return nil, err
	}
	creds, err := s.store.ListCredentials(ctx, projectID)
	if err != nil {
		return nil, err
	}
	for i := range creds {
		if err := s.decryptCredential(&creds[i]); err != nil {
			return nil, err
		}
	}
	return creds, nil
}

func (s *Service) decryptCredential(c *Credential) error {
	plain, err := s.cipher.Decrypt(c.Password)
	if err != nil {
		return err
	}
	c.Password = plain
	return nil
}

// CreateCredential создаёт учётные данные (пароль шифруется).
func (s *Service) CreateCredential(ctx context.Context, projectID int32, username, host *string, password string, actor Actor) (*Credential, error) {
	if _, err := s.ensureProjectNote(ctx, projectID); err != nil {
		return nil, err
	}
	enc, err := s.cipher.Encrypt(password)
	if err != nil {
		return nil, err
	}
	id, err := s.store.InsertCredential(ctx, NewCredential{
		ProjectID:         projectID,
		Username:          username,
		PasswordEncrypted: enc,
		Host:              host,
		CreatedBy:         actor.ID,
	})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{
		UserID:     &actor.ID,
		Action:     "CREATE",
		EntityType: "project_credential",
		EntityID:   &id,
		Details:    mustJSON(map[string]any{"project_id": strconv.Itoa(int(projectID)), "username": username, "host": host}),
	})
	uname := actor.Username
	now := s.now().UTC()
	return &Credential{
		ID:                id,
		ProjectID:         projectID,
		Username:          username,
		Password:          password,
		Host:              host,
		CreatedBy:         actor.ID,
		CreatedByUsername: &uname,
		CreatedAt:         now,
		UpdatedAt:         now,
	}, nil
}

// UpdateCredential правит креды; пустой/отсутствующий пароль означает «не менять».
func (s *Service) UpdateCredential(ctx context.Context, projectID, credentialID int32, username, host, password *string, actor Actor) (*Credential, error) {
	cred, err := s.getCredential(ctx, projectID, credentialID)
	if err != nil {
		return nil, err
	}
	if username != nil {
		cred.Username = username
	}
	if host != nil {
		cred.Host = host
	}
	enc := cred.Password // ciphertext из GetCredential
	if password != nil && *password != "" {
		enc, err = s.cipher.Encrypt(*password)
		if err != nil {
			return nil, err
		}
	}
	if err := s.store.UpdateCredential(ctx, cred.ID, cred.Username, enc, cred.Host); err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{
		UserID:     &actor.ID,
		Action:     "UPDATE",
		EntityType: "project_credential",
		EntityID:   &cred.ID,
		Details:    mustJSON(map[string]any{"project_id": strconv.Itoa(int(projectID)), "username": cred.Username, "host": cred.Host}),
	})
	plain, err := s.cipher.Decrypt(enc)
	if err != nil {
		return nil, err
	}
	cred.Password = plain
	return cred, nil
}

func (s *Service) getCredential(ctx context.Context, projectID, credentialID int32) (*Credential, error) {
	cred, err := s.store.GetCredential(ctx, projectID, credentialID)
	if errors.Is(err, ErrNoRows) {
		return nil, apperr.NotFound("Учётные данные не найдены")
	}
	if err != nil {
		return nil, err
	}
	return cred, nil
}

// DeleteCredential удаляет учётные данные.
func (s *Service) DeleteCredential(ctx context.Context, projectID, credentialID int32, actor Actor) error {
	cred, err := s.getCredential(ctx, projectID, credentialID)
	if err != nil {
		return err
	}
	if err := s.store.DeleteCredential(ctx, cred.ID); err != nil {
		return err
	}
	s.audit(ctx, AuditEntry{
		UserID:     &actor.ID,
		Action:     "DELETE",
		EntityType: "project_credential",
		EntityID:   &credentialID,
		Details:    mustJSON(map[string]any{"project_id": strconv.Itoa(int(projectID)), "username": cred.Username, "host": cred.Host}),
	})
	return nil
}

// ─────────────────────────── hidden ips ───────────────────────────

// ListHiddenIPs — адреса, скрытые из вкладки IP проекта.
func (s *Service) ListHiddenIPs(ctx context.Context, projectID int32) ([]string, error) {
	return s.store.ListHiddenIPs(ctx, projectID)
}

// HideIP «удаляет» адрес из списка IP: сносит отдельные IP-хосты и скрывает адрес.
func (s *Service) HideIP(ctx context.Context, projectID int32, ipAddress string, actorID int32) error {
	ip := strings.TrimSpace(ipAddress)
	if ip == "" {
		return apperr.Validation("Не указан IP-адрес")
	}
	if err := s.store.HideIP(ctx, projectID, ip, actorID); err != nil {
		return err
	}
	s.audit(ctx, AuditEntry{
		UserID:     &actorID,
		Action:     "DELETE",
		EntityType: "ip_address",
		Details:    mustJSON(map[string]any{"project_id": strconv.Itoa(int(projectID)), "ip_address": ip}),
	})
	// TODO(phase2): ws broadcast (host deleted)
	return nil
}

// UnhideIP снимает адрес со скрытия.
func (s *Service) UnhideIP(ctx context.Context, projectID int32, ipAddress string, actorID int32) error {
	ip := strings.TrimSpace(ipAddress)
	if err := s.store.UnhideIP(ctx, projectID, ip); err != nil {
		return err
	}
	s.audit(ctx, AuditEntry{
		UserID:     &actorID,
		Action:     "UPDATE",
		EntityType: "ip_address",
		Details:    mustJSON(map[string]any{"project_id": strconv.Itoa(int(projectID)), "ip_address": ip, "unhidden": true}),
	})
	// TODO(phase2): ws broadcast (host updated)
	return nil
}

// ─────────────────────────── activity ───────────────────────────

// ListProjectActivity — активность по всем сущностям проекта (обогащается уязвимостями).
func (s *Service) ListProjectActivity(ctx context.Context, projectID int32, limit int) ([]ActivityItem, error) {
	if _, err := s.getProject(ctx, projectID); err != nil {
		return nil, err
	}
	items, err := s.store.ListProjectActivity(ctx, projectID, int32(limit))
	if err != nil {
		return nil, err
	}
	var vulnIDs []int32
	for _, it := range items {
		if it.EntityType != nil && *it.EntityType == "vulnerability" && it.EntityID != nil {
			vulnIDs = append(vulnIDs, *it.EntityID)
		}
	}
	byID := map[int32]VulnBrief{}
	if len(vulnIDs) > 0 {
		vulns, err := s.store.VulnsByIDs(ctx, vulnIDs)
		if err != nil {
			return nil, err
		}
		for _, v := range vulns {
			byID[v.ID] = v
		}
	}
	for i := range items {
		it := &items[i]
		if it.EntityType != nil && *it.EntityType == "vulnerability" && it.EntityID != nil {
			if v, ok := byID[*it.EntityID]; ok {
				title := v.Title
				sev := strings.ToLower(v.Severity)
				url := "/projects/" + strconv.Itoa(int(projectID)) + "/vulns/" + strconv.Itoa(int(v.ID))
				it.Title = &title
				it.Severity = &sev
				it.URL = &url
			}
		}
	}
	return items, nil
}

// ListNotesActivity — журнал действий с заметками проекта.
func (s *Service) ListNotesActivity(ctx context.Context, projectID int32, limit int) ([]NotesActivityItem, error) {
	if _, err := s.ensureProjectNote(ctx, projectID); err != nil {
		return nil, err
	}
	return s.store.ListNotesActivity(ctx, projectID, int32(limit))
}

// ─────────────────────────── helpers ───────────────────────────

func (s *Service) audit(ctx context.Context, e AuditEntry) {
	_ = s.store.InsertAudit(ctx, e)
}

func validateProjectDates(start, end *time.Time) error {
	if start != nil && end != nil && end.Before(*start) {
		return apperr.Validation("Дата окончания проекта не может быть раньше даты начала")
	}
	return nil
}

func normalizeFolderSegment(name string) (string, error) {
	normalized := strings.Trim(strings.TrimSpace(name), "/")
	if normalized == "" {
		return "", apperr.Validation("Название папки не может быть пустым")
	}
	if strings.Contains(normalized, "/") {
		return "", apperr.Validation("Название папки не должно содержать '/'")
	}
	return normalized, nil
}

func eqInt32Ptr(a, b *int32) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}
