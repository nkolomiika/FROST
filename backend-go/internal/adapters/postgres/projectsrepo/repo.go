// Package projectsrepo — реализация порта projects.Store поверх sqlc + pgxpool.
// Компаундные операции (перемещение/удаление папки, скрытие IP, reorder заметок)
// выполняются в транзакции через r.tx.
package projectsrepo

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nkolomiika/frost/internal/adapters/postgres/pgconv"
	"github.com/nkolomiika/frost/internal/adapters/postgres/sqlc"
	"github.com/nkolomiika/frost/internal/app/projects"
)

// Repo реализует projects.Store.
type Repo struct {
	pool *pgxpool.Pool
	q    *sqlc.Queries
}

// New создаёт репозиторий поверх пула соединений.
func New(pool *pgxpool.Pool) *Repo {
	return &Repo{pool: pool, q: sqlc.New(pool)}
}

var _ projects.Store = (*Repo)(nil)

func (r *Repo) tx(ctx context.Context, fn func(q *sqlc.Queries) error) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(r.q.WithTx(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func mapErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return projects.ErrNoRows
	}
	return err
}

// ─────────────────────────── projects ───────────────────────────

func mapProject(p sqlc.Project) *projects.Project {
	return &projects.Project{
		ID:               p.ID,
		Name:             p.Name,
		Folder:           p.Folder,
		Description:      pgconv.TextValPtr(p.Description),
		StartDate:        dateValPtr(p.StartDate),
		EndDate:          dateValPtr(p.EndDate),
		TimelineFrozenAt: pgconv.TsValPtr(p.TimelineFrozenAt),
		Status:           string(p.Status),
		CreatedBy:        p.CreatedBy,
		CreatedAt:        pgconv.TsVal(p.CreatedAt),
		UpdatedAt:        pgconv.TsVal(p.UpdatedAt),
	}
}

func nullStatus(status string) sqlc.NullProjectStatus {
	if status == "" {
		return sqlc.NullProjectStatus{}
	}
	return sqlc.NullProjectStatus{ProjectStatus: sqlc.ProjectStatus(status), Valid: true}
}

func (r *Repo) ListProjects(ctx context.Context, p projects.ProjectListParams) ([]projects.Project, int64, error) {
	status := nullStatus(p.Status)
	var rows []sqlc.Project
	var total int64
	var err error
	if p.IsAdmin {
		rows, err = r.q.ListProjectsAdmin(ctx, sqlc.ListProjectsAdminParams{Status: status, Offset: p.Offset, Lim: p.Limit})
		if err != nil {
			return nil, 0, err
		}
		total, err = r.q.CountProjectsAdmin(ctx, status)
	} else {
		rows, err = r.q.ListProjectsForMember(ctx, sqlc.ListProjectsForMemberParams{UserID: p.UserID, Status: status, Offset: p.Offset, Lim: p.Limit})
		if err != nil {
			return nil, 0, err
		}
		total, err = r.q.CountProjectsForMember(ctx, sqlc.CountProjectsForMemberParams{UserID: p.UserID, Status: status})
	}
	if err != nil {
		return nil, 0, err
	}
	out := make([]projects.Project, 0, len(rows))
	for _, row := range rows {
		out = append(out, *mapProject(row))
	}
	return out, total, nil
}

func (r *Repo) GetProject(ctx context.Context, id int32) (*projects.Project, error) {
	p, err := r.q.GetProjectByID(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	return mapProject(p), nil
}

func (r *Repo) ProjectsByIDs(ctx context.Context, ids []int32) ([]projects.Project, error) {
	rows, err := r.q.ListProjectsByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make([]projects.Project, 0, len(rows))
	for _, row := range rows {
		out = append(out, *mapProject(row))
	}
	return out, nil
}

func (r *Repo) AllProjectIDs(ctx context.Context) ([]int32, error) {
	return r.q.ListAllProjectIDs(ctx)
}

func (r *Repo) InsertProject(ctx context.Context, np projects.NewProject) (*projects.Project, error) {
	p, err := r.q.InsertProject(ctx, sqlc.InsertProjectParams{
		Name:        np.Name,
		Folder:      np.Folder,
		Description: pgconv.TextPtr(np.Description),
		StartDate:   toDate(np.StartDate),
		EndDate:     toDate(np.EndDate),
		Status:      sqlc.ProjectStatus(np.Status),
		CreatedBy:   np.CreatedBy,
	})
	if err != nil {
		return nil, err
	}
	return mapProject(p), nil
}

func (r *Repo) UpdateProject(ctx context.Context, up projects.ProjectUpdate) (*projects.Project, error) {
	p, err := r.q.UpdateProject(ctx, sqlc.UpdateProjectParams{
		ID:               up.ID,
		Name:             up.Name,
		Folder:           up.Folder,
		Description:      pgconv.TextPtr(up.Description),
		StartDate:        toDate(up.StartDate),
		EndDate:          toDate(up.EndDate),
		Status:           sqlc.ProjectStatus(up.Status),
		TimelineFrozenAt: pgconv.TsPtr(up.TimelineFrozenAt),
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return mapProject(p), nil
}

func (r *Repo) DeleteProject(ctx context.Context, id int32) error {
	return r.q.DeleteProject(ctx, id)
}

func (r *Repo) IsProjectMember(ctx context.Context, projectID, userID int32) (bool, error) {
	return r.q.IsProjectMember(ctx, sqlc.IsProjectMemberParams{ProjectID: projectID, UserID: userID})
}

func (r *Repo) ProjectStats(ctx context.Context, userID int32, isAdmin bool) ([]projects.ProjectStat, error) {
	out := []projects.ProjectStat{}
	if isAdmin {
		rows, err := r.q.ProjectStatsAdmin(ctx)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			out = append(out, projects.ProjectStat{
				ProjectID: row.ProjectID, Status: string(row.Status),
				HostsCount: row.HostsCount, TotalFindings: row.TotalFindings, OpenFindings: row.OpenFindings,
			})
		}
		return out, nil
	}
	rows, err := r.q.ProjectStatsForMember(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out = append(out, projects.ProjectStat{
			ProjectID: row.ProjectID, Status: string(row.Status),
			HostsCount: row.HostsCount, TotalFindings: row.TotalFindings, OpenFindings: row.OpenFindings,
		})
	}
	return out, nil
}

func (r *Repo) ListProjectMemberIDs(ctx context.Context, projectID int32) ([]int32, error) {
	return r.q.ListMemberUserIDs(ctx, projectID)
}

func (r *Repo) GetUserBrief(ctx context.Context, id int32) (*projects.UserBrief, error) {
	u, err := r.q.GetUserByID(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	return &projects.UserBrief{ID: u.ID, Username: u.Username, Role: string(u.Role), ProjectRole: string(u.ProjectRole)}, nil
}

// ─────────────────────────── members ───────────────────────────

func (r *Repo) ListMembers(ctx context.Context, projectID int32) ([]projects.MemberDetail, error) {
	rows, err := r.q.ListMembers(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]projects.MemberDetail, 0, len(rows))
	for _, row := range rows {
		out = append(out, projects.MemberDetail{
			UserID:      row.UserID,
			Username:    row.Username,
			Email:       row.Email,
			Role:        string(row.Role),
			ProjectRole: string(row.ProjectRole),
			AddedAt:     pgconv.TsVal(row.AddedAt),
		})
	}
	return out, nil
}

func (r *Repo) GetMember(ctx context.Context, projectID, userID int32) (int32, bool, error) {
	m, err := r.q.GetMember(ctx, sqlc.GetMemberParams{ProjectID: projectID, UserID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return m.ID, true, nil
}

func (r *Repo) InsertMember(ctx context.Context, projectID, userID int32) (int32, time.Time, error) {
	m, err := r.q.InsertMember(ctx, sqlc.InsertMemberParams{ProjectID: projectID, UserID: userID})
	if err != nil {
		return 0, time.Time{}, err
	}
	return m.ID, pgconv.TsVal(m.AddedAt), nil
}

func (r *Repo) DeleteMember(ctx context.Context, projectID, userID int32) error {
	return r.q.DeleteMember(ctx, sqlc.DeleteMemberParams{ProjectID: projectID, UserID: userID})
}

// ─────────────────────────── folders ───────────────────────────

func mapFolder(f sqlc.ProjectFolder) *projects.Folder {
	return &projects.Folder{
		ID:        f.ID,
		Name:      f.Name,
		Path:      f.Path,
		ParentID:  pgconv.Int4Val(f.ParentID),
		CreatedBy: f.CreatedBy,
		CreatedAt: pgconv.TsVal(f.CreatedAt),
		UpdatedAt: pgconv.TsVal(f.UpdatedAt),
	}
}

func (r *Repo) ListFolders(ctx context.Context) ([]projects.Folder, error) {
	rows, err := r.q.ListFolders(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]projects.Folder, 0, len(rows))
	for _, row := range rows {
		out = append(out, *mapFolder(row))
	}
	return out, nil
}

func (r *Repo) GetFolderByID(ctx context.Context, id int32) (*projects.Folder, error) {
	f, err := r.q.GetFolderByID(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	return mapFolder(f), nil
}

func (r *Repo) GetFolderByPath(ctx context.Context, path string) (*projects.Folder, error) {
	f, err := r.q.GetFolderByPath(ctx, path)
	if err != nil {
		return nil, mapErr(err)
	}
	return mapFolder(f), nil
}

func (r *Repo) FindSiblingFolder(ctx context.Context, parentID *int32, name string, excludeID int32) (bool, error) {
	_, err := r.q.FindSiblingFolderByName(ctx, sqlc.FindSiblingFolderByNameParams{
		ParentID: pgconv.Int4(parentID), Name: name, ExcludeID: excludeID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (r *Repo) InsertFolder(ctx context.Context, name, path string, parentID *int32, createdBy int32) (*projects.Folder, error) {
	f, err := r.q.InsertFolder(ctx, sqlc.InsertFolderParams{
		Name: name, Path: path, ParentID: pgconv.Int4(parentID), CreatedBy: createdBy,
	})
	if err != nil {
		return nil, err
	}
	return mapFolder(f), nil
}

func (r *Repo) ListSubtreeFolders(ctx context.Context, path string) ([]projects.Folder, error) {
	rows, err := r.q.ListSubtreeFolders(ctx, path)
	if err != nil {
		return nil, err
	}
	out := make([]projects.Folder, 0, len(rows))
	for _, row := range rows {
		out = append(out, *mapFolder(row))
	}
	return out, nil
}

func (r *Repo) ListSubtreeProjects(ctx context.Context, folder string) ([]projects.Project, error) {
	rows, err := r.q.ListSubtreeProjects(ctx, folder)
	if err != nil {
		return nil, err
	}
	out := make([]projects.Project, 0, len(rows))
	for _, row := range rows {
		out = append(out, *mapProject(row))
	}
	return out, nil
}

func (r *Repo) ApplyFolderMove(ctx context.Context, plan projects.FolderMovePlan) error {
	return r.tx(ctx, func(q *sqlc.Queries) error {
		for _, fu := range plan.FolderUpdates {
			if fu.IsRoot {
				if err := q.UpdateFolderPathParent(ctx, sqlc.UpdateFolderPathParentParams{
					ID: fu.ID, Path: fu.Path, ParentID: pgconv.Int4(fu.ParentID),
				}); err != nil {
					return err
				}
				continue
			}
			if err := q.UpdateFolderPath(ctx, sqlc.UpdateFolderPathParams{ID: fu.ID, Path: fu.Path}); err != nil {
				return err
			}
		}
		for _, pm := range plan.ProjectMoves {
			if err := q.UpdateProjectFolderPath(ctx, sqlc.UpdateProjectFolderPathParams{ID: pm.ID, Folder: pm.Folder}); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *Repo) DeleteFolderCascade(ctx context.Context, path string) (int, int, error) {
	subProjects, err := r.q.ListSubtreeProjects(ctx, path)
	if err != nil {
		return 0, 0, err
	}
	subFolders, err := r.q.ListSubtreeFolders(ctx, path)
	if err != nil {
		return 0, 0, err
	}
	err = r.tx(ctx, func(q *sqlc.Queries) error {
		if err := q.DeleteSubtreeProjects(ctx, path); err != nil {
			return err
		}
		return q.DeleteSubtreeFolders(ctx, path)
	})
	if err != nil {
		return 0, 0, err
	}
	return len(subFolders), len(subProjects), nil
}

// ─────────────────────────── notes ───────────────────────────

func mapNoteFull(id, projectID int32, parentID pgtype.Int4, title string, content pgtype.Text, sortOrder, createdBy int32, updatedBy pgtype.Int4, createdAt, updatedAt pgtype.Timestamptz, username pgtype.Text) *projects.Note {
	return &projects.Note{
		ID:                id,
		ProjectID:         projectID,
		ParentID:          pgconv.Int4Val(parentID),
		Title:             title,
		Content:           pgconv.TextValPtr(content),
		SortOrder:         sortOrder,
		CreatedBy:         createdBy,
		UpdatedBy:         pgconv.Int4Val(updatedBy),
		CreatedByUsername: pgconv.TextValPtr(username),
		CreatedAt:         pgconv.TsVal(createdAt),
		UpdatedAt:         pgconv.TsVal(updatedAt),
	}
}

func (r *Repo) ListNotes(ctx context.Context, projectID int32) ([]projects.Note, error) {
	rows, err := r.q.ListNotes(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]projects.Note, 0, len(rows))
	for _, n := range rows {
		out = append(out, *mapNoteFull(n.ID, n.ProjectID, n.ParentID, n.Title, n.Content, n.SortOrder, n.CreatedBy, n.UpdatedBy, n.CreatedAt, n.UpdatedAt, n.CreatedByUsername))
	}
	return out, nil
}

func (r *Repo) GetNote(ctx context.Context, projectID, noteID int32) (*projects.Note, error) {
	n, err := r.q.GetNote(ctx, sqlc.GetNoteParams{ID: noteID, ProjectID: projectID})
	if err != nil {
		return nil, mapErr(err)
	}
	return mapNoteFull(n.ID, n.ProjectID, n.ParentID, n.Title, n.Content, n.SortOrder, n.CreatedBy, n.UpdatedBy, n.CreatedAt, n.UpdatedAt, n.CreatedByUsername), nil
}

func (r *Repo) GetNoteParentID(ctx context.Context, projectID, noteID int32) (*int32, error) {
	n, err := r.q.GetNote(ctx, sqlc.GetNoteParams{ID: noteID, ProjectID: projectID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pgconv.Int4Val(n.ParentID), nil
}

func (r *Repo) SiblingTitleExists(ctx context.Context, projectID int32, parentID *int32, title string, excludeID int32) (bool, error) {
	_, err := r.q.FindSiblingNoteTitle(ctx, sqlc.FindSiblingNoteTitleParams{
		ProjectID: projectID, ParentID: pgconv.Int4(parentID), Title: title, ExcludeID: excludeID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (r *Repo) MaxSiblingSortOrder(ctx context.Context, projectID int32, parentID *int32) (int32, error) {
	return r.q.MaxSiblingSortOrder(ctx, sqlc.MaxSiblingSortOrderParams{ProjectID: projectID, ParentID: pgconv.Int4(parentID)})
}

func (r *Repo) ListSiblingNotes(ctx context.Context, projectID int32, parentID *int32) ([]projects.Note, error) {
	rows, err := r.q.ListSiblingNotes(ctx, sqlc.ListSiblingNotesParams{ProjectID: projectID, ParentID: pgconv.Int4(parentID)})
	if err != nil {
		return nil, err
	}
	out := make([]projects.Note, 0, len(rows))
	for _, n := range rows {
		out = append(out, *mapNoteFull(n.ID, n.ProjectID, n.ParentID, n.Title, n.Content, n.SortOrder, n.CreatedBy, n.UpdatedBy, n.CreatedAt, n.UpdatedAt, n.CreatedByUsername))
	}
	return out, nil
}

func (r *Repo) InsertNote(ctx context.Context, nn projects.NewNote) (*projects.Note, error) {
	n, err := r.q.InsertNote(ctx, sqlc.InsertNoteParams{
		ProjectID: nn.ProjectID,
		ParentID:  pgconv.Int4(nn.ParentID),
		Title:     nn.Title,
		Content:   pgconv.TextPtr(nn.Content),
		SortOrder: nn.SortOrder,
		CreatedBy: nn.CreatedBy,
	})
	if err != nil {
		return nil, err
	}
	return mapNoteFull(n.ID, n.ProjectID, n.ParentID, n.Title, n.Content, n.SortOrder, n.CreatedBy, n.UpdatedBy, n.CreatedAt, n.UpdatedAt, pgtype.Text{}), nil
}

func (r *Repo) UpdateNote(ctx context.Context, id int32, title string, content *string, updatedBy int32) error {
	return r.q.UpdateNote(ctx, sqlc.UpdateNoteParams{
		ID: id, Title: title, Content: pgconv.TextPtr(content), UpdatedBy: pgconv.Int4(&updatedBy),
	})
}

func (r *Repo) MoveNote(ctx context.Context, id int32, parentID *int32, sortOrder, updatedBy int32) error {
	return r.q.MoveNote(ctx, sqlc.MoveNoteParams{
		ID: id, ParentID: pgconv.Int4(parentID), SortOrder: sortOrder, UpdatedBy: pgconv.Int4(&updatedBy),
	})
}

func (r *Repo) ReorderNotes(ctx context.Context, items []projects.ReorderItem, updatedBy int32) error {
	return r.tx(ctx, func(q *sqlc.Queries) error {
		for _, it := range items {
			if err := q.SetNoteSortOrder(ctx, sqlc.SetNoteSortOrderParams{
				ID: it.ID, SortOrder: it.SortOrder, UpdatedBy: pgconv.Int4(&updatedBy),
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *Repo) DeleteNote(ctx context.Context, id int32) error {
	return r.q.DeleteNote(ctx, id)
}

// ─────────────────────────── note comments ───────────────────────────

func (r *Repo) CountNoteComments(ctx context.Context, projectID, noteID int32) (int64, error) {
	return r.q.CountNoteComments(ctx, sqlc.CountNoteCommentsParams{ProjectID: projectID, NoteID: noteID})
}

func (r *Repo) ListNoteComments(ctx context.Context, projectID, noteID int32, offset, limit int32) ([]projects.NoteComment, error) {
	rows, err := r.q.ListNoteComments(ctx, sqlc.ListNoteCommentsParams{ProjectID: projectID, NoteID: noteID, Offset: offset, Limit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]projects.NoteComment, 0, len(rows))
	for _, c := range rows {
		out = append(out, projects.NoteComment{
			ID:        c.ID,
			ProjectID: c.ProjectID,
			NoteID:    c.NoteID,
			UserID:    c.UserID,
			Username:  c.Username,
			Content:   c.Content,
			CreatedAt: pgconv.TsVal(c.CreatedAt),
			UpdatedAt: pgconv.TsVal(c.UpdatedAt),
		})
	}
	return out, nil
}

func (r *Repo) GetNoteComment(ctx context.Context, projectID, noteID, commentID int32) (*projects.NoteComment, error) {
	c, err := r.q.GetNoteComment(ctx, sqlc.GetNoteCommentParams{ID: commentID, NoteID: noteID, ProjectID: projectID})
	if err != nil {
		return nil, mapErr(err)
	}
	return &projects.NoteComment{
		ID: c.ID, ProjectID: c.ProjectID, NoteID: c.NoteID, UserID: c.UserID, Content: c.Content,
		CreatedAt: pgconv.TsVal(c.CreatedAt), UpdatedAt: pgconv.TsVal(c.UpdatedAt),
	}, nil
}

func (r *Repo) InsertNoteComment(ctx context.Context, projectID, noteID, userID int32, content string) (*projects.NoteComment, error) {
	c, err := r.q.InsertNoteComment(ctx, sqlc.InsertNoteCommentParams{ProjectID: projectID, NoteID: noteID, UserID: userID, Content: content})
	if err != nil {
		return nil, err
	}
	return &projects.NoteComment{
		ID: c.ID, ProjectID: c.ProjectID, NoteID: c.NoteID, UserID: c.UserID, Content: c.Content,
		CreatedAt: pgconv.TsVal(c.CreatedAt), UpdatedAt: pgconv.TsVal(c.UpdatedAt),
	}, nil
}

func (r *Repo) UpdateNoteComment(ctx context.Context, id int32, content string) error {
	return r.q.UpdateNoteComment(ctx, sqlc.UpdateNoteCommentParams{ID: id, Content: content})
}

func (r *Repo) DeleteNoteComment(ctx context.Context, id int32) error {
	return r.q.DeleteNoteComment(ctx, id)
}

func (r *Repo) ResolveMentionUsers(ctx context.Context, projectID int32, usernames []string) ([]projects.UserBrief, error) {
	rows, err := r.q.ResolveMentionUsers(ctx, sqlc.ResolveMentionUsersParams{ProjectID: projectID, Usernames: usernames})
	if err != nil {
		return nil, err
	}
	out := make([]projects.UserBrief, 0, len(rows))
	for _, u := range rows {
		out = append(out, projects.UserBrief{ID: u.ID, Username: u.Username})
	}
	return out, nil
}

// ─────────────────────────── credentials ───────────────────────────

func (r *Repo) ListCredentials(ctx context.Context, projectID int32) ([]projects.Credential, error) {
	rows, err := r.q.ListCredentials(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]projects.Credential, 0, len(rows))
	for _, c := range rows {
		out = append(out, projects.Credential{
			ID:                c.ID,
			ProjectID:         c.ProjectID,
			Username:          pgconv.TextValPtr(c.Username),
			Password:          c.PasswordEncrypted, // ciphertext; сервис расшифрует
			Host:              pgconv.TextValPtr(c.Host),
			CreatedBy:         c.CreatedBy,
			CreatedByUsername: pgconv.TextValPtr(c.CreatedByUsername),
			CreatedAt:         pgconv.TsVal(c.CreatedAt),
			UpdatedAt:         pgconv.TsVal(c.UpdatedAt),
		})
	}
	return out, nil
}

func (r *Repo) GetCredential(ctx context.Context, projectID, credentialID int32) (*projects.Credential, error) {
	c, err := r.q.GetCredential(ctx, sqlc.GetCredentialParams{ID: credentialID, ProjectID: projectID})
	if err != nil {
		return nil, mapErr(err)
	}
	return &projects.Credential{
		ID:                c.ID,
		ProjectID:         c.ProjectID,
		Username:          pgconv.TextValPtr(c.Username),
		Password:          c.PasswordEncrypted,
		Host:              pgconv.TextValPtr(c.Host),
		CreatedBy:         c.CreatedBy,
		CreatedByUsername: pgconv.TextValPtr(c.CreatedByUsername),
		CreatedAt:         pgconv.TsVal(c.CreatedAt),
		UpdatedAt:         pgconv.TsVal(c.UpdatedAt),
	}, nil
}

func (r *Repo) InsertCredential(ctx context.Context, nc projects.NewCredential) (int32, error) {
	c, err := r.q.InsertCredential(ctx, sqlc.InsertCredentialParams{
		ProjectID:         nc.ProjectID,
		Username:          pgconv.TextPtr(nc.Username),
		PasswordEncrypted: nc.PasswordEncrypted,
		Host:              pgconv.TextPtr(nc.Host),
		CreatedBy:         nc.CreatedBy,
	})
	if err != nil {
		return 0, err
	}
	return c.ID, nil
}

func (r *Repo) UpdateCredential(ctx context.Context, id int32, username *string, passwordEncrypted string, host *string) error {
	return r.q.UpdateCredential(ctx, sqlc.UpdateCredentialParams{
		ID: id, Username: pgconv.TextPtr(username), PasswordEncrypted: passwordEncrypted, Host: pgconv.TextPtr(host),
	})
}

func (r *Repo) DeleteCredential(ctx context.Context, id int32) error {
	return r.q.DeleteCredential(ctx, id)
}

// ─────────────────────────── hidden ips ───────────────────────────

func (r *Repo) ListHiddenIPs(ctx context.Context, projectID int32) ([]string, error) {
	return r.q.ListHiddenIPs(ctx, projectID)
}

func (r *Repo) HideIP(ctx context.Context, projectID int32, ip string, actorID int32) error {
	return r.tx(ctx, func(q *sqlc.Queries) error {
		hostIDs, err := q.ListStandaloneIPHostIDs(ctx, sqlc.ListStandaloneIPHostIDsParams{ProjectID: projectID, IpAddress: ip})
		if err != nil {
			return err
		}
		for _, hid := range hostIDs {
			if err := q.DeleteHostByID(ctx, hid); err != nil {
				return err
			}
		}
		return q.InsertHiddenIP(ctx, sqlc.InsertHiddenIPParams{ProjectID: projectID, IpAddress: ip, CreatedBy: pgconv.Int4(&actorID)})
	})
}

// BulkHideIPs скрывает список адресов в одной транзакции: для каждого адреса
// сносит отдельные IP-хосты (как HideIP), затем одним апсертом добавляет адреса в
// hidden-ips. Возвращает число реально скрытых (уже скрытые не считаются).
func (r *Repo) BulkHideIPs(ctx context.Context, projectID int32, ips []string, actorID int32) (int64, error) {
	if len(ips) == 0 {
		return 0, nil
	}
	var hidden int64
	err := r.tx(ctx, func(q *sqlc.Queries) error {
		for _, ip := range ips {
			hostIDs, err := q.ListStandaloneIPHostIDs(ctx, sqlc.ListStandaloneIPHostIDsParams{ProjectID: projectID, IpAddress: ip})
			if err != nil {
				return err
			}
			for _, hid := range hostIDs {
				if err := q.DeleteHostByID(ctx, hid); err != nil {
					return err
				}
			}
		}
		n, err := q.BulkInsertHiddenIPs(ctx, sqlc.BulkInsertHiddenIPsParams{
			ProjectID: projectID, Addrs: ips, CreatedBy: pgconv.Int4(&actorID),
		})
		if err != nil {
			return err
		}
		hidden = n
		return nil
	})
	if err != nil {
		return 0, err
	}
	return hidden, nil
}

func (r *Repo) UnhideIP(ctx context.Context, projectID int32, ip string) error {
	return r.q.DeleteHiddenIP(ctx, sqlc.DeleteHiddenIPParams{ProjectID: projectID, IpAddress: ip})
}

// ─────────────────────────── activity ───────────────────────────

func (r *Repo) ListProjectActivity(ctx context.Context, projectID int32, limit int32) ([]projects.ActivityItem, error) {
	rows, err := r.q.ListProjectActivity(ctx, sqlc.ListProjectActivityParams{ProjectID: pgconv.Int4(&projectID), Lim: limit})
	if err != nil {
		return nil, err
	}
	out := make([]projects.ActivityItem, 0, len(rows))
	for _, a := range rows {
		out = append(out, projects.ActivityItem{
			ID:         a.ID,
			Action:     a.Action,
			EntityType: pgconv.TextValPtr(a.EntityType),
			EntityID:   pgconv.Int4Val(a.EntityID),
			UserID:     pgconv.Int4Val(a.UserID),
			Username:   pgconv.TextValPtr(a.Username),
			Details:    a.Details,
			CreatedAt:  pgconv.TsValPtr(a.CreatedAt),
		})
	}
	return out, nil
}

func (r *Repo) VulnsByIDs(ctx context.Context, ids []int32) ([]projects.VulnBrief, error) {
	rows, err := r.q.ListVulnsForActivity(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make([]projects.VulnBrief, 0, len(rows))
	for _, v := range rows {
		out = append(out, projects.VulnBrief{ID: v.ID, Title: v.Title, Severity: string(v.Severity)})
	}
	return out, nil
}

func (r *Repo) ListNotesActivity(ctx context.Context, projectID int32, limit int32) ([]projects.NotesActivityItem, error) {
	rows, err := r.q.ListNotesActivity(ctx, sqlc.ListNotesActivityParams{Column1: itoa(projectID), Limit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]projects.NotesActivityItem, 0, len(rows))
	for _, a := range rows {
		item := projects.NotesActivityItem{
			ID:        a.ID,
			Action:    a.Action,
			NoteID:    pgconv.Int4Val(a.EntityID),
			UserID:    pgconv.Int4Val(a.UserID),
			Username:  pgconv.TextValPtr(a.Username),
			CreatedAt: pgconv.TsValPtr(a.CreatedAt),
		}
		item.NoteTitle = titleFromDetails(a.Details)
		out = append(out, item)
	}
	return out, nil
}

// ─────────────────────────── notifications + audit ───────────────────────────

func (r *Repo) InsertNotification(ctx context.Context, n projects.Notification) error {
	return r.q.InsertNotification(ctx, sqlc.InsertNotificationParams{
		UserID:          n.UserID,
		Type:            sqlc.NotificationType(n.Type),
		CommentID:       pgconv.Int4(n.CommentID),
		NoteCommentID:   pgconv.Int4(n.NoteCommentID),
		ProjectID:       pgconv.Int4(n.ProjectID),
		VulnerabilityID: pgconv.Int4(n.VulnerabilityID),
		ActorID:         pgconv.Int4(n.ActorID),
		Status:          pgconv.Text(n.Status),
	})
}

func (r *Repo) InsertAudit(ctx context.Context, e projects.AuditEntry) error {
	return r.q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		UserID:     pgconv.Int4(e.UserID),
		Action:     e.Action,
		EntityType: pgconv.Text(e.EntityType),
		EntityID:   pgconv.Int4(e.EntityID),
		Details:    e.Details,
		IpAddress:  pgconv.Text(e.IPAddress),
	})
}
