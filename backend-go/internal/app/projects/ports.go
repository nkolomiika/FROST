package projects

import (
	"context"
	"errors"
	"time"
)

// ErrNoRows — репозиторий не нашёл строку. Use-case решает трактовку.
var ErrNoRows = errors.New("no rows")

// ProjectListParams — параметры выборки списка проектов.
type ProjectListParams struct {
	UserID  int32
	IsAdmin bool
	Status  string // UPPERCASE или "" (без фильтра)
	Offset  int32
	Limit   int32
}

// Store — порт хранилища контекста projects (реализуется projectsrepo поверх
// sqlc + pgxpool). Компаундные операции (перемещение/удаление папки, скрытие IP,
// reorder заметок) атомарны внутри адаптера (транзакция).
type Store interface {
	// projects
	ListProjects(ctx context.Context, p ProjectListParams) ([]Project, int64, error)
	GetProject(ctx context.Context, id int32) (*Project, error)
	ProjectsByIDs(ctx context.Context, ids []int32) ([]Project, error)
	AllProjectIDs(ctx context.Context) ([]int32, error)
	InsertProject(ctx context.Context, np NewProject) (*Project, error)
	UpdateProject(ctx context.Context, up ProjectUpdate) (*Project, error)
	DeleteProject(ctx context.Context, id int32) error
	IsProjectMember(ctx context.Context, projectID, userID int32) (bool, error)
	ProjectStats(ctx context.Context, userID int32, isAdmin bool) ([]ProjectStat, error)
	ListProjectMemberIDs(ctx context.Context, projectID int32) ([]int32, error)
	GetUserBrief(ctx context.Context, id int32) (*UserBrief, error)

	// members
	ListMembers(ctx context.Context, projectID int32) ([]MemberDetail, error)
	GetMember(ctx context.Context, projectID, userID int32) (id int32, found bool, err error)
	InsertMember(ctx context.Context, projectID, userID int32) (id int32, addedAt time.Time, err error)
	DeleteMember(ctx context.Context, projectID, userID int32) error

	// folders
	ListFolders(ctx context.Context) ([]Folder, error)
	GetFolderByID(ctx context.Context, id int32) (*Folder, error)
	GetFolderByPath(ctx context.Context, path string) (*Folder, error)
	FindSiblingFolder(ctx context.Context, parentID *int32, name string, excludeID int32) (bool, error)
	InsertFolder(ctx context.Context, name, path string, parentID *int32, createdBy int32) (*Folder, error)
	ListSubtreeFolders(ctx context.Context, path string) ([]Folder, error)
	ListSubtreeProjects(ctx context.Context, folder string) ([]Project, error)
	ApplyFolderMove(ctx context.Context, plan FolderMovePlan) error
	DeleteFolderCascade(ctx context.Context, path string) (deletedFolders, deletedProjects int, err error)

	// notes
	ListNotes(ctx context.Context, projectID int32) ([]Note, error)
	GetNote(ctx context.Context, projectID, noteID int32) (*Note, error)
	GetNoteParentID(ctx context.Context, projectID, noteID int32) (*int32, error)
	SiblingTitleExists(ctx context.Context, projectID int32, parentID *int32, title string, excludeID int32) (bool, error)
	MaxSiblingSortOrder(ctx context.Context, projectID int32, parentID *int32) (int32, error)
	ListSiblingNotes(ctx context.Context, projectID int32, parentID *int32) ([]Note, error)
	InsertNote(ctx context.Context, nn NewNote) (*Note, error)
	UpdateNote(ctx context.Context, id int32, title string, content *string, updatedBy int32) error
	MoveNote(ctx context.Context, id int32, parentID *int32, sortOrder, updatedBy int32) error
	ReorderNotes(ctx context.Context, items []ReorderItem, updatedBy int32) error
	DeleteNote(ctx context.Context, id int32) error

	// note comments
	CountNoteComments(ctx context.Context, projectID, noteID int32) (int64, error)
	ListNoteComments(ctx context.Context, projectID, noteID int32, offset, limit int32) ([]NoteComment, error)
	GetNoteComment(ctx context.Context, projectID, noteID, commentID int32) (*NoteComment, error)
	InsertNoteComment(ctx context.Context, projectID, noteID, userID int32, content string) (*NoteComment, error)
	UpdateNoteComment(ctx context.Context, id int32, content string) error
	DeleteNoteComment(ctx context.Context, id int32) error
	ResolveMentionUsers(ctx context.Context, projectID int32, usernames []string) ([]UserBrief, error)

	// credentials
	ListCredentials(ctx context.Context, projectID int32) ([]Credential, error)
	GetCredential(ctx context.Context, projectID, credentialID int32) (*Credential, error)
	InsertCredential(ctx context.Context, nc NewCredential) (int32, error)
	UpdateCredential(ctx context.Context, id int32, username *string, passwordEncrypted string, host *string) error
	DeleteCredential(ctx context.Context, id int32) error

	// hidden ips
	ListHiddenIPs(ctx context.Context, projectID int32) ([]string, error)
	HideIP(ctx context.Context, projectID int32, ip string, actorID int32) error
	// BulkHideIPs скрывает список адресов в одной транзакции (для каждого — снос
	// отдельных IP-хостов + апсерт в hidden-ips). Возвращает число реально скрытых
	// (уже скрытые адреса не считаются).
	BulkHideIPs(ctx context.Context, projectID int32, ips []string, actorID int32) (int64, error)
	UnhideIP(ctx context.Context, projectID int32, ip string) error

	// activity
	ListProjectActivity(ctx context.Context, projectID int32, limit int32) ([]ActivityItem, error)
	VulnsByIDs(ctx context.Context, ids []int32) ([]VulnBrief, error)
	ListNotesActivity(ctx context.Context, projectID int32, limit int32) ([]NotesActivityItem, error)

	// notifications + audit
	InsertNotification(ctx context.Context, n Notification) error
	InsertAudit(ctx context.Context, e AuditEntry) error
}

// Cipher — шифрование/расшифровка секретов кред (adapters/security.SecretCipher).
type Cipher interface {
	Encrypt(value string) (string, error)
	Decrypt(token string) (string, error)
}
