// Package projects — use-cases контекста «проекты»: сами проекты, папки,
// участники, заметки(+комментарии), учётные данные, скрытые IP, статистика и
// активность. Порт services.py: ProjectService / ProjectNoteService /
// ProjectCredentialService + hidden-ips из AssetService. Слой не зависит от
// pgx/http — только от интерфейсов в ports.go.
package projects

import (
	"encoding/json"
	"time"
)

// Статусы проекта — значения как в БД (имена членов enum, верхний регистр).
const (
	StatusActive                = "ACTIVE"
	StatusFreeze                = "FREEZE"
	StatusHandoverToDevelopment = "HANDOVER_TO_DEVELOPMENT"
	StatusVulnerabilityRecheck  = "VULNERABILITY_RECHECK"
	StatusCompleted             = "COMPLETED"
	StatusArchived              = "ARCHIVED"
)

// validStatuses — множество допустимых значений project_status (верхний регистр).
var validStatuses = map[string]bool{
	StatusActive: true, StatusFreeze: true, StatusHandoverToDevelopment: true,
	StatusVulnerabilityRecheck: true, StatusCompleted: true, StatusArchived: true,
}

// Типы уведомлений (порт NotificationType, значения как в БД).
const (
	NotificationMention              = "MENTION"
	NotificationProjectMemberAdded   = "PROJECT_MEMBER_ADDED"
	NotificationProjectStatusChanged = "PROJECT_STATUS_CHANGED"
)

// Project — проект в терминах домена. Status хранит значение как в БД (UPPERCASE).
type Project struct {
	ID               int32
	Name             string
	Folder           string
	Description      *string
	StartDate        *time.Time
	EndDate          *time.Time
	TimelineFrozenAt *time.Time
	Status           string
	CreatedBy        int32
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// NewProject — данные для вставки проекта.
type NewProject struct {
	Name        string
	Folder      string
	Description *string
	StartDate   *time.Time
	EndDate     *time.Time
	Status      string
	CreatedBy   int32
}

// ProjectUpdate — финальные значения всех колонок для UpdateProject (сервис
// вычисляет их из загруженного проекта + partial-payload, как setattr в Python).
type ProjectUpdate struct {
	ID               int32
	Name             string
	Folder           string
	Description      *string
	StartDate        *time.Time
	EndDate          *time.Time
	Status           string
	TimelineFrozenAt *time.Time
}

// UpdateInput — partial-обновление карточки проекта (nil = поле не прислано/не меняется).
type UpdateInput struct {
	Name        *string
	Folder      *string
	Description *string
	StartDate   *time.Time
	EndDate     *time.Time
	Status      *string // lowercase→UPPERCASE уже приведён на границе http
}

// ProjectStat — счётчики по проекту (для /projects/stats).
type ProjectStat struct {
	ProjectID     int32
	Status        string
	HostsCount    int64
	TotalFindings int64
	OpenFindings  int64
}

// Folder — папка каталога проектов.
type Folder struct {
	ID        int32
	Name      string
	Path      string
	ParentID  *int32
	CreatedBy int32
	CreatedAt time.Time
	UpdatedAt time.Time
}

// FolderMovePlan — вычисленный план перемещения папки (чистая логика в сервисе).
type FolderMovePlan struct {
	FolderID      int32
	NewParentID   *int32
	FolderUpdates []FolderPathUpdate  // новые пути для поддерева папок
	ProjectMoves  []ProjectFolderMove // новые folder-строки проектов поддерева
}

// FolderPathUpdate — новая путь-строка папки (и, для самой перемещаемой, parent_id).
type FolderPathUpdate struct {
	ID       int32
	Path     string
	IsRoot   bool // true для самой перемещаемой папки (обновляется parent_id)
	ParentID *int32
}

// ProjectFolderMove — новая folder-строка проекта.
type ProjectFolderMove struct {
	ID     int32
	Folder string
}

// FolderDeleteSummary — итог каскадного удаления папки.
type FolderDeleteSummary struct {
	Path            string
	DeletedFolders  int
	DeletedProjects int
}

// MemberDetail — участник проекта с профилем пользователя.
type MemberDetail struct {
	UserID      int32
	Username    string
	Email       string
	Role        string
	ProjectRole string
	AddedAt     time.Time
}

// AddMemberResult — частичный ответ add_member (совпадает с Python-dict).
type AddMemberResult struct {
	UserID      int32
	Username    string
	ProjectRole string
	AddedAt     time.Time
}

// UserBrief — минимум о пользователе для проверок и обогащения аудита.
type UserBrief struct {
	ID          int32
	Username    string
	Role        string
	ProjectRole string
}

// Note — страница заметок проекта.
type Note struct {
	ID                int32
	ProjectID         int32
	ParentID          *int32
	Title             string
	Content           *string
	SortOrder         int32
	CreatedBy         int32
	UpdatedBy         *int32
	CreatedByUsername *string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// NewNote — данные для вставки заметки.
type NewNote struct {
	ProjectID int32
	ParentID  *int32
	Title     string
	Content   *string
	SortOrder int32
	CreatedBy int32
}

// ReorderItem — пара (id, sort_order) для ручной сортировки.
type ReorderItem struct {
	ID        int32
	SortOrder int32
}

// NoteComment — комментарий к заметке с автором.
type NoteComment struct {
	ID        int32
	ProjectID int32
	NoteID    int32
	UserID    int32
	Username  string
	AvatarURL *string
	Content   string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Credential — учётные данные проекта (Password — расшифрованный plaintext).
type Credential struct {
	ID                int32
	ProjectID         int32
	Username          *string
	Password          string
	Host              *string
	CreatedBy         int32
	CreatedByUsername *string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// NewCredential — данные для вставки кред (PasswordEncrypted — уже шифртекст).
type NewCredential struct {
	ProjectID         int32
	Username          *string
	PasswordEncrypted string
	Host              *string
	CreatedBy         int32
}

// ActivityItem — запись активности проекта.
type ActivityItem struct {
	ID         int32
	Action     string
	EntityType *string
	EntityID   *int32
	UserID     *int32
	Username   *string
	Title      *string
	Severity   *string
	URL        *string
	Details    json.RawMessage
	CreatedAt  *time.Time
}

// NotesActivityItem — запись активности заметок проекта.
type NotesActivityItem struct {
	ID        int32
	Action    string
	NoteID    *int32
	NoteTitle *string
	UserID    *int32
	Username  *string
	CreatedAt *time.Time
}

// Notification — уведомление пользователю (создаётся при 3 поводах контекста).
type Notification struct {
	UserID          int32
	Type            string
	CommentID       *int32
	NoteCommentID   *int32
	ProjectID       *int32
	VulnerabilityID *int32
	ActorID         *int32
	Status          string // lowercase значение; "" → NULL
}

// AuditEntry — запись журнала действий (best-effort).
type AuditEntry struct {
	UserID     *int32
	Action     string
	EntityType string
	EntityID   *int32
	Details    []byte
	IPAddress  string
}

// VulnBrief — обогащение активности по уязвимости.
type VulnBrief struct {
	ID       int32
	Title    string
	Severity string
}
