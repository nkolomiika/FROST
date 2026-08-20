package vulns

import (
	"context"
	"errors"
)

// ErrNoRows — репозиторий не нашёл строку. Use-case решает трактовку.
var ErrNoRows = errors.New("no rows")

// Store — порт хранилища контекста vulns (реализуется vulnsrepo поверх sqlc +
// pgxpool). Компаундные операции (создание уязвимости + HOST-связь, комментарий +
// упоминания + уведомления, замена упоминаний) атомарны внутри адаптера (транзакция).
type Store interface {
	// vulns
	GetVuln(ctx context.Context, projectID, vulnID int32) (*Vuln, error)
	ListVulns(ctx context.Context, p VulnListParams) ([]Vuln, int64, error)
	ListVulnsForHost(ctx context.Context, p VulnHostListParams) ([]Vuln, int64, error)
	HostExistsInProject(ctx context.Context, hostID, projectID int32) (bool, error)
	CreateVuln(ctx context.Context, nv NewVuln) (int32, error)
	UpdateVuln(ctx context.Context, id int32, w VulnWrite) error
	PatchVulnStatus(ctx context.Context, id int32, status string) error
	DeleteVuln(ctx context.Context, id int32) error
	VulnProjectID(ctx context.Context, vulnID int32) (int32, error)

	// assets
	ListVulnAssets(ctx context.Context, vulnID int32) ([]AssetLink, error)
	FindVulnAsset(ctx context.Context, vulnID int32, assetType string, assetID int32) (bool, error)
	GetVulnAssetLink(ctx context.Context, linkID, vulnID int32) (*AssetLink, error)
	CountHostAssetLinks(ctx context.Context, vulnID int32) (int64, error)
	InsertVulnAsset(ctx context.Context, vulnID int32, assetType string, assetID int32) (*AssetLink, error)
	DeleteVulnAsset(ctx context.Context, linkID int32) error
	AssetInProject(ctx context.Context, assetType string, assetID, projectID int32) (bool, error)
	PrimaryHostID(ctx context.Context, vulnID int32) (int32, bool, error)

	// comments
	CountVulnComments(ctx context.Context, vulnID int32) (int64, error)
	ListVulnComments(ctx context.Context, vulnID, offset, limit int32) ([]Comment, error)
	ListCommentMentions(ctx context.Context, commentID int32) ([]Mention, error)
	GetVulnComment(ctx context.Context, commentID, vulnID int32) (*Comment, error)
	ResolveCommentMentionUsers(ctx context.Context, projectID int32, usernames []string) ([]Mention, error)
	CreateComment(ctx context.Context, d CommentCreateData) (*Comment, error)
	UpdateCommentWithMentions(ctx context.Context, commentID int32, content string, mentions []Mention) error
	DeleteVulnComment(ctx context.Context, id int32) error

	// files
	ListVulnFiles(ctx context.Context, vulnID int32) ([]File, error)
	GetFileByID(ctx context.Context, id int32) (*File, error)
	GetFileForVuln(ctx context.Context, id, vulnID int32) (*File, error)
	InsertFile(ctx context.Context, nf NewFile) (*File, error)
	DeleteFile(ctx context.Context, id int32) error
	CountFileImagesForVuln(ctx context.Context, vulnID int32, ids []int32) (int64, error)

	// membership + notifications + audit
	IsProjectMember(ctx context.Context, projectID, userID int32) (bool, error)
	InsertVulnStatusNotification(ctx context.Context, userID, vulnID, projectID, actorID int32, status string) error
	InsertAudit(ctx context.Context, e AuditEntry) error
}

// Storage — порт объектного хранилища файлов (реализуется адаптером MinIO позже).
type Storage interface {
	Put(ctx context.Context, key string, data []byte, contentType string) (err error)
	Get(ctx context.Context, key string) (data []byte, contentType string, err error)
	Delete(ctx context.Context, key string) error
}
