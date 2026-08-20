// Package vulns — use-cases контекста «уязвимости»: сами уязвимости (+CVSS 4.0),
// привязки активов, комментарии(+упоминания) и файлы доказательной базы. Порт
// services.py: VulnerabilityService / FileService / CommentService. Слой не
// зависит от pgx/http/minio — только от интерфейсов в ports.go.
package vulns

import "time"

// Значения enum severity/status/asset_type — как в БД (UPPERCASE). CVSS-версия
// хранится в доменном слое в API-виде («4.0»/«3.1»); репозиторий мапит в БД-энум.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

const (
	StatusOpen         = "OPEN"
	StatusInProgress   = "IN_PROGRESS"
	StatusFixed        = "FIXED"
	StatusWontFix      = "WONT_FIX"
	StatusAcceptedRisk = "ACCEPTED_RISK"
)

const (
	AssetHost     = "HOST"
	AssetPort     = "PORT"
	AssetService  = "SERVICE"
	AssetEndpoint = "ENDPOINT"
)

// validSeverities / validStatuses — множества допустимых БД-значений (для фильтров).
var validSeverities = map[string]bool{
	SeverityCritical: true, SeverityHigh: true, SeverityMedium: true, SeverityLow: true, SeverityInfo: true,
}

var validStatuses = map[string]bool{
	StatusOpen: true, StatusInProgress: true, StatusFixed: true, StatusWontFix: true, StatusAcceptedRisk: true,
}

var validAssetTypes = map[string]bool{
	AssetHost: true, AssetPort: true, AssetService: true, AssetEndpoint: true,
}

// Actor — аутентифицированный пользователь в терминах контекста vulns.
type Actor struct {
	ID       int32
	Username string
	Role     string // "ADMIN" | "PENTESTER"
}

// IsAdmin — сокращение проверки роли.
func (a Actor) IsAdmin() bool { return a.Role == "ADMIN" }

// WorkflowStep — шаг воспроизведения (порт VulnerabilityWorkflowStep). Сериализуется
// в колонку workflow_steps (JSONB).
type WorkflowStep struct {
	ID                 string  `json:"id"`
	Description        *string `json:"description"`
	ImageFileIDs       []int32 `json:"image_file_ids"`
	EndpointID         *int32  `json:"endpoint_id"`
	EndpointRequestRaw *string `json:"endpoint_request_raw"`
}

// Vuln — уязвимость в терминах домена. Severity/Status — БД-регистр, CvssVersion —
// API-вид («4.0»). WorkflowStepsRaw — сырой JSON из БД; WorkflowSteps — гидрированный
// список (заполняется сервисом).
type Vuln struct {
	ID                int32
	ProjectID         int32
	Title             string
	Description       *string
	Severity          string
	CvssVersion       *string
	CvssScore         *float64
	CvssVector        *string
	CweID             *string
	Status            string
	WorkflowStepsRaw  []byte
	WorkflowSteps     []WorkflowStep
	StepsToReproduce  *string
	Impact            *string
	Recommendations   *string
	CreatedBy         int32
	CreatedByUsername *string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// VulnWrite — набор изменяемых колонок для InsertVuln/UpdateVuln (сервис вычисляет
// финальные значения из текущей уязвимости + payload). WorkflowSteps — сериализованный
// JSON (nil сохраняется как есть — репозиторий не перетирает существующий при update
// без ключа workflow_steps: сервис кладёт сюда текущее значение).
type VulnWrite struct {
	Title            string
	Description      *string
	Severity         string
	CvssVersion      *string
	CvssScore        *float64
	CvssVector       *string
	CweID            *string
	Status           string
	WorkflowSteps    []byte
	StepsToReproduce *string
	Impact           *string
	Recommendations  *string
}

// NewVuln — данные для создания уязвимости (+ обязательная привязка к хосту).
type NewVuln struct {
	ProjectID int32
	CreatedBy int32
	HostID    int32
	Fields    VulnWrite
}

// VulnListParams — параметры выборки списка уязвимостей проекта.
type VulnListParams struct {
	ProjectID int32
	Severity  string // БД-регистр или "" (без фильтра)
	Status    string
	Offset    int32
	Limit     int32
}

// VulnHostListParams — то же, но с привязкой к хосту.
type VulnHostListParams struct {
	ProjectID int32
	HostID    int32
	Severity  string
	Status    string
	Offset    int32
	Limit     int32
}

// AssetLink — строка vulnerability_assets.
type AssetLink struct {
	ID              int32
	VulnerabilityID int32
	AssetType       string // БД-регистр
	AssetID         int32
}

// Mention — упомянутый пользователь.
type Mention struct {
	UserID   int32
	Username string
}

// Comment — комментарий к уязвимости (username/avatar заполняются на чтении).
type Comment struct {
	ID               int32
	VulnerabilityID  int32
	UserID           int32
	Username         string
	AvatarKey        *string
	AvatarUploadedAt *time.Time
	Content          string
	Mentions         []Mention
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// CommentCreateData — данные компаундной вставки комментария (+упоминания и уведомления).
type CommentCreateData struct {
	VulnID   int32
	UserID   int32
	Content  string
	Mentions []Mention // все упомянутые (строки comment_mentions)
	Notify   []int32   // кому шлём уведомление (все, кроме автора)
	ActorID  int32
}

// File — метаданные файла доказательной базы.
type File struct {
	ID              int32
	VulnerabilityID int32
	OriginalName    string
	ContentType     string
	SizeBytes       int64
	MinioBucket     string
	MinioKey        string
	UploadedBy      int32
	UploadedAt      time.Time
}

// NewFile — данные для вставки файла.
type NewFile struct {
	VulnerabilityID int32
	OriginalName    string
	ContentType     string
	SizeBytes       int64
	MinioBucket     string
	MinioKey        string
	UploadedBy      int32
}

// VulnDetail — расширенная карточка уязвимости для GET /{vuln_id}.
type VulnDetail struct {
	Vuln          *Vuln
	Assets        []AssetLink
	Files         []File
	CommentsCount int64
}

// AuditEntry — запись журнала действий (best-effort). IPAddress в контексте vulns
// не пишется (как в services.py — audit.log без ip_address).
type AuditEntry struct {
	UserID     *int32
	Action     string
	EntityType string
	EntityID   *int32
	Details    []byte
}
