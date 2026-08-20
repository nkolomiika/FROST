// Package inventory — use-cases контекста «активы»: hosts / ip-addresses /
// ports / services / endpoints, а также импорт-экспорт (PCF JSON и OpenAPI).
// Порт services.py: AssetService (кроме hidden-ips — они в контексте projects) и
// ImportService. Слой не зависит от pgx/http — только от портов в ports.go.
package inventory

import (
	"encoding/json"
	"time"
)

// Значения enum как в БД (имена членов, верхний регистр).
const (
	HostStatusUnknown = "UNKNOWN"
	OsTypeUnknown     = "UNKNOWN"
	ProtocolTCP       = "TCP"
	PortStateOpen     = "OPEN"
)

var validHostStatus = map[string]bool{"UP": true, "DOWN": true, "UNKNOWN": true}

var validOsType = map[string]bool{
	"WINDOWS": true, "LINUX": true, "MACOS": true, "FREEBSD": true,
	"ANDROID": true, "IOS": true, "OTHER": true, "UNKNOWN": true,
}

var validProtocol = map[string]bool{"TCP": true, "UDP": true}

var validPortState = map[string]bool{"OPEN": true, "CLOSED": true, "FILTERED": true}

// Домен-сущности. Enum-строки хранятся как в БД (UPPERCASE); http-слой приводит
// к нижнему регистру на границе. http_method — UPPERCASE с обеих сторон.

// Host — хост проекта.
type Host struct {
	ID        int32
	ProjectID int32
	IPAddress *string
	Hostname  *string
	Status    string // UPPER
	OsType    string // UPPER
	Notes     *string
	Origin    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// HostIP — IP-адрес хоста (host_ip_addresses).
type HostIP struct {
	ID           int32
	HostID       int32
	IPAddress    string
	Label        *string
	IsPrimary    bool
	Hostnames    json.RawMessage
	IsCloudflare *bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Port — порт на IP-адресе.
type Port struct {
	ID          int32
	HostID      int32
	IPAddressID int32
	PortNumber  int32
	Protocol    string // UPPER
	State       string // UPPER
	HTTPStatus  *int32
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Service — сервис на порту.
type PortService struct {
	ID        int32
	PortID    int32
	Name      string
	Version   *string
	Banner    *string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Endpoint — эндпоинт хоста.
type Endpoint struct {
	ID                 int32
	HostID             int32
	Path               string
	Method             *string // UPPER или nil (колонка nullable)
	Description        *string
	QueryParams        json.RawMessage
	RequestBody        *string
	RequestContentType *string
	RequestHeaders     json.RawMessage
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// ─────────────────────────── агрегаты дерева хоста ───────────────────────────

// HostAggregate — хост с вложенными ip_addresses (→ ports → services) и endpoints.
type HostAggregate struct {
	Host      Host
	IPs       []IPAggregate
	Endpoints []Endpoint
}

// IPAggregate — IP с портами (порты отсортированы по port_number).
type IPAggregate struct {
	IP    HostIP
	Ports []PortAggregate
}

// PortAggregate — порт со списком сервисов.
type PortAggregate struct {
	Port     Port
	Services []PortService
}

// ─────────────────────────── входные структуры ───────────────────────────

// IPEntry — нормализованная запись IP (выход _normalize_host_ip_entries).
type IPEntry struct {
	IPAddress string
	Label     *string
	IsPrimary bool
}

// RawIPEntry — сырой элемент ip_addresses при обновлении хоста (объект).
type RawIPEntry struct {
	IPAddress *string
	Label     *string
	IsPrimary bool
}

// NewHost — данные для вставки хоста (+ нормализованные IP).
type NewHost struct {
	ProjectID int32
	IPAddress *string // primary-mirror
	Hostname  *string
	Status    string
	OsType    string
	Notes     *string
	Origin    string
}

// HostFields — конечные значения не-IP полей хоста при обновлении.
type HostFields struct {
	IPAddress *string
	Hostname  *string
	Status    string
	OsType    string
	Notes     *string
}

// HostUpdateParams — компаундное обновление хоста (в транзакции адаптера).
type HostUpdateParams struct {
	HostID     int32
	Fields     HostFields
	ReplaceIPs bool
	Entries    []IPEntry
}

// HostListParams — параметры списка хостов.
type HostListParams struct {
	ProjectID int32
	Origin    string // "host"|"ip"|"" (все)
	Status    string // UPPER или ""
	Offset    int32
	Limit     int32
}

// NewPort — данные для вставки порта.
type NewPort struct {
	HostID      int32
	IPAddressID int32
	PortNumber  int32
	Protocol    string
	State       string
	HTTPStatus  *int32
}

// UpdatePortParams — конечные значения колонок порта.
type UpdatePortParams struct {
	ID          int32
	IPAddressID int32
	PortNumber  int32
	Protocol    string
	State       string
	HTTPStatus  *int32
}

// NewEndpoint — данные для вставки эндпоинта.
type NewEndpoint struct {
	HostID             int32
	Path               string
	Method             *string
	Description        *string
	QueryParams        []byte
	RequestBody        *string
	RequestContentType *string
	RequestHeaders     []byte
}

// UpdateEndpointParams — конечные значения колонок эндпоинта.
type UpdateEndpointParams struct {
	ID                 int32
	Path               string
	Method             *string
	Description        *string
	QueryParams        []byte
	RequestBody        *string
	RequestContentType *string
	RequestHeaders     []byte
}

// ─────────────────────────── импорт ───────────────────────────

// ImportResult — итог PCF-импорта.
type ImportResult struct {
	HostsCreated     int
	PortsCreated     int
	ServicesCreated  int
	EndpointsCreated int
	Errors           []string
}

// OpenAPIImportResult — итог импорта OpenAPI.
type OpenAPIImportResult struct {
	HostID           int32
	SpecHost         *string
	EndpointsCreated int
	EndpointsSkipped int
	Errors           []string
}

// EndpointImport — уже нормализованный эндпоинт для upsert из импорта.
type EndpointImport struct {
	Path               string
	Method             *string
	Description        *string
	QueryParams        []byte
	RequestBody        *string
	RequestContentType *string
	RequestHeaders     []byte
}

// PcfService/PcfPort/PcfHost — распарсенная структура PCF-импорта.
type PcfService struct {
	Name    string
	Version *string
	Banner  *string
}

type PcfPort struct {
	PortNumber int32
	Protocol   string
	State      string
	Services   []PcfService
}

type PcfHost struct {
	IPAddress *string
	Hostname  *string
	Status    string
	Notes     *string
	Ports     []PcfPort
	Endpoints []EndpointImport
}

// ─────────────────────────── аудит ───────────────────────────

// AuditEntry — запись журнала (best-effort). IPAddress для активов всегда пуст.
type AuditEntry struct {
	UserID     *int32
	Action     string
	EntityType string
	EntityID   *int32
	Details    []byte
	IPAddress  string
}

// qparam — нормализованный query-параметр эндпоинта (порядок ключей как в Python).
type qparam struct {
	Name        string  `json:"name"`
	Value       *string `json:"value"`
	Required    bool    `json:"required"`
	Description *string `json:"description"`
}

// header — нормализованный заголовок эндпоинта.
type header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
