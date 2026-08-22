// Package recon — use-cases рекон-фермы и scanner: постановка/прогон задач
// (host_farm_jobs как durable-очередь), пробив хостов/адресов, скан JS/поддоменов/
// портов и обратный резолв. Порт app/farm/* + worker/recon_worker.py. Сетевую и
// чистую логику держит adapters/recon; персист — порт Store (reconrepo).
package recon

import (
	"time"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
)

// Значения enum как в БД (UPPERCASE) — зеркало inventory.
const (
	statusUP      = "UP"
	statusDOWN    = "DOWN"
	statusUNKNOWN = "UNKNOWN"
	stateOPEN     = "OPEN"
	stateFILTERED = "FILTERED"
)

// Kind — тип задачи фермы (порт enums.ReconJobKind).
const (
	KindHosts   = "hosts"
	KindIPs     = "ips"
	KindJS      = "js"
	KindSubs    = "subs"
	KindPorts   = "ports"
	KindReverse = "reverse"
	// KindFarmRun — полный прогон фермы: subfinder/crt.sh (пассив) + dnsx-брут
	// (актив) параллельно → резолв+liveness (httpx) → скан портов (nmap), с
	// живым прогрессом. Гоняет весь стек одной кнопкой.
	KindFarmRun = "farm_run"
)

// Статусы задачи (порт enums.ReconJobStatus).
const (
	jobPending = "pending"
	jobDone    = "done"
	// jobCancelled — прогон остановлен по запросу пользователя. Это НЕ провал:
	// result хранит частичный итог, error пуст.
	jobCancelled = "cancelled"
)

// Config — тюнинг оркестрации (не сетевой): воркер, попытки, кап result.
// FarmStaleSeconds — отдельное (большое) окно реклейма для farm_run: полный прогон
// идёт минутами, поэтому обычный StaleSeconds к нему не применяем.
type Config struct {
	WorkerEnabled    bool
	MaxAttempts      int32
	StaleSeconds     int32
	FarmStaleSeconds int32
	ResultMaxItems   int
}

// ─────────────────────────── result-структуры (JSON job.result) ───────────────────────────
// Форма и имена полей — точная копия pydantic-схем (model_dump): счётчики всегда
// присутствуют (в т.ч. 0), списки сериализуются как [] (не null) → инициализируем.

// HostnameOut — имя резолва {hostname, source, confirmed}.
type HostnameOut struct {
	Hostname  string `json:"hostname"`
	Source    string `json:"source"`
	Confirmed bool   `json:"confirmed"`
}

// PortResult — порт в result (порт HostFarmPortResult).
type PortResult struct {
	PortNumber int32  `json:"port_number"`
	Protocol   string `json:"protocol"`
	Scheme     string `json:"scheme"`
	HTTPStatus *int32 `json:"http_status"`
	State      string `json:"state"`
	Inferred   bool   `json:"inferred"`
}

// HostResult — хост в result (порт HostFarmHostResult).
type HostResult struct {
	Hostname  *string      `json:"hostname"`
	IPAddress *string      `json:"ip_address"`
	Status    string       `json:"status"`
	Created   bool         `json:"created"`
	Ports     []PortResult `json:"ports"`
}

// HostFarmResult — итог фермы хостов (порт HostFarmResult).
type HostFarmResult struct {
	TargetsParsed  int          `json:"targets_parsed"`
	TargetsInvalid int          `json:"targets_invalid"`
	HostsCreated   int          `json:"hosts_created"`
	HostsUpdated   int          `json:"hosts_updated"`
	HostsSkipped   int          `json:"hosts_skipped"`
	PortsCreated   int          `json:"ports_created"`
	PortsUpdated   int          `json:"ports_updated"`
	HostsOnline    int          `json:"hosts_online"`
	HostsOffline   int          `json:"hosts_offline"`
	IPsPromoted    int          `json:"ips_promoted"`
	Hosts          []HostResult `json:"hosts"`
	Errors         []string     `json:"errors"`
}

func newHostFarmResult() *HostFarmResult {
	return &HostFarmResult{Hosts: []HostResult{}, Errors: []string{}}
}

// IPResult — адрес в result (порт IpFarmIpResult).
type IPResult struct {
	IPAddress              string        `json:"ip_address"`
	HostID                 *int32        `json:"host_id"`
	Hostnames              []HostnameOut `json:"hostnames"`
	IsCloudflare           *bool         `json:"is_cloudflare"`
	Created                bool          `json:"created"`
	AttachedToExistingHost bool          `json:"attached_to_existing_host"`
	Ports                  []PortResult  `json:"ports"`
}

// IpFarmResult — итог фермы IP (порт IpFarmResult).
type IpFarmResult struct {
	TargetsParsed  int        `json:"targets_parsed"`
	TargetsInvalid int        `json:"targets_invalid"`
	IPsCreated     int        `json:"ips_created"`
	IPsUpdated     int        `json:"ips_updated"`
	IPsSkipped     int        `json:"ips_skipped"`
	PortsCreated   int        `json:"ports_created"`
	PortsUpdated   int        `json:"ports_updated"`
	IPsOnline      int        `json:"ips_online"`
	IPsOffline     int        `json:"ips_offline"`
	HostnamesFound int        `json:"hostnames_found"`
	HostsPromoted  int        `json:"hosts_promoted"`
	IPs            []IPResult `json:"ips"`
	Errors         []string   `json:"errors"`
}

func newIpFarmResult() *IpFarmResult { return &IpFarmResult{IPs: []IPResult{}, Errors: []string{}} }

// JSFileResult — файл в result (порт JsFarmFileResult).
type JSFileResult struct {
	URL           string `json:"url"`
	Hostname      string `json:"hostname"`
	Status        string `json:"status"`
	SecretCount   int    `json:"secret_count"`
	EndpointCount int    `json:"endpoint_count"`
}

// JsFarmResult — итог фермы JS (порт JsFarmResult).
type JsFarmResult struct {
	DomainsScanned int            `json:"domains_scanned"`
	FilesFound     int            `json:"files_found"`
	FilesScanned   int            `json:"files_scanned"`
	FilesFailed    int            `json:"files_failed"`
	SecretsFound   int            `json:"secrets_found"`
	EndpointsFound int            `json:"endpoints_found"`
	Files          []JSFileResult `json:"files"`
	Errors         []string       `json:"errors"`
}

func newJsFarmResult() *JsFarmResult {
	return &JsFarmResult{Files: []JSFileResult{}, Errors: []string{}}
}

// SubFarmResult — итог раскрытия поддоменов (порт SubFarmResult).
type SubFarmResult struct {
	RootsScanned    int      `json:"roots_scanned"`
	SubdomainsFound int      `json:"subdomains_found"`
	SubdomainsNew   int      `json:"subdomains_new"`
	HostsCreated    int      `json:"hosts_created"`
	HostsOnline     int      `json:"hosts_online"`
	HostsOffline    int      `json:"hosts_offline"`
	SourcesUsed     []string `json:"sources_used"`
	Subdomains      []string `json:"subdomains"`
	Errors          []string `json:"errors"`
}

func newSubFarmResult() *SubFarmResult {
	return &SubFarmResult{SourcesUsed: []string{}, Subdomains: []string{}, Errors: []string{}}
}

// PortScanHostResult — хост в result скана портов (порт PortScanHostResult).
type PortScanHostResult struct {
	Hostname  *string `json:"hostname"`
	IPAddress *string `json:"ip_address"`
	OpenPorts []int   `json:"open_ports"`
}

// PortScanResult — итог скана портов (порт PortScanResult).
type PortScanResult struct {
	TargetsScanned int                  `json:"targets_scanned"`
	TargetsInvalid int                  `json:"targets_invalid"`
	HostsUp        int                  `json:"hosts_up"`
	PortsFound     int                  `json:"ports_found"`
	PortsCreated   int                  `json:"ports_created"`
	PortsUpdated   int                  `json:"ports_updated"`
	Hosts          []PortScanHostResult `json:"hosts"`
	Errors         []string             `json:"errors"`
}

func newPortScanResult() *PortScanResult {
	return &PortScanResult{Hosts: []PortScanHostResult{}, Errors: []string{}}
}

// ReverseFarmResult — итог обратного резолва (порт ReverseFarmResult).
type ReverseFarmResult struct {
	IPsScanned      int      `json:"ips_scanned"`
	HostnamesFound  int      `json:"hostnames_found"`
	HostsDiscovered int      `json:"hosts_discovered"`
	Errors          []string `json:"errors"`
}

func newReverseFarmResult() *ReverseFarmResult { return &ReverseFarmResult{Errors: []string{}} }

// ─────────────────────────── полный прогон фермы (farm_run) ───────────────────────────

// RunStep — один инструмент, работающий ПРЯМО СЕЙЧАС: чем (Tool), с какими
// аргументами (Args, готовая строка команды) и по какой цели (Target). Живая
// панель во фронте показывает их списком; пассивные и активные шаги видны вместе.
// ID — стабильный целочисленный идентификатор шага (= seq трекера); фронт шлёт
// его в per-step cancel (.../steps/{step_id}/cancel).
type RunStep struct {
	ID        int       `json:"id"`
	Tool      string    `json:"tool"`
	Args      string    `json:"args"`
	Target    string    `json:"target"`
	StartedAt time.Time `json:"started_at"`
}

// RunProgress — снимок прогресса прогона (persist в host_farm_jobs.progress).
// Percent 0..100, Stage — текущая стадия, Steps — активные шаги, плюс бегущие
// счётчики найденного.
type RunProgress struct {
	Percent        int       `json:"percent"`
	Stage          string    `json:"stage"`
	Steps          []RunStep `json:"steps"`
	SubsFound      int       `json:"subs_found"`
	HostsFound     int       `json:"hosts_found"`
	PortsFound     int       `json:"ports_found"`
	EndpointsFound int       `json:"endpoints_found"`
	JsFound        int       `json:"js_found"`
	Done           bool      `json:"done"`
	Errors         []string  `json:"errors"`
}

// FarmRunResult — итог полного прогона (job.result). Счётчики + список ошибок.
type FarmRunResult struct {
	Mode            string   `json:"mode"`
	WordlistSize    string   `json:"wordlist_size"`
	RootsScanned    int      `json:"roots_scanned"`
	SubdomainsFound int      `json:"subdomains_found"`
	SubdomainsNew   int      `json:"subdomains_new"`
	HostsCreated    int      `json:"hosts_created"`
	HostsOnline     int      `json:"hosts_online"`
	PortsFound      int      `json:"ports_found"`
	EndpointsFound  int      `json:"endpoints_found"`
	JsFound         int      `json:"js_found"`
	SourcesUsed     []string `json:"sources_used"`
	Errors          []string `json:"errors"`
}

func newFarmRunResult() *FarmRunResult {
	return &FarmRunResult{SourcesUsed: []string{}, Errors: []string{}}
}

// ─────────────────────────── стейджинг прогона фермы ───────────────────────────
// Полный прогон (farm_run) НЕ пишет находки в проект — он складывает их сюда, в
// «карантин» (recon_farm_staged_hosts). Пользователь смотрит отчёт и импортирует
// выбранное вручную. JSON-теги фиксируют форму провода отчёта (GET .../farm/report).

// StagedPort — один порт staged-хоста. service/version заполняет nmap -sV,
// http_status — httpx-liveness. Все три nullable (null, а не пусто).
type StagedPort struct {
	Port       int     `json:"port"`
	Proto      string  `json:"proto"`
	State      string  `json:"state"`
	Service    *string `json:"service"`
	Version    *string `json:"version"`
	HTTPStatus *int    `json:"http_status"`
}

// StagedHost — одна staged-строка отчёта прогона: что открыл прогон по хосту.
type StagedHost struct {
	ID       int32        `json:"id"`
	Hostname string       `json:"hostname"`
	IP       *string      `json:"ip"`
	Alive    bool         `json:"alive"`
	Source   string       `json:"source"`
	Imported bool         `json:"imported"`
	Ports    []StagedPort `json:"ports"`
}

// StagedHostInput — вход вставки одной staged-строки (прогон кладёт по строке
// на каждый открытый хост).
type StagedHostInput struct {
	ProjectID int32
	JobID     int32
	Hostname  string
	IP        *string
	Alive     bool
	Source    string
	Ports     []StagedPort
}

// StagedEndpoint — одна staged-строка эндпоинта прогона (URL, найденный
// katana/gau/waybackurls). Импорт создаёт реальный endpoint проекта.
type StagedEndpoint struct {
	ID       int32   `json:"id"`
	Host     string  `json:"host"`
	URL      string  `json:"url"`
	Method   *string `json:"method"`
	Source   string  `json:"source"`
	Imported bool    `json:"imported"`
}

// StagedEndpointInput — вход вставки одной staged-строки эндпоинта.
type StagedEndpointInput struct {
	ProjectID int32
	JobID     int32
	Host      string
	URL       string
	Method    *string
	Source    string
}

// StagedJs — одна staged-находка JS-майнинга прогона. Kind различает секрет
// ("secret", Value=preview, Severity) и эндпоинт ("endpoint", Value=path).
type StagedJs struct {
	ID       int32   `json:"id"`
	Host     string  `json:"host"`
	URL      string  `json:"url"`
	Kind     string  `json:"kind"`
	Value    string  `json:"value"`
	Severity *string `json:"severity"`
	Imported bool    `json:"imported"`
}

// StagedJsInput — вход вставки одной staged-находки JS.
type StagedJsInput struct {
	ProjectID int32
	JobID     int32
	Host      string
	URL       string
	Kind      string
	Value     string
	Severity  *string
}

// Kind staged-находки JS.
const (
	stagedJsSecret   = "secret"
	stagedJsEndpoint = "endpoint"
)

// FarmReportSummary — агрегаты отчёта прогона.
type FarmReportSummary struct {
	HostsTotal     int `json:"hosts_total"`
	Alive          int `json:"alive"`
	PortsTotal     int `json:"ports_total"`
	EndpointsTotal int `json:"endpoints_total"`
	JsTotal        int `json:"js_total"`
	Imported       int `json:"imported"`
}

// FarmReport — отчёт стейджинга прогона фермы (GET .../recon/farm/report).
type FarmReport struct {
	JobID       int32             `json:"job_id"`
	Status      string            `json:"status"`
	GeneratedAt time.Time         `json:"generated_at"`
	Summary     FarmReportSummary `json:"summary"`
	Hosts       []StagedHost      `json:"hosts"`
	Endpoints   []StagedEndpoint  `json:"endpoints"`
	Js          []StagedJs        `json:"js"`
}

// FarmImportResult — итог импорта выбранных staged-строк в проект.
type FarmImportResult struct {
	ImportedHosts     int `json:"imported_hosts"`
	ImportedEndpoints int `json:"imported_endpoints"`
	ImportedJs        int `json:"imported_js"`
}

// EndpointImportInput — вход создания реального endpoint проекта из staged-строки.
// Дедуп на (host_id, path, method) как в обычном добавлении эндпоинта.
type EndpointImportInput struct {
	HostID int32
	Path   string
	Method *string
}

// ─────────────────────────── job-структуры ───────────────────────────

// NewJob — данные для вставки задачи (create_job).
type NewJob struct {
	ProjectID      int32
	CreatedBy      int32
	Kind           string
	Status         string
	TargetsTotal   *int32
	Raw            string
	SkippedTargets []string
	Result         []byte // JSON, nil = NULL
	Progress       []byte // JSON снимок прогресса (farm_run), nil = NULL
	Finished       bool   // finished_at=now() при short-circuit done
}

// JobView — задача для ответа API (порт *FarmJobOut).
type JobView struct {
	ID           int32
	ProjectID    int32
	Kind         string
	Status       string
	TargetsTotal *int32
	Result       []byte // сырой JSON (nil = null)
	Progress     []byte // сырой JSON снимка прогресса farm_run (nil = null)
	Error        *string
	CreatedAt    time.Time
}

// JobClaim — задача, взятая в работу воркером (после ClaimJobRunning).
type JobClaim struct {
	ID             int32
	ProjectID      int32
	CreatedBy      int32
	Kind           string
	Raw            string
	SkippedTargets []string
	Attempts       int32
}

// ─────────────────────────── persist input/output ───────────────────────────

// PortWrite — порт к записи. Techs=nil — детект не запускался (сервисы не трогаем);
// Techs=[] (non-nil) — детект прошёл, сервисы порта заменяются на пустой набор.
type PortWrite struct {
	PortNumber int32
	State      string // OPEN | FILTERED
	HTTPStatus *int32
	Techs      []reconnet.Tech
	HasTechs   bool // true = Techs осмысленны (в т.ч. пустой список)
}

// HostPersistInput — вход persist одного хоста фермы хостов.
type HostPersistInput struct {
	ProjectID      int32
	IsIP           bool
	TargetKey      string // hostname (домен) или IP-литерал
	Status         string
	IPs            []string // resolved; primary = IPs[0]
	Blocked        bool
	HasIP          bool // r.ip != nil
	CloudflareHint bool
	CFResponded    bool
	Ports          []PortWrite
}

// HostPersistOutcome — итог persist одного хоста.
type HostPersistOutcome struct {
	Created        bool
	FinalHostname  *string
	FinalIPAddress *string
	PortsCreated   int
	PortsUpdated   int
}

// IPPersistInput — вход persist одного адреса фермы IP.
type IPPersistInput struct {
	ProjectID      int32
	IP             string
	Status         string
	Blocked        bool
	HasIP          bool
	CloudflareHint bool
	CFResponded    bool
	Hostnames      []HostnameOut
	Ports          []PortWrite
}

// IPPersistOutcome — итог persist одного адреса.
type IPPersistOutcome struct {
	HostID       int32
	HostCreated  bool
	Attached     bool
	IPExisted    bool
	IsCloudflare *bool
	PortsCreated int
	PortsUpdated int
}

// ScanHostInput — вход persist одного хоста скана портов.
type ScanHostInput struct {
	ProjectID int32
	IsIP      bool
	TargetKey string
	Status    string
	IPs       []string
	OpenPorts []int
}

// ScanHostOutcome — итог persist скана портов одного хоста.
type ScanHostOutcome struct {
	FinalHostname  *string
	FinalIPAddress *string
	PortsCreated   int
	PortsUpdated   int
}

// SkeletonHost — заготовка хоста (create_job фермы хостов).
type SkeletonHost struct {
	Hostname  *string
	IPAddress *string
}

// JSFileInput — вход upsert одного js-файла.
type JSFileInput struct {
	ProjectID     int32
	HostID        int32
	URL           string
	Status        string
	Error         string
	SHA256        string
	SizeBytes     *int32
	ContentType   string
	Endpoints     []string
	SecretCount   int32
	EndpointCount int32
	Secrets       []JSSecretInput
}

// JSSecretInput — секрет js-файла.
type JSSecretInput struct {
	Kind         string
	MatchPreview string
	Snippet      string
	Severity     string
}

// JSFileView — js-файл для эндпоинта списка (с секретами и hostname).
type JSFileView struct {
	ID            int32
	HostID        int32
	Hostname      *string
	URL           string
	Status        string
	SizeBytes     *int32
	ContentType   *string
	SecretCount   int32
	EndpointCount int32
	Endpoints     []string
	Secrets       []JSSecretInput
	FetchedAt     *time.Time
}

// AuditEntry — запись журнала (best-effort). IPAddress для рекона всегда пуст.
type AuditEntry struct {
	UserID     *int32
	Action     string
	EntityType string
	EntityID   *int32
	Details    []byte
	IPAddress  string
}
