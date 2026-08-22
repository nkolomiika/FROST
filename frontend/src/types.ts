export type UserRole = "admin" | "pentester";

export interface User {
  id: number;
  username: string;
  email: string;
  full_name: string | null;
  avatar_url: string | null;
  role: UserRole;
  /**
   * Global project role. "lead" unlocks team management inside the projects the
   * user is a member of; it is configured workspace-wide on the members page.
   */
  project_role: "lead" | "pentester";
  is_active: boolean;
  /** Административная блокировка (мягкое удаление): заблокированный не может войти. */
  is_locked: boolean;
  /** Включена ли двухфакторная аутентификация (TOTP). */
  totp_enabled: boolean;
  password_changed_at: string | null;
  created_at: string;
}

export interface AuthLoginResponse {
  /** true — пароль принят, но нужен второй шаг (POST /auth/2fa/verify). */
  requires_2fa: boolean;
  id?: number;
  username?: string;
  role?: UserRole;
}

export interface TwoFASetupResponse {
  secret: string;
  otpauth_uri: string;
  /** QR-код в виде data:image/png;base64 — рендерит бэкенд. */
  qr_png_data_url: string;
}

export interface PasswordResetResult {
  ok: boolean;
  email_sent_to: string;
  mail_preview_url: string | null;
}

export interface Invitation {
  id: number;
  email: string;
  full_name: string | null;
  role: UserRole;
  project_role: "lead" | "pentester";
  /** pending | accepted | revoked (в списке админа только pending). */
  status: string;
  is_expired: boolean;
  expires_at: string;
  invited_by: number | null;
  created_at: string;
}

export interface InvitationSentResult {
  invitation: Invitation;
  email_sent_to: string;
  mail_preview_url: string | null;
}

/** Проверка ссылки восстановления пароля. */
export interface PasswordResetInfo {
  valid: boolean;
  username?: string | null;
  /** Причина, когда valid=false: "expired" | "used" | "not_found". */
  reason?: string | null;
}

/** Проверка ссылки возврата деактивированного пользователя (страница /reactivate). */
export interface ReactivationInfo {
  valid: boolean;
  username?: string | null;
  /** Причина, когда valid=false: "expired" | "used" | "not_found". */
  reason?: string | null;
}

/** Публичные данные приглашения по токену (страница активации). */
export interface InvitationInfo {
  valid: boolean;
  email?: string | null;
  full_name?: string | null;
  /** Причина, когда valid=false: "expired" | "used" | "not_found". */
  reason?: string | null;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

export type ProjectStatus =
  | "active"
  /** Работы приостановлены — проект не активен, но и не завершён. */
  | "freeze"
  | "handover_to_development"
  | "vulnerability_recheck"
  | "completed"
  | "archived";

export interface Project {
  id: number;
  name: string;
  folder: string;
  description: string | null;
  start_date: string | null;
  end_date: string | null;
  timeline_frozen_at: string | null;
  status: ProjectStatus;
  created_by: number;
  created_at: string;
  updated_at: string;
}

export interface ProjectStats {
  project_id: number;
  status: ProjectStatus;
  hosts_count: number;
  total_findings: number;
  open_findings: number;
}

export interface ProjectFolder {
  id: number;
  name: string;
  path: string;
  parent_id: number | null;
  created_by: number;
  created_at: string;
  updated_at: string;
}

export interface ProjectMember {
  user_id: number;
  username: string;
  email: string;
  role: UserRole;
  /** Глобальная проектная роль пользователя — настраивается на странице /members. */
  project_role: "lead" | "pentester";
  added_at: string;
}

/** Событие ленты активности проекта (`GET /projects/{id}/activity`). */
export interface ProjectActivityItem {
  id: number;
  action: string;
  entity_type: string | null;
  entity_id: number | null;
  user_id: number | null;
  username: string | null;
  /** Для уязвимостей — название и severity; у остальных сущностей null. */
  title: string | null;
  severity: Vulnerability["severity"] | null;
  /** Ссылка на карточку сущности, например /projects/1/vulns/7. */
  url: string | null;
  details: Record<string, unknown> | null;
  created_at: string | null;
}

export interface ProjectNote {
  id: number;
  project_id: number;
  parent_id: number | null;
  title: string;
  content: string | null;
  sort_order: number;
  created_by: number;
  /** Имя автора — бэкенд резолвит его сам, т.к. /users доступен только админу. */
  created_by_username: string | null;
  updated_by: number | null;
  created_at: string;
  updated_at: string;
}

export interface ProjectCredential {
  id: number;
  project_id: number;
  username: string | null;
  /** Расшифрованный пароль — бэкенд шифрует его at rest. */
  password: string;
  /** К какому хосту относятся креды (IP/имя/кластер) — свободная строка. */
  host: string | null;
  created_by: number;
  /** Имя автора — бэкенд резолвит его сам, т.к. /users доступен только админу. */
  created_by_username: string | null;
  created_at: string;
  updated_at: string;
}

export interface ProjectNoteComment {
  id: number;
  project_id: number;
  note_id: number;
  user_id: number;
  username: string;
  avatar_url: string | null;
  content: string;
  created_at: string;
  updated_at: string;
}

/** Имя, в которое резолвится адрес: провенанс + подтверждение прямым резолвом. */
export interface ResolvedHostname {
  hostname: string;
  /** ptr — PTR-запись адреса; project — имя известного хоста проекта. */
  source: string;
  /** Прямой резолв имени вернул этот же адрес. false — имя оставлено как подсказка. */
  confirmed: boolean;
}

export interface HostIpAddress {
  id: number;
  host_id: number;
  ip_address: string;
  label: string | null;
  is_primary: boolean;
  /** Обратный резолв адреса; у строк, заведённых до фермы IP, пустой. */
  hostnames: ResolvedHostname[];
  /** Трёхзначно: true — за CF, false — достоверно нет, null — ещё неизвестно (пробится). */
  is_cloudflare: boolean | null;
  ports: Port[];
  created_at: string;
  updated_at: string;
}

export type OsType =
  | "windows"
  | "linux"
  | "macos"
  | "freebsd"
  | "android"
  | "ios"
  | "other"
  | "unknown";

export const OS_TYPE_OPTIONS: { value: OsType; label: string }[] = [
  { value: "windows", label: "Windows" },
  { value: "linux", label: "Linux" },
  { value: "macos", label: "macOS" },
  { value: "freebsd", label: "FreeBSD" },
  { value: "android", label: "Android" },
  { value: "ios", label: "iOS" },
  { value: "other", label: "Другая" },
];

/** Путь хоста в списочной выдаче: то, чем таблица Recon рисует строку. Полный
 *  Endpoint (описание, query-параметры, тело, заголовки) отдаёт карточка хоста. */
export interface HostEndpointSummary {
  id: number;
  path: string;
  method: HttpMethod | null;
}

export interface Host {
  id: number;
  project_id: number;
  ip_address: string | null;
  ip_addresses: HostIpAddress[];
  /** Приходят вместе со списком — фронт не добирает их запросом на каждый хост. */
  endpoints: HostEndpointSummary[];
  hostname: string | null;
  status: "up" | "down" | "unknown";
  os_type: OsType;
  notes: string | null;
  /** host — обычный хост; ip — служебный родитель адреса из фермы IP. */
  origin: "host" | "ip";
  created_at: string;
  updated_at: string;
}

export interface HostDetails extends Host {
  endpoints: Endpoint[];
}

export interface HostTreeStats {
  portsCount: number;
  ipAddressesCount: number;
  endpointsCount: number;
  vulnerabilitiesCount: number;
}

export interface Port {
  id: number;
  host_id: number;
  ip_address_id: number;
  port_number: number;
  protocol: "tcp" | "udp";
  state: "open" | "closed" | "filtered";
  /** HTTP-код корня `/` от пробива фермы (null — не пробивался/не ответил). */
  http_status: number | null;
  /** Сервисы порта — бэкенд отдаёт их вместе с портом (PortOut.services). */
  services: Service[];
  created_at: string;
  updated_at: string;
}

/** Ответ пробива одного порта фермой (GET /host-farm/jobs/{id}.result.hosts[].ports[]). */
export interface HostFarmPortResult {
  port_number: number;
  protocol: string;
  scheme: string;
  http_status: number | null;
  state: string;
  inferred: boolean;
}

export interface HostFarmHostResult {
  hostname: string | null;
  ip_address: string | null;
  status: string;
  created: boolean;
  ports: HostFarmPortResult[];
}

export interface HostFarmResult {
  targets_parsed: number;
  targets_invalid: number;
  hosts_created: number;
  hosts_updated: number;
  /** Целей пропущено как уже добавленных ранее — их не пробивали заново. */
  hosts_skipped: number;
  ports_created: number;
  ports_updated: number;
  hosts_online: number;
  hosts_offline: number;
  /** Адресов доменов, отдельно пробитых фермой IP (голым запросом к IP). */
  ips_promoted: number;
  hosts: HostFarmHostResult[];
  errors: string[];
}

/** Фоновая задача фермы. status: pending | queued | running | done | failed. */
export interface HostFarmJob {
  id: number;
  project_id: number;
  kind: string;
  status: string;
  targets_total: number | null;
  result: HostFarmResult | null;
  error: string | null;
  created_at: string;
}

/** Результат по одному адресу (GET /ip-farm/jobs/{id}.result.ips[]). */
export interface IpFarmIpResult {
  ip_address: string;
  host_id: number | null;
  hostnames: ResolvedHostname[];
  /** Трёхзначно: true — за CF, false — достоверно нет, null — ещё неизвестно (пробится). */
  is_cloudflare: boolean | null;
  created: boolean;
  /** Адрес подшит к уже существующему хосту, а не к новой строке origin='ip'. */
  attached_to_existing_host: boolean;
  ports: HostFarmPortResult[];
}

export interface IpFarmResult {
  targets_parsed: number;
  targets_invalid: number;
  ips_created: number;
  ips_updated: number;
  /** Адресов пропущено как уже добавленных ранее — их не пробивали заново. */
  ips_skipped: number;
  ports_created: number;
  ports_updated: number;
  ips_online: number;
  ips_offline: number;
  hostnames_found: number;
  /** Hosts created from confirmed PTR names (promoted through the host farm). */
  hosts_promoted: number;
  ips: IpFarmIpResult[];
  errors: string[];
}

export interface JsSecret {
  kind: string;
  match_preview: string;
  snippet: string | null;
  severity: string;
}

/** JS-файл проекта с находками (GET /projects/{id}/js-files). */
export interface JsFile {
  id: number;
  host_id: number;
  hostname: string | null;
  url: string;
  status: string;
  size_bytes: number | null;
  content_type: string | null;
  secret_count: number;
  endpoint_count: number;
  endpoints: string[];
  secrets: JsSecret[];
  fetched_at: string | null;
}

export interface JsFarmResult {
  domains_scanned: number;
  files_found: number;
  files_scanned: number;
  files_failed: number;
  secrets_found: number;
  endpoints_found: number;
  files: { url: string; hostname: string | null; status: string; secret_count: number; endpoint_count: number }[];
  errors: string[];
}

/** Та же таблица задач фермы, result формы JS (kind=js). */
export interface JsFarmJob {
  id: number;
  project_id: number;
  kind: string;
  status: string;
  targets_total: number | null;
  result: JsFarmResult | null;
  error: string | null;
  created_at: string;
}

/** Та же таблица задач, что у HostFarmJob, но result другой формы (kind=ips). */
export interface IpFarmJob {
  id: number;
  project_id: number;
  kind: string;
  status: string;
  targets_total: number | null;
  result: IpFarmResult | null;
  error: string | null;
  created_at: string;
}

/** Пер-проектная конфигурация recon-фермы (recon-стек). Формат провода зеркалит
 *  Go-структуру FarmConfig (snake_case json-теги). */
export interface ReconFarmConfig {
  // Global — высокоуровневые ручки, единственное, что правит пользователь.
  // "both" гоняет пассивный и активный сбор одновременно.
  mode: "passive" | "active" | "both";
  /** Размер словаря брута — FROST маппит на бандл-файл, пользователь файл не выбирает. */
  wordlist_size: "small" | "medium" | "large";
  rate_limit: number;
  concurrency: number;
  port_scan_scope: "top1000" | "all";
  crawl_depth: number;
  // Stage toggles — какие стадии полного прогона включены. Все по умолчанию true.
  // Выключенная стадия пропускается прогоном, а её под-ручки прячутся в UI.
  stage_subdomains: boolean;
  stage_endpoints: boolean;
  stage_js: boolean;
  stage_ports: boolean;
  /** Стадия утечек: GitHub-скан (секреты/почты/домены) гоняется прямо прогоном. */
  stage_leaks: boolean;
  /** Поиск учёток: breach/OSINT-пробив по доменам/почтам. Отдельный этап от Leaks,
   *  но находки уходят в тот же Leaks-стор. */
  stage_account_search: boolean;
  // Subdomains — внутренние флаги инструментов (UI их не показывает, но провод
  // их несёт, чтобы round-trip сохранял значения).
  subfinder: boolean;
  assetfinder: boolean;
  amass_passive: boolean;
  crtsh: boolean;
  ct_time_correlation: boolean;
  active_brute: boolean;
  subs_max_results: number;
  /** Словарь брута сабдоменов. Разрешение на бэке: кастомный id (>0) → путь
   *  забандленного файла (!="") → тир по `wordlist_size`. */
  subdomain_wordlist_id: number;
  /** Путь забандленного словаря сабдоменов ОТНОСИТЕЛЬНО каталога словарей
   *  ("" = не выбран). Действует, только если `subdomain_wordlist_id` == 0. */
  subdomain_wordlist_path: string;
  // Liveness
  dnsx: boolean;
  httpx: boolean;
  httpx_threads: number;
  // JS mining
  js_mine_enabled: boolean;
  trufflehog_verified_only: boolean;
  // Crawl / URLs
  katana: boolean;
  gau: boolean;
  waybackurls: boolean;
  katana_depth: number;
  /** Режим сбора эндпоинтов: passive = архивы (gau+waybackurls), active = краул
   *  (katana) + dir-fuzz (ffuf), both = всё сразу. */
  endpoints_mode: "passive" | "active" | "both";
  /** Словарь для ffuf dir-fuzz (active/both). Разрешение на бэке: кастомный id (>0)
   *  → путь забандленного файла (!="") → пропуск ffuf. */
  endpoints_wordlist_id: number;
  /** Путь забандленного словаря для ffuf ОТНОСИТЕЛЬНО каталога словарей
   *  ("" = не выбран). Действует, только если `endpoints_wordlist_id` == 0. */
  endpoints_wordlist_path: string;
  // Parameters
  param_discovery: boolean;
  // Dir fuzz
  dir_fuzz: boolean;
  fuzz_wordlist: string;
  // Vulns
  nuclei: boolean;
  nuclei_severity: string;
  // Leaks — цели стадии утечек (см. `stage_leaks`). Каждая — построчный список.
  /** GitHub URL репозиториев/организаций для скана секретов. */
  leaks_github: string[];
  /** Домены для breach/OSINT-поиска (источники активируются ключами интеграций). */
  leaks_domains: string[];
  /** E-mail-адреса для breach/OSINT-поиска. */
  leaks_emails: string[];
}

/** Кастомный (загруженный) словарь брута. Несёт метаданные о загруженном файле;
 *  выбирается по `id`. */
export interface Wordlist {
  id: number;
  name: string;
  size_bytes: number;
  lines: number;
  created_at: string;
}

/** Забандленный на диске словарь (SecLists + n0kovo), отдаётся по оригинальному
 *  имени. `path` — путь ОТНОСИТЕЛЬНО каталога словарей (им же выбирается словарь в
 *  FarmConfig), `category` — каталог ("seclists/Discovery/DNS" или "n0kovo"),
 *  `lines` — дешёвый подсчёт строк с потолком. */
export interface WordlistBundled {
  name: string;
  path: string;
  category: string;
  lines: number;
}

/** Ответ списка словарей: реальные забандленные файлы (по путям) + загруженные
 *  кастомные (по id). */
export interface WordlistsResponse {
  bundled: WordlistBundled[];
  custom: Wordlist[];
}

/** Один инструмент, работающий прямо сейчас в полном прогоне фермы. */
export interface FarmRunStep {
  id: number;
  tool: string;
  args: string;
  target: string;
  started_at: string;
}

/** Снимок прогресса полного прогона (host_farm_jobs.progress). */
export interface FarmRunProgress {
  percent: number;
  stage: string;
  steps: FarmRunStep[];
  subs_found: number;
  hosts_found: number;
  ports_found: number;
  done: boolean;
  errors: string[];
}

/** Итог полного прогона фермы (job.result по завершении). */
export interface FarmRunResult {
  mode: string;
  wordlist_size: string;
  roots_scanned: number;
  subdomains_found: number;
  subdomains_new: number;
  hosts_created: number;
  hosts_online: number;
  ports_found: number;
  /** Опциональны — присутствуют, только если прогон гонял соответствующие стадии. */
  endpoints_found?: number;
  js_found?: number;
  sources_used: string[];
  errors: string[];
}

/** Элемент журнала прошлых прогонов фермы (история сканов). `config` — снимок
 *  настроек, с которыми шёл прогон; `result` — его итоговые счётчики (оба могут
 *  быть null, пока прогон не завершился или если снимок не сохранился). */
export interface FarmRunListItem {
  id: number;
  status: string;
  created_at: string;
  finished_at: string | null;
  config: ReconFarmConfig | null;
  result: FarmRunResult | null;
}

/** Задача полного прогона фермы (kind='farm_run') со статусом и прогрессом. */
export interface FarmRunJob {
  id: number;
  project_id: number;
  kind: string;
  status: string;
  targets_total: number | null;
  progress: FarmRunProgress | null;
  result: FarmRunResult | null;
  error: string | null;
  created_at: string;
}

/** Порт застейдженного хоста в отчёте фермы — плоская форма, без вложенных сервисов. */
export interface StagedPort {
  port: number;
  proto: string;
  state: string;
  service: string | null;
  version: string | null;
  http_status: number | null;
}

/** Хост, застейдженный прогоном фермы: ждёт ручного импорта в проект. */
export interface StagedHost {
  id: number;
  hostname: string;
  ip: string | null;
  alive: boolean;
  source: string;
  imported: boolean;
  ports: StagedPort[];
}

/** Эндпоинт, застейдженный прогоном фермы (краул/JS-майнинг): ждёт импорта. */
export interface StagedEndpoint {
  id: number;
  host: string;
  url: string;
  method: string | null;
  source: string;
  imported: boolean;
}

/** JS-находка, застейдженная прогоном фермы (секрет либо добытый эндпоинт). */
export interface StagedJs {
  id: number;
  host: string;
  url: string;
  kind: string;
  value: string;
  severity: string | null;
  imported: boolean;
}

/** Отчёт фермы: результаты прогона на ревью перед ручным импортом. */
export interface FarmReport {
  job_id: number;
  status: string;
  generated_at: string;
  summary: {
    hosts_total: number;
    alive: number;
    ports_total: number;
    imported: number;
    endpoints_total: number;
    js_total: number;
  };
  hosts: StagedHost[];
  endpoints: StagedEndpoint[];
  js: StagedJs[];
}

// ---- Vault: утечки (OSINT-источники + GitHub-скан) ----

/** Одна найденная утечка на ревью перед импортом. `detail` — сырой пейлоад
 *  источника (форма зависит от `source`/`kind`), показываем только развёрнуто. */
export interface Leak {
  id: number;
  source: string;
  kind: string;
  subject: string;
  value: string;
  detail: Record<string, unknown>;
  verified: boolean;
  imported: boolean;
}

/** Отчёт по утечкам проекта: сводка + список находок (мирроринг отчёта фермы). */
export interface LeaksReport {
  summary: {
    total: number;
    verified: number;
    imported: number;
    by_source: Record<string, number>;
  };
  leaks: Leak[];
}

/** Задача GitHub-скана утечек. Бэкенд возвращает как минимум id+status; поля
 *  прогресса опциональны — поллим до терминального статуса. */
export interface LeakScanJob {
  id: number;
  status: string;
  error?: string | null;
  progress?: { found?: number | null; scanned?: number | null } | null;
}

// ---- Workspace: интеграции (API-ключи источников утечек) ----

/** Один известный ключ интеграции. Значение секрета бэкенд не отдаёт никогда —
 *  только флаг «настроен» и время последнего обновления. */
export interface IntegrationKey {
  key_name: string;
  configured: boolean;
  updated_at: string | null;
}

/** Ответ списка интеграций рабочего пространства (только для админа). */
export interface IntegrationsResponse {
  items: IntegrationKey[];
}

export interface Service {
  id: number;
  port_id: number;
  name: string;
  version: string | null;
  banner: string | null;
  created_at: string;
  updated_at: string;
}

export interface EndpointRequestHeader {
  name: string;
  value: string;
}

/** HTTP-метод эндпоинта. Отдельным именем — его используют и Endpoint, и
 *  сводка HostEndpointSummary в списке хостов. */
export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "QUERY";

export interface Endpoint {
  id: number;
  host_id: number;
  path: string;
  method: HttpMethod | null;
  description: string | null;
  query_params: EndpointQueryParam[];
  request_body: string | null;
  request_content_type: string | null;
  request_headers?: EndpointRequestHeader[];
  created_at: string;
  updated_at: string;
}

export interface EndpointQueryParam {
  name: string;
  value: string | null;
  required: boolean;
  description: string | null;
}

export interface Vulnerability {
  id: number;
  project_id: number;
  title: string;
  description: string | null;
  severity: "critical" | "high" | "medium" | "low" | "info";
  status: "open" | "in_progress" | "fixed" | "wont_fix" | "accepted_risk";
  cvss_version: "4.0" | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  cwe_id: string | null;
  workflow_steps: VulnerabilityWorkflowStep[];
  steps_to_reproduce: string | null;
  impact: string | null;
  recommendations: string | null;
  created_by: number;
  /** Имя автора — бэкенд резолвит его сам, т.к. /users доступен только админу. */
  created_by_username: string | null;
  created_at: string;
  updated_at: string;
}

export interface VulnerabilityWorkflowStep {
  id: string;
  description: string | null;
  image_file_ids: number[];
  endpoint_id: number | null;
  endpoint_request_raw: string | null;
}

export interface VulnerabilityAsset {
  id: number;
  vulnerability_id: number;
  asset_type: "host" | "port" | "service" | "endpoint";
  asset_id: number;
}

export interface VulnerabilityFile {
  id: number;
  original_name: string;
  content_type: string;
  size_bytes: number;
  uploaded_by: number;
  uploaded_at: string;
}

export interface Mention {
  user_id: number;
  username: string;
}

export interface VulnerabilityComment {
  id: number;
  vulnerability_id: number;
  user_id: number;
  username: string;
  avatar_url: string | null;
  content: string;
  mentions: Mention[];
  created_at: string;
  updated_at: string;
}

export interface VulnerabilityDetails extends Vulnerability {
  assets: VulnerabilityAsset[];
  files: VulnerabilityFile[];
  comments_count: number;
}

export interface ImportResult {
  hosts_created: number;
  ports_created: number;
  services_created: number;
  endpoints_created: number;
  errors: string[];
}

export interface OpenApiImportResult {
  host_id: number;
  spec_host: string | null;
  endpoints_created: number;
  endpoints_skipped: number;
  errors: string[];
}

/** Поводы для уведомления — ровно те четыре, что создаёт бэкенд (NotificationType). */
export type NotificationKind =
  /** Упоминание @username в комментарии к находке или заметке. */
  | "mention"
  /** Пользователя добавили в проект. */
  | "project_member_added"
  /** Изменился статус находки, которую он завёл. */
  | "vuln_status_changed"
  /** Изменился статус проекта, в котором он состоит. */
  | "project_status_changed";

export interface Notification {
  id: number;
  type: NotificationKind;
  comment_id: number | null;
  note_comment_id: number | null;
  is_read: boolean;
  created_at: string;
  context: {
    vulnerability_id: number | null;
    vulnerability_title: string | null;
    note_id: number | null;
    note_title: string | null;
    project_id: number | null;
    project_name: string | null;
    host_id: number | null;
    /** Кто это сделал: автор комментария либо тот, кто сменил статус. */
    commenter_username: string | null;
    /** Выставленный статус — у уведомлений о смене статуса. */
    status: string | null;
  } | null;
}

export interface AgentApiToken {
  id: number;
  name: string;
  token_prefix: string;
  scopes: string[];
  all_projects: boolean;
  created_by: number;
  expires_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
  created_at: string;
  updated_at: string;
  project_ids: number[];
}

export interface AuditLog {
  id: number;
  user_id: number | null;
  username: string | null;
  action: string;
  entity_type: string | null;
  entity_id: number | null;
  details: Record<string, unknown> | null;
  ip_address: string | null;
  created_at: string;
}
