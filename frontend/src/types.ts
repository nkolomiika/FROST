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

export interface Host {
  id: number;
  project_id: number;
  ip_address: string | null;
  ip_addresses: HostIpAddress[];
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

export interface Endpoint {
  id: number;
  host_id: number;
  path: string;
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "QUERY" | null;
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

/** Связь уязвимости с задачей в Jira (одна на уязвимость). */
export interface JiraIssueLink {
  id: number;
  vulnerability_id: number;
  /** Ключ задачи, напр. "SEC-123"; пусто, пока экспорт не завершён. */
  jira_issue_key: string;
  /** Ссылка на задачу в Jira; пусто, пока экспорт не завершён. */
  jira_issue_url: string;
  status: "pending" | "linked" | "error";
  last_error: string | null;
  created_at: string;
  updated_at: string;
}

/** Глобальная конфигурация Jira (одна на воркспейс), настраивает админ. api_token не возвращается. */
export interface JiraConfig {
  id: number;
  name: string;
  base_url: string;
  email: string;
  default_issue_type: string;
  is_enabled: boolean;
  created_by: number;
  created_at: string;
  updated_at: string;
}

/** Привязка проекта STORM к проекту Jira (ключ), настраивает админ. */
export interface ProjectJiraLink {
  id: number;
  project_id: number;
  jira_project_key: string;
  created_by: number;
  created_at: string;
  updated_at: string;
}
