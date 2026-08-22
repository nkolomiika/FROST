/* FROST design tokens — the workspace colour system.
   Colour pairs are {bg, color}; single dot/text colours are plain strings. */

import type { HostStatus, Method, PortState, Role, Severity, VStatus, WsRole } from "./data";

export interface ColorPair {
  bg: string;
  color: string;
}

/** Host status dot colours. */
export const STDOT: Record<HostStatus, string> = {
  up: "var(--fr-success)",
  down: "var(--fr-danger)",
  unknown: "var(--fr-warn)",
};

/** Port pill colours by TCP/UDP state. */
export const PORT: Record<PortState, ColorPair> = {
  open: { bg: "var(--fr-success-soft)", color: "var(--fr-success)" },
  filtered: { bg: "var(--fr-warn-soft)", color: "var(--fr-warn)" },
  closed: { bg: "var(--fr-elevated)", color: "var(--fr-text-3)" },
};

/** HTTP method badge colours. */
export const METHOD: Record<Method, ColorPair> = {
  GET: { bg: "var(--fr-success-soft)", color: "var(--fr-success)" },
  POST: { bg: "var(--fr-accent-soft)", color: "var(--fr-accent)" },
  PUT: { bg: "var(--fr-purple-soft)", color: "var(--fr-purple)" },
  PATCH: { bg: "var(--fr-warn-soft)", color: "var(--fr-warn)" },
  DELETE: { bg: "var(--fr-danger-soft)", color: "var(--fr-danger)" },
  QUERY: { bg: "var(--fr-cyan-soft)", color: "var(--fr-cyan)" },
};

/** Severity badge colours. */
export const SEV: Record<Severity, ColorPair> = {
  critical: { bg: "var(--fr-danger-soft)", color: "var(--fr-danger)" },
  high: { bg: "var(--fr-warn-soft)", color: "var(--fr-orange)" },
  medium: { bg: "var(--fr-warn-soft)", color: "var(--fr-warn)" },
  low: { bg: "var(--fr-accent-soft)", color: "var(--fr-accent)" },
  info: { bg: "var(--fr-elevated)", color: "var(--fr-text-3)" },
};

/** Badge colour for a secret found in JS, by its severity. */
export const SECRET_SEV: Record<string, ColorPair> = {
  high: { bg: "var(--fr-danger-soft)", color: "var(--fr-danger)" },
  medium: { bg: "var(--fr-warn-soft)", color: "var(--fr-warn)" },
  low: { bg: "var(--fr-elevated)", color: "var(--fr-text-3)" },
};

/** Vulnerability status dot/text colour. */
export const VSTATUS: Record<VStatus, string> = {
  open: "var(--fr-danger)",
  in_progress: "var(--fr-warn)",
  fixed: "var(--fr-success)",
  wont_fix: "var(--fr-text-3)",
  accepted_risk: "var(--fr-purple)",
};

/** Human labels for the backend's vulnerability statuses. */
export const VSTATUS_LABEL: Record<VStatus, string> = {
  open: "Open",
  in_progress: "In progress",
  fixed: "Fixed",
  wont_fix: "Won't fix",
  accepted_risk: "Accepted risk",
};

/** Statuses in the order they are offered in pickers and filters. */
// Из UI-выбора убран только wont_fix; accepted_risk оставлен. Тип и VSTAT/
// VSTATUS_LABEL для wont_fix сохранены — старые записи с ним ещё отображаются.
export const VSTATUS_ORDER: VStatus[] = ["open", "in_progress", "fixed", "accepted_risk"];

/** A finding still needing work — the "unresolved" filter and the open-count tile. */
export const VSTATUS_OPEN: VStatus[] = ["open", "in_progress"];

/** Default HTTP status shown per method in the endpoints view. */
export const EPSTATUS: Record<Method, string> = {
  GET: "200",
  POST: "201",
  PUT: "200",
  PATCH: "200",
  DELETE: "204",
  QUERY: "200",
};

/** Project status chip: label + colours + dot. Mirrors the backend's ProjectStatus. */
export const PROJ_STATUS: Record<string, { label: string; bg: string; color: string; dot: string }> = {
  active: { label: "Active", bg: "var(--fr-success-soft)", color: "var(--fr-success)", dot: "var(--fr-success)" },
  // Заморожен — голубой.
  freeze: { label: "Freeze", bg: "var(--fr-cyan-soft)", color: "var(--fr-cyan)", dot: "var(--fr-cyan)" },
  handover_to_development: { label: "Handover to dev", bg: "var(--fr-purple-soft)", color: "var(--fr-purple)", dot: "var(--fr-purple)" },
  vulnerability_recheck: { label: "Recheck", bg: "var(--fr-accent-soft)", color: "var(--fr-accent)", dot: "var(--fr-accent-2)" },
  completed: { label: "Completed", bg: "var(--fr-warn-soft)", color: "var(--fr-warn)", dot: "var(--fr-warn)" },
  archived: { label: "Archived", bg: "var(--fr-elevated)", color: "var(--fr-text-3)", dot: "var(--fr-text-faint)" },
};

/** Project role badge colours. */
export const ROLE: Record<Role, ColorPair> = {
  lead: { bg: "var(--fr-accent-soft)", color: "var(--fr-accent)" },
  pentester: { bg: "var(--fr-success-soft)", color: "var(--fr-success)" },
};

/** Workspace (account) role badge colours. */
export const WS_ROLE: Record<WsRole, ColorPair> = {
  admin: { bg: "var(--fr-purple-soft)", color: "var(--fr-purple)" },
  user: { bg: "var(--fr-elevated)", color: "var(--fr-text-3)" },
};

export const WS_ROLE_LABEL: Record<WsRole, string> = {
  admin: "Admin",
  user: "User",
};

/** Activity log tag colours (dark chips — dark in both themes by design). */
export const ATAG: Record<string, ColorPair> = {
  new: { bg: "var(--fr-tag-green-bg)", color: "var(--fr-tag-green)" },
  down: { bg: "var(--fr-tag-red-bg)", color: "var(--fr-tag-red)" },
  changed: { bg: "var(--fr-tag-amber-bg)", color: "var(--fr-tag-amber)" },
  dns: { bg: "var(--fr-tag-blue-bg)", color: "var(--fr-tag-blue)" },
};

/** Host-status summary tiles. */
export const HSTAT: Record<HostStatus, { label: string; color: string; bg: string }> = {
  up: { label: "Up", color: "var(--fr-success)", bg: "var(--fr-success-soft)" },
  down: { label: "Down", color: "var(--fr-danger)", bg: "var(--fr-danger-soft)" },
  unknown: { label: "Unknown", color: "var(--fr-warn)", bg: "var(--fr-warn-soft)" },
};

/** Vulnerability-status summary tiles. */
export const VSTAT: Record<VStatus, { label: string; color: string; bg: string }> = {
  open: { label: "Open", color: "var(--fr-danger)", bg: "var(--fr-danger-soft)" },
  in_progress: { label: "In progress", color: "var(--fr-warn)", bg: "var(--fr-warn-soft)" },
  fixed: { label: "Fixed", color: "var(--fr-success)", bg: "var(--fr-success-soft)" },
  wont_fix: { label: "Won't fix", color: "var(--fr-text-3)", bg: "var(--fr-elevated)" },
  accepted_risk: { label: "Accepted risk", color: "var(--fr-purple)", bg: "var(--fr-purple-soft)" },
};

/** Project-list "findings" badge colours. */
export const FINDING_SEV: Record<"none" | "med" | "high", { fBg: string; fColor: string; fDot: string }> = {
  none: { fBg: "var(--fr-elevated)", fColor: "var(--fr-text-3)", fDot: "var(--fr-text-faint)" },
  med: { fBg: "var(--fr-warn-soft)", fColor: "var(--fr-warn)", fDot: "var(--fr-warn)" },
  high: { fBg: "var(--fr-danger-soft)", fColor: "var(--fr-danger)", fDot: "var(--fr-danger)" },
};

/* Scopes агент-токенов /api/v2. ЕДИНСТВЕННЫЙ источник истины — бэкенд
   (AgentTokenService.ALLOWED_SCOPES / require_agent_scope). Здесь только те права,
   что реально существуют в БД и проверяются на запросе — никаких выдуманных. */
export const API_SCOPES = ["projects:read", "assets:read", "vulns:read", "vulns:write", "notes:read", "notes:write", "leaks:read"];

/** Человекочитаемые подписи scopes для UI выпуска ключа. */
export const API_SCOPE_LABELS: Record<string, string> = {
  "projects:read": "Projects — read",
  "assets:read": "Assets (hosts/IPs/ports/endpoints/JS) — read",
  "vulns:read": "Vulnerabilities — read",
  "vulns:write": "Vulnerabilities — write",
  "notes:read": "Notes — read",
  "notes:write": "Notes — write",
  "leaks:read": "Leaks — read",
};

/** Avatar colour rotation used when adding new project members. */
export const MEMBER_COLORS = ["var(--fr-accent)", "var(--fr-success)", "var(--fr-purple)", "var(--fr-orange)"];

export type EditorType = "host" | "ip" | "endpoint" | "vuln" | "note" | "member" | "cred";

export interface EditorField {
  k: string;
  label: string;
  /** `combo` = free-text input with type-to-search suggestions; use it instead of
      `select` when the option list can grow long (hosts, users). */
  type: "text" | "textarea" | "select" | "tags" | "combo";
  ph?: string;
  opts?: string[];
}

/* Every field here must map onto something the API stores — a field with no
   backend counterpart silently loses whatever the user typed on the next reload.
   `opts: []` is filled in at runtime from live data (hosts, workspace users). */
export const EDITOR_FIELDS: Record<EditorType, EditorField[]> = {
  // Only used for EDITing an existing host now — new hosts come from the "Add hosts"
  // import (server-side probe). Just the hostname: status is set automatically by
  // the probe, and ports hang off an IP the probe materialises.
  host: [{ k: "host", label: "Hostname", type: "text", ph: "e.g. app.acme-corp.com" }],
  // An IP always belongs to a host; `opts` is filled from the project's hosts.
  // There is no per-IP status in the backend — the IPs view shows the parent
  // host's, so this field writes through to the host (see saveIpEditor).
  ip: [
    { k: "hostName", label: "Host", type: "combo", ph: "Start typing a hostname…", opts: [] },
    { k: "ip", label: "IP address", type: "text", ph: "e.g. 10.0.0.7" },
    { k: "status", label: "Status", type: "select", opts: ["up", "down", "unknown"] },
  ],
  endpoint: [
    { k: "hostName", label: "Host", type: "combo", ph: "Start typing a hostname…", opts: [] },
    { k: "method", label: "Method", type: "select", opts: ["GET", "POST", "PUT", "PATCH", "DELETE"] },
    { k: "path", label: "Path", type: "text", ph: "e.g. /api/users" },
  ],
  vuln: [
    { k: "title", label: "Title", type: "text", ph: "e.g. Stored XSS in comments" },
    // Searchable: a project can have many hosts, and a plain select is unusable then.
    { k: "host", label: "Affected host", type: "combo", ph: "Start typing a hostname…", opts: [] },
    // Only on "add" — see saveVulnEditor: severity follows the CVSS vector afterwards.
    { k: "sev", label: "Severity", type: "select", opts: ["critical", "high", "medium", "low", "info"] },
    { k: "status", label: "Status", type: "select", opts: ["open", "in progress", "resolved"] },
  ],
  note: [
    { k: "title", label: "Title", type: "text", ph: "Note title" },
    { k: "excerpt", label: "Content", type: "textarea", ph: "Write your note…" },
  ],
  // The lead/pentester role is global and is set on the workspace Members page —
  // adding someone here only links an existing user to the project. Searchable:
  // a workspace can hold far more people than a dropdown is usable for.
  member: [{ k: "userKey", label: "User", type: "combo", ph: "Start typing a username…", opts: [] }],
  // Cred vault: a shared username/password for the project. On edit the password
  // is left blank = keep the stored one.
  cred: [
    { k: "username", label: "Username", type: "text", ph: "account username" },
    { k: "password", label: "Password", type: "text", ph: "account password" },
    // Binds to a project host — same validated picker as members (the save
    // resolves the value against the project's hosts). `opts` filled at runtime.
    { k: "host", label: "Host", type: "combo", ph: "Start typing a hostname…", opts: [] },
  ],
};

export const TYPELABEL: Record<EditorType, string> = {
  host: "host",
  ip: "IP address",
  endpoint: "endpoint",
  vuln: "vulnerability",
  note: "note",
  member: "member",
  cred: "credential",
};
