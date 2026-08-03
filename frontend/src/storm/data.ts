/* Shapes rendered by the STORM UI.
 *
 * This module used to also carry the prototype's seed data (DETAIL / ALL /
 * NOTIFS / ACTIVITY). Everything the UI shows now comes from the backend, so
 * only the types remain — each entity carries its real backend id.
 */

export type PortState = "open" | "filtered" | "closed";
/** QUERY — метод из RFC-драфта httpbis; остальное — обычные глаголы. */
export type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "QUERY";
export type HostStatus = "up" | "down" | "unknown";
/** Global project role — mirrors the backend's User.project_role. */
export type Role = "lead" | "pentester";
/** Workspace-level (account) role — separate from the project role. */
export type WsRole = "admin" | "user";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
/** Mirrors the backend's VulnerabilityStatus verbatim — no lossy re-mapping. */
export type VStatus = "open" | "in_progress" | "fixed" | "wont_fix" | "accepted_risk";
export type ProjectStatus = "active" | "archived";

export interface Port {
  n: number;
  proto: string;
  state: PortState;
  svc: string;
  /** Технологии порта (whatweb): весь стек чипами. Пусто → в карточке «unknown». */
  techs: { name: string; version: string | null }[];
  /** HTTP-код корня `/` от пробива фермы (null — не пробивался/не ответил). */
  http: number | null;
}

export interface Endpoint {
  /** Backend endpoint id — required to delete it through the API. */
  id: number;
  m: Method;
  p: string;
}

/** One address of a host, with what it reverse-resolves to. */
/** Cloudflare tri-state: true — behind CF, false — confirmed not, null — unknown (still probing). */
export type CfState = boolean | null;

export interface IpEntry {
  ip: string;
  /** Names the address resolves to; `confirmed: false` = PTR without a forward match. */
  hostnames: { hostname: string; source: string; confirmed: boolean }[];
  cloudflare: CfState;
}

/** A JS file discovered on a project domain, with what the scan found in it. */
export interface JsFileEntry {
  id: number;
  /** Domain the file was found on — the JS view groups rows by it. */
  host: string;
  /** Host row id the file hangs off — the per-host archive download scopes by it. */
  hostId: number;
  url: string;
  status: string;
  size: number | null;
  secrets: { kind: string; match: string; snippet: string | null; severity: string }[];
  /** Endpoint paths pulled out of the file (stay in the JS view, not Endpoints). */
  endpoints: string[];
}

export interface Host {
  id: number;
  host: string;
  ip: string;
  status: HostStatus;
  /** ISO creation timestamp — drives the cumulative Overview sparkline. */
  created?: string;
  /** Every IP of the host; `ip` above is the primary one. */
  ips: string[];
  /** Same addresses as `ips`, with reverse-resolution and the Cloudflare flag. */
  ipEntries: IpEntry[];
  /** `ip` — imported through the IP farm; such rows are hidden from the hosts table. */
  origin: "host" | "ip";
  /** Host-level CF (tri-state): true if any address is CF, false if all confirmed not,
   *  null if unknown (no addresses yet / still probing). */
  cloudflare: CfState;
  ports: Port[];
  endpoints: Endpoint[];
}

export interface Member {
  /** Backend user id — required to remove the member through the API. */
  id: number;
  initials: string;
  name: string;
  email: string;
  role: Role;
  color: string;
}

export interface Vuln {
  /** Backend vulnerability id — used for deep links (/projects/{p}/vulns/{id}). */
  id: number;
  sev: Severity;
  title: string;
  host: string;
  status: VStatus;
  author: string;
  updated: string;
  /** ISO creation timestamp — drives the cumulative Overview sparkline. */
  created?: string;
  steps?: string[];
  stepImages?: Record<number, string[]>;
  description?: string;
  impact?: string;
  remediation?: string;
  cwe?: string;
  vector?: string;
}

export interface Note {
  /** Backend project-note id. */
  id: number;
  title: string;
  when: string;
  excerpt: string;
  author: string;
}

/** A stored account for the project — the shared username/password vault. */
export interface Cred {
  /** Backend project-credential id. */
  id: number;
  username: string;
  /** Decrypted password — masked in the table until revealed. */
  password: string;
  /** Which host these creds are for (IP / name / cluster) — free text. */
  host: string;
  author: string;
  when: string;
}

/** The open project, assembled from the backend collections — a view, not a store. */
export interface ProjectDetail {
  status: ProjectStatus;
  desc: string;
  start: string;
  end: string;
  /** Percentage of the engagement window elapsed (derived from start/end). */
  progress: number;
  title: string;
  hosts: Host[];
  members: Member[];
  vulns: Vuln[];
  notes: Note[];
  creds: Cred[];
}

export interface WorkspaceUser {
  /** Backend user id — required to call the users API. */
  id: number;
  key: string;
  name: string;
  email: string;
  role: WsRole;
  projectRole: Role;
  /** Деактивирован (мягкое удаление): показывается с бейджем, вход закрыт. */
  locked: boolean;
}

export interface ApiKey {
  id: number;
  name: string;
  key: string;
  scopes: string[];
  created: string;
  /** Дата истечения (уже отформатирована) или null для бессрочного. */
  expires?: string | null;
  /** Доступ ко всем проектам создателя или к явно выбранным. */
  allProjects?: boolean;
  projectCount?: number;
}
