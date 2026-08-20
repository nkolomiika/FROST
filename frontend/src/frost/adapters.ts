/* Adapters mapping backend payloads to the view shapes the FROST UI renders.
   Kept separate from the screen component so each mapping is unit-testable. */
import { calculateCvssScore, severityFromCvssScore } from "../cvss";
import type {
  Endpoint as ApiEndpoint,
  Host as ApiHost,
  Port as ApiPort,
  Service as ApiService,
  Vulnerability as ApiVulnerability,
  ProjectNote,
  ProjectCredential as ApiProjectCredential,
  ProjectMember as ApiProjectMember,
} from "../types";
import type { CfState, Cred, Endpoint, Host, Member, Method, Note, Severity, Vuln } from "./data";
import { MEMBER_COLORS } from "./tokens";
import { initialsOf, relTime, toDispDate } from "./format";

/** CVSS 4.0 scorer.
 *
 * CVSS 4.0 is scored via the MacroVector lookup tables, not a naive weight sum,
 * so we defer to the spec implementation in ../cvss — the same score the backend
 * computes, so the live preview and the persisted value always agree. */
export function computeCvss4(vector?: string): { score: number; sev: Severity } | null {
  const v = (vector || "").trim();
  if (!/^CVSS:4\.0\//i.test(v)) return null;
  const { score } = calculateCvssScore("4.0", v);
  if (score === null || Number.isNaN(score)) return null;
  return { score, sev: severityFromCvssScore(score) as Severity };
}

/* The backend serialises each port with its services (schemas.py `PortOut.services`),
   but the shared `Port` type in ../types does not declare the field yet. Widen it
   locally rather than reaching outside this module. */
type ApiPortWithServices = ApiPort & { services?: ApiService[] };

export const FROST_METHODS: Method[] = ["GET", "POST", "PUT", "PATCH", "DELETE"];

/** The API also emits HEAD/OPTIONS/null, which Frost's `Method` union has no pill for. */
export function toFrostMethod(m: ApiEndpoint["method"]): Method {
  return m && (FROST_METHODS as string[]).includes(m) ? (m as Method) : "GET";
}

/** A farm job still worth polling. `pending`/`queued` are the recon-worker's
 *  pre-run states — a job sits there until the worker picks it off the queue. */
export function isFarmJobInFlight(status: string): boolean {
  return status === "pending" || status === "queued" || status === "running";
}

/** Ports live under each IP on the backend; Frost shows them flat per host. */
export function toFrostPorts(h: ApiHost): Host["ports"] {
  return h.ip_addresses
    .flatMap((ip) => ip.ports as ApiPortWithServices[])
    .map((p) => ({
      n: p.port_number,
      proto: p.protocol,
      state: p.state,
      svc: p.services?.[0]?.name ?? "",
      techs: (p.services ?? []).map((s) => ({ name: s.name, version: s.version })),
      http: p.http_status ?? null,
    }));
}

/** Host-level CF from its addresses (tri-state): any CF → true; all confirmed-not → false;
 *  otherwise (no addresses / any still unknown) → null. A still-probing host has no
 *  addresses yet, so it reads as unknown rather than "not CF". */
export function hostCf(addrs: { is_cloudflare: boolean | null }[]): CfState {
  if (addrs.some((a) => a.is_cloudflare === true)) return true;
  if (addrs.length > 0 && addrs.every((a) => a.is_cloudflare === false)) return false;
  return null;
}

/** Merge two CF tri-states: any true → true; else any false → false; else unknown. */
export const mergeCf = (a: CfState, b: CfState): CfState =>
  a === true || b === true ? true : a === false || b === false ? false : null;

export function toFrostHost(h: ApiHost, endpoints: Endpoint[] = []): Host {
  return {
    id: h.id,
    host: h.hostname || h.ip_address || "—",
    ip: h.ip_address || "",
    ips: h.ip_addresses.map((a) => a.ip_address),
    ipEntries: h.ip_addresses.map((a) => ({
      ip: a.ip_address,
      hostnames: a.hostnames ?? [],
      cloudflare: a.is_cloudflare ?? null,
    })),
    origin: h.origin === "ip" ? "ip" : "host",
    // Derived, not stored: a host-level column in the DB would need invalidating
    // on every address add/remove, and every address already carries the flag.
    cloudflare: hostCf(h.ip_addresses),
    status: h.status,
    ports: toFrostPorts(h),
    endpoints,
    created: h.created_at,
  };
}

/** Backend workflow steps carry ids/endpoints/images; Frost's editor shows the text only. */
export function toFrostVuln(v: ApiVulnerability, hostName: string): Vuln {
  return {
    id: v.id,
    sev: v.severity,
    title: v.title,
    // Frost speaks the backend's status vocabulary directly — nothing to map.
    status: v.status,
    host: hostName,
    author: v.created_by_username || "—",
    updated: relTime(v.updated_at),
    created: v.created_at,
    steps: v.workflow_steps.map((s) => s.description || "").filter(Boolean),
    description: v.description || "",
    impact: v.impact || "",
    remediation: v.recommendations || "",
    cwe: v.cwe_id || "",
    vector: v.cvss_vector || "",
  };
}

export function toFrostNote(n: ProjectNote): Note {
  return {
    id: n.id,
    title: n.title,
    when: toDispDate((n.updated_at || n.created_at || "").slice(0, 10)),
    excerpt: n.content || "",
    author: n.created_by_username || "—",
  };
}

export function toFrostCred(c: ApiProjectCredential): Cred {
  return {
    id: c.id,
    username: c.username || "",
    password: c.password || "",
    host: c.host || "",
    author: c.created_by_username || "—",
    when: toDispDate((c.updated_at || c.created_at || "").slice(0, 10)),
  };
}

export function toFrostMember(m: ApiProjectMember, idx: number): Member {
  return {
    id: m.user_id,
    initials: initialsOf(m.username),
    name: m.username,
    email: m.email,
    role: m.project_role,
    color: MEMBER_COLORS[idx % MEMBER_COLORS.length],
  };
}
