/* Project activity feed: groups raw audit items into human-readable cards.
   One card per action per entity type ("admin added 3 IP addresses"). */
import type { ProjectActivityItem } from "../types";
import type { Severity } from "./data";
import { relTime } from "./format";

/* Marker + colour for the dark event panel: green + = added, red − = removed,
   amber ~ = changed — tuned to the FROST palette. */
const ACT_TONE = {
  add: { mark: "+", color: "var(--fr-success)" },
  change: { mark: "~", color: "var(--fr-warn)" },
  remove: { mark: "−", color: "var(--fr-danger)" },
  info: { mark: "•", color: "var(--fr-accent-muted)" },
} as const;
export type ActTone = (typeof ACT_TONE)[keyof typeof ACT_TONE];

/** Severity chip on the dark panel — filled with the severity's own colour. */
export const ACT_SEV: Record<Severity, string> = {
  critical: "var(--fr-danger)",
  high: "var(--fr-orange)",
  medium: "var(--fr-warn)",
  low: "var(--fr-accent)",
  info: "var(--fr-text-3)",
};

/** Beyond this many lines a card collapses and offers "Show more". */
export const ACT_LINE_LIMIT = 10;

export interface ActivityLine {
  key: string;
  text: string;
  severity?: Severity | null;
}
export interface ActivityGroup {
  key: string;
  actor: string;
  /** Reads as one sentence with `subject`: "admin added 3 IP addresses". */
  verb: string;
  subject: string;
  tone: ActTone;
  time: string;
  lines: ActivityLine[];
  /** Findings are standalone cards, so the card links to that one finding. */
  vulnId?: number | null;
  /** Farm cards ("added N hosts"): recon-export scope to expand into, or null. */
  farmScope?: string | null;
}

// Фарм-события несут список добавленных объектов в details.items — разворачиваем
// его в строки ленты («admin added 8 hosts» + перечисление).
const FARM_NOUN: Record<string, [string, string]> = {
  host_farm: ["host", "hosts"],
  ip_farm: ["IP address", "IP addresses"],
  js_farm: ["JS file", "JS files"],
  sub_farm: ["subdomain", "subdomains"],
};
// Куда ведёт «показать все» — scope recon-экспорта по типу (null → обычный модал).
const FARM_SCOPE: Record<string, string | null> = {
  host_farm: "hosts",
  ip_farm: "ips",
  js_farm: null,
  sub_farm: null,
};
const farmItems = (a: ProjectActivityItem): string[] => {
  const v = a.details?.items;
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
};

/** Human noun per entity type, singular/plural. Ports are deliberately absent —
    they are excluded from the feed (see ACT_HIDDEN). */
const ACT_NOUN: Record<string, [string, string]> = {
  vulnerability: ["finding", "findings"],
  host: ["host", "hosts"],
  host_ip_address: ["IP address", "IP addresses"],
  ip_address: ["IP address", "IP addresses"],
  service: ["service", "services"],
  endpoint: ["endpoint", "endpoints"],
  project_note: ["note", "notes"],
  note: ["note", "notes"],
  project_credential: ["credential", "credentials"],
  project: ["project", "projects"],
  project_member: ["member", "members"],
  member: ["member", "members"],
  comment: ["comment", "comments"],
  note_comment: ["comment", "comments"],
};

/** Entity types the feed never shows: ports are too noisy to be worth a row. */
const ACT_HIDDEN = new Set(["port"]);
/** Entity types that are always their own card, never merged with siblings. */
const ACT_STANDALONE = new Set(["vulnerability", "project", "host_farm", "ip_farm", "js_farm", "sub_farm"]);

const actDetail = (a: ProjectActivityItem, k: string): string => {
  const v = a.details?.[k];
  return typeof v === "string" ? v : typeof v === "number" ? String(v) : "";
};

/** Resolves an entity id to a display name — see `activityLine`'s fallback. */
export type ActivityResolver = (entityType: string | null, entityId: number | null) => string | null;

/* One feed line: just the thing that was touched. The card header already says
   what kind of objects these are ("added 3 IP addresses"), so the lines carry no
   HOST/IP/ENDPOINT tag — only a coloured +/−/~ marker for added/removed/changed.

   CREATE events carry the entity in their audit details; UPDATE/DELETE ones do
   not, so the name is resolved from the loaded project data instead of printing
   a meaningless "#12". */
function activityLine(a: ProjectActivityItem, resolve: ActivityResolver): ActivityLine {
  const base = { key: String(a.id) };
  const fallback = resolve(a.entity_type, a.entity_id) ?? (a.entity_id != null ? `#${a.entity_id}` : "—");
  switch (a.entity_type) {
    case "vulnerability":
      // A deleted finding cannot be enriched (`title`) or resolved — its name is
      // whatever the DELETE event recorded at the time.
      return { ...base, text: a.title || actDetail(a, "title") || fallback, severity: a.severity ?? (actDetail(a, "severity") as Severity) ?? null };
    case "host": {
      const ip = actDetail(a, "ip_address");
      const name = actDetail(a, "hostname") || ip || fallback;
      return { ...base, text: ip && name !== ip ? `${name} · ${ip}` : name };
    }
    case "host_ip_address":
    case "ip_address":
      // The label (external / internal / mgmt) adds nothing here — just the address.
      return { ...base, text: actDetail(a, "ip_address") || fallback };
    case "service":
      return { ...base, text: actDetail(a, "service") || actDetail(a, "name") || fallback };
    case "endpoint":
      return { ...base, text: actDetail(a, "endpoint") || actDetail(a, "path") || fallback };
    case "project_note":
    case "note":
      return { ...base, text: a.title || actDetail(a, "title") || fallback };
    case "project_credential": {
      // The audit event carries username + host (never the password) — the feed
      // line reads "{username} for {host}", with the +/−/~ marker from the action.
      const who = actDetail(a, "username") || "credential";
      const host = actDetail(a, "host");
      return { ...base, text: host ? `${who} for ${host}` : who };
    }
    case "project":
      return { ...base, text: actDetail(a, "project") || a.title || fallback };
    case "project_member":
    case "member":
      return { ...base, text: actDetail(a, "username") || actDetail(a, "user") || fallback };
    default:
      return { ...base, text: a.title || fallback };
  }
}

/** What the action applied to, straight after the verb: "3 IP addresses", "finding". */
function activitySubject(type: string, n: number): string {
  const noun = ACT_NOUN[type] ?? [type.replace(/_/g, " "), `${type.replace(/_/g, " ")}s`];
  return n === 1 ? noun[0] : `${n} ${noun[1]}`;
}

/* One card per action *per entity type*: adding hosts, IPs and endpoints are
   separate actions and never share a card. Findings and projects are always
   standalone — each reported finding is its own entry. Ports are dropped. */
export function groupActivity(items: ProjectActivityItem[], resolve: ActivityResolver = () => null): ActivityGroup[] {
  const groups: ActivityGroup[] = [];
  let bucket: ProjectActivityItem[] = [];
  const flush = () => {
    if (!bucket.length) return;
    const first = bucket[0];
    const type = first.entity_type || "event";
    // Фарм-события — своя карточка со списком добавленных объектов из details.items.
    const farmNoun = FARM_NOUN[type];
    if (farmNoun) {
      const items = farmItems(first);
      groups.push({
        key: `g${first.id}`,
        actor: first.username || "System",
        verb: "added",
        subject: items.length === 1 ? farmNoun[0] : `${items.length} ${farmNoun[1]}`,
        tone: ACT_TONE.add,
        time: relTime(first.created_at),
        lines: items.map((name, i) => ({ key: `${first.id}-${i}`, text: name })),
        vulnId: null,
        farmScope: FARM_SCOPE[type] ?? null,
      });
      bucket = [];
      return;
    }
    const tone =
      first.action === "CREATE" ? ACT_TONE.add
      : first.action === "DELETE" ? ACT_TONE.remove
      : first.action === "UPDATE" ? ACT_TONE.change
      : ACT_TONE.info;
    // Findings are "reported"; everything else is added / updated / removed.
    const verb =
      first.action === "CREATE" ? (type === "vulnerability" ? "reported" : "added")
      : first.action === "UPDATE" ? "updated"
      : first.action === "DELETE" ? "removed"
      : first.action.toLowerCase().replace(/_/g, " ");
    groups.push({
      key: `g${first.id}`,
      actor: first.username || "System",
      verb,
      subject: activitySubject(type, bucket.length),
      tone,
      time: relTime(first.created_at),
      lines: bucket.map((a) => activityLine(a, resolve)),
      // Findings are standalone, so the card carries exactly one finding to link to.
      vulnId: type === "vulnerability" ? first.entity_id : null,
    });
    bucket = [];
  };
  items
    .filter((a) => !ACT_HIDDEN.has(a.entity_type || ""))
    .forEach((a) => {
      const prev = bucket[0];
      const breaks =
        prev != null &&
        (prev.username !== a.username ||
          prev.action !== a.action ||
          prev.entity_type !== a.entity_type ||
          ACT_STANDALONE.has(a.entity_type || ""));
      if (breaks) flush();
      bucket.push(a);
    });
  flush();
  return groups;
}

/** Percentage of the engagement window that has elapsed (the overview progress bar). */
export function elapsedPct(startISO: string, endISO: string): number {
  const start = Date.parse(startISO);
  const end = Date.parse(endISO);
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) return 0;
  const pct = ((Date.now() - start) / (end - start)) * 100;
  return Math.max(0, Math.min(100, Math.round(pct)));
}
