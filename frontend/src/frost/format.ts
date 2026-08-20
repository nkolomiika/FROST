/* Small pure formatting/utility helpers shared across the FROST workspace.
   No React, no domain types — just string/date/array shaping. */

/** Stop an event from bubbling (used on nested clickable rows). */
export const stop = (e: { stopPropagation: () => void }) => e.stopPropagation();

/** Capitalise the first character. */
export const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

/** Multi-select filter toggle: add the value if absent, drop it if already held. */
export const toggleIn = <T,>(arr: T[], v: T): T[] =>
  arr.includes(v) ? arr.filter((x) => x !== v) : [...arr, v];

/** Coerce an editor-form value (string or tag-array) to a plain string. */
export const fstr = (v: string | string[] | undefined): string => (typeof v === "string" ? v : "");

/** dd.mm.yyyy → yyyy-mm-dd (for <input type=date>). */
export const toISODate = (s?: string): string => {
  if (!s) return "";
  const m = String(s).match(/^(\d{2})\.(\d{2})\.(\d{4})$/);
  return m ? `${m[3]}-${m[2]}-${m[1]}` : s;
};

/** yyyy-mm-dd → dd.mm.yyyy (for display). */
export const toDispDate = (s?: string): string => {
  if (!s) return "";
  const m = String(s).match(/^(\d{4})-(\d{2})-(\d{2})$/);
  return m ? `${m[3]}.${m[2]}.${m[1]}` : s;
};

/** Relative "time ago" from an ISO timestamp. */
export function relTime(iso?: string | null): string {
  if (!iso) return "";
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} h ago`;
  const d = Math.floor(h / 24);
  if (d === 1) return "Yesterday";
  if (d < 30) return `${d} days ago`;
  return `${Math.floor(d / 30)} mo ago`;
}

/** Two-letter avatar initials from a display name (Latin/Cyrillic/digits). */
export function initialsOf(name: string): string {
  const parts = name.trim().split(/[^A-Za-zА-Яа-яЁё0-9]+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return (parts[0] || "U").slice(0, 2).toUpperCase();
}

/** File name from a URL — list column and card title show it, not the whole path. */
export const fileBase = (url: string) => url.split("/").pop() || url;

/** Human-readable file size. */
export const kb = (n: number | null) => (n == null ? "" : n < 1024 ? `${n} B` : `${Math.round(n / 1024)} KB`);
