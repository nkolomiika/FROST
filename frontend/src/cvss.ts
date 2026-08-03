import { calculateBaseScore } from "@rohit_coder/cvss";

import type { Vulnerability } from "./types";

export function normalizeCvssVector(version: Vulnerability["cvss_version"], vector: string | null | undefined): string | null {
  if (!version || !vector) {
    return null;
  }
  const raw = vector.trim();
  if (!raw) {
    return null;
  }
  const normalized = raw.replace(/^CVSS:\d\.\d\//, `CVSS:${version}/`);
  return normalized.startsWith("CVSS:") ? normalized : `CVSS:${version}/${normalized.replace(/^\/+/, "")}`;
}

export function calculateCvssScore(
  version: Vulnerability["cvss_version"],
  vector: string | null | undefined
): { normalizedVector: string | null; score: number | null } {
  const normalizedVector = normalizeCvssVector(version, vector);
  if (!normalizedVector) {
    return { normalizedVector: null, score: null };
  }
  try {
    return {
      normalizedVector,
      score: calculateBaseScore(normalizedVector),
    };
  } catch {
    return {
      normalizedVector,
      score: null,
    };
  }
}

export function severityFromCvssScore(
  score: number | null | undefined,
  fallback: Vulnerability["severity"] = "info"
): Vulnerability["severity"] {
  if (score === null || score === undefined || Number.isNaN(score)) {
    return fallback;
  }
  if (score >= 9.0) {
    return "critical";
  }
  if (score >= 7.0) {
    return "high";
  }
  if (score >= 4.0) {
    return "medium";
  }
  if (score > 0) {
    return "low";
  }
  return "info";
}
