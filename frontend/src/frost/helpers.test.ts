import { describe, expect, it } from "vitest";

import { cap, fstr, initialsOf, kb, toDispDate, toISODate, toggleIn } from "./format";
import { sparkArea } from "./spark";
import { computeCvss4, hostCf, mergeCf, toFrostMethod } from "./adapters";
import { groupActivity } from "./activity";
import type { ProjectActivityItem } from "../types";

describe("format helpers", () => {
  it("cap capitalises the first character", () => {
    expect(cap("hello")).toBe("Hello");
    expect(cap("")).toBe("");
  });

  it("toggleIn adds when absent and removes when present", () => {
    expect(toggleIn([1, 2], 3)).toEqual([1, 2, 3]);
    expect(toggleIn([1, 2, 3], 2)).toEqual([1, 3]);
  });

  it("fstr coerces arrays to empty string, keeps plain strings", () => {
    expect(fstr("x")).toBe("x");
    expect(fstr(["a", "b"])).toBe("");
    expect(fstr(undefined)).toBe("");
  });

  it("round-trips display and ISO dates", () => {
    expect(toISODate("31.12.2026")).toBe("2026-12-31");
    expect(toDispDate("2026-12-31")).toBe("31.12.2026");
    expect(toISODate("")).toBe("");
  });

  it("initialsOf takes two words, else first two letters", () => {
    expect(initialsOf("ivan volkov")).toBe("IV");
    expect(initialsOf("admin")).toBe("AD");
    expect(initialsOf("")).toBe("U");
  });

  it("kb renders human-readable sizes", () => {
    expect(kb(null)).toBe("");
    expect(kb(512)).toBe("512 B");
    expect(kb(2048)).toBe("2 KB");
  });
});

describe("spark geometry", () => {
  it("sparkArea closes the path to the baseline", () => {
    expect(sparkArea("10,5 20,8", 100)).toBe("0,30 10,5 20,8 100,30");
    expect(sparkArea("", 100)).toBe("");
  });
});

describe("adapters", () => {
  it("toFrostMethod falls back to GET for unsupported verbs", () => {
    expect(toFrostMethod("POST")).toBe("POST");
    expect(toFrostMethod("HEAD" as never)).toBe("GET");
    expect(toFrostMethod(null as never)).toBe("GET");
  });

  it("hostCf is a tri-state over address flags", () => {
    expect(hostCf([{ is_cloudflare: true }, { is_cloudflare: false }])).toBe(true);
    expect(hostCf([{ is_cloudflare: false }, { is_cloudflare: false }])).toBe(false);
    expect(hostCf([])).toBe(null);
    expect(hostCf([{ is_cloudflare: null }])).toBe(null);
  });

  it("mergeCf prefers true, then false, else unknown", () => {
    expect(mergeCf(true, false)).toBe(true);
    expect(mergeCf(false, null)).toBe(false);
    expect(mergeCf(null, null)).toBe(null);
  });

  it("computeCvss4 scores 4.0 vectors and rejects others", () => {
    expect(computeCvss4("not-a-vector")).toBeNull();
    expect(computeCvss4("CVSS:3.1/AV:N/AC:L")).toBeNull();
    const r = computeCvss4("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
    expect(r).not.toBeNull();
    expect(r!.score).toBeGreaterThan(0);
    expect(r!.sev).toBe("critical");
  });
});

describe("activity grouping", () => {
  const item = (over: Partial<ProjectActivityItem>): ProjectActivityItem =>
    ({
      id: 1,
      username: "admin",
      action: "CREATE",
      entity_type: "host",
      entity_id: 1,
      title: null,
      severity: null,
      details: {},
      created_at: new Date().toISOString(),
      ...over,
    }) as ProjectActivityItem;

  it("merges same actor+action+type into one card and pluralises the subject", () => {
    const groups = groupActivity([
      item({ id: 1, entity_id: 1, details: { ip_address: "1.1.1.1" } }),
      item({ id: 2, entity_id: 2, details: { ip_address: "1.1.1.2" } }),
    ]);
    expect(groups).toHaveLength(1);
    expect(groups[0].verb).toBe("added");
    expect(groups[0].subject).toBe("2 hosts");
    expect(groups[0].lines).toHaveLength(2);
  });

  it("keeps findings as standalone cards and reports them", () => {
    const groups = groupActivity([
      item({ id: 3, entity_type: "vulnerability", entity_id: 7, title: "SQLi" }),
      item({ id: 4, entity_type: "vulnerability", entity_id: 8, title: "XSS" }),
    ]);
    expect(groups).toHaveLength(2);
    expect(groups[0].verb).toBe("reported");
    expect(groups[0].vulnId).toBe(7);
  });

  it("drops hidden entity types (ports)", () => {
    const groups = groupActivity([item({ id: 5, entity_type: "port", entity_id: 80 })]);
    expect(groups).toHaveLength(0);
  });
});
