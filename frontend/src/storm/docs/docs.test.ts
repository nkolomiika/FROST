import { describe, it, expect } from "vitest";
import { DOC_CHAPTERS, DOC_GROUPS, chaptersForRole } from "./index";

describe("документация /docs: ролевая видимость", () => {
  it("обычный пользователь не видит админских глав (скрытие функций админа)", () => {
    const visible = chaptersForRole(false);
    expect(visible.length).toBeGreaterThan(0);
    // ключевое требование: никаких админских глав
    expect(visible.some((c) => c.audience === "admin")).toBe(false);
    // документ «Пользователь» доступен, Agent API — тоже (токены выпускает любой)
    expect(visible.some((c) => c.audience === "user")).toBe(true);
    expect(visible.some((c) => c.audience === "agent")).toBe(true);
  });

  it("администратор видит все главы", () => {
    expect(chaptersForRole(true)).toEqual(DOC_CHAPTERS);
    // в реестре присутствуют все три аудитории из DOC_GROUPS
    for (const g of DOC_GROUPS) {
      expect(DOC_CHAPTERS.some((c) => c.audience === g.audience)).toBe(true);
    }
  });

  it("у каждой главы непустые заголовок и тело (проверяет ?raw-импорты)", () => {
    for (const c of DOC_CHAPTERS) {
      expect(c.title.trim().length).toBeGreaterThan(0);
      expect(c.body.trim().length).toBeGreaterThan(0);
    }
  });

  it("идентификаторы глав уникальны", () => {
    const ids = DOC_CHAPTERS.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
