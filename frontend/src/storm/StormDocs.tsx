/* Раздел /docs внутри Storm — пользовательская документация.
 *
 * Layout в стиле dev-портала документации: слева сайдбар с поиском и деревом
 * «папка (документ) → страницы», справа — либо лендинг с карточками категорий,
 * либо тело выбранной главы (Markdown). Ролевая видимость: `isAdmin` решает,
 * какие документы видны (chaptersForRole в ./docs) — обычный пользователь не
 * видит документ «Администратор».
 *
 * Цвета — фирменные Storm (синий акцент #2E5FBF), не как в референсе. Тело
 * главы переиспользует markdown-стили редактора заметок (.stormmd-input в
 * storm.css). Ленивый компонент (default export), как StormMarkdownEditor. */
import { useMemo, useState, type ReactNode } from "react";
import ReactMarkdown from "react-markdown";
import { markdownUrlTransform, normalizeMarkdownForRender } from "../markdownUrlTransform";
import { Icon } from "./icons";
import { DOC_GROUPS, chaptersForRole, type DocChapter } from "./docs";

interface Props {
  isAdmin: boolean;
  /** Переход по крошке «Workspace» — как на остальных страницах воркспейса. */
  onNavigateWorkspace?: () => void;
}

const ACCENT = "var(--st-accent)";

/** Русское склонение: 1 страница / 2 страницы / 5 страниц. */
function pagesWord(n: number): string {
  const m10 = n % 10;
  const m100 = n % 100;
  const word = m10 === 1 && m100 !== 11 ? "страница" : m10 >= 2 && m10 <= 4 && (m100 < 10 || m100 >= 20) ? "страницы" : "страниц";
  return `${n} ${word}`;
}

/** Выдержка из тела главы вокруг первого совпадения — чтобы было видно, ЧЕМ
 *  нашлось при поиске по содержимому. Markdown-разметка вычищается для читаемости. */
function bodySnippet(body: string, q: string): string | null {
  const idx = body.toLowerCase().indexOf(q);
  if (idx === -1) return null;
  const start = Math.max(0, idx - 48);
  const end = Math.min(body.length, idx + q.length + 96);
  const cleaned = body
    .slice(start, end)
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, "$1") // ссылки/картинки → текст
    .replace(/[`#>*_|[\]]/g, " ") // прочий markdown-шум
    .replace(/\s+/g, " ")
    .trim();
  return (start > 0 ? "… " : "") + cleaned + (end < body.length ? " …" : "");
}

/** Подсвечивает вхождения запроса (регистронезависимо) в тексте. */
function highlight(text: string, q: string): ReactNode {
  if (!q) return text;
  const lower = text.toLowerCase();
  const out: ReactNode[] = [];
  let i = 0;
  let key = 0;
  while (i < text.length) {
    const at = lower.indexOf(q, i);
    if (at === -1) {
      out.push(text.slice(i));
      break;
    }
    if (at > i) out.push(text.slice(i, at));
    out.push(
      <mark key={key++} style={{ background: "var(--st-warn-soft)", color: "inherit", borderRadius: 3, padding: "0 1px" }}>
        {text.slice(at, at + q.length)}
      </mark>
    );
    i = at + q.length;
  }
  return out;
}

export function StormDocs({ isAdmin, onNavigateWorkspace }: Props) {
  const visible = useMemo(() => chaptersForRole(isAdmin), [isAdmin]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});

  const q = query.trim().toLowerCase();
  // Поиск по одному полю ищет и в названии раздела, и в его содержимом.
  const matches = (c: DocChapter) => !q || c.title.toLowerCase().includes(q) || c.body.toLowerCase().includes(q);

  // Документы (группы) в порядке DOC_GROUPS, только с видимыми главами; при
  // активном поиске главы фильтруются, пустые группы скрываются.
  const groups = DOC_GROUPS.map((g) => ({
    ...g,
    chapters: visible.filter((c) => c.audience === g.audience && matches(c)),
  })).filter((g) => g.chapters.length > 0);

  const active: DocChapter | null = activeId ? visible.find((c) => c.id === activeId) ?? null : null;
  const activeGroup = active ? DOC_GROUPS.find((g) => g.audience === active.audience) : undefined;

  const goHome = () => setActiveId(null);
  const openCategory = (audience: string) => {
    const first = visible.find((c) => c.audience === audience);
    if (first) setActiveId(first.id);
  };
  const toggleGroup = (audience: string) => setCollapsed((s) => ({ ...s, [audience]: !s[audience] }));

  // Совпадения в названии — выше совпадений только по тексту (сортировка стабильна).
  const searchResults = q
    ? visible.filter(matches).sort((a, b) => Number(b.title.toLowerCase().includes(q)) - Number(a.title.toLowerCase().includes(q)))
    : [];

  return (
    <div className="route stdoc" style={{ display: "flex", alignItems: "flex-start", width: "100%", minHeight: "100%" }}>
      <style>{`
        .stdoc-nav { transition: background .12s ease, color .12s ease; }
        .stdoc-nav:hover { background: var(--st-elevated); }
        .stdoc-card { transition: border-color .14s ease, box-shadow .14s ease, transform .14s ease; }
        .stdoc-card:hover { border-color: var(--st-border-strong); box-shadow: 0 6px 18px var(--st-shadow); transform: translateY(-1px); }
        .stdoc-search:focus-within { border-color: var(--st-focus-border); box-shadow: 0 0 0 3px var(--st-focus-ring); background: var(--st-surface); }
        .stdoc-crumb { transition: color .12s ease; }
        .stdoc-crumb:hover { color: var(--st-accent); }
        .stdoc-chev { transition: background .12s ease; }
        .stdoc-chev:hover { background: var(--st-hover); }
      `}</style>

      {/* ------- сайдбар ------- */}
      <aside
        style={{
          flex: "none",
          width: 284,
          position: "sticky",
          top: 0,
          maxHeight: "100vh",
          overflow: "auto",
          padding: "26px 16px 24px 24px",
          borderRight: "1px solid var(--st-divider)",
        }}
      >
        {/* заголовок */}
        <div className="stdoc-nav clk" onClick={goHome} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 6px", borderRadius: 9, marginBottom: 14 }}>
          <Icon name="doc" size={20} color={ACCENT} sw={2} />
          <span style={{ font: "800 15px Inter,sans-serif", color: "var(--st-text)", letterSpacing: "-.2px" }}>Docs</span>
        </div>

        {/* поиск */}
        <label className="stdoc-search" style={{ display: "flex", alignItems: "center", gap: 9, height: 38, padding: "0 12px", background: "var(--st-elevated)", border: "1px solid var(--st-border-light)", borderRadius: 10, marginBottom: 16 }}>
          <Icon name="search" size={15} color="var(--st-text-faint)" sw={2} />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Поиск по Docs…"
            style={{ flex: 1, border: "none", outline: "none", background: "transparent", font: "500 13px Inter,sans-serif", color: "var(--st-text)" }}
          />
        </label>

        {/* дерево */}
        {groups.map((g) => {
          const isCollapsed = !!collapsed[g.audience] && !q;
          return (
            <div key={g.audience} style={{ marginBottom: 6 }}>
              <div
                className="stdoc-nav clk"
                onClick={goHome}
                style={{ display: "flex", alignItems: "center", gap: 9, padding: "8px 8px", borderRadius: 9, cursor: "pointer" }}
              >
                {/* Шеврон — только свернуть/развернуть (клик по имени папки уводит на главную Docs). */}
                <span
                  className="stdoc-chev clk"
                  onClick={(e) => { e.stopPropagation(); toggleGroup(g.audience); }}
                  style={{ display: "flex", alignItems: "center", justifyContent: "center", width: 20, height: 20, borderRadius: 5, flex: "none" }}
                >
                  <Icon name="chevron-down" size={14} color="var(--st-text-faint)" sw={2.4} style={{ transition: "transform .24s ease", transform: isCollapsed ? "rotate(-90deg)" : "none" }} />
                </span>
                <Icon name="folder" size={17} color={ACCENT} sw={2} style={{ flex: "none" }} />
                <span style={{ font: "700 13px Inter,sans-serif", color: "var(--st-text)" }}>{g.title}</span>
              </div>
              {/* Плавное сворачивание: grid-rows 1fr↔0fr анимирует высоту без замера. */}
              <div style={{ display: "grid", gridTemplateRows: isCollapsed ? "0fr" : "1fr", transition: "grid-template-rows .24s ease" }}>
                <div style={{ overflow: "hidden", minHeight: 0 }}>
                  <div style={{ marginLeft: 15, paddingLeft: 12, borderLeft: "1px solid var(--st-divider)", display: "flex", flexDirection: "column", gap: 1, marginTop: 1, opacity: isCollapsed ? 0 : 1, transition: "opacity .2s ease" }}>
                    {g.chapters.map((c) => {
                      const on = c.id === active?.id;
                      return (
                        <div
                          key={c.id}
                          className={on ? "clk" : "stdoc-nav clk"}
                          onClick={() => setActiveId(c.id)}
                          style={{ display: "flex", alignItems: "center", gap: 8, padding: "7px 9px", borderRadius: 8, cursor: "pointer", font: `${on ? 600 : 500} 13px Inter,sans-serif`, color: on ? ACCENT : "var(--st-text-2)", background: on ? "var(--st-accent-soft)" : "transparent" }}
                        >
                          <Icon name="doc" size={14} color={on ? ACCENT : "var(--st-text-faint)"} sw={2} style={{ flex: "none" }} />
                          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.title}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            </div>
          );
        })}
        {groups.length === 0 && <div style={{ padding: "8px 8px", color: "var(--st-text-faint)", fontSize: 12.5 }}>Ничего не найдено.</div>}
      </aside>

      {/* ------- контент ------- */}
      <div style={{ flex: 1, minWidth: 0, padding: "40px 48px 60px" }}>
        {active ? (
          <div style={{ maxWidth: 820 }}>
            {/* хлебные крошки: Workspace / Docs / {папка} / {файл} — тот же корень
                Workspace, что и на лендинге, затем папка (категория) и текущий файл. */}
            <div className="mono" style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 18, fontSize: 11, letterSpacing: 1.2, textTransform: "uppercase", color: "var(--st-text-faint)", fontWeight: 700, flexWrap: "wrap" }}>
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: ACCENT, flex: "none" }} />
              {onNavigateWorkspace ? (
                <span className="stdoc-crumb clk" onClick={onNavigateWorkspace}>Workspace</span>
              ) : (
                <span>Workspace</span>
              )}
              <span>/</span>
              <span className="stdoc-crumb clk" onClick={goHome}>Docs</span>
              {activeGroup && (
                <>
                  <span>/</span>
                  <span className="stdoc-crumb clk" onClick={() => openCategory(active.audience)}>{activeGroup.title}</span>
                </>
              )}
              <span>/</span>
              <span style={{ color: "var(--st-text-3)" }}>{active.title}</span>
            </div>
            <div className="stormmd-input" style={{ fontSize: 14.5 }}>
              <ReactMarkdown urlTransform={markdownUrlTransform}>{normalizeMarkdownForRender(active.body)}</ReactMarkdown>
            </div>
          </div>
        ) : q ? (
          // результаты поиска на лендинге
          <div style={{ maxWidth: 900 }}>
            <h1 style={{ margin: 0, fontSize: 26, fontWeight: 800, letterSpacing: "-.6px", color: "var(--st-text)" }}>Результаты поиска</h1>
            <div style={{ fontSize: 13.5, color: "var(--st-text-3)", marginTop: 6 }}>{pagesWord(searchResults.length)} по запросу «{query.trim()}».</div>
            <div style={{ marginTop: 24, display: "flex", flexDirection: "column", gap: 10, maxWidth: 760 }}>
              {searchResults.map((c) => {
                const group = DOC_GROUPS.find((g) => g.audience === c.audience);
                const snippet = bodySnippet(c.body, q);
                return (
                  <div key={c.id} className="stdoc-card clk" onClick={() => setActiveId(c.id)} style={{ background: "var(--st-surface)", border: "1px solid var(--st-divider)", borderRadius: 12, padding: "14px 18px", cursor: "pointer" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
                      <Icon name="doc" size={16} color={ACCENT} sw={2} style={{ flex: "none" }} />
                      <div style={{ font: "700 14px Inter,sans-serif", color: "var(--st-text)", minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{highlight(c.title, q)}</div>
                      <div style={{ fontSize: 11.5, color: "var(--st-text-faint)", marginLeft: "auto", flex: "none" }}>{group?.title}</div>
                    </div>
                    {snippet && <div style={{ marginTop: 7, fontSize: 12.5, color: "var(--st-text-3)", lineHeight: 1.55 }}>{highlight(snippet, q)}</div>}
                  </div>
                );
              })}
            </div>
          </div>
        ) : (
          // лендинг: карточки категорий
          <div style={{ maxWidth: 900 }}>
            {/* Тот же заголовок-крошки, что и на остальных страницах воркспейса
                (напр. Workspace / Members): точка-акцент, кликабельный корень,
                приглушённый текущий раздел. */}
            <div className="mono" style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10, fontSize: 11, letterSpacing: 1.2, textTransform: "uppercase", color: "var(--st-text-faint)", fontWeight: 700, flexWrap: "wrap" }}>
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: ACCENT, flex: "none" }} />
              {onNavigateWorkspace ? (
                <span className="stdoc-crumb clk" onClick={onNavigateWorkspace}>Workspace</span>
              ) : (
                <span>Workspace</span>
              )}
              <span>/</span>
              <span style={{ color: "var(--st-text-3)" }}>Docs</span>
            </div>
            <div style={{ marginTop: 22, display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(230px, 1fr))", gap: 16, maxWidth: 760 }}>
              {groups.map((g) => (
                <div key={g.audience} className="stdoc-card clk" onClick={() => openCategory(g.audience)} style={{ background: "var(--st-surface)", border: "1px solid var(--st-divider)", borderRadius: 14, padding: "20px 20px 18px", cursor: "pointer" }}>
                  <Icon name="folder" size={24} color={ACCENT} sw={2} />
                  <div style={{ font: "700 15.5px Inter,sans-serif", color: "var(--st-text)", marginTop: 12, letterSpacing: "-.2px" }}>{g.title}</div>
                  <div style={{ fontSize: 12, color: "var(--st-text-faint)", marginTop: 10 }}>{pagesWord(g.chapters.length)}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default StormDocs;
