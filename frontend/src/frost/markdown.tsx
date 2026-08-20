/* Minimal Markdown → React renderer for the read-only note viewer.
   Supports headings, unordered lists, and inline bold/italic/code/links. */
import { type ReactNode } from "react";

/** Render inline spans (**bold**, *italic*, `code`, [text](url)) of one line. */
export function mdInline(text: string, kb: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  let rest = text;
  let key = 0;
  const re = /(\*\*([^*]+)\*\*|\*([^*]+)\*|`([^`]+)`|\[([^\]]+)\]\(([^)]+)\))/;
  let m: RegExpExecArray | null;
  while ((m = re.exec(rest))) {
    if (m.index > 0) nodes.push(rest.slice(0, m.index));
    if (m[2] != null) nodes.push(<strong key={`${kb}-${key++}`}>{m[2]}</strong>);
    else if (m[3] != null) nodes.push(<em key={`${kb}-${key++}`}>{m[3]}</em>);
    else if (m[4] != null)
      nodes.push(
        <code key={`${kb}-${key++}`} style={{ background: "var(--fr-divider)", borderRadius: 5, padding: "1px 5px", fontFamily: "ui-monospace,Menlo,monospace", fontSize: ".9em" }}>
          {m[4]}
        </code>
      );
    else if (m[5] != null)
      nodes.push(
        <a key={`${kb}-${key++}`} href={m[6]} style={{ color: "var(--fr-accent-2)" }}>
          {m[5]}
        </a>
      );
    rest = rest.slice(m.index + m[0].length);
  }
  if (rest) nodes.push(rest);
  return nodes;
}

/** Render a small Markdown document (headings + lists + paragraphs) to React. */
export function renderMarkdown(src: string): ReactNode {
  const lines = src.replace(/\r/g, "").split("\n");
  const blocks: ReactNode[] = [];
  let list: string[] | null = null;
  let key = 0;
  const flush = () => {
    if (list) {
      const items = list;
      const k = key++;
      blocks.push(
        <ul key={`b${k}`} style={{ margin: "4px 0 8px", paddingLeft: 20 }}>
          {items.map((it, i) => (
            <li key={i} style={{ margin: "2px 0" }}>
              {mdInline(it, `li${k}-${i}`)}
            </li>
          ))}
        </ul>
      );
      list = null;
    }
  };
  for (const ln of lines) {
    const hm = ln.match(/^(#{1,3})\s+(.*)$/);
    const li = ln.match(/^\s*[-*]\s+(.*)$/);
    if (hm) {
      flush();
      const lvl = hm[1].length;
      const size = lvl === 1 ? 18 : lvl === 2 ? 15.5 : 13.5;
      const k = key++;
      blocks.push(
        <div key={`b${k}`} style={{ fontWeight: 800, fontSize: size, color: "var(--fr-text)", margin: "8px 0 4px" }}>
          {mdInline(hm[2], `h${k}`)}
        </div>
      );
    } else if (li) {
      (list = list || []).push(li[1]);
    } else if (ln.trim() === "") {
      flush();
    } else {
      flush();
      const k = key++;
      blocks.push(
        <div key={`b${k}`} style={{ margin: "3px 0" }}>
          {mdInline(ln, `p${k}`)}
        </div>
      );
    }
  }
  flush();
  return <div style={{ fontSize: 13.5, lineHeight: 1.6, color: "var(--fr-text-2)" }}>{blocks}</div>;
}
