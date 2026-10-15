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
  // A pending list can be unordered (<ul>) or ordered (<ol>); we buffer items
  // until a non-list line flushes it so consecutive rows join one list.
  let list: { ordered: boolean; items: string[] } | null = null;
  let key = 0;
  const flush = () => {
    if (list) {
      const { ordered, items } = list;
      const k = key++;
      const Tag = ordered ? "ol" : "ul";
      blocks.push(
        <Tag key={`b${k}`} style={{ margin: "4px 0 8px", paddingLeft: 22 }}>
          {items.map((it, i) => (
            <li key={i} style={{ margin: "2px 0" }}>
              {mdInline(it, `li${k}-${i}`)}
            </li>
          ))}
        </Tag>
      );
      list = null;
    }
  };
  // Renders a GitHub-style pipe table once its full run of rows is collected.
  const pushTable = (rows: string[]) => {
    const cells = (row: string) =>
      row.replace(/^\s*\|/, "").replace(/\|\s*$/, "").split("|").map((c) => c.trim());
    const header = cells(rows[0]);
    const body = rows.slice(2).map(cells); // row 1 is the |---|---| separator
    const k = key++;
    blocks.push(
      <div key={`b${k}`} style={{ overflowX: "auto", margin: "8px 0" }}>
        <table style={{ borderCollapse: "collapse", fontSize: 12.5, width: "100%" }}>
          <thead>
            <tr>
              {header.map((h, i) => (
                <th key={i} style={{ textAlign: "left", padding: "6px 10px", borderBottom: "2px solid var(--fr-border)", color: "var(--fr-text)", fontWeight: 700, whiteSpace: "nowrap" }}>
                  {mdInline(h, `th${k}-${i}`)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {body.map((r, ri) => (
              <tr key={ri}>
                {r.map((c, ci) => (
                  <td key={ci} style={{ padding: "6px 10px", borderBottom: "1px solid var(--fr-divider)", verticalAlign: "top" }}>
                    {mdInline(c, `td${k}-${ri}-${ci}`)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };
  const isTableRow = (s: string) => /^\s*\|.*\|\s*$/.test(s);
  const isTableSep = (s: string) => /^\s*\|?[\s:|-]*-[\s:|-]*\|?\s*$/.test(s) && s.includes("-");

  for (let idx = 0; idx < lines.length; idx++) {
    const ln = lines[idx];

    // Fenced code block: ```lang … ``` — verbatim, monospace, horizontally scrollable.
    const fence = ln.match(/^\s*```(.*)$/);
    if (fence) {
      flush();
      const buf: string[] = [];
      idx++;
      while (idx < lines.length && !/^\s*```\s*$/.test(lines[idx])) {
        buf.push(lines[idx]);
        idx++;
      }
      const k = key++;
      blocks.push(
        <pre key={`b${k}`} style={{ margin: "8px 0", padding: "12px 14px", background: "var(--fr-sunken)", border: "1px solid var(--fr-divider)", borderRadius: 10, overflowX: "auto", fontFamily: "ui-monospace,Menlo,monospace", fontSize: 12, lineHeight: 1.5, color: "var(--fr-text-2)" }}>
          {buf.join("\n")}
        </pre>
      );
      continue;
    }

    // Pipe table: a header row followed by a |---|---| separator.
    if (isTableRow(ln) && idx + 1 < lines.length && isTableSep(lines[idx + 1])) {
      flush();
      const rows: string[] = [ln];
      idx++;
      rows.push(lines[idx]); // separator
      while (idx + 1 < lines.length && isTableRow(lines[idx + 1])) {
        idx++;
        rows.push(lines[idx]);
      }
      pushTable(rows);
      continue;
    }

    const hm = ln.match(/^(#{1,3})\s+(.*)$/);
    const uli = ln.match(/^\s*[-*]\s+(.*)$/);
    const oli = ln.match(/^\s*\d+[.)]\s+(.*)$/);
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
    } else if (oli) {
      if (list && !list.ordered) flush();
      (list = list ?? { ordered: true, items: [] }).items.push(oli[1]);
    } else if (uli) {
      if (list && list.ordered) flush();
      (list = list ?? { ordered: false, items: [] }).items.push(uli[1]);
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
