/* Custom dropdown select in the FROST design language — replaces the native
   <select> for short, fixed option lists (e.g. member roles) so options can carry
   a colour dot and a description. Closes on select, click-outside and Esc. */

import { useEffect, useMemo, useRef, useState } from "react";
import "./frost.css";
import { Icon } from "./icons";

export interface FrostSelectOption {
  value: string;
  label: string;
  /** Colour dot shown before the label (e.g. the role's badge colour). */
  dot?: string;
  /** Optional one-line hint under the label. */
  desc?: string;
  /** Optional group header. Consecutive options sharing a group render under one
      sticky-styled header row (optgroup-style). Ungrouped options render flat. */
  group?: string;
}

interface FrostSelectProps {
  value: string;
  options: FrostSelectOption[];
  onChange: (value: string) => void;
  id?: string;
  placeholder?: string;
  /** Show a filter box at the top of the open menu (for long option lists like
      wordlists) — filters by label and group, same idea as the users search. */
  searchable?: boolean;
  searchPlaceholder?: string;
}

export function FrostSelect({ value, options, onChange, id, placeholder, searchable, searchPlaceholder }: FrostSelectProps) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const rootRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const selected = options.find((o) => o.value === value) ?? null;

  // Отфильтрованный список для поиска: по label и по группе (регистронезависимо).
  const shown = useMemo(() => {
    if (!searchable) return options;
    const q = query.trim().toLowerCase();
    if (!q) return options;
    return options.filter((o) => o.label.toLowerCase().includes(q) || (o.group ?? "").toLowerCase().includes(q));
  }, [options, query, searchable]);

  // Сброс запроса при закрытии; автофокус на поле поиска при открытии.
  useEffect(() => {
    if (!open) {
      setQuery("");
      return;
    }
    if (searchable) {
      const h = setTimeout(() => searchRef.current?.focus(), 0);
      return () => clearTimeout(h);
    }
  }, [open, searchable]);

  // Dismiss on outside click / Esc. stopPropagation on Esc keeps a surrounding
  // modal open — the first Esc closes the dropdown, a second closes the modal.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div ref={rootRef} style={{ position: "relative" }}>
      <button
        type="button"
        id={id}
        className="clk"
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        style={{
          width: "100%",
          height: 42,
          display: "flex",
          alignItems: "center",
          gap: 9,
          border: `1px solid ${open ? "var(--fr-focus-border)" : "var(--fr-border)"}`,
          borderRadius: 11,
          padding: "0 12px",
          background: "var(--fr-surface)",
          font: "500 14px Inter,sans-serif",
          color: selected ? "var(--fr-text)" : "var(--fr-text-faint)",
          cursor: "pointer",
          outline: "none",
          boxShadow: open ? "0 0 0 3px var(--fr-focus-ring)" : "none",
          transition: "border-color .12s, box-shadow .12s",
        }}
      >
        {selected?.dot && <span style={{ width: 9, height: 9, borderRadius: "50%", flex: "none", background: selected.dot }} />}
        <span style={{ flex: 1, textAlign: "left", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {selected ? selected.label : placeholder ?? "Select…"}
        </span>
        <Icon
          name="chevron-down"
          size={16}
          color="var(--fr-text-faint)"
          sw={2.2}
          style={{ transition: "transform .18s ease", transform: open ? "rotate(180deg)" : "none" }}
        />
      </button>

      <div
        role="listbox"
        className={`menu ${open ? "open" : ""}`}
        style={{
          position: "absolute",
          top: 48,
          left: 0,
          right: 0,
          background: "var(--fr-surface)",
          border: "1px solid var(--fr-border-light)",
          borderRadius: 12,
          boxShadow: "0 20px 54px var(--fr-shadow-strong)",
          zIndex: 50,
          // Без верхнего паддинга при поиске: иначе прокрученные опции видны в этой
          // 6px-полосе НАД липкой строкой поиска. Верхний отступ даёт сама строка.
          padding: searchable ? "0 6px 6px" : 6,
          transformOrigin: "top",
          maxHeight: searchable ? 340 : undefined,
          overflowY: searchable ? "auto" : undefined,
        }}
      >
        {searchable && (
          <div style={{ position: "sticky", top: 0, background: "var(--fr-surface)", padding: "6px 2px", zIndex: 1 }}>
            <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
              <Icon name="search" size={14} color="var(--fr-text-faint)" style={{ position: "absolute", left: 10, pointerEvents: "none" }} />
              <input
                ref={searchRef}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={searchPlaceholder ?? "Search…"}
                style={{
                  width: "100%",
                  height: 36,
                  border: "1px solid var(--fr-border)",
                  borderRadius: 9,
                  padding: "0 10px 0 30px",
                  background: "var(--fr-elevated)",
                  font: "500 13px Inter,sans-serif",
                  color: "var(--fr-text)",
                  outline: "none",
                }}
              />
            </div>
          </div>
        )}
        {shown.length === 0 && (
          <div style={{ padding: "12px 10px", font: "500 12.5px Inter,sans-serif", color: "var(--fr-text-faint)", textAlign: "center" }}>
            Nothing found
          </div>
        )}
        {shown.map((o, i) => {
          const on = o.value === value;
          // Заголовок группы: рисуем, когда группа опции отличается от предыдущей
          // (первая опция с группой тоже получает заголовок). optgroup-style.
          const prevGroup = i > 0 ? shown[i - 1].group : undefined;
          const showHeader = o.group !== undefined && o.group !== prevGroup;
          return (
            <div key={o.value}>
            {showHeader && (
              <div
                aria-hidden="true"
                style={{
                  padding: "8px 10px 4px",
                  font: "700 10.5px Inter,sans-serif",
                  letterSpacing: ".06em",
                  textTransform: "uppercase",
                  color: "var(--fr-text-faint)",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {o.group}
              </div>
            )}
            <div
              role="option"
              aria-selected={on}
              className="nav clk"
              onClick={() => {
                onChange(o.value);
                setOpen(false);
              }}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                padding: "9px 10px",
                borderRadius: 9,
                cursor: "pointer",
                background: on ? "var(--fr-accent-soft)" : "transparent",
              }}
            >
              {o.dot && <span style={{ width: 9, height: 9, borderRadius: "50%", flex: "none", background: o.dot }} />}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ font: "600 13.5px Inter,sans-serif", color: on ? "var(--fr-accent)" : "var(--fr-text)" }}>{o.label}</div>
                {o.desc && <div style={{ fontSize: 11.5, color: "var(--fr-text-3)", marginTop: 1 }}>{o.desc}</div>}
              </div>
              {on && <Icon name="check" size={16} color="var(--fr-accent)" sw={2.4} />}
            </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
