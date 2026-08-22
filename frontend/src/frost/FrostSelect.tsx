/* Custom dropdown select in the FROST design language — replaces the native
   <select> for short, fixed option lists (e.g. member roles) so options can carry
   a colour dot and a description. Closes on select, click-outside and Esc. */

import { useEffect, useRef, useState } from "react";
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
}

export function FrostSelect({ value, options, onChange, id, placeholder }: FrostSelectProps) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const selected = options.find((o) => o.value === value) ?? null;

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
          padding: 6,
          transformOrigin: "top",
        }}
      >
        {options.map((o, i) => {
          const on = o.value === value;
          // Заголовок группы: рисуем, когда группа опции отличается от предыдущей
          // (первая опция с группой тоже получает заголовок). optgroup-style.
          const prevGroup = i > 0 ? options[i - 1].group : undefined;
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
