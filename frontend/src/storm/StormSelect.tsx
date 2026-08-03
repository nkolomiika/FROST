/* Custom dropdown select in the STORM design language — replaces the native
   <select> for short, fixed option lists (e.g. member roles) so options can carry
   a colour dot and a description. Closes on select, click-outside and Esc. */

import { useEffect, useRef, useState } from "react";
import "./storm.css";
import { Icon } from "./icons";

export interface StormSelectOption {
  value: string;
  label: string;
  /** Colour dot shown before the label (e.g. the role's badge colour). */
  dot?: string;
  /** Optional one-line hint under the label. */
  desc?: string;
}

interface StormSelectProps {
  value: string;
  options: StormSelectOption[];
  onChange: (value: string) => void;
  id?: string;
  placeholder?: string;
}

export function StormSelect({ value, options, onChange, id, placeholder }: StormSelectProps) {
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
          border: `1px solid ${open ? "var(--st-focus-border)" : "var(--st-border)"}`,
          borderRadius: 11,
          padding: "0 12px",
          background: "var(--st-surface)",
          font: "500 14px Inter,sans-serif",
          color: selected ? "var(--st-text)" : "var(--st-text-faint)",
          cursor: "pointer",
          outline: "none",
          boxShadow: open ? "0 0 0 3px var(--st-focus-ring)" : "none",
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
          color="var(--st-text-faint)"
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
          background: "var(--st-surface)",
          border: "1px solid var(--st-border-light)",
          borderRadius: 12,
          boxShadow: "0 20px 54px var(--st-shadow-strong)",
          zIndex: 50,
          padding: 6,
          transformOrigin: "top",
        }}
      >
        {options.map((o) => {
          const on = o.value === value;
          return (
            <div
              key={o.value}
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
                background: on ? "var(--st-accent-soft)" : "transparent",
              }}
            >
              {o.dot && <span style={{ width: 9, height: 9, borderRadius: "50%", flex: "none", background: o.dot }} />}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ font: "600 13.5px Inter,sans-serif", color: on ? "var(--st-accent)" : "var(--st-text)" }}>{o.label}</div>
                {o.desc && <div style={{ fontSize: 11.5, color: "var(--st-text-3)", marginTop: 1 }}>{o.desc}</div>}
              </div>
              {on && <Icon name="check" size={16} color="var(--st-accent)" sw={2.4} />}
            </div>
          );
        })}
      </div>
    </div>
  );
}
