/* STORM-styled date picker. Replaces the native <input type="date"> so the
   calendar looks identical across browsers and matches the STORM design.
   Value is an ISO "yyyy-mm-dd" string (same shape the app already stores);
   `min`/`max` are ISO strings too — days outside the range are disabled. */

import { useEffect, useMemo, useRef, useState } from "react";
import { Icon } from "./icons";

interface Props {
  value: string; // "yyyy-mm-dd" or ""
  onChange: (value: string) => void;
  min?: string;
  max?: string;
  placeholder?: string;
  id?: string;
}

const WEEKDAYS = ["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"];
const MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

const pad = (n: number) => String(n).padStart(2, "0");
const toISO = (y: number, m: number, d: number) => `${y}-${pad(m + 1)}-${pad(d)}`;
/** yyyy-mm-dd -> dd.mm.yyyy for display (matches the rest of the app). */
const toDisplay = (iso: string) => {
  const [y, m, d] = iso.split("-");
  return y && m && d ? `${d}.${m}.${y}` : "";
};

export function StormDatePicker({ value, onChange, min, max, placeholder = "Select date", id }: Props) {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);

  const today = new Date();
  const todayISO = toISO(today.getFullYear(), today.getMonth(), today.getDate());

  // Month currently shown in the grid — seeded from the value, else today.
  const [view, setView] = useState(() => {
    const [y, m] = value.split("-").map(Number);
    return value && y && m ? { y, m: m - 1 } : { y: today.getFullYear(), m: today.getMonth() };
  });

  // Re-seed the visible month whenever the picker opens with a value.
  useEffect(() => {
    if (open && value) {
      const [y, m] = value.split("-").map(Number);
      if (y && m) setView({ y, m: m - 1 });
    }

  }, [open]);

  // Close on outside click / Esc.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const cells = useMemo(() => {
    const first = new Date(view.y, view.m, 1);
    const lead = (first.getDay() + 6) % 7; // Monday-first offset
    const daysInMonth = new Date(view.y, view.m + 1, 0).getDate();
    const out: (string | null)[] = [];
    for (let i = 0; i < lead; i++) out.push(null);
    for (let d = 1; d <= daysInMonth; d++) out.push(toISO(view.y, view.m, d));
    return out;
  }, [view]);

  const disabled = (iso: string) => (min && iso < min) || (max && iso > max) || false;
  const prevMonth = () => setView((v) => (v.m === 0 ? { y: v.y - 1, m: 11 } : { y: v.y, m: v.m - 1 }));
  const nextMonth = () => setView((v) => (v.m === 11 ? { y: v.y + 1, m: 0 } : { y: v.y, m: v.m + 1 }));

  return (
    <div ref={wrapRef} style={{ position: "relative" }}>
      {/* field */}
      <button
        type="button"
        id={id}
        className="finp clk"
        onClick={() => setOpen((o) => !o)}
        style={{ width: "100%", display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, cursor: "pointer", textAlign: "left", background: "var(--st-surface)" }}
      >
        <span style={{ color: value ? "var(--st-text)" : "var(--st-text-faint)", font: "600 13.5px Inter,sans-serif" }}>{value ? toDisplay(value) : placeholder}</span>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
          {value && (
            <span
              role="button"
              aria-label="Clear date"
              onClick={(e) => {
                e.stopPropagation();
                onChange("");
                setOpen(false);
              }}
              style={{ display: "inline-flex", color: "var(--st-text-faint)" }}
            >
              <Icon name="close" size={14} sw={2.2} />
            </span>
          )}
          <Icon name="calendar" size={16} color="var(--st-text-2)" sw={1.9} />
        </span>
      </button>

      {/* popover calendar */}
      {open && (
        <div
          style={{
            position: "absolute",
            top: "calc(100% + 6px)",
            left: 0,
            zIndex: 80,
            width: 268,
            background: "var(--st-surface)",
            border: "1px solid var(--st-border-light)",
            borderRadius: 14,
            boxShadow: "0 20px 50px rgba(15,27,45,.18)",
            padding: 14,
          }}
        >
          {/* month nav */}
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
            <button type="button" className="clk" onClick={prevMonth} style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 30, height: 30, border: "1px solid var(--st-border-light)", borderRadius: 9, background: "var(--st-surface)", cursor: "pointer", color: "var(--st-text-2)" }}>
              <Icon name="chevron-left" size={16} sw={2.2} />
            </button>
            <div style={{ font: "700 13.5px Inter,sans-serif", color: "var(--st-text)" }}>{MONTHS[view.m]} {view.y}</div>
            <button type="button" className="clk" onClick={nextMonth} style={{ display: "inline-flex", alignItems: "center", justifyContent: "center", width: 30, height: 30, border: "1px solid var(--st-border-light)", borderRadius: 9, background: "var(--st-surface)", cursor: "pointer", color: "var(--st-text-2)" }}>
              <Icon name="chevron-right" size={16} sw={2.2} />
            </button>
          </div>

          {/* weekday header */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(7,1fr)", gap: 2, marginBottom: 4 }}>
            {WEEKDAYS.map((w) => (
              <div key={w} style={{ textAlign: "center", font: "700 10.5px Inter,sans-serif", letterSpacing: ".3px", color: "var(--st-text-faint)", textTransform: "uppercase", padding: "4px 0" }}>{w}</div>
            ))}
          </div>

          {/* day grid */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(7,1fr)", gap: 2 }}>
            {cells.map((iso, i) => {
              if (!iso) return <div key={`e${i}`} />;
              const day = Number(iso.slice(8, 10));
              const isSel = iso === value;
              const isToday = iso === todayISO;
              const off = disabled(iso);
              return (
                <button
                  key={iso}
                  type="button"
                  disabled={off}
                  onClick={() => {
                    onChange(iso);
                    setOpen(false);
                  }}
                  className={off ? undefined : "clk"}
                  style={{
                    height: 32,
                    borderRadius: 9,
                    border: isToday && !isSel ? "1px solid var(--st-accent-muted)" : "1px solid transparent",
                    background: isSel ? "var(--st-accent)" : "transparent",
                    color: off ? "var(--st-border-strong)" : isSel ? "var(--st-on-accent)" : "var(--st-text)",
                    font: `${isSel ? 700 : 600} 12.5px Inter,sans-serif`,
                    cursor: off ? "not-allowed" : "pointer",
                  }}
                >
                  {day}
                </button>
              );
            })}
          </div>

          {/* quick actions */}
          <div style={{ display: "flex", justifyContent: "space-between", marginTop: 10, paddingTop: 10, borderTop: "1px solid var(--st-divider)" }}>
            <button
              type="button"
              className="clk"
              disabled={disabled(todayISO)}
              onClick={() => {
                if (disabled(todayISO)) return;
                onChange(todayISO);
                setOpen(false);
              }}
              style={{ border: "none", background: "transparent", font: "700 12px Inter,sans-serif", color: disabled(todayISO) ? "var(--st-border-strong)" : "var(--st-accent)", cursor: disabled(todayISO) ? "not-allowed" : "pointer" }}
            >
              Today
            </button>
            <button
              type="button"
              className="clk"
              onClick={() => {
                onChange("");
                setOpen(false);
              }}
              style={{ border: "none", background: "transparent", font: "700 12px Inter,sans-serif", color: "var(--st-text-3)", cursor: "pointer" }}
            >
              Clear
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
