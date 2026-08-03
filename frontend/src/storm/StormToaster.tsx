/* Bottom-right toast notifications in the STORM design language.
   Reads the shared useToastStore, so any part of the app can pushToast(). */

import { useEffect } from "react";
import "./storm.css";
import { Icon, type IconName } from "./icons";
import { useToastStore } from "../store";

type Severity = "error" | "warning" | "info" | "success";

const SEV: Record<Severity, { bar: string; bg: string; icon: IconName; color: string }> = {
  error: { bar: "var(--st-danger)", bg: "var(--st-danger-soft)", icon: "alert-triangle", color: "var(--st-danger)" },
  warning: { bar: "var(--st-warn)", bg: "var(--st-warn-soft)", icon: "alert-triangle", color: "var(--st-warn)" },
  info: { bar: "var(--st-accent)", bg: "var(--st-accent-soft)", icon: "info", color: "var(--st-accent)" },
  success: { bar: "var(--st-success)", bg: "var(--st-success-soft)", icon: "check-circle", color: "var(--st-success)" },
};

export function StormToaster() {
  const toasts = useToastStore((s) => s.toasts);
  const dismiss = useToastStore((s) => s.dismissToast);

  useEffect(() => {
    if (toasts.length === 0) return;
    const timers = toasts.map((t) => window.setTimeout(() => dismiss(t.id), 8000));
    return () => timers.forEach((id) => window.clearTimeout(id));
  }, [toasts, dismiss]);

  if (toasts.length === 0) return null;

  return (
    <div className="storm" style={{ position: "fixed", right: 24, bottom: 24, zIndex: 9999, display: "flex", flexDirection: "column", gap: 12, pointerEvents: "none" }}>
      {toasts.map((t) => {
        const s = SEV[(t.severity as Severity)] ?? SEV.info;
        return (
          <div
            key={t.id}
            style={{
              pointerEvents: "auto",
              minWidth: 300,
              maxWidth: 420,
              display: "flex",
              alignItems: "flex-start",
              gap: 11,
              background: "var(--st-surface)",
              border: "1px solid var(--st-border-light)",
              borderLeft: `4px solid ${s.bar}`,
              borderRadius: 12,
              boxShadow: "0 16px 44px rgba(15,27,45,.16)",
              padding: "13px 14px",
              animation: "storm-fade .22s ease both",
            }}
          >
            <span style={{ width: 30, height: 30, flex: "none", borderRadius: 8, background: s.bg, color: s.color, display: "flex", alignItems: "center", justifyContent: "center" }}>
              <Icon name={s.icon} size={17} color={s.color} sw={2.2} />
            </span>
            <div style={{ flex: 1, minWidth: 0, font: "600 13px Inter,sans-serif", color: "var(--st-text)", lineHeight: 1.45, paddingTop: 3 }}>{t.message}</div>
            <div className="clk actbtn" onClick={() => dismiss(t.id)} style={{ flex: "none" }}><Icon name="close" size={16} /></div>
          </div>
        );
      })}
    </div>
  );
}
