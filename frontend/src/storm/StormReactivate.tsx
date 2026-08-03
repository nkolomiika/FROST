/* STORM «с возвращением» — возврат деактивированного пользователя по ссылке из
   письма. Публичная страница (без сессии): проверяем токен, показываем одну
   кнопку — по клику аккаунт разблокируется, бэкенд ставит cookie-сессию, а мы
   подхватываем её (refreshUser) и StormRoot сразу открывает приложение.

   Клик, а не авто-POST на загрузке: state-changing запрос под CSRF-защитой не
   должен срабатывать от предпросмотра ссылки почтовым сканером. */

import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import "./storm.css";
import { Icon } from "./icons";
import { completeReactivation, getApiErrorMessage, getReactivationInfo } from "../api";
import type { ReactivationInfo } from "../types";
import { useAuthStore, useToastStore } from "../store";

const REASON_TEXT: Record<string, string> = {
  expired: "The link has expired. Ask an admin to send a new one.",
  used: "This link has already been used. Try signing in normally.",
  not_found: "The link is invalid. Make sure you opened it in full, or ask an admin to resend it.",
};

const card: React.CSSProperties = {
  background: "var(--st-surface)",
  border: "1px solid var(--st-border-light)",
  borderRadius: 20,
  boxShadow: "0 24px 60px rgba(15,27,45,.10)",
  padding: "32px 34px 30px",
};

export function StormReactivate() {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const refreshUser = useAuthStore((s) => s.refreshUser);
  const pushToast = useToastStore((s) => s.pushToast);

  const [info, setInfo] = useState<ReactivationInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    let cancelled = false;
    if (!token) {
      setInfo({ valid: false, reason: "not_found" });
      setLoading(false);
      return;
    }
    void (async () => {
      try {
        const data = await getReactivationInfo(token);
        if (!cancelled) setInfo(data);
      } catch {
        if (!cancelled) setInfo({ valid: false, reason: "not_found" });
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [token]);

  const handleActivate = async () => {
    if (!info?.valid || submitting) return;
    setSubmitting(true);
    try {
      await completeReactivation(token);
      pushToast("Welcome back!", "success");
      // Бэкенд уже выдал сессию (cookie) — подхватываем её; StormRoot покажет приложение.
      await refreshUser();
    } catch (err) {
      setSubmitting(false);
      pushToast(getApiErrorMessage(err, "Couldn't reactivate the account"), "error");
    }
  };

  return (
    <div className="storm" style={{ minHeight: "100vh", display: "flex", flexDirection: "column", background: "var(--st-bg)" }}>
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}>
        <div style={{ width: 420, maxWidth: "100%" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 11, justifyContent: "center", marginBottom: 22 }}>
            <div style={{ fontWeight: 800, fontSize: 22, letterSpacing: 3, color: "var(--st-text)" }}>STORM</div>
          </div>

          {loading ? (
            <div style={{ ...card, textAlign: "center", color: "var(--st-text-3)", fontSize: 14 }}>Checking the link…</div>
          ) : !info?.valid ? (
            <div style={card}>
              <h1 style={{ margin: "0 0 12px", fontSize: 24, fontWeight: 800, letterSpacing: "-.5px", color: "var(--st-text)" }}>Invalid link</h1>
              <p style={{ margin: "0 0 22px", fontSize: 13.5, color: "var(--st-text-2)", lineHeight: 1.55 }}>
                {REASON_TEXT[info?.reason ?? "not_found"] ?? REASON_TEXT.not_found}
              </p>
              <a
                href="/login"
                className="clk"
                style={{ display: "inline-flex", alignItems: "center", gap: 8, height: 44, padding: "0 20px", borderRadius: 12, background: "var(--st-accent)", color: "var(--st-on-accent)", font: "700 14px Inter,sans-serif", textDecoration: "none" }}
              >
                Go to sign in
                <Icon name="chevron-right" size={16} color="var(--st-on-accent)" sw={2.4} />
              </a>
            </div>
          ) : (
            <div style={card}>
              <h1 style={{ margin: "0 0 8px", fontSize: 26, fontWeight: 800, letterSpacing: "-.6px", color: "var(--st-text)" }}>Welcome back</h1>
              <p style={{ margin: "0 0 22px", fontSize: 13.5, color: "var(--st-text-2)", lineHeight: 1.5 }}>
                Your access to STORM has been restored for <b style={{ color: "var(--st-text)" }}>{info.username}</b>. Click below to sign in.
              </p>
              <button
                type="button"
                className="clk"
                onClick={handleActivate}
                disabled={submitting}
                style={{
                  width: "100%",
                  height: 46,
                  border: "none",
                  borderRadius: 12,
                  background: submitting ? "var(--st-accent-muted)" : "var(--st-accent)",
                  color: "var(--st-on-accent)",
                  font: "700 14px Inter,sans-serif",
                  cursor: submitting ? "not-allowed" : "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: 9,
                  boxShadow: "0 6px 18px rgba(46,95,191,.28)",
                }}
              >
                {submitting ? "Signing you in…" : "Return to my account"}
                {!submitting && <Icon name="chevron-right" size={16} color="var(--st-on-accent)" sw={2.4} />}
              </button>
            </div>
          )}
        </div>
      </div>

      <footer style={{ flex: "none", display: "flex", alignItems: "center", justifyContent: "center", gap: 8, padding: 16, fontSize: 12.5, color: "var(--st-text-faint)", flexWrap: "wrap" }}>
        <span style={{ fontWeight: 700, color: "var(--st-text-3)" }}>STORM</span>
        <span>·</span>
        <span>Copyright © 2026. All rights reserved.</span>
      </footer>
    </div>
  );
}

export default StormReactivate;
