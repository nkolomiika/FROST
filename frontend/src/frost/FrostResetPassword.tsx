/* FROST «забыли пароль» — шаг 2: установка нового пароля по ссылке из письма.
   Публичная страница (без сессии). Ссылка одноразовая: после успешной смены
   бэкенд гасит токен и отзывает все активные сессии, поэтому дальше уводим
   пользователя на обычный вход. */

import { useEffect, useState, type FormEvent } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import "./frost.css";
import { Icon } from "./icons";
import { PasswordInput } from "./PasswordInput";
import { confirmPasswordReset, getApiErrorMessage, getPasswordResetInfo } from "../api";
import type { PasswordResetInfo } from "../types";
import { useToastStore } from "../store";

const REASON_TEXT: Record<string, string> = {
  expired: "The link has expired. Request a new password reset.",
  used: "This link has already been used. Request a new one if you still need to reset your password.",
  not_found: "The link is invalid. Make sure you opened it in full, or request a new one.",
};

const card: React.CSSProperties = {
  background: "var(--fr-surface)",
  border: "1px solid var(--fr-border-light)",
  borderRadius: 20,
  boxShadow: "0 24px 60px rgba(15,27,45,.10)",
  padding: "32px 34px 30px",
};

export function FrostResetPassword() {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const navigate = useNavigate();
  const pushToast = useToastStore((s) => s.pushToast);

  const [info, setInfo] = useState<PasswordResetInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
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
        const data = await getPasswordResetInfo(token);
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

  const passwordValid = password.length >= 8;
  const confirmValid = confirm.length > 0 && confirm === password;
  const canSubmit = !!info?.valid && passwordValid && confirmValid && !submitting;

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    setSubmitting(true);
    try {
      await confirmPasswordReset(token, password);
      pushToast("Password updated — sign in with your new password", "success");
      navigate("/login", { replace: true });
    } catch (err) {
      setSubmitting(false);
      pushToast(getApiErrorMessage(err, "Couldn't reset the password"), "error");
    }
  };

  return (
    <div className="frost" style={{ minHeight: "100vh", display: "flex", flexDirection: "column", background: "var(--fr-bg)" }}>
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}>
        <div style={{ width: 420, maxWidth: "100%" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 11, justifyContent: "center", marginBottom: 22 }}>
            <div style={{ fontWeight: 800, fontSize: 22, letterSpacing: 3, color: "var(--fr-text)" }}>FROST</div>
          </div>

          {loading ? (
            <div style={{ ...card, textAlign: "center", color: "var(--fr-text-3)", fontSize: 14 }}>Checking the link…</div>
          ) : !info?.valid ? (
            <div style={card}>
              <h1 style={{ margin: "0 0 12px", fontSize: 24, fontWeight: 800, letterSpacing: "-.5px", color: "var(--fr-text)" }}>Invalid link</h1>
              <p style={{ margin: "0 0 22px", fontSize: 13.5, color: "var(--fr-text-2)", lineHeight: 1.55 }}>
                {REASON_TEXT[info?.reason ?? "not_found"] ?? REASON_TEXT.not_found}
              </p>
              <button
                type="button"
                className="clk"
                onClick={() => navigate("/login", { replace: true })}
                style={{ display: "inline-flex", alignItems: "center", gap: 8, height: 44, padding: "0 20px", border: "none", borderRadius: 12, background: "var(--fr-accent)", color: "var(--fr-on-accent)", font: "700 14px Inter,sans-serif", cursor: "pointer" }}
              >
                Go to sign in
                <Icon name="chevron-right" size={16} color="var(--fr-on-accent)" sw={2.4} />
              </button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} style={card}>
              <h1 style={{ margin: "0 0 8px", fontSize: 26, fontWeight: 800, letterSpacing: "-.6px", color: "var(--fr-text)" }}>Set a new password</h1>
              <p style={{ margin: "0 0 22px", fontSize: 13.5, color: "var(--fr-text-2)", lineHeight: 1.5 }}>
                For account <b style={{ color: "var(--fr-text)" }}>{info.username}</b>.
              </p>

              <div style={{ marginBottom: 15 }}>
                <label className="flabel" htmlFor="rp-pass">New password</label>
                <PasswordInput id="rp-pass" autoComplete="new-password" autoFocus placeholder="at least 8 characters" value={password} onChange={setPassword} />
              </div>

              <div style={{ marginBottom: 22 }}>
                <label className="flabel" htmlFor="rp-confirm">Confirm password</label>
                <PasswordInput id="rp-confirm" autoComplete="new-password" placeholder="repeat the password" value={confirm} onChange={setConfirm} />
                {confirm.length > 0 && !confirmValid && (
                  <div style={{ marginTop: 6, fontSize: 12, fontWeight: 600, color: "var(--fr-danger)" }}>Passwords don't match</div>
                )}
              </div>

              <button
                type="submit"
                className="clk"
                disabled={!canSubmit}
                style={{
                  width: "100%",
                  height: 46,
                  border: "none",
                  borderRadius: 12,
                  background: !canSubmit ? "var(--fr-accent-muted)" : "var(--fr-accent)",
                  color: "var(--fr-on-accent)",
                  font: "700 14px Inter,sans-serif",
                  cursor: !canSubmit ? "not-allowed" : "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: 9,
                  boxShadow: "0 6px 18px rgba(46,95,191,.28)",
                }}
              >
                {submitting ? "Saving…" : "Save password"}
                {!submitting && <Icon name="chevron-right" size={16} color="var(--fr-on-accent)" sw={2.4} />}
              </button>
            </form>
          )}
        </div>
      </div>

      <footer style={{ flex: "none", display: "flex", alignItems: "center", justifyContent: "center", gap: 8, padding: 16, fontSize: 12.5, color: "var(--fr-text-faint)", flexWrap: "wrap" }}>
        <span style={{ fontWeight: 700, color: "var(--fr-text-3)" }}>FROST</span>
        <span>·</span>
        <span>Copyright © 2026. All rights reserved.</span>
      </footer>
    </div>
  );
}
