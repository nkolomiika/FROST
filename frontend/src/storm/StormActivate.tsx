/* STORM invitation activation screen. Public (no session): the invitee opens the
   link from the email, picks a username (checked for availability) and a password.
   On success the backend auto-logs them in; we refresh the session and StormRoot
   swaps in the app. */

import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";
import "./storm.css";
import { Icon } from "./icons";
import { PasswordInput } from "./PasswordInput";
import {
  acceptInvitation,
  checkInvitationUsername,
  getApiErrorMessage,
  getInvitationInfo,
} from "../api";
import type { InvitationInfo } from "../types";
import { useAuthStore, useToastStore } from "../store";

const USERNAME_RE = /^[A-Za-z0-9._-]{3,100}$/;

const REASON_TEXT: Record<string, string> = {
  expired: "The link has expired. Ask an admin to resend the invitation.",
  used: "This invitation has already been activated. Try signing in normally.",
  not_found: "The link is invalid. Make sure you opened it in full, or request a new one.",
};

const card: React.CSSProperties = {
  background: "var(--st-surface)",
  border: "1px solid var(--st-border-light)",
  borderRadius: 20,
  boxShadow: "0 24px 60px rgba(15,27,45,.10)",
  padding: "32px 34px 30px",
};

export function StormActivate() {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const refreshUser = useAuthStore((s) => s.refreshUser);
  const pushToast = useToastStore((s) => s.pushToast);

  const [info, setInfo] = useState<InvitationInfo | null>(null);
  const [loadingInfo, setLoadingInfo] = useState(true);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [submitting, setSubmitting] = useState(false);
  // null — ещё не проверяли; иначе результат последней проверки занятости.
  const [available, setAvailable] = useState<boolean | null>(null);
  const [checking, setChecking] = useState(false);

  const usernameValid = USERNAME_RE.test(username);

  // Загрузка данных приглашения по токену.
  useEffect(() => {
    let cancelled = false;
    if (!token) {
      setInfo({ valid: false, reason: "not_found" });
      setLoadingInfo(false);
      return;
    }
    void (async () => {
      try {
        const data = await getInvitationInfo(token);
        if (!cancelled) setInfo(data);
      } catch {
        if (!cancelled) setInfo({ valid: false, reason: "not_found" });
      } finally {
        if (!cancelled) setLoadingInfo(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [token]);

  // Debounced-проверка занятости username (только при валидном формате).
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    setAvailable(null);
    if (!info?.valid || !usernameValid) {
      setChecking(false);
      return;
    }
    setChecking(true);
    debounceRef.current = setTimeout(() => {
      let cancelled = false;
      void (async () => {
        try {
          const ok = await checkInvitationUsername(token, username);
          if (!cancelled) setAvailable(ok);
        } catch {
          if (!cancelled) setAvailable(null);
        } finally {
          if (!cancelled) setChecking(false);
        }
      })();
      return () => {
        cancelled = true;
      };
    }, 400);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [username, usernameValid, info?.valid, token]);

  const passwordValid = password.length >= 8;
  const confirmValid = confirm.length > 0 && confirm === password;
  const canSubmit =
    !!info?.valid && usernameValid && available === true && passwordValid && confirmValid && !submitting;

  const usernameHint = useMemo(() => {
    if (!username) return null;
    if (!usernameValid) return { text: "3–100 characters: letters, digits, . _ -", color: "var(--st-danger)" };
    if (checking) return { text: "Checking…", color: "var(--st-text-3)" };
    if (available === true) return { text: "Username available", color: "var(--st-success)" };
    if (available === false) return { text: "Username already taken", color: "var(--st-danger)" };
    return null;
  }, [username, usernameValid, checking, available]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    setSubmitting(true);
    try {
      await acceptInvitation(token, { username: username.trim(), password });
      pushToast("Account activated. Welcome!", "success");
      // Бэкенд уже выдал сессию (cookie) — подхватываем её; StormRoot покажет приложение.
      await refreshUser();
    } catch (err) {
      setSubmitting(false);
      pushToast(getApiErrorMessage(err, "Couldn't activate the invitation"), "error");
    }
  };

  return (
    <div className="storm" style={{ minHeight: "100vh", display: "flex", flexDirection: "column", background: "var(--st-bg)" }}>
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}>
        <div style={{ width: 440, maxWidth: "100%" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 11, justifyContent: "center", marginBottom: 22 }}>
            <div style={{ fontWeight: 800, fontSize: 22, letterSpacing: 3, color: "var(--st-text)" }}>STORM</div>
          </div>

          {loadingInfo ? (
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
            <form onSubmit={handleSubmit} style={card}>
              <h1 style={{ margin: "0 0 22px", fontSize: 26, fontWeight: 800, letterSpacing: "-.6px", color: "var(--st-text)" }}>Complete your registration</h1>

              <div style={{ marginBottom: 15 }}>
                <label className="flabel">Email</label>
                <input className="finp" value={info.email ?? ""} readOnly disabled style={{ background: "var(--st-elevated)", color: "var(--st-text-2)" }} />
              </div>

              <div style={{ marginBottom: 15 }}>
                <label className="flabel" htmlFor="act-user">Username</label>
                <input
                  id="act-user"
                  className="finp"
                  autoComplete="username"
                  autoFocus
                  placeholder="ivanov"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                />
                {usernameHint && <div style={{ marginTop: 6, fontSize: 12, fontWeight: 600, color: usernameHint.color }}>{usernameHint.text}</div>}
              </div>

              <div style={{ marginBottom: 15 }}>
                <label className="flabel" htmlFor="act-pass">Password</label>
                <PasswordInput
                  id="act-pass"
                  autoComplete="new-password"
                  placeholder="••••••••"
                  value={password}
                  onChange={setPassword}
                />
              </div>

              <div style={{ marginBottom: 22 }}>
                <label className="flabel" htmlFor="act-confirm">Confirm password</label>
                <PasswordInput
                  id="act-confirm"
                  autoComplete="new-password"
                  placeholder="••••••••"
                  value={confirm}
                  onChange={setConfirm}
                />
                {confirm.length > 0 && !confirmValid && (
                  <div style={{ marginTop: 6, fontSize: 12, fontWeight: 600, color: "var(--st-danger)" }}>Passwords don't match</div>
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
                  background: !canSubmit ? "var(--st-accent-muted)" : "var(--st-accent)",
                  color: "var(--st-on-accent)",
                  font: "700 14px Inter,sans-serif",
                  cursor: !canSubmit ? "not-allowed" : "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: 9,
                  boxShadow: "0 6px 18px rgba(46,95,191,.28)",
                }}
              >
                {submitting ? "Activating…" : "Activate and sign in"}
                {!submitting && <Icon name="chevron-right" size={16} color="var(--st-on-accent)" sw={2.4} />}
              </button>
            </form>
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
