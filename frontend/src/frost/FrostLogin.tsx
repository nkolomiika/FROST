/* FROST sign-in screen. Styled in the FROST design language and wired to the
   real backend auth via useAuthStore.signIn (POST /api/v1/auth/login). */

import { useState, type FormEvent } from "react";
import "./frost.css";
import { Icon } from "./icons";
import { PasswordInput } from "./PasswordInput";
import { FrostMark, FrostWordmark } from "./Brand";
import { getApiErrorMessage, requestPasswordReset } from "../api";
import { useAuthStore, useToastStore } from "../store";

export function FrostLogin() {
  const signIn = useAuthStore((s) => s.signIn);
  const completeTwoFactor = useAuthStore((s) => s.completeTwoFactor);
  const isLoading = useAuthStore((s) => s.isLoading);
  const pushToast = useToastStore((s) => s.pushToast);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  /* "credentials" — логин/пароль; "twofa" — код из аутентификатора;
     "forgot" — ввод email для ссылки сброса; "forgotSent" — подтверждение. */
  const [stage, setStage] = useState<"credentials" | "twofa" | "forgot" | "forgotSent">("credentials");
  const [code, setCode] = useState("");
  const [resetEmail, setResetEmail] = useState("");
  const [resetBusy, setResetBusy] = useState(false);

  const disabled = isLoading || !username.trim() || !password;
  const codeDisabled = isLoading || code.trim().length < 6;
  const resetDisabled = resetBusy || !resetEmail.trim();

  const handleForgot = async (e: FormEvent) => {
    e.preventDefault();
    if (resetDisabled) return;
    setResetBusy(true);
    try {
      await requestPasswordReset(resetEmail.trim());
      // Ответ бэкенда одинаков независимо от того, есть такой email или нет,
      // поэтому и текст подтверждения намеренно нейтральный.
      setStage("forgotSent");
    } catch (err) {
      pushToast(getApiErrorMessage(err, "Couldn't send the reset link"), "error");
    } finally {
      setResetBusy(false);
    }
  };

  const backToLogin = () => {
    setStage("credentials");
    setResetEmail("");
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (disabled) return;
    try {
      const res = await signIn(username.trim(), password);
      if (res.status === "2fa_required") {
        setStage("twofa");
        setCode("");
        return;
      }
      // On success the auth store sets `user`; FrostRoot swaps in the app.
    } catch (err) {
      // Surface the (now status-aware) error as a bottom-right toast.
      const message = err instanceof Error && err.message.trim() ? err.message : "Couldn't sign in";
      pushToast(message, "error");
    }
  };

  const handleVerify = async (e: FormEvent) => {
    e.preventDefault();
    if (codeDisabled) return;
    try {
      await completeTwoFactor(code.trim());
      // On success the auth store sets `user`; FrostRoot swaps in the app.
    } catch (err) {
      const message = err instanceof Error && err.message.trim() ? err.message : "Couldn't verify the code";
      pushToast(message, "error");
    }
  };

  const backToCredentials = () => {
    setStage("credentials");
    setCode("");
    setPassword("");
  };

  return (
    <div className="frost" style={{ minHeight: "100vh", display: "flex", flexDirection: "column", background: "var(--fr-bg)" }}>
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}>
        <div style={{ width: 420, maxWidth: "100%" }}>
          {/* brand */}
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 11, marginBottom: 24 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <FrostMark size={40} />
              <FrostWordmark size={27} spacing={4} />
            </div>
            <div className="mono" style={{ fontSize: 9.5, letterSpacing: 2.5, color: "var(--fr-text-faint)", fontWeight: 600 }}>OFFENSIVE RESEARCH &amp; MANAGEMENT</div>
          </div>

          {stage === "credentials" ? (
            <form onSubmit={handleSubmit} style={{ background: "var(--fr-surface)", border: "1px solid var(--fr-border-light)", borderRadius: 20, boxShadow: "0 24px 60px rgba(15,27,45,.10)", padding: "32px 34px 30px" }}>
              <h1 style={{ margin: "0 0 22px", fontSize: 26, fontWeight: 800, letterSpacing: "-.6px", color: "var(--fr-text)" }}>Sign in</h1>

              <div style={{ marginBottom: 15 }}>
                <label className="flabel" htmlFor="frost-user">Username</label>
                <input id="frost-user" className="finp" autoComplete="username" placeholder="ivanov" value={username} onChange={(e) => setUsername(e.target.value)} />
              </div>
              <div style={{ marginBottom: 22 }}>
                <label className="flabel" htmlFor="frost-pass">Password</label>
                <PasswordInput id="frost-pass" autoComplete="current-password" placeholder="••••••••" value={password} onChange={setPassword} />
              </div>

              <button
                type="submit"
                className="clk"
                disabled={disabled}
                style={{
                  width: "100%",
                  height: 46,
                  border: "none",
                  borderRadius: 12,
                  background: disabled ? "var(--fr-accent-muted)" : "var(--fr-accent)",
                  color: "var(--fr-on-accent)",
                  font: "700 14px Inter,sans-serif",
                  cursor: disabled ? "not-allowed" : "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: 9,
                  boxShadow: "0 6px 18px rgba(46,95,191,.28)",
                }}
              >
                {isLoading ? "Signing in…" : "Sign in"}
                {!isLoading && <Icon name="chevron-right" size={16} color="var(--fr-on-accent)" sw={2.4} />}
              </button>

              <button
                type="button"
                className="clk"
                onClick={() => setStage("forgot")}
                style={{ width: "100%", marginTop: 12, height: 38, border: "none", borderRadius: 10, background: "transparent", color: "var(--fr-text-2)", font: "600 13px Inter,sans-serif", cursor: "pointer" }}
              >
                Forgot password?
              </button>
            </form>
          ) : stage === "forgot" ? (
            <form onSubmit={handleForgot} style={{ background: "var(--fr-surface)", border: "1px solid var(--fr-border-light)", borderRadius: 20, boxShadow: "0 24px 60px rgba(15,27,45,.10)", padding: "32px 34px 30px" }}>
              <h1 style={{ margin: "0 0 8px", fontSize: 26, fontWeight: 800, letterSpacing: "-.6px", color: "var(--fr-text)" }}>Reset password</h1>
              <p style={{ margin: "0 0 22px", fontSize: 13.5, color: "var(--fr-text-2)", lineHeight: 1.5 }}>
                Enter the email address of your account — we'll send you a link to set a new password.
              </p>

              <div style={{ marginBottom: 22 }}>
                <label className="flabel" htmlFor="frost-reset-email">Email</label>
                <input
                  id="frost-reset-email"
                  className="finp"
                  type="email"
                  autoComplete="email"
                  autoFocus
                  placeholder="user@company.com"
                  value={resetEmail}
                  onChange={(e) => setResetEmail(e.target.value)}
                />
              </div>

              <button
                type="submit"
                className="clk"
                disabled={resetDisabled}
                style={{
                  width: "100%",
                  height: 46,
                  border: "none",
                  borderRadius: 12,
                  background: resetDisabled ? "var(--fr-accent-muted)" : "var(--fr-accent)",
                  color: "var(--fr-on-accent)",
                  font: "700 14px Inter,sans-serif",
                  cursor: resetDisabled ? "not-allowed" : "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: 9,
                  boxShadow: "0 6px 18px rgba(46,95,191,.28)",
                }}
              >
                {resetBusy ? "Sending…" : "Send reset link"}
                {!resetBusy && <Icon name="chevron-right" size={16} color="var(--fr-on-accent)" sw={2.4} />}
              </button>

              <button
                type="button"
                className="clk"
                onClick={backToLogin}
                style={{ width: "100%", marginTop: 12, height: 40, border: "none", borderRadius: 10, background: "transparent", color: "var(--fr-text-2)", font: "600 13px Inter,sans-serif", cursor: "pointer" }}
              >
                Back to sign in
              </button>
            </form>
          ) : stage === "forgotSent" ? (
            <div style={{ background: "var(--fr-surface)", border: "1px solid var(--fr-border-light)", borderRadius: 20, boxShadow: "0 24px 60px rgba(15,27,45,.10)", padding: "32px 34px 30px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 14 }}>
                <span style={{ width: 42, height: 42, flex: "none", borderRadius: "50%", background: "var(--fr-accent-soft)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                  <Icon name="mail" size={20} color="var(--fr-accent)" sw={2} />
                </span>
                <h1 style={{ margin: 0, fontSize: 22, fontWeight: 800, letterSpacing: "-.5px", color: "var(--fr-text)" }}>Check your email</h1>
              </div>
              {/* Формулировка намеренно не подтверждает существование аккаунта. */}
              <p style={{ margin: "0 0 22px", fontSize: 13.5, color: "var(--fr-text-2)", lineHeight: 1.6 }}>
                If an account exists for <b style={{ color: "var(--fr-text)" }}>{resetEmail.trim()}</b>, we've sent it a link to set a new password. The link is single-use and expires shortly.
              </p>
              <button
                type="button"
                className="clk"
                onClick={backToLogin}
                style={{ width: "100%", height: 46, border: "none", borderRadius: 12, background: "var(--fr-accent)", color: "var(--fr-on-accent)", font: "700 14px Inter,sans-serif", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center", gap: 9 }}
              >
                Back to sign in
                <Icon name="chevron-right" size={16} color="var(--fr-on-accent)" sw={2.4} />
              </button>
            </div>
          ) : (
            <form onSubmit={handleVerify} style={{ background: "var(--fr-surface)", border: "1px solid var(--fr-border-light)", borderRadius: 20, boxShadow: "0 24px 60px rgba(15,27,45,.10)", padding: "32px 34px 30px" }}>
              <h1 style={{ margin: "0 0 8px", fontSize: 26, fontWeight: 800, letterSpacing: "-.6px", color: "var(--fr-text)" }}>Two-factor code</h1>
              <p style={{ margin: "0 0 22px", fontSize: 13.5, color: "var(--fr-text-2)", lineHeight: 1.5 }}>Enter the 6-digit code from your authenticator app.</p>

              <div style={{ marginBottom: 22 }}>
                <label className="flabel" htmlFor="frost-2fa">Authentication code</label>
                <input
                  id="frost-2fa"
                  className="finp"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  autoFocus
                  maxLength={6}
                  placeholder="000000"
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                  style={{ font: "700 18px 'JetBrains Mono',monospace", letterSpacing: 6, textAlign: "center" }}
                />
              </div>

              <button
                type="submit"
                className="clk"
                disabled={codeDisabled}
                style={{
                  width: "100%",
                  height: 46,
                  border: "none",
                  borderRadius: 12,
                  background: codeDisabled ? "var(--fr-accent-muted)" : "var(--fr-accent)",
                  color: "var(--fr-on-accent)",
                  font: "700 14px Inter,sans-serif",
                  cursor: codeDisabled ? "not-allowed" : "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: 9,
                  boxShadow: "0 6px 18px rgba(46,95,191,.28)",
                }}
              >
                {isLoading ? "Verifying…" : "Verify"}
                {!isLoading && <Icon name="chevron-right" size={16} color="var(--fr-on-accent)" sw={2.4} />}
              </button>

              <button
                type="button"
                className="clk"
                onClick={backToCredentials}
                style={{ width: "100%", marginTop: 12, height: 40, border: "none", borderRadius: 10, background: "transparent", color: "var(--fr-text-2)", font: "600 13px Inter,sans-serif", cursor: "pointer" }}
              >
                Back to sign in
              </button>
            </form>
          )}
        </div>
      </div>

      <footer style={{ flex: "none", display: "flex", alignItems: "center", justifyContent: "center", gap: 8, padding: 16, background: "transparent", fontSize: 12.5, color: "var(--fr-text-faint)", flexWrap: "wrap" }}>
        <FrostMark size={14} />
        <span>·</span>
        <span>Copyright © 2026. All rights reserved.</span>
      </footer>
    </div>
  );
}
