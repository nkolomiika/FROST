import React, { useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import { StormActivate } from "./storm/StormActivate";
import { StormApp } from "./storm/StormApp";
import { StormReactivate } from "./storm/StormReactivate";
import { StormResetPassword } from "./storm/StormResetPassword";
import { StormLogin } from "./storm/StormLogin";
import { StormToaster } from "./storm/StormToaster";
import { useAuthStore } from "./store";
import { useThemeStore } from "./storm/theme";

/** The signed-out URL. Everything else belongs to the authenticated app. */
export const LOGIN_PATH = "/login";
/** Public invitation-activation URL (?token=...). Reachable without a session. */
export const ACTIVATE_PATH = "/activate";
/** Public password-reset URL (?token=...). Reachable without a session. */
export const RESET_PATH = "/reset-password";
/** Public reactivation URL (?token=...): returns a deactivated user, then logs in. */
export const REACTIVATE_PATH = "/reactivate";

/** Auth gate: initialise the session, then show the login screen or the app. */
export function StormRoot() {
  const initialize = useAuthStore((s) => s.initialize);
  const isInitialized = useAuthStore((s) => s.isInitialized);
  const user = useAuthStore((s) => s.user);
  const theme = useThemeStore((s) => s.theme);
  const navigate = useNavigate();
  const location = useLocation();

  /* The dark theme is a signed-in preference: the login / activate / reset
     screens always render light (and in English). Once auth resolves, reflect
     the saved theme for a signed-in user, else force light. Before it resolves
     we leave whatever initTheme() applied, so a signed-in dark user doesn't
     flash light on reload. */
  useEffect(() => {
    if (!isInitialized) return;
    document.documentElement.setAttribute("data-theme", user ? theme : "light");
  }, [isInitialized, user, theme]);

  useEffect(() => {
    void initialize();
  }, [initialize]);

  /* The URL has to follow the auth state, not just the rendered component:
     signing out must leave /projects/1 for /login, and signing in must not strand
     the user on /login. `replace` keeps signed-out pages out of the back history.
     Waits for isInitialized, otherwise a reload would bounce to /login before the
     session is known. */
  const onActivate = location.pathname === ACTIVATE_PATH;
  const onReset = location.pathname === RESET_PATH;
  const onReactivate = location.pathname === REACTIVATE_PATH;
  // Публичные страницы: на них не гоним на /login при отсутствии сессии.
  const onPublicPage = onActivate || onReset || onReactivate;

  useEffect(() => {
    if (!isInitialized) return;
    // /activate — публичная страница активации. Не гоним на /login, пока сессии
    // нет; как только активация выдала сессию (user появился) — уводим в приложение.
    if (onPublicPage) {
      if (user) navigate("/projects", { replace: true });
      return;
    }
    if (!user && location.pathname !== LOGIN_PATH) navigate(LOGIN_PATH, { replace: true });
    else if (user && location.pathname === LOGIN_PATH) navigate("/projects", { replace: true });
  }, [isInitialized, user, location.pathname, navigate, onPublicPage]);

  let content: React.ReactNode;
  if (!isInitialized) {
    content = (
      <div className="storm" style={{ minHeight: "100vh", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 16, background: "var(--st-bg)" }}>
        <div style={{ fontWeight: 800, fontSize: 26, letterSpacing: "-.4px", color: "var(--st-text)" }}>STORM</div>
        <div className="mono" style={{ fontSize: 11, letterSpacing: 2, color: "var(--st-text-faint)", fontWeight: 700 }}>LOADING STORM…</div>
      </div>
    );
  } else if (onActivate && !user) {
    content = <StormActivate />;
  } else if (onReset && !user) {
    content = <StormResetPassword />;
  } else if (onReactivate && !user) {
    content = <StormReactivate />;
  } else if (!user) {
    content = <StormLogin />;
  } else {
    content = <StormApp />;
  }

  return (
    <>
      {content}
      <StormToaster />
    </>
  );
}
