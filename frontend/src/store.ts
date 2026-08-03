import { create } from "zustand";
import { getApiErrorMessage, getMe, login, logout, verifyTwoFactor } from "./api";
import type { User } from "./types";

/** Результат первого шага входа: либо мы уже вошли, либо нужен код 2FA. */
export type SignInResult = { status: "ok"; user: User } | { status: "2fa_required" };

interface AuthState {
  user: User | null;
  isLoading: boolean;
  isInitialized: boolean;
  error: string | null;
  initialize: () => Promise<void>;
  signIn: (username: string, password: string) => Promise<SignInResult>;
  completeTwoFactor: (code: string) => Promise<User>;
  signOut: () => Promise<void>;
  setUser: (user: User | null) => void;
  refreshUser: () => Promise<User | null>;
}

type ToastSeverity = "error" | "warning" | "info" | "success";

interface ToastItem {
  id: number;
  message: string;
  severity: ToastSeverity;
}

interface ToastState {
  nextId: number;
  toasts: ToastItem[];
  pushToast: (message: string, severity?: ToastSeverity) => void;
  dismissToast: (id: number) => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  isLoading: false,
  isInitialized: false,
  error: null,
  initialize: async () => {
    // На странице логина смысла дёргать /users/me нет — пользователь явно
    // не авторизован, лишний 401 в DevTools только сбивает с толку.
    if (typeof window !== "undefined" && window.location.pathname === "/login") {
      set({ user: null, isInitialized: true, isLoading: false, error: null });
      return;
    }
    set({ isLoading: true, error: null });
    try {
      const me = await getMe();
      set({ user: me, isInitialized: true, isLoading: false });
    } catch {
      set({ user: null, isInitialized: true, isLoading: false });
    }
  },
  signIn: async (username, password) => {
    set({ isLoading: true, error: null });
    try {
      const res = await login(username, password);
      if (res.requires_2fa) {
        // Пароль принят — второй шаг завершит completeTwoFactor. Сессии ещё нет.
        set({ isLoading: false });
        return { status: "2fa_required" };
      }
      const me = await getMe();
      set({ user: me, isLoading: false });
      return { status: "ok", user: me };
    } catch (error) {
      const message = getApiErrorMessage(error, "Couldn't sign in");
      set({ error: message, isLoading: false });
      throw new Error(message);
    }
  },
  completeTwoFactor: async (code) => {
    set({ isLoading: true, error: null });
    try {
      await verifyTwoFactor(code);
      const me = await getMe();
      set({ user: me, isLoading: false });
      return me;
    } catch (error) {
      const message = getApiErrorMessage(error, "Couldn't verify the code");
      set({ error: message, isLoading: false });
      throw new Error(message);
    }
  },
  signOut: async () => {
    await logout();
    set({ user: null });
  },
  setUser: (user) => set({ user }),
  refreshUser: async () => {
    try {
      const me = await getMe();
      set({ user: me });
      return me;
    } catch {
      set({ user: null });
      return null;
    }
  },
}));

export const useToastStore = create<ToastState>((set) => ({
  nextId: 1,
  toasts: [],
  pushToast: (message, severity = "error") =>
    set((state) => ({
      nextId: state.nextId + 1,
      toasts: [...state.toasts, { id: state.nextId, message, severity }],
    })),
  dismissToast: (id) =>
    set((state) => ({
      toasts: state.toasts.filter((toast) => toast.id !== id),
    })),
}));
