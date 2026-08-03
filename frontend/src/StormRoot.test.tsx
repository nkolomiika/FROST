import { fireEvent, render, screen } from "@testing-library/react";
import { vi } from "vitest";
import { MemoryRouter, useLocation } from "react-router-dom";

import { StormRoot } from "./StormRoot";
import { useAuthStore } from "./store";
import type { User } from "./types";

// The gate only needs auth to resolve; the app's own loaders are stubbed out.
vi.mock("./api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./api")>();
  const empty = { items: [], total: 0, page: 1, size: 20, pages: 1 };
  return {
    ...actual,
    logout: vi.fn(async () => undefined),
    getProjects: vi.fn(async () => empty),
    getProjectStats: vi.fn(async () => []),
    getUsers: vi.fn(async () => empty),
    listNotifications: vi.fn(async () => empty),
  };
});

const admin: User = {
  id: 1, username: "admin", email: "admin@example.com", full_name: null, avatar_url: null,
  role: "admin", project_role: "lead", is_active: true, is_locked: false, totp_enabled: false, password_changed_at: null,
  created_at: "2026-01-01T00:00:00Z",
};

const Path = () => <span data-testid="path">{useLocation().pathname}</span>;

const renderAt = (path: string) =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <StormRoot />
      <Path />
    </MemoryRouter>
  );

describe("StormRoot auth gate", () => {
  afterEach(() => {
    useAuthStore.setState({ user: null, isInitialized: false });
  });

  it("sends a signed-out visitor to /login", async () => {
    useAuthStore.setState({ user: null, isInitialized: true });
    renderAt("/projects/1/vulns");
    expect(await screen.findByTestId("path")).toHaveTextContent("/login");
  });

  it("keeps a signed-in user on their deep link", async () => {
    useAuthStore.setState({ user: admin, isInitialized: true });
    renderAt("/projects/1/notes");
    expect(screen.getByTestId("path")).toHaveTextContent("/projects/1/notes");
  });

  it("does not bounce to /login before the session is known", () => {
    useAuthStore.setState({ user: null, isInitialized: false });
    renderAt("/projects/1");
    // Still initialising: the URL must be left alone, or a reload would lose it.
    expect(screen.getByTestId("path")).toHaveTextContent("/projects/1");
  });

  it("moves a signed-in user off /login", async () => {
    useAuthStore.setState({ user: admin, isInitialized: true });
    renderAt("/login");
    expect(await screen.findByTestId("path")).toHaveTextContent("/projects");
  });

  // Logout must change the URL too, not just swap the rendered screen.
  it("redirects to /login on logout", async () => {
    useAuthStore.setState({ user: admin, isInitialized: true });
    renderAt("/projects/1/vulns");
    expect(screen.getByTestId("path")).toHaveTextContent("/projects/1/vulns");

    fireEvent.click(await screen.findByText("Logout"));

    expect(await screen.findByTestId("path")).toHaveTextContent("/login");
    expect(useAuthStore.getState().user).toBeNull();
  });
});
