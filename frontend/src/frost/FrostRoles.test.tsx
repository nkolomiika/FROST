import { fireEvent, render, screen, within } from "@testing-library/react";
import { vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { FrostApp } from "./FrostApp";
import { useAuthStore } from "../store";
import type { User, UserRole } from "../types";

// Every collection Frost renders is backend-driven, so the API module is mocked
// wholesale. Project 1 is created by admin (id 1); project 2 by d.petrov (id 4).
vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  const mk = (id: number, name: string, status: string, createdBy: number) => ({
    id, name, folder: "", description: `${name} — assessment`, start_date: "2026-04-27",
    end_date: "2026-07-27", timeline_frozen_at: null, status, created_by: createdBy,
    created_at: "2026-01-01T00:00:00Z", updated_at: "2026-07-10T00:00:00Z",
  });
  const projects = [
    mk(1, "Acme Corp — External Perimeter", "active", 1),
    mk(2, "Northwind API", "active", 4),
    mk(3, "Globex VPN Audit", "archived", 1),
  ];
  // Workspace members are backend-driven too: admin + alice are project leads,
  // diana is not — mirrors the real seeded users.
  const mkUser = (id: number, username: string, role: string, isLead: boolean) => ({
    id, username, email: `${username}@example.com`, full_name: null, avatar_url: null,
    role, project_role: isLead ? "lead" : "pentester", is_active: true, totp_enabled: false, password_changed_at: null,
    created_at: "2026-01-01T00:00:00Z",
  });
  const users = [
    mkUser(1, "admin", "admin", true),
    mkUser(2, "alice", "pentester", true),
    mkUser(5, "diana", "pentester", false),
  ];
  const mkMember = (userId: number, username: string, isLead: boolean) => ({
    user_id: userId, username, email: `${username}@example.com`, role: "pentester",
    project_role: isLead ? "lead" : "pentester", added_at: "2026-05-01T00:00:00Z",
  });
  // Project members per project id — what the Members tab renders.
  const membersByProject: Record<number, ReturnType<typeof mkMember>[]> = {
    1: [mkMember(3, "i.volkov", false)],
    2: [mkMember(4, "d.petrov", false), mkMember(6, "m.antonov", true)],
    3: [],
  };
  return {
    ...actual,
    getProjects: vi.fn(async () => ({ items: projects, total: projects.length, page: 1, size: 100, pages: 1 })),
    // Without this the projects loader falls through to a real XHR.
    getProjectStats: vi.fn(async () =>
      projects.map((p) => ({ project_id: p.id, status: p.status, hosts_count: 2, total_findings: 3, open_findings: 1 }))
    ),
    getUsers: vi.fn(async () => ({ items: users, total: users.length, page: 1, size: 200, pages: 1 })),
    getInvitations: vi.fn(async () => []),
    getProjectMembers: vi.fn(async (projectId: number) => membersByProject[projectId] ?? []),
    getHosts: vi.fn(async () => ({ items: [], total: 0, page: 1, size: 100, pages: 1 })),
    getVulnerabilities: vi.fn(async () => ({ items: [], total: 0, page: 1, size: 100, pages: 1 })),
    listProjectNotes: vi.fn(async () => []),
    getProjectActivity: vi.fn(async () => []),
    listNotifications: vi.fn(async () => ({ items: [], total: 0, page: 1, size: 20, pages: 1 })),
    createProject: vi.fn(async () => projects[0]),
    updateProject: vi.fn(async () => projects[0]),
    deleteProject: vi.fn(async () => undefined),
  };
});

const asUser = (id: number, username: string, role: UserRole, projectRole: "lead" | "pentester" = "pentester"): User => ({
  id,
  username,
  email: `${username}@example.com`,
  full_name: null,
  avatar_url: null,
  role,
  project_role: projectRole,
  is_active: true,
  is_locked: false,
  totp_enabled: false,
  password_changed_at: null,
  created_at: "2026-01-01T00:00:00Z",
});

describe("FROST role model", () => {
  afterEach(() => {
    useAuthStore.setState({ user: null, isInitialized: false });
  });

  // NB: rule 1.1 (a non-admin only sees projects they belong to) is enforced by
  // the backend (GET /projects), verified separately — not a client-side concern.

  // 1.2 — a plain project member can VIEW the member list, but not manage it.
  // i.volkov (id 3) is a plain member of project 1, which admin (id 1) created.
  it("lets a non-lead project member view members but not manage them", async () => {
    useAuthStore.setState({ user: asUser(3, "i.volkov", "pentester"), isInitialized: true });
    render(<MemoryRouter><FrostApp /></MemoryRouter>);
    fireEvent.click(await screen.findByText("Acme Corp — External Perimeter"));
    const main = document.querySelector("main") as HTMLElement;
    // Team card offers a read-only "View all →", never the manager's "Manage →".
    expect(await within(main).findByText("View all →")).toBeInTheDocument();
    expect(within(main).queryByText("Manage →")).not.toBeInTheDocument();
    // The Members tab is visible and lists members…
    fireEvent.click(within(main).getByText("Members"));
    expect(await within(main).findByText("i.volkov")).toBeInTheDocument();
    // …but the add/remove controls are hidden for a non-manager.
    expect(within(main).queryByText("Add member")).not.toBeInTheDocument();
  });

  // 1.3 — only admins see the workspace Members admin page (sidebar item).
  it("hides the workspace Members nav item from non-admins", () => {
    useAuthStore.setState({ user: asUser(3, "i.volkov", "pentester"), isInitialized: true });
    render(<MemoryRouter><FrostApp /></MemoryRouter>);
    expect(screen.queryByText("Members")).not.toBeInTheDocument();
  });

  // 1.3 / 1.4 / req.2 — admin sees the page, role badges, and can filter by workspace role.
  const pill = (main: HTMLElement, label: string) =>
    within(main).getAllByText(label).find((el) => el.classList.contains("clk")) as HTMLElement;

  it("lets an admin view and filter workspace members by role", async () => {
    useAuthStore.setState({ user: asUser(1, "admin", "admin", "lead"), isInitialized: true });
    render(<MemoryRouter><FrostApp /></MemoryRouter>);
    fireEvent.click(screen.getByText("Members"));
    const main = document.querySelector("main") as HTMLElement;
    expect(await within(main).findByText("alice")).toBeInTheDocument();
    expect(within(main).getByText("diana")).toBeInTheDocument();
    fireEvent.click(pill(main, "Admin"));
    expect(within(main).getByText("admin")).toBeInTheDocument();
    expect(within(main).queryByText("alice")).not.toBeInTheDocument();
    expect(within(main).queryByText("diana")).not.toBeInTheDocument();
  });

  // req.6 — role pills toggle: clicking an active pill clears it again.
  it("toggles a workspace role filter off when clicked twice", async () => {
    useAuthStore.setState({ user: asUser(1, "admin", "admin", "lead"), isInitialized: true });
    render(<MemoryRouter><FrostApp /></MemoryRouter>);
    fireEvent.click(screen.getByText("Members"));
    const main = document.querySelector("main") as HTMLElement;
    await within(main).findByText("alice");
    fireEvent.click(pill(main, "Admin"));
    expect(within(main).queryByText("alice")).not.toBeInTheDocument();
    fireEvent.click(pill(main, "Admin"));
    expect(within(main).getByText("alice")).toBeInTheDocument();
    expect(within(main).getByText("diana")).toBeInTheDocument();
  });

  // req.6 — filters combine: AND across the ROLE and PROJECT groups.
  it("combines the workspace role and project role filters", async () => {
    useAuthStore.setState({ user: asUser(1, "admin", "admin", "lead"), isInitialized: true });
    render(<MemoryRouter><FrostApp /></MemoryRouter>);
    fireEvent.click(screen.getByText("Members"));
    const main = document.querySelector("main") as HTMLElement;
    await within(main).findByText("alice");
    // "User" + "Lead" → alice (pentester account, lead somewhere); not diana, not admin.
    fireEvent.click(pill(main, "User"));
    fireEvent.click(pill(main, "Lead"));
    expect(within(main).getByText("alice")).toBeInTheDocument();
    expect(within(main).queryByText("diana")).not.toBeInTheDocument();
    expect(within(main).queryByText("admin")).not.toBeInTheDocument();
  });

  // req.2 — project members come from the backend and can be searched by username.
  it("searches project members by username", async () => {
    useAuthStore.setState({ user: asUser(1, "admin", "admin", "lead"), isInitialized: true });
    render(<MemoryRouter><FrostApp /></MemoryRouter>);
    fireEvent.click(await screen.findByText("Northwind API"));
    const main = document.querySelector("main") as HTMLElement;
    fireEvent.click(within(main).getByText("Members"));
    expect(await within(main).findByText("d.petrov")).toBeInTheDocument();
    fireEvent.change(within(main).getByPlaceholderText("Search by username…"), { target: { value: "antonov" } });
    expect(within(main).getByText("m.antonov")).toBeInTheDocument();
    expect(within(main).queryByText("d.petrov")).not.toBeInTheDocument();
  });
});
