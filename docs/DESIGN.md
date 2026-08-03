# 🎯 Промпт для Codex: UI/UX дизайн STORM

> Скопируй этот промпт целиком в Codex (или любую другую модель). 
> Подставь конкретные экраны по необходимости.

---

## SYSTEM / ROLE

You are a senior product designer and React/TypeScript engineer specialising in security tooling.
Your target users are **pentesters and security engineers** — technical, keyboard-driven, used to tools like Burp Suite, Metasploit, and Linear. They work under time pressure and need dense, scannable UIs, not marketing pages.

The product is **STORM — Offensive Security Research & Management**: a closed web application for managing pentest projects, tracking vulnerabilities, documenting infrastructure assets, and generating reports. It is NOT a public SaaS — it runs internally via Docker Compose.

---

## AESTHETIC DIRECTION

Commit to this aesthetic: **industrial-terminal meets modern SaaS** — think Vercel Dashboards crossed with a monochrome hacker terminal. Key traits:
- Dark theme, near-black backgrounds (`#0a0a0b`), subtle cool-gray surfaces
- Monospace font for all data-dense elements (IPs, CVEs, port numbers, CVSS vectors)
- A single accent color — deep red (`#dc2626`) used exclusively for critical severity badges, danger actions, and primary CTAs
- Tight spacing, high information density — pentesters work with lists, not cards
- No rounded corners on tables, sharp 2px borders on interactive elements
- Severity colors strictly follow industry standard: Critical=red, High=orange, Medium=yellow, Low=blue, Info=gray


---

## TECH STACK

- **React + TypeScript**
- **Tailwind CSS** (utility-first, no external component library)
- **shadcn/ui** for primitives (Dialog, DropdownMenu, Tooltip, Badge) — dark variant only
- **react-router-dom v6** for routing
- **Axios + withCredentials: true** (httpOnly cookie auth — NO Authorization header, NO localStorage token)
- **Zustand** for global state (auth, notifications, websocket)
- Custom fonts: `JetBrains Mono` for data, `IBM Plex Sans` for UI prose

---

## APPLICATION STRUCTURE

### Routes
| Path | Page | Access |
|---|---|---|
| `/login` | LoginPage | Public |
| `/projects` | ProjectsPage | All authenticated |
| `/projects/:projectId` | ProjectDetailPage | Project member or admin |
| `/projects/:projectId/vulnerabilities/:vulnId` | VulnerabilityDetailPage | Project member or admin |
| `/admin/users` | UsersPage | Admin only |
| `/admin/audit` | AuditLogsPage | Admin only |

### Global Layout (authenticated pages)
```
┌─────────────────────────────────────────────────────┐
│ TopBar: [STORM logo] [breadcrumb] [🔔 badge] [user] │
├──────────┬──────────────────────────────────────────┤
│ Sidebar  │  Main content area                       │
│ (240px)  │                                          │
│          │                                          │
└──────────┴──────────────────────────────────────────┘
```

Sidebar items:
- Projects (all roles)
- Users (admin only)
- Audit Log (admin only)

---

## DATA MODELS (from DB schema — use these exact types)

```typescript
// Severity levels — used EVERYWHERE, must be consistent
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// Vulnerability statuses
type VulnStatus = 'open' | 'in_progress' | 'fixed' | 'wont_fix' | 'accepted_risk';

// Project statuses
type ProjectStatus = 'active' | 'completed' | 'archived';

// Host statuses
type HostStatus = 'up' | 'down' | 'unknown';

// Port states
type PortState = 'open' | 'closed' | 'filtered';

// HTTP methods
type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';

interface User {
  id: string;
  username: string;
  email: string;
  role: 'admin' | 'pentester';
  is_active: boolean;
  created_at: string;
}

interface Project {
  id: string;
  name: string;
  description?: string;
  start_date?: string;
  end_date?: string;
  status: ProjectStatus;
  created_by: string;
  created_at: string;
  updated_at: string;
}

interface Host {
  id: string;
  project_id: string;
  ip_address?: string;
  hostname?: string;
  os?: string;
  status: HostStatus;
  notes?: string;
  ports?: Port[];
  endpoints?: Endpoint[];
}

interface Port {
  id: string;
  host_id: string;
  port_number: number;
  protocol: 'tcp' | 'udp';
  state: PortState;
  services?: Service[];
}

interface Service {
  id: string;
  port_id: string;
  name: string;
  version?: string;
  banner?: string;
}

interface Endpoint {
  id: string;
  host_id: string;
  path: string;
  method?: HttpMethod;
  description?: string;
}

interface Vulnerability {
  id: string;
  project_id: string;
  title: string;
  description?: string;
  severity: Severity;
  cvss_version?: '3.1' | '4.0';
  cvss_score?: number;
  cvss_vector?: string;
  cwe_id?: string;
  status: VulnStatus;
  steps_to_reproduce?: string;
  impact?: string;
  recommendations?: string;
  created_by: string;
  assets?: VulnerabilityAsset[];
  files?: FileRecord[];
  comments_count?: number;
}

interface VulnerabilityAsset {
  id: string;
  asset_type: 'host' | 'port' | 'service' | 'endpoint';
  asset_id: string;
  asset_detail: Record<string, unknown>;
}

interface Comment {
  id: string;
  user_id: string;
  username: string;
  content: string; // may contain @mentions
  mentions: { user_id: string; username: string }[];
  created_at: string;
  updated_at: string;
}

interface Notification {
  id: string;
  type: 'mention';
  comment_id: string;
  is_read: boolean;
  created_at: string;
  context: {
    vulnerability_id: string;
    vulnerability_title: string;
    project_id: string;
    commenter_username: string;
  };
}
```

---

## SCREENS TO DESIGN

Design each screen below. For each screen provide:
1. **Full JSX component** (TypeScript, functional, with mock data inline)
2. **Inline comments** explaining every key UX decision
3. **State variants** where relevant: loading skeleton, empty state, error state
4. **List of reusable sub-components** extracted from this screen

---

### SCREEN 1 — LoginPage (`/login`)

**Context:** Entry point. The system is closed — no registration link. Admin creates accounts.

**Requirements:**
- Username + Password fields (not email — users log in by username)
- "Sign in" button — POST /api/v1/auth/login with `withCredentials: true`
- On 401 — show "Invalid credentials" inline (not toast)
- On success — redirect to `/projects`
- NO "forgot password" link (admin resets passwords)
- STORM logo + short tagline at top: "Offensive Security Research & Management"

**Aesthetic note:** Terminal-style — large monospace heading, subtle scan-line texture on background, minimal form.

---

### SCREEN 2 — ProjectsPage (`/projects`)

**Context:** Landing page after login. Pentesters see only their projects. Admins see all.

**Layout:**
```
[Header: "Projects"]  [+ New Project (admin only)]
[Filter tabs: All | Active | Completed | Archived]
[Project cards grid — 3 columns desktop, 1 mobile]
```

**Each project card must show:**
- Project name (large, monospace)
- Status badge: active=green, completed=gray, archived=dimmed
- Date range (start — end) or "No deadline"
- Member count (avatars or "N members")
- Vuln summary: mini bar showing Critical/High/Medium/Low counts (color-coded, like a severity spectrum)
- Quick action: click card → navigate to project detail

**Empty state:** "No projects assigned. Contact your administrator."

**Admin extras:**
- "+ New Project" button → opens Dialog with form
- Project card has "⋮" menu: Edit, Archive, Delete

---

### SCREEN 3 — ProjectDetailPage (`/projects/:projectId`)

**Context:** Main workspace. Most time is spent here.

**This is the most complex page — design it with tabs:**

```
[Project name + status badge]  [Actions: Import | Generate Report | Edit (admin)]
[Tabs: Overview | Hosts | Vulnerabilities | Members]
```

**Tab: Overview**
- Stats row: Total hosts, Open vulns, Critical vulns, Fixed vulns (4 stat cards)
- Severity distribution donut chart (or horizontal bar)
- Status distribution bar: open / in_progress / fixed / wont_fix / accepted_risk
- Recent activity feed (last 10 WebSocket events in project)

**Tab: Hosts**
- Toolbar: [Search by IP/hostname] [+ Add Host] [Import JSON]
- Table columns: IP Address | Hostname | OS | Status (up/down/unknown) | Ports | Endpoints | Actions
- Expandable row: clicking a host row expands it to show ports tree:
  ```
  ▼ 192.168.1.1 (target.local) — Ubuntu 22.04 — UP
      Ports:
        80/tcp  open   http  Apache/2.4.51
        443/tcp open   https nginx/1.21
      Endpoints:
        POST /api/login
        GET  /api/users
  ```
- Port state badge: open=green, filtered=yellow, closed=gray
- "+ Add Port" and "+ Add Endpoint" inline within expanded row

**Tab: Vulnerabilities**
- Toolbar: [Search] [Filter: severity ▾] [Filter: status ▾] [+ Add Vulnerability]
- Table columns: Severity | Title | CVSS | Status | Assets | Files | Comments | Created | Actions
- Severity column: colored icon + label (Critical/High/Medium/Low/Info)
- Status column: pill badge with status-specific color
- Clicking title → navigate to VulnerabilityDetailPage
- PATCH /status accessible from row dropdown (quick status change without leaving page)
- Pagination controls at bottom

**Tab: Members (admin only)**
- List of members: Avatar | Username | Role | Added date | Remove button
- "+ Add Member" → dropdown/autocomplete to search existing users

---

### SCREEN 4 — VulnerabilityDetailPage (`/projects/:projectId/vulnerabilities/:vulnId`)

**Context:** Full vulnerability record — the most information-dense page.

**Layout (two-column on desktop):**
```
Left column (60%):           Right column (40%):
──────────────────           ───────────────────
Title (editable)             Severity badge (large)
Status (editable pill)       CVSS score (large number)
                             CVSS version + vector (mono)
Description (markdown)       CWE ID
Steps to Reproduce (mono)    Status change dropdown
Impact                       Linked Assets section
Recommendations              Files section
                             
Comments section (full width below)
```

**Severity badge:** When severity is Critical — show pulsing red dot animation.

**CVSS section:**
- Large number (e.g. "9.8") in accent color
- Version selector: v3.1 / v4.0 toggle
- Vector field: monospace, inline edit
- Visual CVSS score bar (0-10 color gradient: green→yellow→red)

**Linked Assets section (right column):**
- Each asset shown as a chip: `[host] 192.168.1.1` or `[endpoint] POST /api/login`
- "+ Link Asset" → opens modal with tree selector (Host → Port → Service / Endpoint)
- Clicking an asset chip highlights it / navigates to host context

**Files section:**
- Grid of file thumbnails (images shown as preview, other types as icon + filename)
- Drag-and-drop upload zone with dotted border
- On hover: overlay with Download and Delete icons
- Max file size: 50MB — show progress bar on upload

**Comments section (full width, below both columns):**
- Chronological list of comments
- Each comment: Avatar | Username (monospace) | Timestamp | Content | Edit/Delete (own only)
- @mentions highlighted in accent color
- Comment input: textarea with @mention autocomplete (search project members)
- Submit: Ctrl+Enter or button

**All fields are inline-editable** (click to edit, Escape to cancel, Enter/blur to save via PUT).

---

### SCREEN 5 — UsersPage (`/admin/users`) — Admin only

**Layout:**
```
[Heading: "Users"]  [+ Create User]
[Table: Username | Email | Role | Status | Created | Actions]
```

- Role badge: admin=purple, pentester=blue
- Status badge: active=green, inactive=red
- Actions per row: Edit (opens dialog), Reset Password, Toggle active, Delete
- "Delete" disabled if user = current user (with tooltip explaining why)
- "+ Create User" → Dialog with form: Username, Email, Password, Role

---

### SCREEN 6 — AuditLogsPage (`/admin/audit`) — Admin only

**Context:** Security audit trail. Append-only. Read-only view.

**Layout:**
- Filters bar: [User dropdown] [Action type] [Entity type] [Date range picker]
- Table (dense, monospace for key fields):

| Timestamp | User | Action | Entity | Details | IP |
|---|---|---|---|---|---|
| 2024-01-01 14:32 | nikita | STATUS_CHANGE | vulnerability | open → fixed | 10.0.0.1 |

- Action badge colors: LOGIN=blue, CREATE=green, UPDATE=yellow, DELETE=red, STATUS_CHANGE=purple
- "Details" column: renders JSONB details field inline (collapsed, click to expand)
- No edit/delete controls — read-only

---

### SCREEN 7 — Notifications Panel (global, in TopBar)

**Context:** Bell icon in TopBar. Click → slide-in panel from right.

**Panel:**
- Header: "Notifications" + "Mark all as read"
- List: each notification = type 'mention':
  - "@ivan mentioned you in: **SQL Injection in login form**"
  - Timestamp (relative: "2 min ago")
  - Unread = slightly brighter background
  - Click → navigate to vulnerability + scroll to comment
- Empty state: "No notifications"
- Unread badge count on bell icon (WebSocket-updated in real time)

---

## REUSABLE DESIGN SYSTEM COMPONENTS

After designing the screens, extract these into a `components/ui/` design system:

```
SeverityBadge          — props: severity: Severity. Colored pill. Used everywhere.
VulnStatusBadge        — props: status: VulnStatus. Colored pill with status label.
HostStatusDot          — props: status: HostStatus. Pulsing green/red/gray dot.
PortStateBadge         — props: state: PortState. Small colored tag.
HttpMethodBadge        — props: method: HttpMethod. Monospace colored tag (GET=green, POST=blue, DELETE=red, etc.)
CvssScoreBar           — props: score: number. Visual 0-10 bar with gradient.
SeverityDistribution   — props: counts: Record<Severity, number>. Horizontal stacked bar.
InlineEditField        — props: value, onSave, type. Click-to-edit field with save/cancel.
AssetChip              — props: asset_type, label. Clickable chip with type icon.
MentionTextarea        — Textarea with @mention autocomplete. Props: members, onSubmit.
EmptyState             — props: message, icon?. Centered empty state component.
LoadingSkeleton        — Shimmer skeleton matching the shape of its parent content.
PaginationBar          — props: total, page, size, onPageChange.
```

---

## WEBSOCKET INTEGRATION NOTE

Implement a `useProjectWebSocket(projectId)` hook that:
1. Connects to `WS /ws/projects/{projectId}` (cookie auth — no token param)
2. On `event: "created" | "updated" | "deleted"` for any entity → invalidate relevant queries (use react-query or update Zustand store)
3. On `event: "notification"` → push to notification store, increment unread count badge
4. Auto-reconnect on disconnect (exponential backoff, max 5 attempts)
5. Show subtle "● Live" green dot in TopBar when connected, gray "○ Offline" when disconnected

---

## OUTPUT FORMAT

For each screen:
```
## [Screen Name]

### UX Rationale
[2-3 sentences explaining the layout decisions]

### Component
```tsx
// Full TypeScript JSX code with mock data
```

### Sub-components to extract
- ComponentName — purpose
```

---

## RULES

- Every component must compile (no missing imports, correct TypeScript)
- Use Tailwind classes only (no inline styles except for dynamic values like CVSS score width)
- All mock data must be realistic: real-looking IPs, CVE-style titles, real CVSS vectors
- Accessibility: all interactive elements have aria-labels, keyboard navigation works
- No `any` TypeScript types
- Comment every non-obvious design decision
- After all screens, write a `DESIGN_DECISIONS.md` section summarising 5 architectural choices made and why
