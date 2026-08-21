/* FROST — Findings, Research, Offensive Security & Testing Console.
   Root screen of the FROST workspace. Every collection it renders is loaded
   from the backend; data.ts carries the view shapes only. */

import {
  lazy,
  Suspense,
  useEffect,
  useRef,
  useState,
  type ChangeEvent,
  type ClipboardEvent as ReactClipboardEvent,
  type CSSProperties,
  type KeyboardEvent as ReactKeyboardEvent,
  type MouseEvent as ReactMouseEvent,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";
import { useLocation, useNavigate } from "react-router-dom";
import "./frost.css";
import { Icon } from "./icons";

/* TipTap/ProseMirror is ~460 kB — more than the rest of the app put together, and
   only the note editor needs it. Loading it on demand keeps that weight off every
   other screen. */
const FrostMarkdownEditor = lazy(() => import("./FrostMarkdownEditor"));
const FrostDocs = lazy(() => import("./FrostDocs"));
import { FrostDatePicker } from "./FrostDatePicker";
import { PasswordInput } from "./PasswordInput";
import { useAuthStore, useToastStore } from "../store";
import { useThemeStore } from "./theme";
import { FrostSelect } from "./FrostSelect";
import { FrostMark, FrostWordmark } from "./Brand";
import { t, useLangStore } from "./i18n";
import {
  getApiErrorMessage as rawGetApiErrorMessage,
  getApiErrorStatus,
  getProjects,
  getProjectStats,
  getUsers,
  createProject as apiCreateProject,
  updateProject as apiUpdateProject,
  deleteProject as apiDeleteProject,
  createInvitation as apiCreateInvitation,
  getInvitations as apiGetInvitations,
  resendInvitation as apiResendInvitation,
  revokeInvitation as apiRevokeInvitation,
  updateUser as apiUpdateUser,
  deleteUser as apiDeleteUser,
  reactivateUser as apiReactivateUser,
  getHosts as apiGetHosts,
  getHiddenIps as apiGetHiddenIps,
  hideIp as apiHideIp,
  getHost as apiGetHost,
  updateHost as apiUpdateHost,
  deleteHost as apiDeleteHost,
  startHostFarm as apiStartHostFarm,
  getHostFarmJob as apiGetHostFarmJob,
  startIpFarm as apiStartIpFarm,
  getIpFarmJob as apiGetIpFarmJob,
  startJsScan as apiStartJsScan,
  getJsScanJob as apiGetJsScanJob,
  getJsFiles as apiGetJsFiles,
  downloadJsArchive as apiDownloadJsArchive,
  createEndpoint as apiCreateEndpoint,
  getEndpoints as apiGetEndpoints,
  deleteEndpoint as apiDeleteEndpoint,
  getProjectMembers as apiGetProjectMembers,
  addProjectMember as apiAddProjectMember,
  removeProjectMember as apiRemoveProjectMember,
  getVulnerabilities as apiGetVulnerabilities,
  getVulnerability as apiGetVulnerability,
  createVulnerability as apiCreateVulnerability,
  updateVulnerability as apiUpdateVulnerability,
  deleteVulnerability as apiDeleteVulnerability,
  addVulnerabilityAsset as apiAddVulnerabilityAsset,
  deleteVulnerabilityAsset as apiDeleteVulnerabilityAsset,
  listProjectNotes as apiListProjectNotes,
  createProjectNote as apiCreateProjectNote,
  updateProjectNote as apiUpdateProjectNote,
  deleteProjectNote as apiDeleteProjectNote,
  listProjectCredentials as apiListProjectCredentials,
  createProjectCredential as apiCreateProjectCredential,
  updateProjectCredential as apiUpdateProjectCredential,
  deleteProjectCredential as apiDeleteProjectCredential,
  getProjectActivity as apiGetProjectActivity,
  listNotifications as apiListNotifications,
  uploadMyAvatar as apiUploadMyAvatar,
  markNotificationRead as apiMarkNotificationRead,
  markAllNotificationsRead as apiMarkAllNotificationsRead,
  listAgentTokens as apiListAgentTokens,
  createAgentToken as apiCreateAgentToken,
  revokeAgentToken as apiRevokeAgentToken,
  downloadProjectCertificationReport as apiDownloadCertificationReport,
  downloadProjectAcceptanceReport as apiDownloadAcceptanceReport,
  setupTwoFactor as apiSetupTwoFactor,
  confirmTwoFactor as apiConfirmTwoFactor,
  changeMyPassword as apiChangeMyPassword,
  disableTwoFactor as apiDisableTwoFactor,
} from "../api";
import { calculateCvssScore, severityFromCvssScore } from "../cvss";
import { PROJECT_STATUS_ORDER } from "../projectStatus";
import type {
  Notification as ApiNotification,
  ProjectActivityItem,
  ProjectMember as ApiProjectMember,
  ProjectNote,
  ProjectCredential as ApiProjectCredential,
  ProjectStats,
  ProjectStatus,
  Endpoint as ApiEndpoint,
  Host as ApiHost,
  HostFarmJob as ApiHostFarmJob,
  IpFarmJob as ApiIpFarmJob,
  JsFarmJob as ApiJsFarmJob,
  JsFile as ApiJsFile,
  Port as ApiPort,
  Service as ApiService,
  Vulnerability as ApiVulnerability,
  Invitation as ApiInvitation,
} from "../types";
import {
  type ApiKey,
  type CfState,
  type Cred,
  type Endpoint,
  type Host,
  type JsFileEntry,
  type Member,
  type Method,
  type Note,
  type ProjectDetail,
  type Role,
  type Severity,
  type Vuln,
  type VStatus,
  type WorkspaceUser,
  type WsRole,
} from "./data";
import { cap, fileBase, fstr, initialsOf, kb, relTime, stop, toDispDate, toggleIn } from "./format";
import { cumulativeSpark, sparkArea, sparkline } from "./spark";
import { renderMarkdown } from "./markdown";
import {
  computeCvss4,
  FROST_METHODS,
  isFarmJobInFlight,
  mergeCf,
  toFrostCred,
  toFrostHost,
  toFrostMember,
  toFrostMethod,
  toFrostNote,
  toFrostVuln,
} from "./adapters";
import {
  ACT_LINE_LIMIT,
  ACT_SEV,
  elapsedPct,
  groupActivity,
  type ActivityLine,
  type ActivityResolver,
  type ActTone,
} from "./activity";
import {
  API_SCOPES,
  API_SCOPE_LABELS,
  EDITOR_FIELDS,
  FINDING_SEV,
  MEMBER_COLORS,
  METHOD,
  PORT,
  PROJ_STATUS,
  ROLE,
  SECRET_SEV,
  SEV,
  STDOT,
  TYPELABEL,
  VSTATUS,
  VSTATUS_LABEL,
  VSTATUS_OPEN,
  VSTATUS_ORDER,
  WS_ROLE,
  WS_ROLE_LABEL,
  type EditorType,
} from "./tokens";

/* Localize API/backend error messages. rawGetApiErrorMessage returns the backend's
   `detail` (or an English fallback); t() maps our canonical English messages to the
   active locale — English in the English locale, Russian in RU. Backend messages not
   yet migrated to an English source key have no entry and pass through unchanged, so
   this is safe to wrap every error toast in. (Login lives outside this component and
   keeps calling api.ts directly, so it stays English-only.) */
const getApiErrorMessage = (error: unknown, fallback: string): string =>
  t(rawGetApiErrorMessage(error, fallback));

type NavId = "projects" | "tasks" | "mine" | "docs" | "members";
type ViewId = "list" | "detail" | "profile" | "workspaceMembers";
type SectionId = "overview" | "hosts" | "vulns" | "notes" | "creds" | "members" | "activity";
type ReconView = "hosts" | "ips" | "endpoints" | "js";
type ProfileTab = "account" | "security" | "api" | "customizing";
/** Word report templates the backend can generate (POST /projects/{id}/reports/{kind}). */
type ReportKind = "szi" | "pp";
/** What the export dialog exports: the project report, or one of the recon lists.
 *  Находки JS-фермы выгружаются двумя раздельными списками — пути и секреты
 *  нужны разным инструментам, и смешивать их в одном файле бессмысленно. */
type ExportScope = "report" | "hosts" | "ips" | "endpoints" | "js-endpoints" | "js-secrets";
/** How many type-to-search suggestions a combo field offers at once. */
const COMBO_MAX = 5;
const REPORT_KINDS: { kind: ReportKind; title: string; desc: string }[] = [
  { kind: "szi", title: "Certification report", desc: "Security-system test report — for certification testing." },
  { kind: "pp", title: "Internal acceptance report", desc: "Acceptance protocol — for internal acceptance of the work." },
];

interface NoteForm {
  title: string;
  excerpt: string;
  author: string;
}

interface VulnDetailForm {
  title?: string;
  host?: string;
  sev?: Severity;
  status?: VStatus;
  stepsList?: string[];
  stepImages?: Record<number, string[]>;
  description?: string;
  impact?: string;
  remediation?: string;
  cwe?: string;
  vector?: string;
}

interface FrostState {
  userMenuOpen: boolean;
  notifOpen: boolean;
  modalOpen: boolean;
  sidebarCollapsed: boolean;
  lightboxSrc: string | null;
  apiProjects: ApiProjectRow[] | null;
  projectsLoading: boolean;
  projectsError: string | null;
  /* Per-project "added at" timestamps for the projects-list stat sparklines,
     keyed by project id. Fetched lazily (hosts + vulns per project) so the
     Hosts / Open issues cards can chart real add-frequency, not just a total.
     `null` = not fetched yet. */
  aggTimes: Record<number, { hosts: string[]; openVulns: string[] }> | null;
  reloadTick: number;
  projEditId: number | null;
  confirmProjectId: number | null;
  /** Удаляемый пользователь на странице /members (там нет открытого проекта). */
  confirmUserId: number | null;
  /* ---- project detail: every collection below is backend-backed ----
     `null` = not loaded yet, `[]` = loaded and empty. Each has a `*Tick`
     counter that its loader effect watches, so a mutation reloads it. */
  activity: ProjectActivityItem[] | null;
  activityLoading: boolean;
  activityError: string | null;
  activityTick: number;
  /** Key of the activity group whose full list is open in a modal. */
  activityModalKey: string | null;
  /** Real hosts for `openProjectId`, mapped to Frost's shape. `null` = not loaded yet. */
  apiHosts: Host[] | null;
  hostsLoading: boolean;
  hostsTick: number;
  /** Адреса, скрытые из вкладки IP («удалённые» из списка) — грузятся вместе с хостами. */
  hiddenIps: string[];
  // ---- "Add hosts" import (server-side probe farm) ----
  hostImportOpen: boolean;
  hostImportRaw: string;
  /** Deduped, normalized preview of what will actually be imported (editable). */
  hostImportPreview: string;
  hostImportBusy: boolean;
  // ---- "Add IPs" import (same farm, reverse-resolves each address) ----
  ipImportOpen: boolean;
  ipImportRaw: string;
  ipImportPreview: string;
  ipImportBusy: boolean;
  // ---- "Add endpoints" import (paste a list of URLs, bulk-create) ----
  epImportOpen: boolean;
  epImportRaw: string;
  epImportPreview: string;
  epImportBusy: boolean;
  /** Hosts filter pills (multi-select, empty = all): "up" | "down" | HTTP code. */
  hostFilters: string[];
  /** Same status filter, for the IPs view. */
  ipFilters: string[];
  /** Cloudflare filter: "" = all, "yes" = behind CF, "no" = not. Separate per view. */
  ipCfFilter: "" | "yes" | "no";
  hostCfFilter: "" | "yes" | "no";
  /** The running/finished probe job being polled, or null when idle. */
  hostFarmJob: ApiHostFarmJob | null;
  ipFarmJob: ApiIpFarmJob | null;
  /** The running/finished JS scan job being polled, or null when idle. */
  jsFarmJob: ApiJsFarmJob | null;
  /** Project JS files (backend-loaded). `null` = not loaded yet. */
  apiJsFiles: ApiJsFile[] | null;
  /** Открытая карточка JS-файла (id) — как openHostId/openIp у хостов и адресов. */
  openJsFileId: number | null;
  jsTick: number;
  jsQuery: string;
  /** Only show files that leaked at least one secret. */
  jsSecretsOnly: boolean;
  /** Which JS files are expanded (by url). */
  jsExpanded: string[];
  /** The domain-selection page shown before a scan starts (mirrors the export page). */
  jsScanSetupOpen: boolean;
  /** Editable "will be scanned" domain list on that page — the coarse host filters
      seed it, hand edits refine it (same contract as the export page's list). */
  jsScanText: string;
  apiMembers: Member[] | null;
  membersTick: number;
  apiVulns: Vuln[] | null;
  vulnsTick: number;
  apiNotes: Note[] | null;
  notesTick: number;
  /** Project credential vault for `openProjectId`. `null` = not loaded yet. */
  apiCreds: Cred[] | null;
  credsTick: number;
  /** Ids of creds whose secret is currently un-masked (reveal is per-row, opt-in). */
  revealedCredIds: number[];
  /** Set when the backend answers 403 for the open project → renders the no-access screen. */
  accessDenied: boolean;
  notifs: ApiNotification[];
  reconView: ReconView;
  openHostId: number | null;
  /** The IP address whose detail card is open (IPs have no stored id — keyed by address). */
  openIp: string | null;
  reconMenuOpen: boolean;
  hostQuery: string;
  /* Recon view filters. Methods are multi-select like every other pill filter:
     empty = all. */
  epMethods: Method[];
  epHostQuery: string;
  epPathQuery: string;
  ipQuery: string;
  epExpanded: string[];
  confirmOpen: boolean;
  confirmType: EditorType | null;
  confirmIndex: number;
  confirmLabel: string;
  noteEditorOpen: boolean;
  noteEditorMode: "add" | "edit";
  noteEditorIndex: number;
  noteForm: NoteForm;
  epOpen: boolean;
  epData: { method: Method; path: string; host: string; hostId: number; endpointId: number };
  /** Raw request being edited — saved to the endpoint (request_raw). */
  epRequest: string;
  /* The response is a scratchpad: there is no column for it on the backend, so it
     is deliberately not saved — it exists to be tweaked and copied out. */
  epResponse: string;
  epSaving: boolean;
  exportModalOpen: boolean;
  /** Backend report template: "szi" = certification, "pp" = internal acceptance. */
  exportKind: ReportKind;
  exportBusy: boolean;
  /** What the export dialog is for: the project's Word report, or a recon list. */
  exportScope: ExportScope;
  exportFormat: "list" | "openapi";
  /** Recon exports open as a full page (like "Add hosts"), not a modal. */
  exportPageOpen: boolean;
  /* The right-hand pane: the lines that will actually be written to the file.
     Seeded from the filtered list and editable, so rows can be dropped before
     downloading — the left pane mirrors whatever is left here. */
  exportText: string;
  /** Note open in the viewer, by backend id — it is part of the URL. */
  openNoteId: number | null;
  editorOpen: boolean;
  editorType: EditorType;
  editorMode: "add" | "edit";
  editorIndex: number;
  editorForm: Record<string, string | string[]>;
  tagDrafts: Record<string, string>;
  /** Key of the combo field whose suggestion list is open, if any. */
  comboOpen: string | null;
  /** Index of the keyboard-highlighted suggestion in that list. */
  comboHi: number;
  /** «Affected host» на карточке уязвимости — свой комбо (тот же пикер хостов, что и в форме). */
  vdHostComboOpen: boolean;
  vdHostComboHi: number;
  nav: NavId;
  tab: "active" | "archived";
  query: string;
  projSort: "last" | "first";
  newName: string;
  newDesc: string;
  newStart: string;
  newEnd: string;
  view: ViewId;
  openProjectId: number | null;
  projEditOpen: boolean;
  projEditName: string;
  projEditDesc: string;
  projEditStart: string;
  projEditEnd: string;
  projEditStatus: ProjectStatus;
  section: SectionId;
  expanded: number[];
  profileTab: ProfileTab;
  apiKeys: ApiKey[];
  apiKeyModalOpen: boolean;
  apiKeyName: string;
  apiKeyScopes: Record<string, boolean>;
  /** Доступ ключа: все свои проекты (true) или явно выбранные (false). */
  apiKeyAllProjects: boolean;
  apiKeyProjectIds: number[];
  /** Expiry ключа (YYYY-MM-DD); пусто = бессрочный. */
  apiKeyExpiry: string;
  workspaceUsers: WorkspaceUser[];
  /** Неактивированные приглашения (pending), показываются над списком участников. */
  pendingInvites: ApiInvitation[];
  usersTick: number;
  /** Активные / архивные (деактивированные) участники — как вкладки у проектов. */
  wsUserTab: "active" | "archived";
  wsUserModalOpen: boolean;
  wsUserMode: "add" | "edit";
  wsUserIndex: number;
  wsUserName: string;
  wsUserEmail: string;
  wsUserRole: WsRole;
  wsUserProjectRole: Role;
  memberQuery: string;
  /** Multi-select project-role filter (empty = no filtering). */
  memberRoles: Role[];
  wsMemberQuery: string;
  /** Multi-select workspace-role filter (empty = no filtering). */
  wsMemberRoles: WsRole[];
  /** Multi-select project-role filter on the workspace Members page (empty = no filtering). */
  wsMemberProjectRoles: Role[];
  twoFASetupOpen: boolean;
  twoFACode: string;
  // Данные привязки, полученные от POST /users/me/2fa/setup.
  twoFAQr: string | null;
  twoFASecret: string | null;
  // Диалог отключения (требует пароль аккаунта).
  twoFADisableOpen: boolean;
  twoFADisablePassword: string;
  // ---- Смена собственного пароля (вкладка Security) ----
  pwCurrent: string;
  pwNew: string;
  pwConfirm: string;
  pwBusy: boolean;
  pwError: string | null;
  twoFABusy: boolean;
  vulnFilterAuthor: string;
  /* Multi-select filters: every pill toggles, and an empty selection means "All"
     — so deselecting the last pill lands back on All by itself. */
  vulnFilterStatuses: VStatus[];
  vulnFilterSeverities: Severity[];
  vulnFilterHost: string;
  /** Real backend vulnerability id (not a list index) — it is part of the URL. */
  openVulnId: number | null;
  vulnDetailForm: VulnDetailForm;
}

const initialState: FrostState = {
  userMenuOpen: false,
  notifOpen: false,
  modalOpen: false,
  sidebarCollapsed: false,
  lightboxSrc: null,
  apiProjects: null,
  projectsLoading: false,
  projectsError: null,
  aggTimes: null,
  reloadTick: 0,
  projEditId: null,
  confirmProjectId: null,
  confirmUserId: null,
  activity: null,
  activityLoading: false,
  activityError: null,
  activityTick: 0,
  activityModalKey: null,
  apiHosts: null,
  hostsLoading: false,
  hostsTick: 0,
  hiddenIps: [],
  hostImportOpen: false,
  ipCfFilter: "",
  hostCfFilter: "",
  ipImportOpen: false,
  ipImportRaw: "",
  ipImportPreview: "",
  ipImportBusy: false,
  epImportOpen: false,
  epImportRaw: "",
  epImportPreview: "",
  epImportBusy: false,
  ipFarmJob: null,
  jsFarmJob: null,
  apiJsFiles: null,
  openJsFileId: null,
  jsTick: 0,
  jsQuery: "",
  jsSecretsOnly: false,
  jsExpanded: [],
  jsScanSetupOpen: false,
  jsScanText: "",
  hostImportRaw: "",
  hostImportPreview: "",
  hostImportBusy: false,
  hostFilters: [],
  ipFilters: [],
  hostFarmJob: null,
  apiMembers: null,
  membersTick: 0,
  apiVulns: null,
  vulnsTick: 0,
  apiNotes: null,
  notesTick: 0,
  apiCreds: null,
  credsTick: 0,
  revealedCredIds: [],
  accessDenied: false,
  notifs: [],
  reconView: "hosts",
  openHostId: null,
  openIp: null,
  reconMenuOpen: false,
  hostQuery: "",
  epMethods: [],
  epHostQuery: "",
  epPathQuery: "",
  ipQuery: "",
  epExpanded: [],
  confirmOpen: false,
  confirmType: null,
  confirmIndex: -1,
  confirmLabel: "",
  noteEditorOpen: false,
  noteEditorMode: "add",
  noteEditorIndex: -1,
  noteForm: { title: "", excerpt: "", author: "" },
  epOpen: false,
  epData: { method: "GET", path: "", host: "", hostId: 0, endpointId: 0 },
  epRequest: "",
  epResponse: "",
  epSaving: false,
  exportModalOpen: false,
  exportKind: "szi",
  exportBusy: false,
  exportScope: "report",
  exportFormat: "list",
  exportPageOpen: false,
  exportText: "",
  openNoteId: null,
  editorOpen: false,
  editorType: "host",
  editorMode: "add",
  editorIndex: -1,
  editorForm: {},
  tagDrafts: {},
  comboOpen: null,
  comboHi: 0,
  vdHostComboOpen: false,
  vdHostComboHi: 0,
  nav: "projects",
  tab: "active",
  query: "",
  projSort: "last",
  newName: "",
  newDesc: "",
  newStart: "",
  newEnd: "",
  view: "list",
  openProjectId: null,
  projEditOpen: false,
  projEditName: "",
  projEditDesc: "",
  projEditStart: "",
  projEditEnd: "",
  projEditStatus: "active",
  section: "overview",
  expanded: [],
  profileTab: "account",
  apiKeys: [],
  apiKeyModalOpen: false,
  apiKeyName: "",
  apiKeyScopes: {},
  apiKeyAllProjects: true,
  apiKeyProjectIds: [],
  apiKeyExpiry: "",
  workspaceUsers: [],
  pendingInvites: [],
  usersTick: 0,
  wsUserTab: "active",
  wsUserModalOpen: false,
  wsUserMode: "add",
  wsUserIndex: -1,
  wsUserName: "",
  wsUserEmail: "",
  wsUserRole: "user",
  wsUserProjectRole: "pentester",
  memberQuery: "",
  memberRoles: [],
  wsMemberQuery: "",
  wsMemberRoles: [],
  wsMemberProjectRoles: [],
  twoFASetupOpen: false,
  twoFACode: "",
  twoFAQr: null,
  twoFASecret: null,
  twoFADisableOpen: false,
  twoFADisablePassword: "",
  pwCurrent: "",
  pwNew: "",
  pwConfirm: "",
  pwBusy: false,
  pwError: null,
  twoFABusy: false,
  vulnFilterAuthor: "",
  vulnFilterStatuses: [],
  vulnFilterSeverities: [],
  vulnFilterHost: "",
  openVulnId: null,
  vulnDetailForm: {},
};

const CARD: CSSProperties = { background: "var(--fr-surface)", border: "1px solid var(--fr-border-light)", borderRadius: 16 };
const PILL_ON: CSSProperties = { background: "var(--fr-accent-2)", color: "var(--fr-on-accent)", border: "1px solid var(--fr-accent-2)" };
const PILL_OFF: CSSProperties = { background: "var(--fr-surface)", color: "var(--fr-text-2)", border: "1px solid var(--fr-border)" };

/* Styled hover tooltip — a themed replacement for the browser's native `title`
   bubble. Rendered through a portal to document.body so it is never clipped by an
   ancestor's `overflow: hidden` (the recon cards clip), and positioned `fixed`
   against the hovered element's box. */
function Tip({ label, children }: { label: string; children: ReactNode }) {
  const [box, setBox] = useState<DOMRect | null>(null);
  return (
    <span
      style={{ display: "inline-flex" }}
      onMouseEnter={(e) => setBox(e.currentTarget.getBoundingClientRect())}
      onMouseLeave={() => setBox(null)}
      onClickCapture={() => setBox(null)}
    >
      {children}
      {box != null &&
        createPortal(
          <div
            style={{
              position: "fixed",
              left: box.left + box.width / 2,
              top: box.top - 9,
              transform: "translate(-50%, -100%)",
              padding: "5px 9px",
              borderRadius: 7,
              background: "var(--fr-text)",
              color: "var(--fr-surface)",
              font: "600 11.5px Inter, sans-serif",
              whiteSpace: "nowrap",
              pointerEvents: "none",
              boxShadow: "0 8px 24px rgba(15,27,45,.22)",
              zIndex: 200,
            }}
          >
            {label}
          </div>,
          document.body,
        )}
    </span>
  );
}

/** Build the URL path that represents the current navigation state.
 *
 * The open vulnerability is part of the path (`…/vulns/{id}`) so that a finding
 * can be deep-linked — that is what notification and activity-feed links point
 * at. Keep this in sync with `navStateFromPath`: any field encoded here must be
 * parsed back there, or the round-trip through the router will drop it.
 */
function pathFor(s: {
  view: ViewId;
  nav: NavId;
  openProjectId: number | null;
  section: SectionId;
  reconView: ReconView;
  profileTab: ProfileTab;
  openVulnId: number | null;
  openNoteId: number | null;
  openHostId: number | null;
  openIp: string | null;
}): string {
  if (s.view === "profile") return s.profileTab === "account" ? "/profile" : `/profile/${s.profileTab}`;
  if (s.view === "workspaceMembers") return "/members";
  if (s.view === "detail" && s.openProjectId != null) {
    const base = `/projects/${s.openProjectId}`;
    if (s.section === "overview") return base;
    if (s.section === "hosts") {
      // An open host/IP card is the last path segment, so the card is deep-linkable
      // (an IP carries dots but stays a single segment — encode it to be safe).
      if (s.reconView === "hosts" && s.openHostId != null) return `${base}/hosts/${s.openHostId}`;
      if (s.reconView === "ips" && s.openIp != null) return `${base}/ips/${encodeURIComponent(s.openIp)}`;
      return `${base}/${s.reconView}`;
    }
    if (s.section === "vulns" && s.openVulnId != null) return `${base}/vulns/${s.openVulnId}`;
    if (s.section === "notes" && s.openNoteId != null) return `${base}/notes/${s.openNoteId}`;
    return `${base}/${s.section}`;
  }
  return ({ projects: "/projects", tasks: "/tasks", mine: "/my-tasks", docs: "/docs", members: "/members" } as Record<NavId, string>)[s.nav] || "/projects";
}

/** Parse a URL path back into the navigation-state fields it encodes. */
function navStateFromPath(path: string): Partial<FrostState> {
  const parts = path.split("/").filter(Boolean);
  const head = parts[0];
  if (!head) return { view: "list", nav: "projects" };
  if (head === "projects") {
    if (parts.length === 1) return { view: "list", nav: "projects", openProjectId: null, openVulnId: null, openNoteId: null, openHostId: null, openIp: null };
    const id = Number(parts[1]);
    const seg = parts[2];
    const base: Partial<FrostState> = {
      view: "detail",
      nav: "projects",
      openProjectId: Number.isFinite(id) ? id : null,
      openVulnId: null,
      openNoteId: null,
      openHostId: null,
      openIp: null,
    };
    /** `/…/vulns/7` → 7; a missing or non-numeric segment → null. */
    const entityId = () => {
      const n = Number(parts[3]);
      return parts[3] != null && Number.isFinite(n) ? n : null;
    };
    if (!seg) return { ...base, section: "overview" };
    // /projects/{id}/hosts/{hostId} and /projects/{id}/ips/{ip} deep-link an open card.
    if (seg === "hosts") {
      const hid = Number(parts[3]);
      return { ...base, section: "hosts", reconView: "hosts", openHostId: parts[3] != null && Number.isFinite(hid) ? hid : null };
    }
    if (seg === "ips") {
      return { ...base, section: "hosts", reconView: "ips", openIp: parts[3] != null ? decodeURIComponent(parts[3]) : null };
    }
    if (seg === "endpoints" || seg === "js") return { ...base, section: "hosts", reconView: seg };
    // /projects/{id}/vulns/{vulnId} and /projects/{id}/notes/{noteId} — deep links.
    if (seg === "vulns") return { ...base, section: "vulns", openVulnId: entityId() };
    if (seg === "notes") return { ...base, section: "notes", openNoteId: entityId() };
    if (seg === "creds" || seg === "members" || seg === "activity") return { ...base, section: seg };
    return { ...base, section: "overview" };
  }
  if (head === "tasks") return { view: "list", nav: "tasks" };
  if (head === "my-tasks") return { view: "list", nav: "mine" };
  if (head === "docs") return { view: "list", nav: "docs" };
  if (head === "members") return { view: "workspaceMembers", nav: "members" };
  if (head === "profile") return { view: "profile", profileTab: ["security", "api", "customizing"].includes(parts[1]) ? (parts[1] as ProfileTab) : "account" };
  return { view: "list", nav: "projects" };
}

/** A project row as shown in the (backend-backed) Projects list. */
interface ApiProjectRow {
  id: number;
  name: string;
  description: string;
  status: ProjectStatus;
  startISO: string;
  endISO: string;
  /** Project creation timestamp — the "added at" point for the count sparklines. */
  createdISO: string;
  updated: string;
  createdBy: number;
  openFindings: number;
  totalFindings: number;
  hostsCount: number;
}

export function FrostApp() {
  const [state, setStateRaw] = useState<FrostState>(initialState);
  const setState = (patch: Partial<FrostState> | ((s: FrostState) => Partial<FrostState>)) =>
    setStateRaw((prev) => ({ ...prev, ...(typeof patch === "function" ? patch(prev) : patch) }));
  const toggle = (k: keyof FrostState) => setStateRaw((s) => ({ ...s, [k]: !s[k] }));

  // ---- logged-in user (real backend auth) ----
  const authUser = useAuthStore((s) => s.user);
  const signOut = useAuthStore((s) => s.signOut);
  const refreshUser = useAuthStore((s) => s.refreshUser);
  const setUser = useAuthStore((s) => s.setUser);
  // 2FA берём из реального профиля, а не из локального состояния.
  const twoFAEnabled = !!authUser?.totp_enabled;
  const pushToast = useToastStore((s) => s.pushToast);
  const theme = useThemeStore((s) => s.theme);
  const setTheme = useThemeStore((s) => s.setTheme);
  // Subscribe so the whole app re-renders (and every t() re-evaluates) on switch.
  const lang = useLangStore((s) => s.lang);
  const setLang = useLangStore((s) => s.setLang);
  const navigate = useNavigate();
  const location = useLocation();
  const realUsername = authUser?.username || "";
  const realIsAdmin = authUser?.role === "admin";
  const me = realUsername;
  const meWsRole: WsRole = realIsAdmin ? "admin" : "user";
  const isAdmin = meWsRole === "admin";
  const meEmail = authUser?.email || "";
  const meDisplay = authUser?.full_name || realUsername;
  const meRoleLabel = meWsRole === "admin" ? t("Administrator") : t("User");
  const meId = String(authUser?.id ?? "");
  const meInitials = initialsOf(authUser?.full_name || realUsername || "U");

  // ================= avatar upload =================
  /* Mirrors the backend limits (UserService.upload_avatar): ≤5 MB, image only. */
  const AVATAR_MAX_BYTES = 5 * 1024 * 1024;
  const AVATAR_TYPES = ["image/png", "image/jpeg", "image/webp", "image/gif"];
  const [avatarFile, setAvatarFile] = useState<File | null>(null);
  const [avatarPreview, setAvatarPreview] = useState<string | null>(null);
  const [avatarUploading, setAvatarUploading] = useState(false);

  const clearAvatarPick = () => {
    setAvatarPreview((prev) => {
      if (prev) URL.revokeObjectURL(prev);
      return null;
    });
    setAvatarFile(null);
  };

  const onAvatarPick = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0] ?? null;
    e.target.value = ""; // позволяет выбрать тот же файл повторно после ошибки
    if (!file) return;
    if (!AVATAR_TYPES.includes(file.type)) {
      pushToast("Avatar must be a PNG, JPEG, WEBP or GIF image", "error");
      return;
    }
    if (file.size > AVATAR_MAX_BYTES) {
      pushToast("Avatar exceeds the 5 MB limit", "error");
      return;
    }
    setAvatarFile(file);
    setAvatarPreview((prev) => {
      if (prev) URL.revokeObjectURL(prev);
      return URL.createObjectURL(file);
    });
  };

  const submitAvatar = async () => {
    if (!avatarFile || avatarUploading) return;
    setAvatarUploading(true);
    try {
      const updated = await apiUploadMyAvatar(avatarFile);
      setUser(updated); // avatar_url меняется → круги по всему интерфейсу обновятся
      clearAvatarPick();
      pushToast("Avatar updated", "success");
    } catch (err) {
      pushToast(getApiErrorMessage(err, "Couldn't upload avatar"), "error");
    } finally {
      setAvatarUploading(false);
    }
  };

  /** Круг-аватар текущего пользователя: фото, если оно есть, иначе инициалы. */
  const meAvatar = (size: number, fontPx: number, text: string, src: string | null = authUser?.avatar_url ?? null) =>
    src ? (
      <img
        src={src}
        alt={meDisplay}
        style={{ width: size, height: size, flex: "none", borderRadius: "50%", objectFit: "cover", display: "block" }}
      />
    ) : (
      <div
        style={{
          width: size,
          height: size,
          flex: "none",
          borderRadius: "50%",
          background: "var(--fr-accent)",
          color: "var(--fr-on-accent)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          font: `700 ${fontPx}px 'JetBrains Mono',monospace`,
        }}
      >
        {text}
      </div>
    );

  /** Any request that 403s for the open project flips the no-access screen on. */
  const handleProjectError = (e: unknown, fallback: string) => {
    if (getApiErrorStatus(e) === 403 || getApiErrorStatus(e) === 404) {
      setStateRaw((s) => ({ ...s, accessDenied: true }));
      return;
    }
    pushToast(getApiErrorMessage(e, fallback), "error");
  };

  // ================= projects: load from backend =================
  const reloadProjects = () => setStateRaw((s) => ({ ...s, reloadTick: s.reloadTick + 1 }));
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      setStateRaw((s) => ({ ...s, projectsLoading: true, projectsError: null }));
      try {
        const [res, stats] = await Promise.all([
          getProjects(1, 100),
          // Aggregate stats are best-effort: fall back to zeros rather than failing the list.
          getProjectStats().catch(() => [] as ProjectStats[]),
        ]);
        const statsById = new Map(stats.map((s) => [s.project_id, s]));
        const rows: ApiProjectRow[] = res.items.map((p) => {
          const st = statsById.get(p.id);
          return {
            id: p.id,
            name: p.name,
            description: p.description || "No description yet",
            status: p.status,
            startISO: p.start_date || "",
            endISO: p.end_date || "",
            createdISO: p.created_at || "",
            updated: relTime(p.updated_at),
            createdBy: p.created_by,
            openFindings: st?.open_findings ?? 0,
            totalFindings: st?.total_findings ?? 0,
            hostsCount: st?.hosts_count ?? 0,
          };
        });
        if (!cancelled) setStateRaw((s) => ({ ...s, apiProjects: rows, projectsLoading: false }));
      } catch (e) {
        if (!cancelled) setStateRaw((s) => ({ ...s, apiProjects: [], projectsError: getApiErrorMessage(e, "Couldn't load projects"), projectsLoading: false }));
      }
    })();
    return () => {
      cancelled = true;
    };

  }, [state.reloadTick]);

  /* ================= projects list: per-project "added at" timestamps =========
     The stat cards on the projects page chart real add-frequency, which needs
     each host's and each open finding's creation time — data the list endpoint
     does not carry. Fetch it lazily while the list is on screen, in bounded
     batches so a large workspace does not fire hundreds of requests at once, and
     cache by project id so switching tabs (or reopening the list) reuses it. */
  useEffect(() => {
    if (state.view !== "list" || state.nav !== "projects") return;
    const rows = state.apiProjects;
    if (!rows || rows.length === 0) return;
    const known = state.aggTimes ?? {};
    const need = rows.filter((r) => !(r.id in known));
    if (need.length === 0) return;

    let cancelled = false;
    void (async () => {
      const CONCURRENCY = 6;
      for (let i = 0; i < need.length && !cancelled; i += CONCURRENCY) {
        const batch = need.slice(i, i + CONCURRENCY);
        const settled = await Promise.all(
          batch.map(async (r) => {
            // Best-effort per project: a 403/404 on one project must not blank the
            // whole card — that project simply contributes no points.
            const [hostsRes, vulnsRes] = await Promise.all([
              apiGetHosts(r.id).catch(() => null),
              apiGetVulnerabilities(r.id).catch(() => null),
            ]);
            const hosts = (hostsRes?.items ?? []).map((h) => h.created_at);
            const openVulns = (vulnsRes?.items ?? [])
              .filter((v) => (VSTATUS_OPEN as readonly string[]).includes(v.status))
              .map((v) => v.created_at);
            return [r.id, { hosts, openVulns }] as const;
          })
        );
        if (cancelled) return;
        setStateRaw((s) => ({ ...s, aggTimes: { ...(s.aggTimes ?? {}), ...Object.fromEntries(settled) } }));
      }
    })();
    return () => {
      cancelled = true;
    };

  }, [state.apiProjects, state.view, state.nav]);

  /* ================= workspace users: load from backend =================
     `GET /users` is admin-only, so this must not run for anyone else: it would
     403 and pop a "Insufficient permissions" toast on every page (that is what showed
     up while simply sitting on the Activity tab). `project_role` is a global
     user attribute and the workspace members page is where it is configured. */
  const reloadUsers = () => setStateRaw((s) => ({ ...s, usersTick: s.usersTick + 1 }));
  useEffect(() => {
    if (!isAdmin) {
      setStateRaw((s) => (s.workspaceUsers.length === 0 && s.pendingInvites.length === 0 ? s : { ...s, workspaceUsers: [], pendingInvites: [] }));
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        // Активные пользователи и незавершённые приглашения грузим вместе —
        // и то и другое показывается на странице участников (invite-flow).
        const [res, invites] = await Promise.all([getUsers(1, 200), apiGetInvitations()]);
        const rows: WorkspaceUser[] = res.items.map((u) => ({
          id: u.id,
          key: u.username,
          name: u.username,
          email: u.email,
          role: u.role === "admin" ? "admin" : "user",
          projectRole: u.project_role,
          locked: u.is_locked,
        }));
        if (!cancelled) setStateRaw((s) => ({ ...s, workspaceUsers: rows, pendingInvites: invites }));
      } catch (e) {
        // Best-effort: keep the list empty rather than breaking the app.
        if (!cancelled) {
          setStateRaw((s) => ({ ...s, workspaceUsers: [], pendingInvites: [] }));
          pushToast(getApiErrorMessage(e, "Couldn't load users"), "error");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.usersTick, isAdmin]);

  // ================= hosts: load from backend =================
  /* Endpoints are fetched up-front alongside the list because the Recon →
     Endpoints view aggregates them across every host, so loading them lazily on
     row expand would leave that view permanently empty. */
  /* Последний удачно загруженный список хостов на проект. Уход со страницы проекта
     обнуляет apiHosts, и без кэша возврат снова упирался в пустой экран «Loading
     hosts…» на всю загрузку — при том, что данные почти всегда те же самые.
     Держим их здесь и на входе показываем сразу, а сеть догоняет в фоне
     (stale-while-revalidate): экран заполнен мгновенно, свежесть не теряется.
     Ref, а не state: подмена кэша не должна сама по себе вызывать ререндер. */
  const hostsCacheRef = useRef<Map<number, Host[]>>(new Map());
  const reloadHosts = () => setStateRaw((s) => ({ ...s, hostsTick: s.hostsTick + 1 }));
  useEffect(() => {
    const pid = state.openProjectId;
    if (pid == null) {
      setStateRaw((s) => (s.apiHosts === null && !s.hostsLoading ? s : { ...s, apiHosts: null, hostsLoading: false, hiddenIps: [] }));
      return;
    }
    let cancelled = false;
    // Скрытые IP грузим параллельно списку хостов — вкладка IP фильтрует по ним.
    void (async () => {
      try {
        const hidden = await apiGetHiddenIps(pid);
        if (!cancelled) setStateRaw((s) => ({ ...s, hiddenIps: hidden }));
      } catch {
        if (!cancelled) setStateRaw((s) => (s.hiddenIps.length === 0 ? s : { ...s, hiddenIps: [] }));
      }
    })();
    void (async () => {
      const cached = hostsCacheRef.current.get(pid);
      // Есть кэш — рисуем его тут же и молча обновляем: спиннер поверх готовых
      // строк выглядел бы как повторная загрузка, хотя данные уже на экране.
      setStateRaw((s) => (cached ? { ...s, apiHosts: cached, hostsLoading: false } : { ...s, hostsLoading: true }));
      try {
        const res = await apiGetHosts(pid);
        // Пути приезжают внутри списка (HostOut.endpoints) — раньше здесь был
        // запрос на каждый хост, и проект с 69 хостами открывался за 70 round-trip'ов.
        const rows = res.items.map((h) =>
          toFrostHost(h, (h.endpoints ?? []).map((e) => ({ id: e.id, m: toFrostMethod(e.method), p: e.path })))
        );
        hostsCacheRef.current.set(pid, rows);
        if (!cancelled) setStateRaw((s) => ({ ...s, apiHosts: rows, hostsLoading: false }));
      } catch (e) {
        if (!cancelled) {
          // Кэш при ошибке не трогаем: показанные строки честнее пустой таблицы.
          setStateRaw((s) => ({ ...s, apiHosts: cached ?? [], hostsLoading: false }));
          handleProjectError(e, "Couldn't load hosts");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.openProjectId, state.hostsTick]);

  // ================= JS files: backend-loaded, refreshed by jsTick =================
  const reloadJsFiles = () => setStateRaw((s) => ({ ...s, jsTick: s.jsTick + 1 }));
  useEffect(() => {
    const pid = state.openProjectId;
    if (pid == null) {
      setStateRaw((s) => (s.apiJsFiles === null ? s : { ...s, apiJsFiles: null }));
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        const files = await apiGetJsFiles(pid);
        if (!cancelled) setStateRaw((s) => ({ ...s, apiJsFiles: files }));
      } catch {
        if (!cancelled) setStateRaw((s) => ({ ...s, apiJsFiles: [] }));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [state.openProjectId, state.jsTick]);

  /* Completion toast for a finished host/IP probe. Reused by the poll effect and
     by the submit handlers when the server closes the job immediately (nothing new
     to probe — every target was already added). Added = new targets probed this
     run; skipped = already-present targets left untouched. */
  const hostFarmDoneToast = (r: NonNullable<ApiHostFarmJob["result"]>) => {
    const added = r.hosts_created + r.hosts_updated;
    const skipped = r.hosts_skipped ? `, ${r.hosts_skipped} ${t("skipped")}` : "";
    pushToast(
      `${t("Probe done")} — ${added} ${t("added")}${skipped}, ${r.hosts_online} ${t("up")}, ${r.hosts_offline} ${t("down")}`,
      "success",
    );
  };
  const ipFarmDoneToast = (r: NonNullable<ApiIpFarmJob["result"]>) => {
    const promoted = r.hosts_promoted ? `, ${r.hosts_promoted} ${t("hosts")}` : "";
    const skipped = r.ips_skipped ? `, ${r.ips_skipped} ${t("skipped")}` : "";
    pushToast(
      `${t("Probe done")} — ${r.ips_created} ${t("IPs")}${skipped}, ${r.hostnames_found} ${t("hostnames")}${promoted}`,
      "success",
    );
  };

  // ================= host farm: poll the running probe job =================
  useEffect(() => {
    const job = state.hostFarmJob;
    const pid = state.openProjectId;
    if (!job || pid == null || !isFarmJobInFlight(job.status)) return;
    let cancelled = false;
    const timer = setTimeout(async () => {
      try {
        const next = await apiGetHostFarmJob(pid, job.id);
        if (cancelled) return;
        // Reload every tick so the per-host commits show up as statuses fill in.
        reloadHosts();
        if (isFarmJobInFlight(next.status)) {
          setStateRaw((s) => (s.hostFarmJob && s.hostFarmJob.id === next.id ? { ...s, hostFarmJob: next } : s));
        } else {
          setStateRaw((s) => (s.hostFarmJob && s.hostFarmJob.id === next.id ? { ...s, hostFarmJob: null } : s));
          if (next.status === "done" && next.result) {
            hostFarmDoneToast(next.result);
          } else if (next.status === "failed") {
            pushToast(next.error || t("Probe failed"), "error");
          }
        }
      } catch {
        // Transient error — re-arm the poll by nudging the reference.
        if (!cancelled) setStateRaw((s) => (s.hostFarmJob ? { ...s, hostFarmJob: { ...s.hostFarmJob } } : s));
      }
    }, 1500);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.hostFarmJob, state.openProjectId]);

  // ================= ip farm: poll the running resolve+probe job =================
  useEffect(() => {
    const job = state.ipFarmJob;
    const pid = state.openProjectId;
    if (!job || pid == null || !isFarmJobInFlight(job.status)) return;
    let cancelled = false;
    const timer = setTimeout(async () => {
      try {
        const next = await apiGetIpFarmJob(pid, job.id);
        if (cancelled) return;
        // The IP farm commits per address, so rows stream in as it goes.
        reloadHosts();
        if (isFarmJobInFlight(next.status)) {
          setStateRaw((s) => (s.ipFarmJob && s.ipFarmJob.id === next.id ? { ...s, ipFarmJob: next } : s));
        } else {
          setStateRaw((s) => (s.ipFarmJob && s.ipFarmJob.id === next.id ? { ...s, ipFarmJob: null } : s));
          if (next.status === "done" && next.result) {
            ipFarmDoneToast(next.result);
          } else if (next.status === "failed") {
            pushToast(next.error || t("Probe failed"), "error");
          }
        }
      } catch {
        if (!cancelled) setStateRaw((s) => (s.ipFarmJob ? { ...s, ipFarmJob: { ...s.ipFarmJob } } : s));
      }
    }, 1500);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.ipFarmJob, state.openProjectId]);

  // ================= js farm: poll the running scan job =================
  useEffect(() => {
    const job = state.jsFarmJob;
    const pid = state.openProjectId;
    if (!job || pid == null || !isFarmJobInFlight(job.status)) return;
    let cancelled = false;
    const timer = setTimeout(async () => {
      try {
        const next = await apiGetJsScanJob(pid, job.id);
        if (cancelled) return;
        // The scan commits per file, so found files stream in as it runs.
        reloadJsFiles();
        if (isFarmJobInFlight(next.status)) {
          setStateRaw((s) => (s.jsFarmJob && s.jsFarmJob.id === next.id ? { ...s, jsFarmJob: next } : s));
        } else {
          setStateRaw((s) => (s.jsFarmJob && s.jsFarmJob.id === next.id ? { ...s, jsFarmJob: null } : s));
          if (next.status === "done" && next.result) {
            pushToast(`${t("Scan done")} — ${next.result.files_scanned} JS, ${next.result.secrets_found} ${t("secrets")}, ${next.result.endpoints_found} ${t("paths")}`, "success");
          } else if (next.status === "failed") {
            pushToast(next.error || t("Scan failed"), "error");
          }
        }
      } catch {
        if (!cancelled) setStateRaw((s) => (s.jsFarmJob ? { ...s, jsFarmJob: { ...s.jsFarmJob } } : s));
      }
    }, 1500);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.jsFarmJob, state.openProjectId]);

  /** Hosts rendered by the whole Recon section. Backend-only — never the seed. */
  const hosts: Host[] = state.apiHosts ?? [];
  const hostNameById = (id: number) => hosts.find((h) => h.id === id)?.host ?? "";
  /* Subdomains are not a stored field — they are simply the project's other hosts
     that live under this one's name (www.acme.com under acme.com). Derived here so
     the tree reflects the real host list instead of a parallel, hand-kept one. */
  const subdomainsOf = (host: Host): Host[] =>
    hosts.filter((h) => h.id !== host.id && h.host.toLowerCase().endsWith(`.${host.host.toLowerCase()}`));

  // ================= members: load from backend =================
  const reloadMembers = () => setStateRaw((s) => ({ ...s, membersTick: s.membersTick + 1 }));
  useEffect(() => {
    const pid = state.openProjectId;
    if (pid == null) {
      setStateRaw((s) => (s.apiMembers === null ? s : { ...s, apiMembers: null }));
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        // Readable by every project member (require_project_access) — a 403 here
        // means no access to the project at all, so it raises the no-access screen.
        const rows = await apiGetProjectMembers(pid);
        if (!cancelled) setStateRaw((s) => ({ ...s, apiMembers: rows.map(toFrostMember) }));
      } catch (e) {
        if (!cancelled) {
          setStateRaw((s) => ({ ...s, apiMembers: [] }));
          handleProjectError(e, "Couldn't load members");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.openProjectId, state.membersTick]);

  // ================= vulnerabilities: load from backend =================
  /* The list endpoint does not say which host a finding is on — that lives in its
     asset links — so the affected host is resolved per finding against the
     project's already-loaded hosts. The author's name, by contrast, ships with
     the payload (`created_by_username`), because /users is admin-only. */
  const reloadVulns = () => setStateRaw((s) => ({ ...s, vulnsTick: s.vulnsTick + 1 }));
  useEffect(() => {
    const pid = state.openProjectId;
    if (pid == null) {
      setStateRaw((s) => (s.apiVulns === null ? s : { ...s, apiVulns: null }));
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        const res = await apiGetVulnerabilities(pid);
        const rows = await Promise.all(
          res.items.map(async (v) => {
            let hostName = "";
            try {
              const det = await apiGetVulnerability(pid, v.id);
              const link = det.assets.find((a) => a.asset_type === "host");
              if (link) hostName = hostNameById(link.asset_id);
            } catch {
              /* best-effort: a finding without a resolvable host still lists */
            }
            return toFrostVuln(v, hostName);
          })
        );
        if (!cancelled) setStateRaw((s) => ({ ...s, apiVulns: rows }));
      } catch (e) {
        if (!cancelled) {
          setStateRaw((s) => ({ ...s, apiVulns: [] }));
          handleProjectError(e, "Couldn't load vulnerabilities");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.openProjectId, state.vulnsTick, state.apiHosts]);

  // ================= notes: load from backend =================
  const reloadNotes = () => setStateRaw((s) => ({ ...s, notesTick: s.notesTick + 1 }));
  useEffect(() => {
    const pid = state.openProjectId;
    if (pid == null) {
      setStateRaw((s) => (s.apiNotes === null ? s : { ...s, apiNotes: null }));
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        const rows = await apiListProjectNotes(pid);
        if (!cancelled) setStateRaw((s) => ({ ...s, apiNotes: rows.map(toFrostNote) }));
      } catch (e) {
        if (!cancelled) {
          setStateRaw((s) => ({ ...s, apiNotes: [] }));
          handleProjectError(e, "Couldn't load notes");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.openProjectId, state.notesTick]);

  // ================= credentials: load from backend =================
  const reloadCreds = () => setStateRaw((s) => ({ ...s, credsTick: s.credsTick + 1 }));
  useEffect(() => {
    const pid = state.openProjectId;
    if (pid == null) {
      setStateRaw((s) => (s.apiCreds === null ? s : { ...s, apiCreds: null, revealedCredIds: [] }));
      return;
    }
    let cancelled = false;
    void (async () => {
      try {
        const rows = await apiListProjectCredentials(pid);
        if (!cancelled) setStateRaw((s) => ({ ...s, apiCreds: rows.map(toFrostCred) }));
      } catch (e) {
        if (!cancelled) {
          setStateRaw((s) => ({ ...s, apiCreds: [] }));
          handleProjectError(e, "Couldn't load credentials");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.openProjectId, state.credsTick]);

  // ================= notifications: load from backend =================
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const res = await apiListNotifications();
        if (!cancelled) setStateRaw((s) => ({ ...s, notifs: res.items }));
      } catch {
        // Best-effort: an empty bell beats breaking the shell.
        if (!cancelled) setStateRaw((s) => ({ ...s, notifs: [] }));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // ================= current project detail =================
  /* `d` is assembled from the collections loaded above — it is a view over real
     backend state, not a store. Nothing mutates it: every edit calls the API and
     bumps the matching `*Tick` to reload. */
  const projRow = state.apiProjects?.find((p) => p.id === state.openProjectId) ?? null;
  const projName = projRow?.name ?? "";
  const d: ProjectDetail = {
    status: projRow && (projRow.status === "archived" || projRow.status === "completed") ? "archived" : "active",
    desc: projRow?.description === "No description yet" ? "" : projRow?.description ?? "",
    start: toDispDate(projRow?.startISO),
    end: toDispDate(projRow?.endISO),
    progress: elapsedPct(projRow?.startISO ?? "", projRow?.endISO ?? ""),
    title: projName,
    hosts,
    members: state.apiMembers ?? [],
    vulns: state.apiVulns ?? [],
    notes: state.apiNotes ?? [],
    creds: state.apiCreds ?? [],
  };

  // ================= role model / access control =================
  // Project visibility (rule 1.1) is enforced by the backend — getProjects only
  // returns projects the caller may see, and the detail endpoints 403 otherwise.
  const isProjectCreator = projRow != null && authUser != null && projRow.createdBy === authUser.id;
  /** The lead role is global (User.project_role); it only unlocks anything inside a project the user belongs to. */
  const isProjectLead = authUser?.project_role === "lead" && (state.apiMembers ?? []).some((m) => m.id === authUser.id);
  /** Любой участник проекта (в т.ч. простой пентестер) — он есть в списке apiMembers. */
  const isProjectMember = authUser != null && (state.apiMembers ?? []).some((m) => m.id === authUser.id);
  /** Rule 1.2 — управлять составом команды (add/remove) могут только админ / создатель / лид.
      Бэкенд — источник истины (ensure_can_manage_members), это лишь прячет кнопки. */
  const canManageMembers = isAdmin || isProjectCreator || isProjectLead;
  /** Видеть список участников может любой участник проекта — но только смотреть, без управления. */
  const canViewMembers = canManageMembers || isProjectMember;
  /** The same three roles may edit the project card (name / description / dates).
      Mirrors ProjectService.ensure_can_edit_project — the backend is the gate,
      this only hides a button the user would be refused anyway. */
  const canEditProject = isAdmin || isProjectCreator || isProjectLead;
  /* In the projects list there is no membership loaded per row, but a non-admin
     only ever receives projects they belong to (rule 1.1) — so a listed row plus
     the global lead role already means "lead of a project I'm in". */
  const canEditProjectRow = (row: ApiProjectRow) =>
    isAdmin || (authUser != null && row.createdBy === authUser.id) || authUser?.project_role === "lead";

  // ================= navigation =================
  // Возврат к списку обязан сбрасывать открытый проект — иначе состояние всё ещё
  // «в проекте», и URL может залипнуть на /projects/{id}.
  const selProjects = () =>
    setState({
      nav: "projects",
      view: "list",
      openProjectId: null,
      section: "overview",
      expanded: [],
      openVulnId: null,
      openNoteId: null,
      openHostId: null,
      openIp: null,
    });
  const openProject = (id: number) =>
    setState({ view: "detail", openProjectId: id, section: "overview", expanded: [], openVulnId: null, openNoteId: null, accessDenied: false });
  const openProfile = () => setState({ view: "profile", userMenuOpen: false, profileTab: "account" });
  const selWSMembers = () => setState({ nav: "members", view: "workspaceMembers" });
  /* Project activity, not the global audit log: /projects/{id}/activity is scoped to
     the project and readable by every member, while /audit-logs stays admin-only. */
  const reloadActivity = () => setStateRaw((s) => ({ ...s, activityTick: s.activityTick + 1 }));
  const loadActivity = (pid: number) => {
    setStateRaw((s) => ({ ...s, activityLoading: true, activityError: null }));
    void (async () => {
      try {
        const items = await apiGetProjectActivity(pid, 50);
        setStateRaw((s) => ({ ...s, activity: items, activityLoading: false }));
      } catch (e) {
        if (getApiErrorStatus(e) === 403 || getApiErrorStatus(e) === 404) {
          setStateRaw((s) => ({ ...s, activity: [], activityLoading: false, accessDenied: true }));
          return;
        }
        setStateRaw((s) => ({ ...s, activity: [], activityError: getApiErrorMessage(e, "Couldn't load activity"), activityLoading: false }));
      }
    })();
  };
  /** A section tab always lands on that section's list, never on a card left open in it. */
  /* Leaving Recon resets its sub-view, so coming back later opens on Hosts
     instead of restoring whichever list was picked several sections ago. */
  /* Leaving a section abandons the full-page forms that live inside it (export,
     "Add hosts") — otherwise coming back would drop the user into a stale form
     instead of the list they asked for. */
  const setSection = (s: SectionId) =>
    setState({ section: s, ...(s === "hosts" ? {} : { reconView: "hosts" as ReconView }), reconMenuOpen: false, openVulnId: null, openNoteId: null, noteEditorOpen: false, openJsFileId: null, exportPageOpen: false, hostImportOpen: false, ipImportOpen: false, epImportOpen: false, jsScanSetupOpen: false });
  const selRecon = (v: ReconView) => setState({ section: "hosts", reconView: v, reconMenuOpen: false, openHostId: null, openIp: null, openJsFileId: null, exportPageOpen: false, hostImportOpen: false, ipImportOpen: false, epImportOpen: false, jsScanSetupOpen: false });

  /* ---- URL ↔ navigation-state sync (deep links to sections / projects) ----
     Two effects mirror each other: URL → state, and state → URL. They must never
     both act on the same change, because the second one always runs with the
     state of the render it was scheduled in — i.e. the *old* state:

     - On mount that state is `initialState` (projects list), so URL → state must
       win or the deep link gets overwritten with "/projects" (navSyncMounted).
     - On browser Back the URL changes first; state → URL then still sees the
       previous screen and navigates straight back *forward*, so Back appears
       dead and history grows on every press (adoptingUrlRef).

     Whoever changed first wins; the other side stands down for that one run. */
  const adoptingUrlRef = useRef(false);
  useEffect(() => {
    const patch = navStateFromPath(location.pathname);
    const keys = Object.keys(patch) as (keyof FrostState)[];
    // `state` here is the render the URL change arrived in — comparing against it
    // tells us whether this is an external navigation we still have to adopt.
    if (!keys.some((k) => state[k] !== patch[k])) return;
    adoptingUrlRef.current = true;
    setStateRaw((s) => ({ ...s, ...patch }));
    // Deps are the pathname alone on purpose: this must fire only when the URL
    // moves. Adding `state` would re-run it on every state change and re-apply
    // the old URL over a navigation the user just made.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.pathname]);
  const navSyncMounted = useRef(false);
  useEffect(() => {
    if (!navSyncMounted.current) {
      navSyncMounted.current = true;
      return;
    }
    if (adoptingUrlRef.current) {
      adoptingUrlRef.current = false;
      return;
    }
    const p = pathFor({
      view: state.view,
      nav: state.nav,
      openProjectId: state.openProjectId,
      section: state.section,
      reconView: state.reconView,
      profileTab: state.profileTab,
      openVulnId: state.openVulnId,
      openNoteId: state.openNoteId,
      openHostId: state.openHostId,
      openIp: state.openIp,
    });
    if (p !== location.pathname) navigate(p);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.view, state.nav, state.openProjectId, state.section, state.reconView, state.profileTab, state.openVulnId, state.openNoteId, state.openHostId, state.openIp, location.pathname]);
  /* Loaded as soon as the project opens, like every other collection — the tab's
     counter has to be right before the tab is ever visited. Entering the tab
     re-fetches, since the feed is a shared audit trail that others add to. */
  useEffect(() => {
    if (state.openProjectId != null) loadActivity(state.openProjectId);
    else setStateRaw((s) => (s.activity === null ? s : { ...s, activity: null }));
  }, [state.openProjectId, state.activityTick]);
  useEffect(() => {
    if (state.view === "detail" && state.section === "activity" && state.openProjectId != null) reloadActivity();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.view, state.section]);
  // Leaving a project clears a previous 403 so the next one starts from a clean slate.
  useEffect(() => {
    setStateRaw((s) => (s.accessDenied ? { ...s, accessDenied: false } : s));
  }, [state.openProjectId]);
  /* Deep link (/projects/{p}/vulns/{v}, e.g. from a notification): the URL sets
     openVulnId before the findings have loaded, so the edit form is filled in
     once the matching finding arrives. */
  useEffect(() => {
    if (state.openVulnId == null || state.apiVulns == null) return;
    const v = state.apiVulns.find((x) => x.id === state.openVulnId);
    if (!v) return;
    setStateRaw((s) => (s.vulnDetailForm.title === v.title ? s : { ...s, vulnDetailForm: vulnFormFrom(v) }));
     
  }, [state.openVulnId, state.apiVulns]);

  /* Esc dismisses the frontmost open overlay, mirroring a backdrop click. Modals
     and the notifications panel each carry their own onClose on `.modalback` /
     `.notifback`, so clicking the topmost open one (highest z-index) closes that
     layer alone and leaves anything beneath it — any modal following the shared
     pattern is covered without touching this. The user menu has no backdrop of
     its own, so it's dismissed by flag. */
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || e.defaultPrevented) return;
      const open = Array.from(
        document.querySelectorAll<HTMLElement>(".modalback.open, .notifback.open")
      );
      if (open.length) {
        open
          .reduce((top, el) =>
            (parseInt(getComputedStyle(el).zIndex) || 0) >= (parseInt(getComputedStyle(top).zIndex) || 0) ? el : top
          )
          .click();
        return;
      }
      setStateRaw((s) => (s.userMenuOpen || s.reconMenuOpen ? { ...s, userMenuOpen: false, reconMenuOpen: false } : s));
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  // ================= projects list (backend-backed) =================
  /** The backend rejects this too (422) — checked here so the form says so before submitting. */
  const datesInvalid = (startISO: string, endISO: string) => !!startISO && !!endISO && endISO < startISO;
  const DATES_ERROR = "Start date can't be after end date";

  const createProject = async () => {
    const name = state.newName.trim();
    if (!name) {
      setState({ modalOpen: false });
      return;
    }
    if (datesInvalid(state.newStart, state.newEnd)) {
      pushToast(DATES_ERROR, "error");
      return;
    }
    try {
      await apiCreateProject({
        name,
        description: state.newDesc.trim() || undefined,
        start_date: state.newStart || undefined,
        end_date: state.newEnd || undefined,
      });
      setState({ modalOpen: false, newName: "", newDesc: "", newStart: "", newEnd: "", tab: "active" });
      reloadProjects();
    } catch (e) {
      pushToast(getApiErrorMessage(e, "Couldn't create project"), "error");
    }
  };

  // ================= edit project =================
  // Opened from a list row → targets a real backend project (projEditId set).
  const openProjEditRow = (row: ApiProjectRow) =>
    setState({
      projEditOpen: true,
      projEditId: row.id,
      projEditName: row.name,
      projEditDesc: row.description === "No description yet" ? "" : row.description,
      projEditStart: row.startISO,
      projEditEnd: row.endISO,
      projEditStatus: row.status,
    });
  // Opened from the project detail — targets the open project.
  const openProjEdit = () =>
    setState({
      projEditOpen: true,
      projEditId: state.openProjectId,
      projEditName: projRow?.name ?? "",
      projEditDesc: d.desc,
      projEditStart: projRow?.startISO ?? "",
      projEditEnd: projRow?.endISO ?? "",
      projEditStatus: projRow?.status ?? "active",
    });
  const closeProjEdit = () => setState({ projEditOpen: false });
  const saveProjEdit = async () => {
    const name = state.projEditName.trim();
    if (!name || !state.projEditId) {
      setState({ projEditOpen: false });
      return;
    }
    if (datesInvalid(state.projEditStart, state.projEditEnd)) {
      pushToast(DATES_ERROR, "error");
      return;
    }
    try {
      await apiUpdateProject(state.projEditId, {
        name,
        description: state.projEditDesc.trim(),
        start_date: state.projEditStart || undefined,
        end_date: state.projEditEnd || undefined,
        status: state.projEditStatus,
      });
      setState({ projEditOpen: false });
      reloadProjects();
    } catch (e) {
      pushToast(getApiErrorMessage(e, "Couldn't save project"), "error");
    }
  };
  const askDeleteProject = (row: ApiProjectRow) => setState({ confirmOpen: true, confirmType: null, confirmProjectId: row.id, confirmLabel: row.name });

  // ================= export: Word reports =================
  /* Both reports are generated by the backend from the project's real data
     (ReportService.generate). `kind` is the backend's template id — "szi" and
     "pp" — surfaced under readable names. */
  const openExportModal = () => setState({ exportModalOpen: true, exportKind: "szi", exportScope: "report" });
  const closeExportModal = () => setState({ exportModalOpen: false });

  /* ---- recon exports (hosts / IPs / endpoints) ----
     The dialog exports exactly what the view's filters left on screen, so the
     filter row above the table is the selection UI — no second set of controls
     that could disagree with it. Generated client-side from data already loaded. */
  const downloadText = (text: string, filename: string, mime = "text/plain") => {
    const url = URL.createObjectURL(new Blob([text], { type: `${mime};charset=utf-8` }));
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const slug = (s: string) => (s.replace(/[^\w.-]+/g, "_").replace(/^_+|_+$/g, "") || "export").slice(0, 60);

  /** Non-empty, trimmed lines of the editable pane — what actually gets written. */
  const exportTextLines = (text: string): string[] => text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);

  /* The line format for every recon export: one row per host:port pair, so a row
     can be dropped without taking the rest of the host with it. A host with no
     known ports still contributes its bare name — otherwise it would vanish from
     an export that is supposed to list it. */
  const exportLinesFor = (scope: ExportScope): string[] => {
    /* Источник для JS-выгрузок: открытая карточка файла, если мы в ней, иначе
       весь отфильтрованный список. Так кнопка «Экспорт» на странице файла даёт
       ровно его находки, а та же кнопка в списке — находки всего раздела. */
    if (scope === "js-endpoints" || scope === "js-secrets") {
      const src = _jsd ? [_jsd] : jsFilesFiltered;
      const out: string[] = [];
      const uniq = new Set<string>();
      for (const f of src) {
        const lines =
          scope === "js-endpoints"
            ? f.endpoints
            // Вид и значение — табом: секрет может содержать что угодно, включая
            // двоеточия и пробелы, а таб переживает и grep, и вставку в таблицу.
            : f.secrets.map((sec) => `${sec.kind}\t${sec.match}`);
        for (const line of lines) {
          const v = line.trim();
          if (!v || uniq.has(v)) continue;
          uniq.add(v);
          out.push(v);
        }
      }
      return out;
    }
    if (scope === "ips") {
      // The row already carries the ports of every host sharing this address.
      return ipsRows.flatMap((r) => (r.ports.length ? r.ports.map((p) => `${r.ip}:${p.n}`) : [r.ip]));
    }
    if (scope === "endpoints") {
      // Only the endpoint URL — no method prefix.
      return endpointGroups.flatMap((g) => g.endpoints.map((e) => `https://${g.host}${e.p}`));
    }
    // Ровно те строки, что видны в таблице (вместе с вложенными поддоменами).
    const rows = visibleHostRows();
    return rows.flatMap((h) => (h.ports.length ? h.ports.map((p) => `${h.host}:${p.n}`) : [h.host]));
  };

  /** Rebuilds the OpenAPI doc from the edited lines, so edits reach the JSON too. */
  const endpointLinesToOpenApi = (lines: string[]): string => {
    const paths: Record<string, Record<string, unknown>> = {};
    lines.forEach((line) => {
      // Export lines are now bare URLs; still accept a leading METHOD for
      // hand-edited lines. No method → default to GET.
      const parts = line.trim().split(/\s+/);
      const hasMethod = parts.length >= 2 && !/^https?:/i.test(parts[0]);
      const method = hasMethod ? parts[0] : "GET";
      const url = hasMethod ? parts[1] : parts[0];
      if (!url) return;
      let host: string;
      let path: string;
      try {
        const u = new URL(url);
        host = u.host;
        path = u.pathname;
      } catch {
        return; // a hand-edited line that is no longer a URL is skipped, not fatal
      }
      // OpenAPI keys by path, so the host goes into the operation's server list.
      paths[path] = paths[path] ?? {};
      paths[path][method.toLowerCase()] = {
        summary: `${method} ${path}`,
        servers: [{ url: `https://${host}` }],
        responses: { "200": { description: "OK" } },
      };
    });
    return JSON.stringify({ openapi: "3.0.3", info: { title: `${projName} — endpoints`, version: "1.0.0" }, paths }, null, 2);
  };

  const doReconExport = () => {
    const name = slug(projName);
    const lines = exportTextLines(state.exportText);
    if (state.exportScope === "endpoints" && state.exportFormat === "openapi") {
      downloadText(endpointLinesToOpenApi(lines), `${name}_endpoints.json`, "application/json");
    } else {
      const file =
        state.exportScope === "hosts" ? "hosts"
        : state.exportScope === "ips" ? "ips"
        : state.exportScope === "js-endpoints" ? "js_paths"
        : state.exportScope === "js-secrets" ? "js_secrets"
        : "endpoints";
      downloadText(lines.join("\n"), `${name}_${file}.txt`);
    }
    closeReconExport();
  };

  const openReconExport = (scope: ExportScope) =>
    setState({ exportPageOpen: true, exportScope: scope, exportFormat: "list", exportText: exportLinesFor(scope).join("\n") });
  const closeReconExport = () => setState({ exportPageOpen: false, exportText: "" });
  const doExport = async () => {
    const pid = state.openProjectId;
    if (pid == null) return;
    const kind = state.exportKind;
    setState({ exportBusy: true });
    try {
      const blob = kind === "szi" ? await apiDownloadCertificationReport(pid) : await apiDownloadAcceptanceReport(pid);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${projName || "report"}_${kind}.docx`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setState({ exportModalOpen: false, exportBusy: false });
    } catch (e) {
      setState({ exportBusy: false });
      pushToast(getApiErrorMessage(e, "Couldn't generate report"), "error");
    }
  };

  // ================= detail: hosts / recon =================
  const toggleHost = (id: number) =>
    setState((s) => ({ expanded: s.expanded.includes(id) ? s.expanded.filter((x) => x !== id) : [...s.expanded, id] }));
  const openHostDetail = (id: number) => setState({ openHostId: id });
  const closeHostDetail = () => setState({ openHostId: null });
  const openIpDetail = (ip: string) => setState({ openIp: ip });
  const closeIpDetail = () => setState({ openIp: null });
  const toggleReconMenu = () => setState((s) => ({ reconMenuOpen: !s.reconMenuOpen }));

  const toggleEpGroup = (host: string) =>
    setState((s) => ({ epExpanded: s.epExpanded.includes(host) ? s.epExpanded.filter((x) => x !== host) : [...s.epExpanded, host] }));
  // JS files share the epExpanded set, namespaced "js:<host>" so a host and its
  // JS group don't collide.
  /* Раскрытие домена в разделе JS. Файлы больше не раскрываются на месте: клик
     по файлу открывает его карточку, как у хостов и адресов. */
  const toggleJsGroup = (host: string) => {
    const key = `js:host:${host}`;
    setState((s) => ({ epExpanded: s.epExpanded.includes(key) ? s.epExpanded.filter((x) => x !== key) : [...s.epExpanded, key] }));
  };
  /* Starts the scan on exactly the domains left in the setup page's list — the
     backend takes that list verbatim (empty would fall back to every project
     domain, which the setup page exists to avoid), so an empty list is blocked. */
  const submitJsScan = async () => {
    const pid = state.openProjectId;
    if (pid == null) return;
    const domains = state.jsScanText.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    if (domains.length === 0) {
      pushToast(t("Pick at least one domain to scan."), "error");
      return;
    }
    try {
      const job = await apiStartJsScan(pid, domains.join("\n"));
      setState({ jsFarmJob: job, jsScanSetupOpen: false });
      pushToast(`${t("Scanning")} ${job.targets_total ?? ""} ${t("domains…")}`.replace("  ", " "), "success");
    } catch (e) {
      pushToast(getApiErrorMessage(e, t("Couldn't start JS scan")), "error");
    }
  };
  /* Per-host (or whole-project) zip of the discovered .js. The files were never
     stored, so the backend re-downloads them on demand — this can take a moment
     and may skip files that no longer resolve. */
  const downloadJsArchive = async (hostId: number | undefined, label: string) => {
    const pid = state.openProjectId;
    if (pid == null) return;
    pushToast(t("Preparing JS archive…"), "success");
    try {
      const blob = await apiDownloadJsArchive(pid, hostId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `js-${(label || "project").replace(/[^a-zA-Z0-9._-]+/g, "_")}.zip`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      pushToast(getApiErrorMessage(e, t("Couldn't download JS archive.")), "error");
    }
  };
  /* The raw request is loaded from the endpoint itself — what was stored, not a
     made-up template. When it has never been filled in, a skeleton request line
     is offered as a starting point. The response has no backend field, so it
     starts empty and stays local. */
  const openEndpoint = (ep: { method: Method; path: string; host: string; hostId: number; endpointId: number }) => {
    setState({ epOpen: true, epData: ep, epRequest: "", epResponse: "", epSaving: false });
    const pid = state.openProjectId;
    if (pid == null) return;
    void (async () => {
      try {
        const list = await apiGetEndpoints(pid, ep.hostId);
        const stored = list.find((e) => e.id === ep.endpointId);
        const headers = (stored?.request_headers ?? []).map((h) => `${h.name}: ${h.value}`).join("\n");
        const body = stored?.request_body ?? "";
        const raw = [`${ep.method} ${ep.path} HTTP/1.1`, `Host: ${ep.host}`, headers, "", body].filter((p, i) => p !== "" || i === 3).join("\n");
        setStateRaw((s) => (s.epOpen && s.epData.endpointId === ep.endpointId ? { ...s, epRequest: raw.trimEnd() } : s));
      } catch {
        /* best-effort: an empty box is better than a fabricated one */
      }
    })();
  };
  const closeEndpoint = () => setState({ epOpen: false });


  const copyText = (text: string, what: string) => {
    try {
      void navigator.clipboard?.writeText(text);
      pushToast(`${what} copied to clipboard`, "success");
    } catch {
      pushToast("Clipboard unavailable", "error");
    }
  };
  /** Toggle whether one credential's secret is shown in clear text. */
  const toggleCredReveal = (id: number) =>
    setState((s) => ({
      revealedCredIds: s.revealedCredIds.includes(id) ? s.revealedCredIds.filter((x) => x !== id) : [...s.revealedCredIds, id],
    }));
  const copyCurl = (ep: { method: Method; path: string; host: string }) => {
    try {
      void navigator.clipboard?.writeText(`curl -X ${ep.method} 'https://${ep.host}${ep.path}'`);
      pushToast(t("cURL copied"), "success");
    } catch {
      /* clipboard unavailable */
    }
  };
  const deleteEndpoint = async (hostId: number, endpointId: number) => {
    const pid = state.openProjectId;
    if (pid == null) return;
    try {
      await apiDeleteEndpoint(pid, hostId, endpointId);
      reloadHosts();
    } catch (e) {
      pushToast(getApiErrorMessage(e, "Couldn't delete endpoint"), "error");
    }
  };

  // ================= entity editor (host / vuln / note / member) =================
  const updateForm = (k: string, v: string) => setState((s) => ({ editorForm: { ...s.editorForm, [k]: v } }));
  const setTagDraft = (k: string, v: string) => setState((s) => ({ tagDrafts: { ...s.tagDrafts, [k]: v } }));
  const addEditorTag = (k: string, val: string) => {
    const v = val.trim();
    if (!v) return;
    setState((s) => {
      const cur = s.editorForm[k];
      const arr = Array.isArray(cur) ? cur : [];
      return { editorForm: { ...s.editorForm, [k]: [...arr, v] }, tagDrafts: { ...s.tagDrafts, [k]: "" } };
    });
  };
  const removeEditorTag = (k: string, idx: number) =>
    setState((s) => {
      const cur = s.editorForm[k];
      const arr = Array.isArray(cur) ? cur : [];
      return { editorForm: { ...s.editorForm, [k]: arr.filter((_, i) => i !== idx) } };
    });
  const openEditor = (type: EditorType, mode: "add" | "edit", index: number) => {
    let form: Record<string, string | string[]> = {};
    if (mode === "edit") {
      if (type === "host") {
        const e = hosts[index];
        if (!e) return;
        form = { host: e.host };
      } else if (type === "vuln") {
        const e = d.vulns[index];
        if (!e) return;
        form = { title: e.title, host: e.host, sev: e.sev, status: e.status };
      } else if (type === "note") {
        const e = d.notes[index];
        if (!e) return;
        form = { title: e.title, excerpt: e.excerpt };
      } else if (type === "cred") {
        const e = d.creds[index];
        if (!e) return;
        // Password is left blank on edit — sending it blank keeps the stored one, so
        // it is neither pre-filled into the form nor overwritten unless retyped.
        form = { username: e.username, password: "", host: e.host };
      }
    } else if (type === "host") form = { status: "up", ports: [] };
    else if (type === "ip") form = { hostName: "", ip: "", status: "unknown" };
    else if (type === "endpoint") form = { hostName: "", method: "GET", path: "" };
    else if (type === "vuln") form = { sev: "info", status: "open" };
    else if (type === "member") form = { userKey: "" };
    else if (type === "cred") form = { username: "", password: "", host: "" };
    setState({ editorOpen: true, editorType: type, editorMode: mode, editorIndex: index, editorForm: form, tagDrafts: {} });
  };
  const closeEditor = () => setState({ editorOpen: false });


  // ================= host farm: paste-a-list import =================
  /* One pasted token → its canonical `host` / `host:port` form (or null if junk).
     Mirrors the backend parser closely enough for a live preview; the backend
     re-parses authoritatively on submit. Scheme without a port keeps the scheme's
     default port so `https://x` stays 443 (JS URL would otherwise drop it). */
  const normalizeHostToken = (token: string): string | null => {
    const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(token);
    if (hasScheme && !/^https?:\/\//i.test(token)) return null; // non-web scheme → rejected
    let u: URL;
    try {
      u = new URL(hasScheme ? token : `http://${token}`);
    } catch {
      return null;
    }
    const host = u.hostname.toLowerCase().replace(/\.$/, "");
    if (!host) return null;
    let port = u.port;
    if (!port && hasScheme) port = /^https:/i.test(token) ? "443" : "80";
    return port ? `${host}:${port}` : host;
  };
  /** Raw paste → deduped, normalized host list (the "will be imported" preview). */
  const normalizeHostList = (raw: string): string => {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const line of raw.split(/\r?\n/)) {
      const l = line.trim();
      if (!l || l.startsWith("#") || l.startsWith("//")) continue;
      for (const tok of l.split(/[\s,]+/)) {
        const n = tok.trim() ? normalizeHostToken(tok.trim()) : null;
        if (n && !seen.has(n)) {
          seen.add(n);
          out.push(n);
        }
      }
    }
    return out.join("\n");
  };
  /** Raw paste → deduped IP list. Same normalization, minus anything that is not
   *  an address literal — the IP farm rejects hostnames server-side anyway, so
   *  filtering here keeps the preview honest about what will actually be sent. */
  const isIpLiteral = (host: string): boolean => {
    const bare = host.replace(/^\[|\]$/g, "");
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(bare)) return bare.split(".").every((o) => Number(o) <= 255);
    return bare.includes(":");
  };
  const normalizeIpList = (raw: string): string =>
    normalizeHostList(raw)
      .split("\n")
      .filter((line) => {
        // Strip a trailing :port, but only when it is not part of an IPv6 literal.
        const m = /^(\[[^\]]+\]|[^:]+)(?::(\d+))?$/.exec(line);
        return isIpLiteral(m ? m[1] : line);
      })
      .join("\n");

  // Note: never null hostFarmJob here — a running probe keeps polling in the
  // background (banner + live statuses) whether or not this page is open.
  const openHostImport = () => setState({ hostImportOpen: true, hostImportRaw: "", hostImportPreview: "", hostImportBusy: false });
  const closeHostImport = () => setState({ hostImportOpen: false, hostImportRaw: "", hostImportPreview: "", hostImportBusy: false });
  const openIpImport = () => setState({ ipImportOpen: true, ipImportRaw: "", ipImportPreview: "", ipImportBusy: false });
  const closeIpImport = () => setState({ ipImportOpen: false, ipImportRaw: "", ipImportPreview: "", ipImportBusy: false });
  const submitIpImport = async () => {
    const pid = state.openProjectId;
    const raw = state.ipImportPreview.trim();
    if (pid == null || !raw) {
      pushToast(t("Paste at least one IP"), "error");
      return;
    }
    setState({ ipImportBusy: true });
    try {
      const job = await apiStartIpFarm(pid, raw);
      setState({ ipImportOpen: false, ipImportRaw: "", ipImportPreview: "", ipImportBusy: false });
      reloadHosts();
      // Nothing new to probe — every address was already added. The server closed
      // the job on the spot; report the skip instead of a "Probing 0 IPs…" banner.
      if (!isFarmJobInFlight(job.status)) {
        setState({ ipFarmJob: null });
        if (job.result) ipFarmDoneToast(job.result);
        return;
      }
      // Unlike the host farm there are no skeleton rows: until an address is
      // reverse-resolved we cannot tell whether it belongs to an existing host.
      // Rows still stream in — the farm commits per address.
      setState({ ipFarmJob: job });
      pushToast(`${t("Probing")} ${job.targets_total ?? ""} ${t("IPs")}…`.replace("  ", " "), "success");
    } catch (e) {
      setState({ ipImportBusy: false });
      pushToast(getApiErrorMessage(e, t("Couldn't start IP import")), "error");
    }
  };
  const submitHostImport = async () => {
    const pid = state.openProjectId;
    // Submit the edited preview (the final list the user sees), not the raw paste.
    const raw = state.hostImportPreview.trim();
    if (pid == null || !raw) {
      pushToast(t("Paste at least one host"), "error");
      return;
    }
    setState({ hostImportBusy: true });
    try {
      const job = await apiStartHostFarm(pid, raw);
      // The server creates the hosts up front, so close the page and show them now;
      // statuses/ports fill in as the background probe commits per host (poll effect).
      setState({ hostImportOpen: false, hostImportRaw: "", hostImportPreview: "", hostImportBusy: false });
      reloadHosts();
      // Nothing new to probe — every host was already added. The server closed the
      // job on the spot; report the skip instead of a "Probing 0 hosts…" banner.
      if (!isFarmJobInFlight(job.status)) {
        setState({ hostFarmJob: null });
        if (job.result) hostFarmDoneToast(job.result);
        return;
      }
      setState({ hostFarmJob: job });
      pushToast(`${t("Probing")} ${job.targets_total ?? ""} ${t("hosts")}…`.replace("  ", " "), "success");
    } catch (e) {
      setState({ hostImportBusy: false });
      pushToast(getApiErrorMessage(e, t("Couldn't start host import")), "error");
    }
  };

  /* "Add endpoints" mirrors "Add hosts/IPs": paste a list, preview the normalized
     form, submit. Each line is a URL (with an optional leading METHOD); the host is
     taken from the URL and matched to an existing project host — endpoints hang off
     a host, so a line whose host is not in the project is skipped on submit. */
  const EP_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "QUERY"]);
  const parseEpLine = (line: string): { host: string; method: string; path: string } | null => {
    const l = line.trim();
    if (!l || l.startsWith("#") || l.startsWith("//")) return null;
    const parts = l.split(/\s+/);
    let method = "GET";
    let target = l;
    if (parts.length >= 2 && EP_METHODS.has(parts[0].toUpperCase())) {
      method = parts[0].toUpperCase();
      target = parts.slice(1).join(" ").trim();
    }
    let host: string;
    let path: string;
    try {
      const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(target) ? target : `https://${target}`);
      host = u.hostname.toLowerCase();
      path = (u.pathname || "/") + (u.search || "");
    } catch {
      return null;
    }
    // Need a real host to attach to (domain or IP); a bare path has none.
    if (!host || !host.includes(".")) return null;
    return { host, method, path };
  };
  const normalizeEpList = (raw: string): string => {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const line of raw.split(/\r?\n/)) {
      const p = parseEpLine(line);
      if (!p) continue;
      const canon = `${p.method} https://${p.host}${p.path}`;
      if (!seen.has(canon)) {
        seen.add(canon);
        out.push(canon);
      }
    }
    return out.join("\n");
  };
  const openEpImport = () => setState({ epImportOpen: true, epImportRaw: "", epImportPreview: "", epImportBusy: false });
  const closeEpImport = () => setState({ epImportOpen: false, epImportRaw: "", epImportPreview: "", epImportBusy: false });
  const submitEpImport = async () => {
    const pid = state.openProjectId;
    const parsed = state.epImportPreview
      .split(/\r?\n/)
      .map(parseEpLine)
      .filter((x): x is { host: string; method: string; path: string } => x != null);
    if (pid == null || parsed.length === 0) {
      pushToast(t("Paste at least one endpoint"), "error");
      return;
    }
    setState({ epImportBusy: true });
    let added = 0;
    let skipped = 0;
    for (const ep of parsed) {
      const host = hosts.find((h) => h.host.toLowerCase() === ep.host);
      if (!host) {
        skipped++;
        continue;
      }
      try {
        await apiCreateEndpoint(pid, host.id, { path: ep.path, method: ep.method as Method });
        added++;
      } catch {
        skipped++;
      }
    }
    setState({ epImportOpen: false, epImportRaw: "", epImportPreview: "", epImportBusy: false });
    reloadHosts();
    pushToast(
      skipped ? `${t("Added")} ${added} · ${skipped} ${t("skipped (host not found)")}` : `${t("Added")} ${added} ${t("endpoints")}`,
      added ? "success" : "error",
    );
  };

  /* Host editing only renames — status comes from the probe and ports hang off an
     IP the probe materialises, so neither is editable here. New hosts come from the
     "Add hosts" import, never this editor. */
  const saveHostEditor = async () => {
    const { editorIndex: index, editorForm: f } = state;
    const pid = state.openProjectId;
    if (pid == null) {
      setState({ editorOpen: false });
      return;
    }
    const target = hosts[index];
    if (!target) {
      setState({ editorOpen: false });
      return;
    }
    const hostname = fstr(f.host).trim();
    try {
      await apiUpdateHost(pid, target.id, { hostname });
      setState({ editorOpen: false });
      reloadHosts();
    } catch (e) {
      pushToast(getApiErrorMessage(e, "Couldn't save host"), "error");
    }
  };

  /* A finding must hang off a host (`host_id` is required on create), so the
     "Affected host" field is a searchable picker over the project's real hosts.
     Severity is only settable on create: once a finding has a CVSS score the
     backend derives severity from it on every update (ProjectService keeps the
     score authoritative), so an edit-time severity field would be a no-op. It is
     changed by editing the CVSS vector on the finding's card. */
  /* Resolve a typed host to a real project host, case-insensitively — the same
     binding the member picker uses (match an existing entity, not free text). */
  const resolveProjectHost = (typed: string) => {
    const q = typed.trim().toLowerCase();
    return q ? hosts.find((h) => h.host.toLowerCase() === q) : undefined;
  };

  const saveVulnEditor = async () => {
    const { editorMode: mode, editorIndex: index, editorForm: f } = state;
    const pid = state.openProjectId;
    if (pid == null) return;
    const title = (fstr(f.title) || "Untitled").trim();
    const status = (fstr(f.status) as VStatus) || "open";
    try {
      if (mode === "add") {
        const typedHost = fstr(f.host).trim();
        const host = resolveProjectHost(typedHost);
        if (!host) {
          pushToast(typedHost ? `Host “${typedHost}” not found` : "Select the host this finding belongs to", "error");
          return;
        }
        // Add asks only for Title + Host; severity/status default here and the
        // user completes the finding on its detail card — redirect straight there.
        // Severity starts "info": it is refined once the author fills the CVSS vector.
        const created = await apiCreateVulnerability(pid, { title, status: "open", severity: "info", host_id: host.id });
        reloadVulns();
        setState({ editorOpen: false, section: "vulns", openVulnId: created.id, vulnDetailForm: {} });
        return;
      }
      const target = d.vulns[index];
      if (!target) return;
      // No `severity` here on purpose: sending one would either be ignored (when
      // a CVSS score exists) or silently overwrite the real severity.
      await apiUpdateVulnerability(pid, target.id, { title, status });
      await relinkVulnHost(pid, target.id, fstr(f.host));
      setState({ editorOpen: false });
      reloadVulns();
    } catch (e) {
      pushToast(getApiErrorMessage(e, mode === "add" ? "Couldn't add vulnerability" : "Couldn't save vulnerability"), "error");
    }
  };

  /* `host_id` only exists on create, so moving a finding to another host means
     repointing its host asset link. Without this the "Affected host" field would
     silently do nothing when editing. */
  const relinkVulnHost = async (pid: number, vulnId: number, hostName: string) => {
    const host = resolveProjectHost(hostName);
    if (!host) return;
    const det = await apiGetVulnerability(pid, vulnId);
    const link = det.assets.find((a) => a.asset_type === "host");
    if (link?.asset_id === host.id) return;
    await apiAddVulnerabilityAsset(pid, vulnId, { asset_type: "host", asset_id: host.id });
    if (link) await apiDeleteVulnerabilityAsset(pid, vulnId, link.id);
  };

  const saveNoteEditorEntity = async () => {
    const { editorMode: mode, editorIndex: index, editorForm: f } = state;
    const pid = state.openProjectId;
    if (pid == null) return;
    const payload = { title: (fstr(f.title) || "Untitled").trim(), content: fstr(f.excerpt).trim() };
    try {
      if (mode === "add") await apiCreateProjectNote(pid, payload);
      else {
        const target = d.notes[index];
        if (!target) return;
        await apiUpdateProjectNote(pid, target.id, payload);
      }
      setState({ editorOpen: false });
      reloadNotes();
    } catch (e) {
      pushToast(getApiErrorMessage(e, mode === "add" ? "Couldn't add note" : "Couldn't save note"), "error");
    }
  };

  /* Adding a member only links an existing user to the project — the lead /
     pentester role is global and is set on the workspace Members page, never here. */
  const saveMemberEditor = async () => {
    const pid = state.openProjectId;
    if (pid == null) return;
    // The field is free text with suggestions, so a half-typed name lands here —
    // say so instead of closing the dialog as if it had worked.
    const typed = fstr(state.editorForm.userKey).trim();
    const u = state.workspaceUsers.find((x) => x.key.toLowerCase() === typed.toLowerCase());
    if (!u) {
      pushToast(typed ? `User “${typed}” not found` : "Select a user", "error");
      return;
    }
    try {
      await apiAddProjectMember(pid, u.id);
      setState({ editorOpen: false });
      reloadMembers();
    } catch (e) {
      pushToast(getApiErrorMessage(e, "Couldn't add member"), "error");
    }
  };

  /* There is no per-IP endpoint: a host's addresses are replaced wholesale via
     updateHost. The current list is re-fetched first so labels and is_primary of
     the existing addresses survive the round-trip. */
  const saveIpEditor = async () => {
    const pid = state.openProjectId;
    const f = state.editorForm;
    if (pid == null) return;
    const host = hosts.find((h) => h.host === fstr(f.hostName));
    const ip = fstr(f.ip).trim();
    if (!host || !ip) {
      pushToast(host ? "Specify an IP address" : "Select a host", "error");
      return;
    }
    try {
      const current = await apiGetHost(pid, host.id);
      if (current.ip_addresses.some((a) => a.ip_address === ip)) {
        pushToast("This host already has that IP", "error");
        return;
      }
      /* There is no per-IP status: the IPs view renders the parent host's, so the
         field writes through to the host. "unknown" is the untouched default —
         treat it as "leave as is" so adding an address can't downgrade a host
         already known to be up or down. */
      const picked = fstr(f.status) as Host["status"];
      await apiUpdateHost(pid, host.id, {
        ...(picked && picked !== "unknown" ? { status: picked } : {}),
        ip_addresses: [
          ...current.ip_addresses.map((a) => ({ ip_address: a.ip_address, label: a.label, is_primary: a.is_primary })),
          { ip_address: ip, label: null, is_primary: current.ip_addresses.length === 0 },
        ],
      });
      setState({ editorOpen: false });
      reloadHosts();
    } catch (e) {
      pushToast(getApiErrorMessage(e, "Couldn't add IP address"), "error");
    }
  };

  const saveEndpointEditor = async () => {
    const pid = state.openProjectId;
    const f = state.editorForm;
    if (pid == null) return;
    const host = hosts.find((h) => h.host === fstr(f.hostName));
    const path = fstr(f.path).trim();
    if (!host || !path) {
      pushToast(host ? "Specify the endpoint path" : "Select a host", "error");
      return;
    }
    try {
      await apiCreateEndpoint(pid, host.id, { path, method: (fstr(f.method) as Method) || "GET" });
      setState({ editorOpen: false });
      reloadHosts();
    } catch (e) {
      pushToast(getApiErrorMessage(e, "Couldn't add endpoint"), "error");
    }
  };

  /* Cred vault. On add the password is required; on edit a blank password means
     "keep the stored one" (see openEditor / updateProjectCredential), so the
     existing password is never round-tripped through the form. */
  const saveCredEditor = async () => {
    const { editorMode: mode, editorIndex: index, editorForm: f } = state;
    const pid = state.openProjectId;
    if (pid == null) return;
    const username = fstr(f.username).trim();
    const password = fstr(f.password);
    // Host binds to a project host, like the member picker: if entered, it must
    // match an existing host (case-insensitive) and is stored by its canonical
    // name; empty means no host binding.
    const typedHost = fstr(f.host).trim();
    let host: string | null = null;
    if (typedHost) {
      const h = resolveProjectHost(typedHost);
      if (!h) {
        pushToast(`Host “${typedHost}” not found`, "error");
        return;
      }
      host = h.host;
    }
    try {
      if (mode === "add") {
        if (!password.trim()) {
          pushToast("Enter the password", "error");
          return;
        }
        await apiCreateProjectCredential(pid, { username: username || null, password, host });
      } else {
        const target0 = d.creds[index];
        if (!target0) return;
        await apiUpdateProjectCredential(pid, target0.id, {
          username: username || null,
          host,
          // Blank = keep the stored password; only send it when the user retyped one.
          ...(password.trim() ? { password } : {}),
        });
      }
      setState({ editorOpen: false });
      reloadCreds();
    } catch (e) {
      pushToast(getApiErrorMessage(e, mode === "add" ? "Couldn't add credential" : "Couldn't save credential"), "error");
    }
  };

  const saveEditor = async () => {
    if (state.editorType === "host") return saveHostEditor();
    if (state.editorType === "ip") return saveIpEditor();
    if (state.editorType === "endpoint") return saveEndpointEditor();
    if (state.editorType === "vuln") return saveVulnEditor();
    if (state.editorType === "note") return saveNoteEditorEntity();
    if (state.editorType === "member") return saveMemberEditor();
    if (state.editorType === "cred") return saveCredEditor();
  };

  // ================= delete confirm =================
  const askDelete = (type: EditorType, index: number, label: string) =>
    setState({ confirmOpen: true, confirmType: type, confirmIndex: index, confirmLabel: label, confirmProjectId: null, confirmUserId: null });
  const closeConfirm = () => setState({ confirmOpen: false, confirmProjectId: null, confirmUserId: null });
  const confirmDelete = async () => {
    if (state.confirmProjectId) {
      const id = state.confirmProjectId;
      setState({ confirmOpen: false, confirmProjectId: null });
      try {
        await apiDeleteProject(id);
        reloadProjects();
      } catch (e) {
        pushToast(getApiErrorMessage(e, "Couldn't delete project"), "error");
      }
      return;
    }
    // Удаление пользователя идёт со страницы /members — там нет openProjectId,
    // поэтому обрабатываем до общей ветки, как и удаление проекта.
    if (state.confirmUserId) {
      const id = state.confirmUserId;
      setState({ confirmOpen: false, confirmUserId: null });
      try {
        await apiDeleteUser(id);
        reloadUsers();
      } catch (e) {
        pushToast(getApiErrorMessage(e, "Couldn't block user"), "error");
      }
      return;
    }
    const { confirmType: t, confirmIndex: i } = state;
    const pid = state.openProjectId;
    setState({ confirmOpen: false });
    if (!t || pid == null) return;
    // Every collection is backend-backed: delete through the API, then reload.
    const targets: Record<EditorType, { id: number | undefined; call: (id: number) => Promise<void>; reload: () => void; err: string }> = {
      host: { id: hosts[i]?.id, call: (id) => apiDeleteHost(pid, id), reload: reloadHosts, err: "Couldn't delete host" },
      // Rows in the IPs view address one address of a host, not the host itself.
      // «Удаление» IP скрывает адрес из списка, но не рвёт его привязку к домен-
      // хостам (та остаётся в карточке хоста). Бэк сносит только отдельную IP-запись.
      ip: { id: ipsRows[i] ? i : undefined, call: () => apiHideIp(pid, ipsRows[i].ip), reload: reloadHosts, err: "Couldn't delete IP address" },
      endpoint: { id: endpointRows[i]?.endpointId, call: (id) => apiDeleteEndpoint(pid, endpointRows[i].hostId, id), reload: reloadHosts, err: "Couldn't delete endpoint" },
      vuln: { id: d.vulns[i]?.id, call: (id) => apiDeleteVulnerability(pid, id), reload: reloadVulns, err: "Couldn't delete vulnerability" },
      note: { id: d.notes[i]?.id, call: (id) => apiDeleteProjectNote(pid, id), reload: reloadNotes, err: "Couldn't delete note" },
      cred: { id: d.creds[i]?.id, call: (id) => apiDeleteProjectCredential(pid, id), reload: reloadCreds, err: "Couldn't delete credential" },
      member: {
        id: d.members[i]?.id,
        call: (id) => apiRemoveProjectMember(pid, id),
        /* Removing yourself removes the project from your list (rule 1.1: a
           non-admin only sees projects they belong to), so leave the detail —
           staying would mean 403s on the next request and a project the list
           still shows. Admins keep access regardless of membership. */
        reload: () => {
          const leftMyself = d.members[i]?.id === authUser?.id && !isAdmin;
          if (!leftMyself) {
            reloadMembers();
            return;
          }
          selProjects();
          reloadProjects();
          pushToast("You left the project — it's no longer in your list", "success");
        },
        err: "Couldn't remove member",
      },
    };
    const target = targets[t];
    if (target.id == null) return;
    try {
      await target.call(target.id);
      target.reload();
    } catch (e) {
      pushToast(getApiErrorMessage(e, target.err), "error");
    }
  };

  // ================= notes =================
  const openNoteEditor = (mode: "add" | "edit", index: number) => {
    const n = mode === "edit" ? d.notes[index] : null;
    setState({
      noteEditorOpen: true,
      noteEditorMode: mode,
      noteEditorIndex: index,
      noteForm: { title: n ? n.title : "", excerpt: n ? n.excerpt : "", author: n ? n.author : me },
    });
  };
  const closeNoteEditor = () => setState({ noteEditorOpen: false });
  /* Opening a note always shows it rendered — including your own. Editing is a
     deliberate act (the pencil / the viewer's Edit button), not what a click on
     the note means. `id` is the backend id: it goes into the URL. */
  const openNoteViewer = (id: number) => setState({ section: "notes", openNoteId: id, noteEditorOpen: false });
  const closeNoteViewer = () => setState({ openNoteId: null, noteEditorOpen: false });
  const updateNoteForm = (k: keyof NoteForm, v: string) => setState((s) => ({ noteForm: { ...s.noteForm, [k]: v } }));
  const saveNote = async () => {
    const { noteEditorMode: mode, noteEditorIndex: index, noteForm: f } = state;
    const pid = state.openProjectId;
    if (pid == null) return;
    const payload = { title: (f.title || "Untitled").trim(), content: (f.excerpt || "").trim() };
    try {
      if (mode === "add") await apiCreateProjectNote(pid, payload);
      else {
        const target = d.notes[index];
        if (!target) return;
        await apiUpdateProjectNote(pid, target.id, payload);
      }
      setState({ noteEditorOpen: false });
      reloadNotes();
    } catch (e) {
      pushToast(getApiErrorMessage(e, mode === "add" ? "Couldn't create note" : "Couldn't save note"), "error");
    }
  };

  // ================= vulnerability detail =================
  /** The overview's "open findings" tile — everything still needing work. */
  const goToOpenVulns = () => setState({ section: "vulns", vulnFilterStatuses: [...VSTATUS_OPEN], vulnFilterAuthor: "", vulnFilterSeverities: [], vulnFilterHost: "" });
  const goToMyFindings = () => setState({ section: "vulns", vulnFilterAuthor: me, vulnFilterStatuses: [], vulnFilterSeverities: [], vulnFilterHost: "" });
  const vulnFormFrom = (v: Vuln): VulnDetailForm => {
    const stepsList = Array.isArray(v.steps) ? v.steps.slice() : [];
    return {
      title: v.title,
      host: v.host,
      sev: v.sev,
      status: v.status,
      stepsList: stepsList.length ? stepsList : [""],
      stepImages: v.stepImages ?? {},
      description: v.description || "",
      impact: v.impact || "",
      remediation: v.remediation || "",
      cwe: v.cwe || "",
      vector: v.vector || "",
    };
  };
  /** `id` is the real backend id — it goes into the URL, so findings can be deep-linked. */
  const openVulnDetail = (id: number) => {
    const v = d.vulns.find((x) => x.id === id);
    setState({ section: "vulns", openVulnId: id, vulnDetailForm: v ? vulnFormFrom(v) : {} });
  };
  const closeVulnDetail = () => setState({ openVulnId: null });
  const updateVulnDetailForm = <K extends keyof VulnDetailForm>(k: K, v: VulnDetailForm[K]) =>
    setState((s) => ({ vulnDetailForm: { ...s.vulnDetailForm, [k]: v } }));
  const addVdStep = () => setState((s) => ({ vulnDetailForm: { ...s.vulnDetailForm, stepsList: [...(s.vulnDetailForm.stepsList ?? []), ""] } }));
  const removeVdStep = (i: number) =>
    setState((s) => {
      const imgs = { ...(s.vulnDetailForm.stepImages ?? {}) };
      delete imgs[i];
      const shifted: Record<number, string[]> = {};
      Object.keys(imgs).forEach((k) => {
        const n = +k;
        shifted[n > i ? n - 1 : n] = imgs[n];
      });
      return { vulnDetailForm: { ...s.vulnDetailForm, stepsList: (s.vulnDetailForm.stepsList ?? []).filter((_, idx) => idx !== i), stepImages: shifted } };
    });
  const updateVdStep = (i: number, val: string) =>
    setState((s) => {
      const list = [...(s.vulnDetailForm.stepsList ?? [])];
      list[i] = val;
      return { vulnDetailForm: { ...s.vulnDetailForm, stepsList: list } };
    });
  const pasteVdStepImage = (i: number, e: ReactClipboardEvent<HTMLInputElement>) => {
    const items = e.clipboardData?.items ?? [];
    for (const it of Array.from(items)) {
      if (it.type && it.type.indexOf("image") === 0) {
        e.preventDefault();
        const file = it.getAsFile();
        if (!file) continue;
        const reader = new FileReader();
        reader.onload = (ev) =>
          setState((s) => {
            const imgs = { ...(s.vulnDetailForm.stepImages ?? {}) };
            imgs[i] = [...(imgs[i] ?? []), String(ev.target?.result ?? "")];
            return { vulnDetailForm: { ...s.vulnDetailForm, stepImages: imgs } };
          });
        reader.readAsDataURL(file);
      }
    }
  };
  const removeVdStepImage = (i: number, imgIdx: number) =>
    setState((s) => {
      const imgs = { ...(s.vulnDetailForm.stepImages ?? {}) };
      imgs[i] = (imgs[i] ?? []).filter((_, idx) => idx !== imgIdx);
      return { vulnDetailForm: { ...s.vulnDetailForm, stepImages: imgs } };
    });
  const saveVulnDetail = async () => {
    const { openVulnId: id, vulnDetailForm: f } = state;
    const pid = state.openProjectId;
    if (id == null || pid == null) return;
    const current = d.vulns.find((v) => v.id === id);
    if (!current) return;
    // A valid vector wins over the severity picker — that is what the score means.
    const c = computeCvss4(f.vector);
    const vector = (f.vector ?? "").trim();
    try {
      await apiUpdateVulnerability(pid, id, {
        title: (f.title ?? current.title).trim(),
        severity: (c ? c.sev : f.sev) || current.sev,
        status: f.status || current.status,
        description: f.description ?? "",
        impact: f.impact ?? "",
        recommendations: f.remediation ?? "",
        cwe_id: (f.cwe ?? "").trim() || null,
        cvss_vector: vector || null,
        cvss_version: vector ? "4.0" : null,
        cvss_score: c ? c.score : null,
        // Step images are still client-only (they are pasted data URLs, not uploads),
        // so only the step text round-trips through the backend.
        workflow_steps: (f.stepsList ?? [])
          .filter((s) => s.trim())
          .map((s, i) => ({ id: `step-${i + 1}`, description: s })),
      });
      setState({ openVulnId: null });
      reloadVulns();
    } catch (e) {
      pushToast(getApiErrorMessage(e, "Couldn't save vulnerability"), "error");
    }
  };

  // ================= profile / API keys / 2FA / workspace users =================
  /* "API keys" are the backend's agent tokens. The raw token is returned once, on
     creation, and only its prefix is stored — so the list shows `prefix…`, never a
     full key. */
  const reloadApiKeys = () => {
    void (async () => {
      try {
        const rows = await apiListAgentTokens();
        setStateRaw((s) => ({
          ...s,
          apiKeys: rows
            .filter((t) => !t.revoked_at)
            .map((t) => ({
              id: t.id,
              name: t.name,
              key: `${t.token_prefix}…`,
              scopes: t.scopes,
              created: toDispDate(t.created_at.slice(0, 10)),
              expires: t.expires_at ? toDispDate(t.expires_at.slice(0, 10)) : null,
              allProjects: t.all_projects,
              projectCount: t.project_ids.length,
            })),
        }));
      } catch {
        // Best-effort: список грузится под текущего пользователя; на ошибке — пусто.
        setStateRaw((s) => ({ ...s, apiKeys: [] }));
      }
    })();
  };
  useEffect(() => {
    if (state.view === "profile" && state.profileTab === "api") reloadApiKeys();

  }, [state.view, state.profileTab]);
  // Проекты нужны для выбора доступа ключа — подтягиваем свежий список при открытии.
  const openApiKeyModal = () => {
    reloadProjects();
    setState({ apiKeyModalOpen: true, apiKeyName: "", apiKeyScopes: {}, apiKeyAllProjects: true, apiKeyProjectIds: [], apiKeyExpiry: "" });
  };
  const closeApiKeyModal = () => setState({ apiKeyModalOpen: false });
  const toggleApiScope = (s: string) => setState((st) => ({ apiKeyScopes: { ...st.apiKeyScopes, [s]: !st.apiKeyScopes[s] } }));
  const toggleApiProject = (id: number) =>
    setState((st) => ({
      apiKeyProjectIds: st.apiKeyProjectIds.includes(id)
        ? st.apiKeyProjectIds.filter((p) => p !== id)
        : [...st.apiKeyProjectIds, id],
    }));
  const createApiKey = async () => {
    const name = state.apiKeyName.trim();
    if (!name) return;
    const scopes = API_SCOPES.filter((s) => state.apiKeyScopes[s]);
    if (!scopes.length) {
      pushToast("Select at least one scope", "error");
      return;
    }
    // Явный список проектов не может быть пустым — иначе токен ни к чему не даёт доступ.
    if (!state.apiKeyAllProjects && state.apiKeyProjectIds.length === 0) {
      pushToast("Select projects or enable “All my projects”", "error");
      return;
    }
    // Пусто = бессрочный; иначе конец выбранного дня.
    const expires_at = state.apiKeyExpiry ? new Date(`${state.apiKeyExpiry}T23:59:59`).toISOString() : null;
    try {
      const created = await apiCreateAgentToken({
        name,
        scopes,
        project_ids: state.apiKeyAllProjects ? [] : state.apiKeyProjectIds,
        all_projects: state.apiKeyAllProjects,
        expires_at,
      });
      setState({ apiKeyModalOpen: false });
      // The token is shown once and never again — the backend keeps only its hash.
      pushToast(`Token created — copy it now: ${created.token}`, "success");
      reloadApiKeys();
    } catch (e) {
      pushToast(getApiErrorMessage(e, "Couldn't create token"), "error");
    }
  };
  const revokeApiKey = async (id: number) => {
    try {
      await apiRevokeAgentToken(id);
      reloadApiKeys();
    } catch (e) {
      pushToast(getApiErrorMessage(e, "Couldn't revoke token"), "error");
    }
  };

  const openWSUserEditor = (mode: "add" | "edit", index: number) => {
    const u = mode === "edit" ? state.workspaceUsers[index] : null;
    setState({
      wsUserModalOpen: true,
      wsUserMode: mode,
      wsUserIndex: index,
      wsUserName: u ? u.name : "",
      wsUserEmail: u ? u.email : "",
      wsUserRole: u ? u.role : "user",
      wsUserProjectRole: u ? u.projectRole : "pentester",
    });
  };
  const closeWSUserEditor = () => setState({ wsUserModalOpen: false });
  // The workspace role maps onto the backend account role; the project role is a
  // global user attribute and is sent alongside it.
  const saveWSUser = async () => {
    const name = state.wsUserName.trim();
    const email = state.wsUserEmail.trim();
    const role = state.wsUserRole === "admin" ? "admin" : "pentester";
    const projectRole = state.wsUserProjectRole;
    const adding = state.wsUserMode === "add";
    // В режиме приглашения username не задаём — его выберет сам приглашённый.
    if (adding ? !email : (!name || !email)) return;
    try {
      if (adding) {
        const res = await apiCreateInvitation({ email, role, project_role: projectRole });
        const preview = res.mail_preview_url ? ` (email preview: ${res.mail_preview_url})` : "";
        pushToast(`Invitation sent to ${res.email_sent_to}${preview}`, "success");
      } else {
        const u = state.workspaceUsers[state.wsUserIndex];
        if (!u) return;
        // Юзернейм неизменяем (см. read-only поле в редакторе) — шлём только роли.
        await apiUpdateUser(u.id, { role, project_role: projectRole });
      }
      setState({ wsUserModalOpen: false });
      reloadUsers();
    } catch (e) {
      pushToast(getApiErrorMessage(e, adding ? "Couldn't send invitation" : "Couldn't save user"), "error");
    }
  };
  /* «Удаление» пользователя на деле деактивирует его (мягкое удаление на бэке:
     строка остаётся, выставляется is_locked) — сначала подтверждаем в общем
     диалоге, сам вызов apiDeleteUser — в confirmDelete по confirmUserId. */
  const askDeleteWSUser = (index: number) => {
    const u = state.workspaceUsers[index];
    if (!u) return;
    setState({ confirmOpen: true, confirmType: null, confirmIndex: -1, confirmLabel: u.name, confirmProjectId: null, confirmUserId: u.id });
  };
  /* Возврат деактивированного пользователя: не разблокируем напрямую, а шлём ему
     письмо-возврат. Доступ вернётся, когда он сам перейдёт по ссылке (там же сразу
     выдаётся сессия). Строка остаётся в архиве до перехода по ссылке. */
  const reactivateUser = async (index: number) => {
    const u = state.workspaceUsers[index];
    if (!u) return;
    try {
      const res = await apiReactivateUser(u.id);
      const preview = res.mail_preview_url ? ` (email preview: ${res.mail_preview_url})` : "";
      pushToast(`${t("Reactivation link sent to")} ${res.email_sent_to}${preview}`, "success");
      reloadUsers();
    } catch (e) {
      pushToast(getApiErrorMessage(e, "Couldn't send the reactivation link"), "error");
    }
  };
  const resendInvite = async (id: number) => {
    try {
      const res = await apiResendInvitation(id);
      const preview = res.mail_preview_url ? ` (email preview: ${res.mail_preview_url})` : "";
      pushToast(`Invitation re-sent to ${res.email_sent_to}${preview}`, "success");
      reloadUsers();
    } catch (e) {
      pushToast(getApiErrorMessage(e, "Couldn't resend invitation"), "error");
    }
  };
  const revokeInvite = async (id: number) => {
    try {
      await apiRevokeInvitation(id);
      reloadUsers();
    } catch (e) {
      pushToast(getApiErrorMessage(e, "Couldn't revoke invitation"), "error");
    }
  };

  const startTwoFA = async () => {
    setState({ twoFABusy: true });
    try {
      const setup = await apiSetupTwoFactor();
      setState({ twoFASetupOpen: true, twoFACode: "", twoFAQr: setup.qr_png_data_url, twoFASecret: setup.secret, twoFABusy: false });
    } catch (e) {
      setState({ twoFABusy: false });
      pushToast(getApiErrorMessage(e, "Couldn't start 2FA setup"), "error");
    }
  };
  const cancelTwoFA = () => setState({ twoFASetupOpen: false, twoFACode: "", twoFAQr: null, twoFASecret: null });
  const confirmTwoFA = async () => {
    if (state.twoFACode.trim().length < 6 || state.twoFABusy) return;
    setState({ twoFABusy: true });
    try {
      await apiConfirmTwoFactor(state.twoFACode.trim());
      await refreshUser();
      setState({ twoFASetupOpen: false, twoFACode: "", twoFAQr: null, twoFASecret: null, twoFABusy: false });
      pushToast("Two-factor authentication enabled", "success");
    } catch (e) {
      setState({ twoFABusy: false });
      pushToast(getApiErrorMessage(e, "Invalid code — try again"), "error");
    }
  };
  /* Смена собственного пароля. Бэкенд отзывает ВСЕ refresh-токены пользователя,
     включая текущий: иначе украденная сессия пережила бы смену пароля, ради
     которой её и меняют. Поэтому после успеха сразу разлогиниваем — иначе
     access-токен дожил бы до истечения и оборвался бы посреди работы
     непонятным 401. */
  const PW_MIN = 8;
  const changeOwnPassword = async () => {
    if (state.pwBusy) return;
    if (state.pwNew.length < PW_MIN) {
      setState({ pwError: t("New password must be at least 8 characters.") });
      return;
    }
    if (state.pwNew !== state.pwConfirm) {
      setState({ pwError: t("The new passwords do not match.") });
      return;
    }
    if (state.pwNew === state.pwCurrent) {
      setState({ pwError: t("The new password must differ from the current one.") });
      return;
    }
    setState({ pwBusy: true, pwError: null });
    try {
      await apiChangeMyPassword({ current_password: state.pwCurrent, new_password: state.pwNew });
      setState({ pwBusy: false, pwCurrent: "", pwNew: "", pwConfirm: "", pwError: null });
      pushToast(t("Password changed — sign in again with the new one."), "success");
      await signOut();
    } catch (e) {
      setState({ pwBusy: false, pwError: getApiErrorMessage(e, "Couldn't change the password") });
    }
  };
  const openDisableTwoFA = () => setState({ twoFADisableOpen: true, twoFADisablePassword: "" });
  const cancelDisableTwoFA = () => setState({ twoFADisableOpen: false, twoFADisablePassword: "" });
  const disableTwoFA = async () => {
    if (!state.twoFADisablePassword || state.twoFABusy) return;
    setState({ twoFABusy: true });
    try {
      await apiDisableTwoFactor(state.twoFADisablePassword);
      await refreshUser();
      setState({ twoFADisableOpen: false, twoFADisablePassword: "", twoFABusy: false });
      pushToast("Two-factor authentication disabled", "success");
    } catch (e) {
      setState({ twoFABusy: false });
      pushToast(getApiErrorMessage(e, "Couldn't disable 2FA"), "error");
    }
  };

  // ================= notifications =================
  /* Each notification carries the ids of what it is about (context.project_id /
     vulnerability_id), so clicking it navigates straight to the finding. The
     previous version matched a seed project *by name* against the real projects,
     which never matched — openProjectId stayed null and the click fell back to
     the projects list. */
  const goToNotif = (n: ApiNotification) => {
    const pid = n.context?.project_id ?? null;
    const vid = n.context?.vulnerability_id ?? null;
    const nid = n.context?.note_id ?? null;
    void apiMarkNotificationRead(n.id).catch(() => {
      /* best-effort: the read flag is not worth blocking navigation on */
    });
    // Land on whatever the notification is actually about: the finding, the note,
    // or — for "added to project" / project status — the project itself.
    const section: SectionId = vid != null ? "vulns" : nid != null ? "notes" : "overview";
    setStateRaw((s) => ({
      ...s,
      notifs: s.notifs.map((x) => (x.id === n.id ? { ...x, is_read: true } : x)),
      notifOpen: false,
      ...(pid == null
        ? {}
        : {
            view: "detail" as const,
            nav: "projects" as const,
            openProjectId: pid,
            section,
            expanded: [],
            openVulnId: vid,
            openNoteId: nid,
            vulnDetailForm: {},
            accessDenied: false,
          }),
    }));
    if (pid == null) pushToast("Notification isn't linked to a project", "error");
  };

  const markAllNotifsRead = () => {
    void apiMarkAllNotificationsRead().catch((e) => pushToast(getApiErrorMessage(e, "Couldn't mark notifications"), "error"));
    setStateRaw((s) => ({ ...s, notifs: s.notifs.map((x) => ({ ...x, is_read: true })) }));
  };

  // ---------------------------------------------------------------- derived
  const isActive = state.tab === "active";
  const q = state.query.trim().toLowerCase();
  // Rule 1.1 is enforced server-side: getProjects returns only visible projects.
  const allProjects = state.apiProjects ?? [];
  const isArchivedStatus = (s: ProjectStatus) => s === "archived" || s === "completed";
  const projRows = allProjects
    .filter((p) => (state.tab === "active" ? !isArchivedStatus(p.status) : isArchivedStatus(p.status)))
    .filter((p) => !q || p.name.toLowerCase().includes(q));
  // Newest first by default ("Last updated") — a just-added project lands at the
  // top, not buried at the end; "First updated" flips to oldest-first. id is a
  // monotonic proxy for creation order (safe: projRows is a fresh filtered array).
  projRows.sort((a, b) => (state.projSort === "first" ? a.id - b.id : b.id - a.id));

  const activeCount = allProjects.filter((p) => !isArchivedStatus(p.status)).length;
  const archivedCount = allProjects.filter((p) => isArchivedStatus(p.status)).length;
  // Tab-scoped (no search filter): stat tiles must not react to `query`.
  const tabProjects = allProjects.filter((p) => (isActive ? !isArchivedStatus(p.status) : isArchivedStatus(p.status)));

  // ---- stat-card sparklines: real cumulative growth over the projects' window ----
  const activeRows = allProjects.filter((p) => !isArchivedStatus(p.status));
  const archivedRows = allProjects.filter((p) => isArchivedStatus(p.status));
  const parseAll = (arr: (string | undefined)[]) => arr.map((s) => Date.parse(s ?? "")).filter((n) => Number.isFinite(n));
  /** Combined [start, end] window across a set of projects — the sparkline's X axis. */
  const projWindow = (rows: ApiProjectRow[]): [number, number] => {
    const starts = parseAll(rows.map((r) => r.startISO || r.createdISO));
    const ends = parseAll(rows.map((r) => r.endISO));
    return [starts.length ? Math.min(...starts) : NaN, ends.length ? Math.max(...ends) : NaN];
  };
  const projCreatedTimes = (rows: ApiProjectRow[]) => rows.map((r) => r.createdISO || r.startISO);
  const aggHostTimes = (rows: ApiProjectRow[]) => rows.flatMap((r) => state.aggTimes?.[r.id]?.hosts ?? []);
  const aggOpenVulnTimes = (rows: ApiProjectRow[]) => rows.flatMap((r) => state.aggTimes?.[r.id]?.openVulns ?? []);

  // Невыбранным пунктам НЕ задаём inline-фон (undefined), иначе он перебивает
  // CSS `.nav:hover` и подсветка при наведении не появляется.
  const navBg = (id: NavId) => (state.nav === id ? "var(--fr-accent-soft)" : undefined);
  const navColor = (id: NavId) => (state.nav === id ? "var(--fr-accent)" : "var(--fr-text-2)");

  const isList = state.view === "list" && state.nav === "projects";
  const isDocs = state.view === "list" && state.nav === "docs";
  const isStub = state.view === "list" && state.nav !== "projects" && state.nav !== "members" && state.nav !== "docs";
  const stubTitle = ({ tasks: "Tasks", mine: "My Tasks" } as Record<string, string>)[state.nav] || "";
  const stubDesc =
    ({ tasks: "Track and assign engagement tasks across the team.", mine: "Your personally assigned tasks and reviews." } as Record<string, string>)[
      state.nav
    ] || "";

  /* Notification rows, built from the backend payload. There are exactly four
     reasons to be notified (NotificationKind), and each reads differently — the
     row is a sentence: "<who> <action> <subject>". */
  const NOTIF_AVATAR_COLORS = ["var(--fr-accent)", "var(--fr-purple)", "var(--fr-orange)", "var(--fr-danger)", "var(--fr-success)"];
  const notifs = state.notifs.map((n) => {
    const ctx = n.context;
    const who = ctx?.commenter_username || "System";
    const project = ctx?.project_name || state.apiProjects?.find((p) => p.id === ctx?.project_id)?.name || "";
    const statusLabel = ctx?.status ? VSTATUS_LABEL[ctx.status as VStatus] ?? PROJ_STATUS[ctx.status]?.label ?? ctx.status : "";
    const row = { action: "", subject: "" };
    switch (n.type) {
      case "project_member_added":
        row.action = "added you to";
        row.subject = project;
        break;
      case "vuln_status_changed":
        row.action = `set your finding to ${statusLabel} —`;
        row.subject = ctx?.vulnerability_title || "";
        break;
      case "project_status_changed":
        row.action = `changed the project status to ${statusLabel} —`;
        row.subject = project;
        break;
      default:
        row.action = "mentioned you in";
        row.subject = ctx?.vulnerability_title || ctx?.note_title || "";
    }
    return {
      key: n.id,
      initials: initialsOf(who),
      avBg: NOTIF_AVATAR_COLORS[n.id % NOTIF_AVATAR_COLORS.length],
      user: `@${who}`,
      action: row.action,
      where: row.subject,
      // The project is already the subject of project-level events; don't repeat it.
      meta: [n.type === "mention" || n.type === "vuln_status_changed" ? project : "", relTime(n.created_at)].filter(Boolean).join(" · "),
      unread: !n.is_read,
      onClick: () => goToNotif(n),
    };
  });
  const newCount = notifs.filter((n) => n.unread).length;
  const hasUnread = newCount > 0;

  const sideW = state.sidebarCollapsed ? "76px" : "236px";

  // ---- section tab styling ----
  const sec = state.section;
  const secStyle = (k: SectionId) => ({
    // The tab's own underline/colour is CSS-driven off `active` (see .sectab);
    // `color` stays for the badges, which are still styled inline.
    active: sec === k,
    color: sec === k ? "var(--fr-accent)" : "var(--fr-text-2)",
    badgeColor: sec === k ? "var(--fr-accent)" : "var(--fr-text-3)",
    badgeBg: sec === k ? "var(--fr-accent-soft)" : "var(--fr-bg)",
  });

  // ---- hosts / recon derived ----
  const rv = state.reconView;
  const portPillsOf = (ports: Host["ports"]) => ports.map((p) => ({ label: `${p.n}/${p.proto}`, http: p.http, ...(PORT[p.state] ?? PORT.closed) }));
  /** Colour for an HTTP status code next to a port: 2xx green, 3xx amber, else red. */
  const httpStatusColor = (code: number): string =>
    code < 300 ? "var(--fr-success)" : code < 400 ? "var(--fr-warn)" : "var(--fr-danger)";

  // Hosts are searched by name here; addresses have their own search in the IPs view.
  /** A host that is a subdomain of another host in the project (shown nested, not top-level). */
  const isNestedSubdomain = (h: Host) =>
    hosts.some((p) => p.origin !== "ip" && p.id !== h.id && h.host.toLowerCase().endsWith(`.${p.host.toLowerCase()}`));
  /* Rows the hosts table shows. The IP farm has to create a parent Host per address
     (ports hang off host_ip_addresses, which hangs off hosts), but the user added an
     address, not a host — a nameless row here would just be noise. They stay visible
     in the IPs view, which is what they are. */
  const isIpFarmRow = (h: Host) => h.origin === "ip";
  /* Status filter pills, classified by the ports' HTTP codes (not the raw backend
     status): up = any 2xx/3xx/4xx; down = any 5xx or an offline entity; a numeric
     pill = that exact code on some port. Shared by the hosts and IPs views. */
  const matchesStatusFilters = (ports: Host["ports"], status: Host["status"], filters: string[]): boolean => {
    if (filters.length === 0) return true;
    const codes = ports.map((p) => p.http).filter((c): c is number => c != null);
    return filters.some((k) => {
      if (k === "up") return codes.some((c) => c >= 200 && c < 500);
      if (k === "down") return status === "down" || codes.some((c) => c >= 500);
      return codes.includes(Number(k));
    });
  };
  /** Признак Cloudflare — отдельный вопрос («что за прокси»), а не разновидность
   *  статуса, поэтому свой переключатель, а не ещё одна пилюля в общем ряду. */
  const matchesCfFilter = (cloudflare: CfState, filter: "" | "yes" | "no"): boolean =>
    filter === "" || cloudflare === (filter === "yes");  // unknown (null) — только под "all"
  /* Единственное место, где решается судьба строки в таблице хостов, — через него
     же идёт экспорт (exportLinesFor → hostsList/visibleSubdomainsOf), поэтому
     фильтры не могут разъехаться между тем, что видно, и тем, что выгружается. */
  const hostMatchesFilters = (h: Host): boolean =>
    matchesStatusFilters(h.ports, h.status, state.hostFilters) && matchesCfFilter(h.cloudflare, state.hostCfFilter);
  /** Status pills offered in the hosts and IPs views (empty selection = all). */
  const STATUS_FILTER_KEYS = ["up", "200", "301", "401", "403", "down"];
  /** Subdomains of a host, filtered by the active pills (empty = all). */
  const visibleSubdomainsOf = (h: Host): Host[] => subdomainsOf(h).filter(hostMatchesFilters);
  const hostsList = hosts
    .map((h, idx) => ({ h, idx }))
    .filter((x) => {
      const hq = state.hostQuery.trim().toLowerCase();
      // Only a *search* flattens the tree; filtering keeps subdomains nested under
      // their parent. A parent is shown if it OR a subdomain matches the filter.
      const flat = hq !== "";
      const nameOk = hq ? x.h.host.toLowerCase().includes(hq) : true;
      const nestOk = flat || !isNestedSubdomain(x.h);
      const filterOk = hostMatchesFilters(x.h) || (!flat && visibleSubdomainsOf(x.h).length > 0);
      return !isIpFarmRow(x.h) && nameOk && nestOk && filterOk;
    });

  /* Каждый хост, реально показанный в таблице: корневые строки плюс раскрытые
     под ними поддомены, без дублей. Таблица держит поддомены вложенными, поэтому
     hostsList сам по себе — это только корни (домен с 68 поддоменами даёт длину 1).
     Счётчик «Total hosts», экспорт и список доменов для JS-скана обязаны видеть
     одно и то же множество, иначе разъезжаются. Дедуп нужен, потому что поиск
     распрямляет дерево (поддомен уже идёт отдельной строкой), а subdomainsOf
     отдаёт всех потомков — на глубоких деревьях они повторяются. */
  const visibleHostRows = (): Host[] => {
    const seen = new Set<number>();
    const rows: Host[] = [];
    const add = (x: Host) => {
      if (seen.has(x.id)) return;
      seen.add(x.id);
      rows.push(x);
    };
    hostsList.forEach(({ h }) => {
      // Родитель попадает в список и тогда, когда пилюлям соответствует только его
      // поддомен, — сам он засчитывается лишь если проходит фильтры и сам.
      if (hostMatchesFilters(h)) add(h);
      visibleSubdomainsOf(h).forEach(add);
    });
    return rows;
  };

  const _hd = state.openHostId != null ? hosts.find((h) => h.id === state.openHostId) : undefined;

  const sevCounts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  d.vulns.forEach((v) => (sevCounts[v.sev] = (sevCounts[v.sev] || 0) + 1));
  const sevBars = (["critical", "high", "medium", "low", "info"] as Severity[]).map((k) => ({
    label: cap(k),
    color: SEV[k].color,
    tileBg: SEV[k].bg,
    count: sevCounts[k],
    onClick: () => setState({ section: "vulns", vulnFilterSeverities: [k], vulnFilterStatuses: [], vulnFilterAuthor: "", vulnFilterHost: "" }),
  }));

  const vulnStCounts = Object.fromEntries(VSTATUS_ORDER.map((k) => [k, 0])) as Record<VStatus, number>;
  d.vulns.forEach((v) => (vulnStCounts[v.status] = (vulnStCounts[v.status] || 0) + 1));
  const openVulnCount = VSTATUS_OPEN.reduce((n, k) => n + vulnStCounts[k], 0);
  const myFindingsCount = d.vulns.filter((v) => v.author === me).length;

  const vfA = state.vulnFilterAuthor.trim().toLowerCase();
  const vfS = state.vulnFilterStatuses;
  const vfSev = state.vulnFilterSeverities;
  const vfH = state.vulnFilterHost.trim().toLowerCase();
  // Within a group the selected values are OR-ed; the groups are AND-ed. An empty
  // group filters nothing, which is what makes "All" light up on its own.
  const vulns = d.vulns
    .map((v, idx) => ({ v, idx }))
    .filter(
      ({ v }) =>
        (!vfA || v.author.toLowerCase().includes(vfA)) &&
        (vfS.length === 0 || vfS.includes(v.status)) &&
        (vfSev.length === 0 || vfSev.includes(v.sev)) &&
        (!vfH || v.host.toLowerCase().includes(vfH))
    )
    // Newest first: a just-added finding lands at the top, not buried at the end.
    // idx is captured above, so edit/delete still address the right d.vulns entry.
    .sort((a, b) => b.v.id - a.v.id)
    .map(({ v, idx }, i) => ({
      id: v.id,
      num: i + 1,
      sev: v.sev,
      title: v.title,
      host: v.host,
      status: v.status,
      author: v.author,
      updated: v.updated,
      // The card is addressed by backend id (it lands in the URL); the editor and
      // delete still address the list position.
      onOpen: () => openVulnDetail(v.id),
      onEdit: (e: ReactMouseEvent) => {
        e.stopPropagation();
        openEditor("vuln", "edit", idx);
      },
      onDelete: (e: ReactMouseEvent) => {
        e.stopPropagation();
        askDelete("vuln", idx, v.title);
      },
    }));

  /** Pill styling for a multi-select filter; `on` also covers the "All" pill (empty selection). */
  const vfPill = (on: boolean): CSSProperties => (on ? PILL_ON : PILL_OFF);

  // A host can carry several IPs (external / internal / mgmt) — the IPs view lists
  // them all, one row per address. Row actions target the address, not the host.
  // One search box matches either side of the row: the address or its host.
  const ipQ = state.ipQuery.trim().toLowerCase();
  /* One row per address, whatever it hangs off. The same address legitimately
     belongs to several hosts (shared hosting, a CDN edge, or simply a hostname
     imported after its address was) — those collapse into one row whose Hostname
     cell lists every name, rather than repeating the address per host. */
  type IpRowNames = { hostname: string; source: string; confirmed: boolean }[];
  /* Ports/status are tracked in two buckets and never blended: the bare-IP probe
     (from an origin="ip" host — the IP farm hits the address directly) and the
     domain probe (from origin="host" hosts — the host farm hits the address with a
     Host header). A vhost legitimately answers differently to the two, so the IPs
     view shows the bare-IP measurement when there is one, and falls back to the
     domain probe only when the address was merely resolved from a domain and never
     scanned as an IP. The Hosts view keeps showing the domain probe, so the two no
     longer overwrite each other. */
  type IpBucket = { ports: Host["ports"]; status: Host["status"] };
  const mergeBucket = (into: IpBucket | null, h: Host): IpBucket => {
    if (into === null) return { ports: [...h.ports], status: h.status };
    const seen = new Set(into.ports.map((p) => `${p.n}/${p.proto}`));
    return {
      ports: [...into.ports, ...h.ports.filter((p) => !seen.has(`${p.n}/${p.proto}`))],
      status: into.status !== "up" && h.status === "up" ? h.status : into.status,
    };
  };
  const ipRowsByAddr = new Map<
    string,
    { ip: string; hostIdx: number; names: IpRowNames; cloudflare: CfState; ipMeas: IpBucket | null; domainMeas: IpBucket | null }
  >();
  hosts.forEach((h, idx) => {
    h.ipEntries.forEach((entry) => {
      if (!entry.ip || entry.ip === "—") return;
      // A host's own name counts as a name for its address even when the address
      // never went through reverse resolution (added by hand or by the host farm).
      const own: IpRowNames =
        h.origin === "host" && h.host && h.host !== "—" ? [{ hostname: h.host, source: "host", confirmed: true }] : [];
      const acc =
        ipRowsByAddr.get(entry.ip) ??
        (() => {
          const fresh = { ip: entry.ip, hostIdx: idx, names: [] as IpRowNames, cloudflare: null as CfState, ipMeas: null as IpBucket | null, domainMeas: null as IpBucket | null };
          ipRowsByAddr.set(entry.ip, fresh);
          return fresh;
        })();
      acc.names.push(...entry.hostnames, ...own);
      acc.cloudflare = mergeCf(acc.cloudflare, entry.cloudflare);
      // Prefer a real host as the row's edit/delete target over the IP farm's
      // nameless parent — that is the row a user means when they click edit.
      if (h.origin === "host" && hosts[acc.hostIdx]?.origin === "ip") acc.hostIdx = idx;
      if (h.origin === "ip") acc.ipMeas = mergeBucket(acc.ipMeas, h);
      else acc.domainMeas = mergeBucket(acc.domainMeas, h);
    });
  });
  const ipsRows = [...ipRowsByAddr.values()]
    // Скрытые («удалённые» из списка) адреса не показываем — привязка к хостам при
    // этом сохранена на бэке, адрес просто не значится во вкладке IP.
    .filter((row0) => !state.hiddenIps.includes(row0.ip))
    .map((row0) => {
      // Bare-IP measurement wins; domain probe is the fallback for addresses only
      // ever resolved from a domain.
      const meas = row0.ipMeas ?? row0.domainMeas ?? { ports: [], status: "unknown" as Host["status"] };
      const row = { ...row0, ports: meas.ports, status: meas.status };
      // Dedup names across every host that carries the address; a name confirmed
      // by any of them is confirmed. PTR entries win over a bare host name.
      const byName = new Map<string, { hostname: string; source: string; confirmed: boolean }>();
      for (const n of row.names) {
        const cur = byName.get(n.hostname);
        if (!cur) byName.set(n.hostname, { ...n });
        else {
          cur.confirmed = cur.confirmed || n.confirmed;
          if (cur.source !== "ptr" && n.source === "ptr") cur.source = n.source;
        }
      }
      const names = [...byName.values()].sort(
        (a, b) => Number(b.confirmed) - Number(a.confirmed) || a.hostname.localeCompare(b.hostname),
      );
      return { ...row, names };
    })
    .filter(
      (row) =>
        !ipQ ||
        row.ip.toLowerCase().includes(ipQ) ||
        row.names.some((n) => n.hostname.toLowerCase().includes(ipQ)),
    )
    // Same status filter as hosts. The Status *column* is gone from this table,
    // but filtering by HTTP code still answers a real question here.
    .filter((row) => matchesStatusFilters(row.ports, row.status, state.ipFilters))
    .filter((row) => matchesCfFilter(row.cloudflare, state.ipCfFilter))
    .map((row, i) => ({
      ...row,
      onEdit: (e: ReactMouseEvent) => {
        e.stopPropagation();
        openEditor("host", "edit", row.hostIdx);
      },
      onDelete: (e: ReactMouseEvent) => {
        e.stopPropagation();
        askDelete("ip", i, row.ip);
      },
    }));
  /** The IP row whose detail card is open (looked up by address, like _hd by id). */
  const _ipd = state.openIp != null ? ipsRows.find((r) => r.ip === state.openIp) : undefined;
  /** Flat endpoint list, so a confirm dialog can address one by position. */
  const endpointRows = hosts.flatMap((h) => h.endpoints.map((e) => ({ hostId: h.id, endpointId: e.id, host: h.host, label: `${e.m} ${e.p}` })));
  /* Endpoints view filters: method pills (empty = all), plus separate searches for
     the host and the endpoint path — they are different questions ("everything on
     this host" vs "where is /login"), so one combined box would answer neither. */
  const epHostQ = state.epHostQuery.trim().toLowerCase();
  const epPathQ = state.epPathQuery.trim().toLowerCase();
  const endpointGroups = hosts
    .filter((h) => !epHostQ || h.host.toLowerCase().includes(epHostQ))
    .map((h) => ({
      hostId: h.id,
      host: h.host,
      endpoints: h.endpoints.filter(
        (e) => (state.epMethods.length === 0 || state.epMethods.includes(e.m)) && (!epPathQ || e.p.toLowerCase().includes(epPathQ))
      ),
      expanded: state.epExpanded.includes(h.host),
    }))
    .filter((g) => g.endpoints.length > 0)
    .map((g) => ({ ...g, count: g.endpoints.length }));
  // Counts what the filters actually left on screen.
  const endpointTotal = endpointGroups.reduce((s, g) => s + g.count, 0);

  /* JS files pulled from the backend, filtered by the JS view's controls, then
     grouped by the domain they were found on — the table mirrors the endpoints
     layout (a card per host, files expand to show their secrets + paths). */
  const jsQ = state.jsQuery.trim().toLowerCase();
  const jsFiles: JsFileEntry[] = (state.apiJsFiles ?? []).map((f) => ({
    id: f.id,
    host: f.hostname || "—",
    hostId: f.host_id,
    url: f.url,
    status: f.status,
    size: f.size_bytes,
    secrets: f.secrets.map((s) => ({ kind: s.kind, match: s.match_preview, snippet: s.snippet, severity: s.severity })),
    endpoints: f.endpoints,
  }));
  const jsFilesFiltered = jsFiles.filter(
    (f) =>
      (!jsQ || f.url.toLowerCase().includes(jsQ) || f.host.toLowerCase().includes(jsQ)) &&
      (!state.jsSecretsOnly || f.secrets.length > 0),
  );
  /** Открытая карточка JS-файла. Ищем по всему списку, а не по отфильтрованному:
   *  карточка не должна захлопываться, если фильтр списка перестал её пропускать. */
  const _jsd = state.openJsFileId != null ? jsFiles.find((f) => f.id === state.openJsFileId) : undefined;
  const openJsFile = (id: number) => setState({ openJsFileId: id });
  const closeJsFile = () => setState({ openJsFileId: null });
  const jsGroups = [...new Set(jsFilesFiltered.map((f) => f.host))].map((host) => {
    const files = jsFilesFiltered.filter((f) => f.host === host);
    // Every file in a group shares one host, so its id names the archive scope.
    return { host, hostId: files[0]?.hostId, files, count: files.length };
  });

  /* Домены, доступные JS-скану: ВСЕ домены проекта, кроме IP-строк фермы и
     IP-литералов (ферма ходит по именам, а не по адресам). Поддомены попадают
     наравне с корнями — в списке хостов они лежат вложенными, но целями скана
     являются сами по себе.
     Фильтры раздела «Хосты» сюда намеренно не переносятся: пилюли статусов и
     поиск — это способ разглядывать таблицу, а не выбор целей скана. Раньше
     оставленный включённым фильтр молча урезал набор, и скан уходил по
     нескольким доменам вместо всех. Сузить список можно прямо в textarea на
     странице запуска — это и есть явный выбор. */
  const jsScanDomains = (): string[] => {
    const rows = hosts;
    const out: string[] = [];
    const uniq = new Set<string>();
    for (const h of rows) {
      const name = h.host.trim().toLowerCase();
      if (!name || h.origin === "ip" || isIpLiteral(name) || uniq.has(name)) continue;
      uniq.add(name);
      out.push(name);
    }
    return out;
  };
  const openJsScanSetup = () => setState({ jsScanSetupOpen: true, jsScanText: jsScanDomains().join("\n") });
  const closeJsScanSetup = () => setState({ jsScanSetupOpen: false });
  /** Row count of the active recon view — shown next to the section title. */
  const reconTotal = rv === "ips" ? ipsRows.length : rv === "endpoints" ? endpointTotal : rv === "js" ? jsFilesFiltered.length : visibleHostRows().length;
  /** Wording for that count, matching the active view. */
  const reconTotalLabel = rv === "ips" ? t("Total IPs") : rv === "endpoints" ? t("Total endpoints") : rv === "js" ? t("Total JS files") : t("Total hosts");

  /* Retuning a filter reseeds the editable pane from what the filter left on
     screen. Hand edits are dropped on purpose: the filters are the coarse
     selection and the pane the fine one, so the coarse one has to win. Only the
     filter inputs are deps — a background hosts refresh must not wipe edits. */
  useEffect(() => {
    if (!state.exportPageOpen) return;
    setStateRaw((s) => {
      const next = exportLinesFor(s.exportScope).join("\n");
      return s.exportText === next ? s : { ...s, exportText: next };
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.exportPageOpen, state.exportScope, state.hostQuery, state.hostFilters, state.hostCfFilter, state.ipQuery, state.ipCfFilter, state.epHostQuery, state.epPathQuery, state.epMethods, state.jsQuery, state.jsSecretsOnly]);

  /* Список целей скана наполняется один раз при открытии страницы и дальше живёт
     сам: фильтры раздела «Хосты» на него не влияют (см. jsScanDomains), а
     перечитывать его на фоновом обновлении хостов нельзя — это стёрло бы правки
     руками. Поэтому единственная зависимость — сам факт открытия страницы. */
  useEffect(() => {
    if (!state.jsScanSetupOpen) return;
    setStateRaw((s) => {
      const next = jsScanDomains().join("\n");
      return s.jsScanText === next ? s : { ...s, jsScanText: next };
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.jsScanSetupOpen]);

  // The chip shows the project's real status (active / freeze / …), not the
  // coarse active-vs-archived split the tabs use.
  const stCh = PROJ_STATUS[projRow?.status ?? "active"] ?? PROJ_STATUS.active;

  const sectionLabel =
    sec === "hosts"
      ? ({ hosts: "Hosts", ips: "IPs", endpoints: "Endpoints", js: "JS scan" } as Record<string, string>)[rv] || "Hosts"
      : ({ overview: "Overview", vulns: "Vulnerabilities", notes: "Notes", creds: "Creds", members: "Members", activity: "Activity" } as Record<string, string>)[sec] || "Overview";
  /** The item open inside the section, if any — the last crumb (e.g. the note's title). */
  const crumbLeaf =
    // The recon full-page forms are crumbs of their own: Project / Hosts / Export,
    // which makes the middle crumb the way back to the list.
    sec === "hosts" && state.exportPageOpen
      ? t("Export")
      : sec === "hosts" && state.hostImportOpen
        ? t("Add hosts")
        : sec === "hosts" && state.ipImportOpen
        ? t("Add IPs")
        : sec === "hosts" && state.epImportOpen
        ? t("Add endpoints")
        : sec === "hosts" && rv === "js" && state.jsScanSetupOpen
        ? t("Choose domains")
        : sec === "notes" && state.openNoteId != null
          ? d.notes.find((n) => n.id === state.openNoteId)?.title ?? ""
          : sec === "vulns" && state.openVulnId != null
            ? d.vulns.find((v) => v.id === state.openVulnId)?.title ?? ""
            : sec === "hosts" && _hd
              ? _hd.host
              : sec === "hosts" && _ipd
                ? _ipd.ip
                : sec === "hosts" && _jsd
                  ? fileBase(_jsd.url)
                  : "";

  // ---- editor fields (options that depend on live data are filled in here) ----
  let efCfg = EDITOR_FIELDS[state.editorType] ?? [];
  if (state.editorType === "member") {
    const existing = d.members.map((m) => m.name);
    const avail = state.workspaceUsers.filter((u) => !existing.includes(u.name));
    efCfg = efCfg.map((f) => (f.k === "userKey" ? { ...f, opts: avail.map((u) => u.key) } : f));
  }
  if (state.editorType === "vuln") {
    // On add we ask for just Title + Host — severity/status get sensible defaults
    // and everything else is filled on the finding's detail card, where we redirect.
    // On edit, severity is driven by the CVSS vector afterwards, so drop it here too.
    if (state.editorMode === "add") efCfg = efCfg.filter((f) => f.k === "title" || f.k === "host");
    else efCfg = efCfg.filter((f) => f.k !== "sev");
    // A finding must point at a real host — the picker offers the project's hosts.
    efCfg = efCfg.map((f) => (f.k === "host" ? { ...f, opts: hosts.map((h) => h.host) } : f));
  }
  // IPs and endpoints hang off a host, so their pickers list the project's hosts.
  if (state.editorType === "ip" || state.editorType === "endpoint") {
    efCfg = efCfg.map((f) => (f.k === "hostName" ? { ...f, opts: hosts.map((h) => h.host) } : f));
  }
  // Cred host binds to a project host — same validated picker as members (the
  // save resolves the typed value against the project's hosts).
  if (state.editorType === "cred") {
    efCfg = efCfg.map((f) => (f.k === "host" ? { ...f, opts: hosts.map((h) => h.host) } : f));
    // On edit the password is intentionally blank — say what leaving it blank does.
    if (state.editorMode === "edit") {
      efCfg = efCfg.map((f) => (f.k === "password" ? { ...f, ph: "leave blank to keep the current password" } : f));
    }
  }
  const editorFields = efCfg.map((f) => {
    /* `sub` is the secondary line of a suggestion (a user's email); selects only
       ever render `label`, so widening the shape here leaves them untouched. */
    const options = (f.opts ?? []).map((o) => ({
      value: o,
      // Selects title-case their options (up → Up); combos (hosts, usernames)
      // show the value verbatim — capitalising a hostname would misrepresent it.
      label: f.type === "select" ? cap(o) : o,
      sub: f.k === "userKey" ? state.workspaceUsers.find((u) => u.key === o)?.email ?? "" : "",
    }));
    const typed = fstr(state.editorForm[f.k]);
    const q = typed.trim().toLowerCase();
    /* Suggestions are ranked, not just filtered: typing "ad" puts every ad*
       nickname first, then any other hit on the nickname or email. Capped at
       COMBO_MAX so the list stays scannable instead of dumping the workspace. */
    const suggestions = options
      .map((o) => {
        if (!q) return { o, rank: 0 };
        if (o.value.toLowerCase().startsWith(q)) return { o, rank: 0 };
        if (`${o.value} ${o.sub}`.toLowerCase().includes(q)) return { o, rank: 1 };
        return null;
      })
      .filter((x): x is { o: (typeof options)[number]; rank: number } => x !== null)
      .sort((a, b) => a.rank - b.rank)
      .slice(0, COMBO_MAX)
      .map((x) => x.o);
    const hi = Math.min(state.comboHi, Math.max(suggestions.length - 1, 0));
    const pick = (v: string) => setState({ editorForm: { ...state.editorForm, [f.k]: v }, comboOpen: null, comboHi: 0 });
    return {
      key: f.k,
      label: f.label,
      isText: f.type === "text",
      isTextarea: f.type === "textarea",
      isSelect: f.type === "select",
      isTags: f.type === "tags",
      isCombo: f.type === "combo",
      value: typed,
      placeholder: f.ph || "",
      onInput: (e: ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => updateForm(f.k, e.target.value),
      tagDraft: state.tagDrafts[f.k] || "",
      onTagDraft: (e: ChangeEvent<HTMLInputElement>) => setTagDraft(f.k, e.target.value),
      onTagKeyDown: (e: ReactKeyboardEvent<HTMLInputElement>) => {
        if (e.key === "Enter") {
          e.preventDefault();
          addEditorTag(f.k, e.currentTarget.value);
        }
      },
      tags: (Array.isArray(state.editorForm[f.k]) ? (state.editorForm[f.k] as string[]) : []).map((t, ti) => ({ value: t, onRemove: () => removeEditorTag(f.k, ti) })),
      options,
      // ---- combo (type-to-search) ----
      suggestions: suggestions.map((o, i) => ({ ...o, active: i === hi, onPick: () => pick(o.value) })),
      comboOpen: state.comboOpen === f.k && suggestions.length > 0,
      onComboInput: (e: ChangeEvent<HTMLInputElement>) => {
        updateForm(f.k, e.target.value);
        setState({ comboOpen: f.k, comboHi: 0 });
      },
      onComboFocus: () => setState({ comboOpen: f.k, comboHi: 0 }),
      onComboBlur: () => setState({ comboOpen: null }),
      onComboKeyDown: (e: ReactKeyboardEvent<HTMLInputElement>) => {
        if (state.comboOpen !== f.k || suggestions.length === 0) {
          if (e.key === "ArrowDown") setState({ comboOpen: f.k, comboHi: 0 });
          return;
        }
        if (e.key === "ArrowDown") {
          e.preventDefault();
          setState({ comboHi: (hi + 1) % suggestions.length });
        } else if (e.key === "ArrowUp") {
          e.preventDefault();
          setState({ comboHi: (hi - 1 + suggestions.length) % suggestions.length });
        } else if (e.key === "Enter") {
          e.preventDefault();
          pick(suggestions[hi].value);
        } else if (e.key === "Escape") {
          setState({ comboOpen: null });
        }
      },
    };
  });

  const so = secStyle("overview");
  const sh = secStyle("hosts");
  const sv = secStyle("vulns");
  const sn = secStyle("notes");
  const scr = secStyle("creds");
  const sm = secStyle("members");
  const sa = secStyle("activity");

  const vd = state.vulnDetailForm;
  const vdCvss = computeCvss4(vd.vector);
  const vdSev: Severity = (vdCvss ? vdCvss.sev : vd.sev) || "medium";
  const vdScore = vdCvss ? vdCvss.score.toFixed(1) : "—";

  const pfNav = (tab: ProfileTab): CSSProperties =>
    state.profileTab === tab ? { background: "var(--fr-accent-soft)", color: "var(--fr-accent)", boxShadow: "inset 3px 0 0 var(--fr-accent)" } : { background: "transparent", color: "var(--fr-text-2)", boxShadow: "inset 3px 0 0 transparent" };

  // ================================================================= RENDER

  const eyebrow = (crumbs: { label: string; onClick?: () => void; muted?: boolean }[]): ReactNode => (
    <div className="mono" style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11, letterSpacing: 1.2, textTransform: "uppercase", color: "var(--fr-text-faint)", fontWeight: 700, marginBottom: 10 }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--fr-accent)" }} />
      {crumbs.map((c, i) => (
        <span key={i} style={{ display: "contents" }}>
          {i > 0 && <span>/</span>}
          <span className={c.onClick ? "clk" : undefined} onClick={c.onClick} style={{ cursor: c.onClick ? "pointer" : undefined, color: c.muted ? "var(--fr-text-3)" : undefined }}>
            {t(c.label)}
          </span>
        </span>
      ))}
    </div>
  );

  // ---------- Projects list ----------
  const renderProjects = () => (
    <div className="route" style={{ padding: "40px 48px 36px", width: "100%" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 20 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 40, fontWeight: 800, letterSpacing: "-1px", color: "var(--fr-text)" }}>{t("Projects")}</h1>
          <div style={{ fontSize: 15, color: "var(--fr-text-3)", marginTop: 8 }}>
            {isActive ? `${t("Showing active projects")} · ${activeCount} ${t("active")}` : `${t("Showing archived projects")} · ${archivedCount} ${t("archived")}`}
          </div>
        </div>
        <button className="clk" onClick={() => setState({ modalOpen: true })} style={{ display: "flex", alignItems: "center", gap: 9, height: 46, padding: "0 22px", border: "none", borderRadius: 13, background: "var(--fr-accent-2)", color: "var(--fr-on-accent)", font: "700 14px Inter,sans-serif" }}>
          <Icon name="plus" size={17} sw={2.4} />
          {t("New project")}
        </button>
      </div>

      {/* stat cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5,minmax(0,1fr))", gap: 16, margin: "26px 0 22px" }}>
        {[
          { icon: "trend-up" as const, iconColor: "var(--fr-accent-2)", label: "Active", value: String(activeCount), spark: cumulativeSpark(projCreatedTimes(activeRows), ...projWindow(activeRows)), stroke: "var(--fr-accent-2)", w: 111 },
          { icon: "archive" as const, iconColor: "var(--fr-text-3)", label: "Archived", value: String(archivedCount), spark: cumulativeSpark(projCreatedTimes(archivedRows), ...projWindow(archivedRows)), stroke: "var(--fr-text-faint)", w: 111 },
          { icon: "clock" as const, iconColor: "var(--fr-danger)", label: "Open issues", value: String(tabProjects.reduce((s, p) => s + p.openFindings, 0)), spark: cumulativeSpark(aggOpenVulnTimes(tabProjects), ...projWindow(tabProjects)), stroke: "var(--fr-danger)", w: 111 },
          { icon: "star" as const, iconColor: "var(--fr-accent-2)", label: "Projects", value: String(tabProjects.length), spark: cumulativeSpark(projCreatedTimes(tabProjects), ...projWindow(tabProjects)), stroke: "var(--fr-accent-muted)", w: 111 },
          { icon: "server" as const, iconColor: "var(--fr-success)", label: "Hosts", value: String(tabProjects.reduce((s, p) => s + p.hostsCount, 0)), spark: cumulativeSpark(aggHostTimes(tabProjects), ...projWindow(tabProjects)), stroke: "var(--fr-success)", w: 111 },
        ].map((c) => (
          <div key={c.label} className="statc" style={{ ...CARD, padding: "16px 18px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--fr-text-3)", font: "600 11.5px Inter,sans-serif", letterSpacing: ".5px", textTransform: "uppercase" }}>
              <Icon name={c.icon} size={15} color={c.iconColor} sw={2.1} />
              {c.label}
            </div>
            <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", marginTop: 8 }}>
              <div className="mono" style={{ fontWeight: 800, fontSize: 26, color: "var(--fr-text)", lineHeight: 1, letterSpacing: "-1px" }}>{c.value}</div>
              <svg height="30" viewBox={`0 0 ${c.w} 30`} preserveAspectRatio="none" fill="none" style={{ flex: 1, minWidth: 0, width: "100%", maxWidth: 100, marginLeft: 14 }}>
                <polygon points={sparkArea(c.spark, c.w)} fill={c.stroke} fillOpacity={0.15} />
                <polyline points={c.spark} stroke={c.stroke} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
              </svg>
            </div>
          </div>
        ))}
      </div>

      {/* controls */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 16, flexWrap: "wrap" }}>
        <div style={{ display: "flex", gap: 8 }}>
          <div className="tab" onClick={() => setState({ tab: "active" })} style={{ display: "flex", alignItems: "center", gap: 9, padding: "9px 15px", borderRadius: 11, font: "700 13.5px Inter,sans-serif", background: isActive ? "var(--fr-surface)" : "transparent", border: `1px solid ${isActive ? "var(--fr-border)" : "transparent"}`, color: isActive ? "var(--fr-text)" : "var(--fr-text-3)" }}>
            <Icon name="trend-up" size={15} sw={2.2} />
            {t("Active")}
            <span className="mono" style={{ minWidth: 20, height: 20, padding: "0 5px", borderRadius: 6, background: isActive ? "var(--fr-accent-2)" : "var(--fr-accent-soft)", color: isActive ? "var(--fr-on-accent)" : "var(--fr-accent-2)", fontSize: 11, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center" }}>{activeCount}</span>
          </div>
          <div className="tab" onClick={() => setState({ tab: "archived" })} style={{ display: "flex", alignItems: "center", gap: 9, padding: "9px 15px", borderRadius: 11, font: "700 13.5px Inter,sans-serif", background: !isActive ? "var(--fr-surface)" : "transparent", border: `1px solid ${!isActive ? "var(--fr-border)" : "transparent"}`, color: !isActive ? "var(--fr-text)" : "var(--fr-text-3)" }}>
            <Icon name="archive" size={15} />
            {t("Archived")}
            <span className="mono" style={{ minWidth: 20, height: 20, padding: "0 5px", borderRadius: 6, background: !isActive ? "var(--fr-accent-2)" : "var(--fr-accent-soft)", color: !isActive ? "var(--fr-on-accent)" : "var(--fr-accent-2)", fontSize: 11, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center" }}>{archivedCount}</span>
          </div>
        </div>
        <div style={{ flex: 1 }} />
        <label className="fq" style={{ position: "relative", display: "flex", alignItems: "center", width: 280 }}>
          <svg style={{ position: "absolute", left: 13 }} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--fr-text-faint)" strokeWidth="2" strokeLinecap="round">
            <circle cx="11" cy="11" r="7" />
            <path d="M21 21l-4-4" />
          </svg>
          <input placeholder={t("Filter projects…")} value={state.query} onChange={(e) => setState({ query: e.target.value })} />
        </label>
        <div className="clk iconbtn" onClick={() => setState((s) => ({ projSort: s.projSort === "first" ? "last" : "first" }))} style={{ display: "flex", alignItems: "center", gap: 9, height: 40, padding: "0 16px", border: "1px solid var(--fr-border)", borderRadius: 20, background: "var(--fr-surface)", font: "500 13.5px Inter,sans-serif", color: "var(--fr-text-2)" }}>
          <Icon name="sort" size={16} />
          {state.projSort === "first" ? t("First updated") : t("Last updated")}
        </div>
      </div>

      {/* table */}
      <div style={{ ...CARD, overflow: "hidden" }}>
        {projRows.length > 0 && (
          <div style={{ display: "grid", gridTemplateColumns: "48px minmax(0,1fr) minmax(0,1fr) minmax(0,1fr) 150px 70px", padding: "13px 22px", borderBottom: "1px solid var(--fr-divider)", font: "700 11px Inter,sans-serif", letterSpacing: ".6px", color: "var(--fr-text-faint)", textTransform: "uppercase" }}>
            <div>#</div>
            <div>{t("Project")}</div>
            <div>{t("Description")}</div>
            <div>{t("Findings")}</div>
            <div>{t("Last updated")}</div>
            <div style={{ textAlign: "right" }}>{t("Actions")}</div>
          </div>
        )}
        {projRows.map((r, i) => {
          const fsev = r.openFindings === 0 ? FINDING_SEV.none : r.openFindings >= 3 ? FINDING_SEV.high : FINDING_SEV.med;
          const findingsLabel = r.openFindings === 0 ? (r.totalFindings > 0 ? t("No open") : t("No findings")) : `${r.openFindings} ${t("open")}`;
          return (
            <div key={r.id} className="prow clk" onClick={() => openProject(r.id)} style={{ display: "grid", gridTemplateColumns: "48px minmax(0,1fr) minmax(0,1fr) minmax(0,1fr) 150px 70px", alignItems: "center", padding: "11px 22px", borderBottom: "1px solid var(--fr-divider)" }}>
              <div className="mono" style={{ color: "var(--fr-text-faint)", fontSize: 13, fontWeight: 600 }}>{String(i + 1).padStart(2, "0")}</div>
              <div style={{ minWidth: 0, paddingRight: 12 }}>
                <div style={{ font: "700 14.5px Inter,sans-serif", color: "var(--fr-text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.name}</div>
              </div>
              <div style={{ fontSize: 13, color: "var(--fr-text-3)", paddingRight: 16, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.description}</div>
              <div>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "4px 10px", borderRadius: 8, background: fsev.fBg, color: fsev.fColor, font: "600 12px Inter,sans-serif" }}>
                  <span style={{ width: 7, height: 7, borderRadius: "50%", background: fsev.fDot }} />
                  {findingsLabel}
                </span>
              </div>
              <div style={{ fontSize: 13, color: "var(--fr-text-3)" }}>{r.updated}</div>
              {/* Edit: admin / creator / lead. Delete: admin only — both mirror the backend. */}
              <div style={{ display: "flex", justifyContent: "flex-end", gap: 4 }}>
                {canEditProjectRow(r) && (
                  <div className="actbtn" onClick={(e) => { e.stopPropagation(); openProjEditRow(r); }}><Icon name="edit" size={15} /></div>
                )}
                {isAdmin && (
                  <div className="actbtn del" onClick={(e) => { e.stopPropagation(); askDeleteProject(r); }}><Icon name="trash" size={15} /></div>
                )}
              </div>
            </div>
          );
        })}
        {state.projectsLoading && projRows.length === 0 && <div style={{ padding: 52, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 14 }}>{t("Loading projects…")}</div>}
        {state.projectsError && <div style={{ padding: 52, textAlign: "center", color: "var(--fr-danger)", fontSize: 14 }}>{state.projectsError}</div>}
        {!state.projectsLoading && !state.projectsError && projRows.length === 0 && <div style={{ padding: 52, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 14 }}>{t("No projects found.")}</div>}
      </div>
    </div>
  );

  // ---------- Stub page ----------
  const renderStub = () => (
    <div className="route" style={{ padding: "40px 48px 36px", width: "100%" }}>
      {eyebrow([{ label: "Workspace", onClick: selProjects }, { label: stubTitle, muted: true }])}
      <h1 style={{ margin: 0, fontSize: 30, fontWeight: 800, letterSpacing: "-.7px", color: "var(--fr-text)" }}>{t(stubTitle)}</h1>
      <div style={{ fontSize: 13.5, color: "var(--fr-text-3)", marginTop: 6 }}>{t(stubDesc)}</div>
      <div style={{ marginTop: 32, ...CARD, padding: "60px 24px", display: "flex", flexDirection: "column", alignItems: "center", textAlign: "center", gap: 14 }}>
        <div style={{ width: 56, height: 56, borderRadius: 14, background: "var(--fr-hover)", color: "var(--fr-text-faint)", display: "flex", alignItems: "center", justifyContent: "center" }}>
          <Icon name="calendar" size={26} sw={1.8} />
        </div>
        <div style={{ font: "700 15px Inter,sans-serif", color: "var(--fr-text)" }}>{t("Coming soon")}</div>
        <div style={{ fontSize: 13, color: "var(--fr-text-3)", maxWidth: 340 }}>{t("This area is under construction. Head back to Projects to continue your work.")}</div>
        <button className="clk" onClick={selProjects} style={{ marginTop: 6, height: 40, padding: "0 18px", border: "none", borderRadius: 10, background: "var(--fr-accent-2)", color: "var(--fr-on-accent)", font: "700 13px Inter,sans-serif", cursor: "pointer" }}>{t("Back to Projects")}</button>
      </div>
    </div>
  );

  // ---------- Workspace members (admin) ----------
  const renderWorkspaceMembers = () => (
    <div className="route" style={{ padding: "40px 48px 36px", width: "100%" }}>
      {eyebrow([{ label: "Workspace", onClick: selProjects }, { label: "Members", muted: true }])}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 20 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 30, fontWeight: 800, letterSpacing: "-.7px", color: "var(--fr-text)" }}>{t("Members")}</h1>
          <div style={{ fontSize: 13.5, color: "var(--fr-text-3)", marginTop: 6 }}>{t("Invite people by email — they set their own username and password from the link")}</div>
        </div>
        <button className="clk" onClick={() => openWSUserEditor("add", -1)} style={{ flex: "none", display: "inline-flex", alignItems: "center", gap: 8, height: 42, padding: "0 18px", border: "none", borderRadius: 11, background: "var(--fr-accent)", color: "var(--fr-on-accent)", font: "700 13.5px Inter,sans-serif", cursor: "pointer" }}>
          <Icon name="plus" size={15} sw={2.2} />
          {t("Invite member")}
        </button>
      </div>
      {/* Одна строка управления: вкладки активные/заблокированные — слева (там,
          где раньше был поиск по пользователям), поиск и фильтры — справа. */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 22, flexWrap: "wrap" }}>
        <div className="tab" onClick={() => setState({ wsUserTab: "active" })} style={{ display: "flex", alignItems: "center", gap: 9, padding: "9px 15px", borderRadius: 11, font: "700 13.5px Inter,sans-serif", background: state.wsUserTab === "active" ? "var(--fr-surface)" : "transparent", border: `1px solid ${state.wsUserTab === "active" ? "var(--fr-border)" : "transparent"}`, color: state.wsUserTab === "active" ? "var(--fr-text)" : "var(--fr-text-3)" }}>
          <Icon name="unlock" size={15} sw={2.2} />
          {lang === "ru" ? "Активные" : "Active"}
          <span className="mono" style={{ minWidth: 20, height: 20, padding: "0 5px", borderRadius: 6, background: state.wsUserTab === "active" ? "var(--fr-accent-2)" : "var(--fr-accent-soft)", color: state.wsUserTab === "active" ? "var(--fr-on-accent)" : "var(--fr-accent-2)", fontSize: 11, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center" }}>{state.workspaceUsers.filter((u) => !u.locked).length}</span>
        </div>
        <div className="tab" onClick={() => setState({ wsUserTab: "archived" })} style={{ display: "flex", alignItems: "center", gap: 9, padding: "9px 15px", borderRadius: 11, font: "700 13.5px Inter,sans-serif", background: state.wsUserTab === "archived" ? "var(--fr-surface)" : "transparent", border: `1px solid ${state.wsUserTab === "archived" ? "var(--fr-border)" : "transparent"}`, color: state.wsUserTab === "archived" ? "var(--fr-text)" : "var(--fr-text-3)" }}>
          <Icon name="lock" size={15} sw={2.2} />
          {lang === "ru" ? "Заблокированные" : "Blocked"}
          <span className="mono" style={{ minWidth: 20, height: 20, padding: "0 5px", borderRadius: 6, background: state.wsUserTab === "archived" ? "var(--fr-accent-2)" : "var(--fr-accent-soft)", color: state.wsUserTab === "archived" ? "var(--fr-on-accent)" : "var(--fr-accent-2)", fontSize: 11, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center" }}>{state.workspaceUsers.filter((u) => u.locked).length}</span>
        </div>
        <div style={{ flex: 1 }} />
        {/* Поиск переехал сюда — в правую часть строки, вплотную к фильтрам. */}
        <label className="fq" style={{ position: "relative", display: "flex", alignItems: "center", width: 240 }}>
          <svg style={{ position: "absolute", left: 13 }} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--fr-text-faint)" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="7" /><path d="M21 21l-4-4" /></svg>
          <input placeholder={t("Search by username…")} value={state.wsMemberQuery} onChange={(e) => setState({ wsMemberQuery: e.target.value })} />
        </label>
        {/* Every pill toggles; filters combine (AND across groups, OR inside one).
            An empty group means "All", so unpicking the last pill re-selects it. */}
        <span className="mono" style={{ fontSize: 10.5, letterSpacing: 1, color: "var(--fr-text-faint)", fontWeight: 700 }}>{t("ROLE")}</span>
        <div className="clk" onClick={() => setState({ wsMemberRoles: [] })} style={{ font: "600 12px Inter,sans-serif", padding: "6px 12px", borderRadius: 20, cursor: "pointer", ...vfPill(state.wsMemberRoles.length === 0) }}>{t("All")}</div>
        {([{ label: "Admin", v: "admin" as const }, { label: "User", v: "user" as const }]).map((o) => (
          <div key={o.v} className="clk" onClick={() => setState((s) => ({ wsMemberRoles: toggleIn(s.wsMemberRoles, o.v) }))} style={{ font: "600 12px Inter,sans-serif", padding: "6px 12px", borderRadius: 20, cursor: "pointer", ...vfPill(state.wsMemberRoles.includes(o.v)) }}>{t(o.label)}</div>
        ))}
        <span className="mono" style={{ fontSize: 10.5, letterSpacing: 1, color: "var(--fr-text-faint)", fontWeight: 700, marginLeft: 8 }}>{t("PROJECT")}</span>
        <div className="clk" onClick={() => setState({ wsMemberProjectRoles: [] })} style={{ font: "600 12px Inter,sans-serif", padding: "6px 12px", borderRadius: 20, cursor: "pointer", ...vfPill(state.wsMemberProjectRoles.length === 0) }}>{t("All")}</div>
        {([{ label: "Lead", v: "lead" as const }, { label: "Pentester", v: "pentester" as const }]).map((o) => (
          <div key={o.v} className="clk" onClick={() => setState((s) => ({ wsMemberProjectRoles: toggleIn(s.wsMemberProjectRoles, o.v) }))} style={{ font: "600 12px Inter,sans-serif", padding: "6px 12px", borderRadius: 20, cursor: "pointer", ...vfPill(state.wsMemberProjectRoles.includes(o.v)) }}>{t(o.label)}</div>
        ))}
      </div>
      {/* Ожидающие приглашения — это будущие активные участники, показываем их
          только на вкладке «Активные». */}
      {state.wsUserTab === "active" && state.pendingInvites.length > 0 && (
        <div style={{ marginTop: 16, ...CARD, overflow: "hidden" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "13px 20px", borderBottom: "1px solid var(--fr-divider)", font: "700 11px Inter,sans-serif", letterSpacing: ".6px", color: "var(--fr-text-faint)", textTransform: "uppercase" }}>
            <Icon name="mail" size={14} color="var(--fr-text-faint)" />
            {t("Pending invitations ·")} {state.pendingInvites.length}
          </div>
          {state.pendingInvites.map((inv) => (
            <div key={inv.id} className="prow" style={{ display: "grid", gridTemplateColumns: "1.4fr 168px 150px", alignItems: "center", padding: "13px 20px", borderBottom: "1px solid var(--fr-divider)", gap: 12 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 11, minWidth: 0 }}>
                <span style={{ width: 32, height: 32, flex: "none", borderRadius: "50%", background: "var(--fr-divider)", color: "var(--fr-text-3)", display: "flex", alignItems: "center", justifyContent: "center" }}><Icon name="mail" size={15} color="var(--fr-text-3)" /></span>
                <div style={{ minWidth: 0 }}>
                  <div className="mono" style={{ fontSize: 12.5, color: "var(--fr-text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{inv.email}</div>
                  <div style={{ fontSize: 11, color: inv.is_expired ? "var(--fr-danger)" : "var(--fr-text-3)", fontWeight: 600, marginTop: 2 }}>{inv.is_expired ? "Link expired — resend it" : "Pending activation"}</div>
                </div>
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                <span style={{ font: "700 10px Inter,sans-serif", textTransform: "uppercase", letterSpacing: ".5px", borderRadius: 6, padding: "3px 9px", background: WS_ROLE[inv.role === "admin" ? "admin" : "user"].bg, color: WS_ROLE[inv.role === "admin" ? "admin" : "user"].color }}>{t(WS_ROLE_LABEL[inv.role === "admin" ? "admin" : "user"])}</span>
                <span style={{ font: "700 10px Inter,sans-serif", textTransform: "uppercase", letterSpacing: ".5px", borderRadius: 6, padding: "3px 9px", background: ROLE[inv.project_role].bg, color: ROLE[inv.project_role].color }}>{inv.project_role}</span>
              </div>
              <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
                <button className="clk" onClick={() => resendInvite(inv.id)} style={{ height: 30, padding: "0 12px", border: "1px solid var(--fr-border-strong)", borderRadius: 8, background: "var(--fr-surface)", color: "var(--fr-accent)", font: "600 12px Inter,sans-serif", cursor: "pointer" }}>{t("Resend")}</button>
                <div className="actbtn del" onClick={() => revokeInvite(inv.id)} title={t("Revoke invitation")}><Icon name="trash" size={15} /></div>
              </div>
            </div>
          ))}
        </div>
      )}
      <div style={{ marginTop: 16, ...CARD, overflow: "hidden" }}>
        {(() => {
          const wq = state.wsMemberQuery.trim().toLowerCase();
          const filtered = state.workspaceUsers
            .map((u, idx) => ({ u, idx }))
            .filter(
              ({ u }) =>
                // Вкладка: активные = не заблокированные, архив = деактивированные.
                (state.wsUserTab === "archived" ? u.locked : !u.locked) &&
                (state.wsMemberRoles.length === 0 || state.wsMemberRoles.includes(u.role)) &&
                (state.wsMemberProjectRoles.length === 0 || state.wsMemberProjectRoles.includes(u.projectRole)) &&
                (!wq || u.name.toLowerCase().includes(wq))
            );
          if (filtered.length === 0)
            return (
              <div style={{ padding: 44, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 14 }}>
                {state.wsUserTab === "archived" ? t("No deactivated members.") : t("No members match.")}
              </div>
            );
          return (
            <>
              {/* Column headers only make sense with rows — hide them when empty. */}
              <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1.4fr 168px 72px", padding: "13px 20px", borderBottom: "1px solid var(--fr-divider)", font: "700 11px Inter,sans-serif", letterSpacing: ".6px", color: "var(--fr-text-faint)", textTransform: "uppercase" }}>
                <div>{t("Name")}</div>
                <div>{t("Email")}</div>
                <div>{t("Role")}</div>
                <div />
              </div>
              {filtered.map(({ u, idx }) => (
            <div key={u.key + idx} className="prow" style={{ display: "grid", gridTemplateColumns: "1.2fr 1.4fr 168px 72px", alignItems: "center", padding: "14px 20px", borderBottom: "1px solid var(--fr-divider)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 11, minWidth: 0 }}>
                <span className="mono" style={{ width: 32, height: 32, flex: "none", borderRadius: "50%", background: u.locked ? "var(--fr-text-faint)" : "var(--fr-accent)", color: "var(--fr-on-accent)", display: "flex", alignItems: "center", justifyContent: "center", font: "700 13px 'JetBrains Mono',monospace" }}>{(u.name[0] || "U").toUpperCase()}</span>
                <span style={{ font: "600 13.5px Inter,sans-serif", color: "var(--fr-text)" }}>{u.name}</span>
              </div>
              <div className="mono" style={{ fontSize: 12.5, color: "var(--fr-text-2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{u.email}</div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                <span style={{ font: "700 10px Inter,sans-serif", textTransform: "uppercase", letterSpacing: ".5px", borderRadius: 6, padding: "3px 9px", background: WS_ROLE[u.role].bg, color: WS_ROLE[u.role].color }}>{t(WS_ROLE_LABEL[u.role])}</span>
                <span style={{ font: "700 10px Inter,sans-serif", textTransform: "uppercase", letterSpacing: ".5px", borderRadius: 6, padding: "3px 9px", background: ROLE[u.projectRole].bg, color: ROLE[u.projectRole].color }}>{u.projectRole}</span>
              </div>
              <div style={{ display: "flex", justifyContent: "flex-end", gap: 2 }}>
                <div className="actbtn" onClick={() => openWSUserEditor("edit", idx)}><Icon name="edit" size={15} /></div>
                {u.locked ? (
                  <div className="actbtn" title={t("Reactivate user")} onClick={() => reactivateUser(idx)}><Icon name="unlock" size={15} /></div>
                ) : (
                  <div className="actbtn del" title={t("Block user")} onClick={() => askDeleteWSUser(idx)}><Icon name="trash" size={15} /></div>
                )}
              </div>
            </div>
              ))}
            </>
          );
        })()}
      </div>
    </div>
  );

  // ---------- Project detail ----------
  const tabItem = (label: string, icon: Parameters<typeof Icon>[0]["name"], st: { active: boolean }, onClick: () => void, badge?: { text: string; color: string; bg: string }, extra?: ReactNode) => (
    <div className={`clk sectab${st.active ? " on" : ""}`} onClick={onClick} style={{ display: "flex", alignItems: "center", gap: 8, padding: "15px 15px", marginBottom: -1, whiteSpace: "nowrap", font: "600 14px Inter,sans-serif" }}>
      <Icon name={icon} size={17} />
      {label}
      {extra}
      {badge && <span className="mono" style={{ fontSize: 11, fontWeight: 700, color: badge.color, background: badge.bg, borderRadius: 6, padding: "1px 7px" }}>{badge.text}</span>}
    </div>
  );

  const renderDetail = () => (
    <div className="route" style={{ padding: "0 0 36px", width: "100%" }}>
      {/* Backdrop ПОД баром вкладок (zIndex ниже), не над ним: клик по пустому
          месту закрывает меню Recon, но вкладки остаются наводимыми и
          кликабельными поверх него даже при открытом списке. */}
      {state.reconMenuOpen && <div onClick={() => setState({ reconMenuOpen: false })} style={{ position: "fixed", inset: 0, zIndex: 20 }} />}
      {/* tabs */}
      <div style={{ display: "flex", alignItems: "center", gap: 2, padding: "0 48px", borderBottom: "1px solid var(--fr-border-light)", background: "var(--fr-surface)", overflow: "visible", position: "relative", zIndex: 30 }}>
        {tabItem(t("Overview"), "layout", so, () => setSection("overview"))}
        <div style={{ position: "relative", display: "flex" }}>
          {/* Recon открывает меню, а не раздел напрямую, но выделяется как
              обычная вкладка — той же синей линией снизу, что и соседние. */}
          {tabItem(t("Recon"), "server", sh, toggleReconMenu, undefined, <Icon name="chevron-down" size={14} sw={2.2} style={{ transform: state.reconMenuOpen ? "rotate(180deg)" : "none", transition: "transform .2s ease" }} />)}
          <div className={`menu ${state.reconMenuOpen ? "open" : ""}`} style={{ position: "absolute", top: 52, left: 8, width: 214, background: "var(--fr-surface)", border: "1px solid var(--fr-border-light)", borderRadius: 14, boxShadow: "0 20px 54px rgba(15,27,45,.16)", zIndex: 50, padding: 8, transformOrigin: "top left" }}>
            <div className="mono" style={{ fontSize: 10, letterSpacing: 1.5, color: "var(--fr-text-faint)", fontWeight: 700, padding: "8px 10px" }}>{t("RECON")}</div>
            {([
              { v: "hosts" as const, icon: "server" as const, label: "Hosts", count: hosts.length },
              { v: "ips" as const, icon: "card" as const, label: "IPs", count: ipsRows.length },
              { v: "endpoints" as const, icon: "link" as const, label: "Endpoints", count: endpointTotal },
              { v: "js" as const, icon: "doc" as const, label: "JS", count: jsFiles.length },
            ]).map((it) => {
              // Nothing is highlighted while another section is open: the recon
              // view only counts as active when Recon itself is the open section.
              const on = sec === "hosts" && rv === it.v;
              return (
                <div key={it.v} className={`reconrow clk${on ? " on" : ""}`} onClick={() => selRecon(it.v)} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 11px", borderRadius: 10, marginBottom: 3, font: "600 13.5px Inter,sans-serif" }}>
                  <Icon name={it.icon} size={17} />
                  {t(it.label)}
                  <span className="mono" style={{ marginLeft: "auto", minWidth: 22, textAlign: "center", fontSize: 11, fontWeight: 700, color: on ? "var(--fr-accent)" : "var(--fr-text-3)", background: on ? "var(--fr-accent-soft)" : "var(--fr-hover)", border: `1px solid ${on ? "var(--fr-accent-muted)" : "var(--fr-border-light)"}`, borderRadius: 6, padding: "1px 6px" }}>{it.count}</span>
                </div>
              );
            })}
          </div>
        </div>
        {tabItem(t("Vulnerabilities"), "star2", sv, () => setSection("vulns"), { text: String(d.vulns.length), color: sv.badgeColor, bg: sv.badgeBg })}
        {tabItem(t("Notes"), "doc", sn, () => setSection("notes"), { text: String(d.notes.length), color: sn.badgeColor, bg: sn.badgeBg })}
        {tabItem(t("Creds"), "lock", scr, () => setSection("creds"), { text: String(d.creds.length), color: scr.badgeColor, bg: scr.badgeBg })}
        {canViewMembers && tabItem(t("Members"), "users", sm, () => setSection("members"), { text: String(d.members.length), color: sm.badgeColor, bg: sm.badgeBg })}
        {tabItem(t("Activity"), "activity", sa, () => setSection("activity"), { text: String(activityGroups.length), color: sa.color, bg: "var(--fr-bg)" })}
      </div>

      <div style={{ padding: "26px 48px 0" }}>
        {/* Project / Section / <open item>. The section stays clickable while an
            item is open, so it is the way back to that section's list. */}
        <div className="mono" style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: "var(--fr-text-faint)", fontWeight: 600, marginBottom: 14 }}>
          <span className="clk" onClick={() => setSection("overview")} style={{ color: "var(--fr-accent-2)", cursor: "pointer" }}>{projName}</span>
          <span>/</span>
          {crumbLeaf ? (
            <>
              <span className="clk" onClick={() => setSection(sec)} style={{ color: "var(--fr-accent-2)", cursor: "pointer" }}>{sectionLabel}</span>
              <span>/</span>
              <span style={{ color: "var(--fr-text-3)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{crumbLeaf}</span>
            </>
          ) : (
            <span style={{ color: "var(--fr-text-3)" }}>{sectionLabel}</span>
          )}
        </div>

        {/* header row */}
        {sec === "overview" ? (
          <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 20, marginBottom: 24 }}>
            <div style={{ minWidth: 0 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
                <h1 style={{ margin: 0, fontSize: 32, fontWeight: 800, letterSpacing: "-.8px", color: "var(--fr-text)" }}>{d.title || projName}</h1>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "5px 12px", borderRadius: 20, background: stCh.bg, color: stCh.color, font: "700 12px Inter,sans-serif" }}>
                  <span style={{ width: 6, height: 6, borderRadius: "50%", background: stCh.dot }} />
                  {t(stCh.label)}
                </span>
              </div>
              <div style={{ fontSize: 14, color: "var(--fr-text-3)", marginTop: 8 }}>{d.desc}</div>
            </div>
            <div style={{ display: "flex", gap: 10, flex: "none" }}>
              <button className="clk" onClick={openExportModal} style={{ height: 42, padding: "0 16px", border: "1px solid var(--fr-border)", borderRadius: 10, background: "var(--fr-surface)", font: "700 13px Inter,sans-serif", color: "var(--fr-accent-2)", display: "inline-flex", alignItems: "center", gap: 7 }}>
                <Icon name="file-check" size={16} sw={2.2} color="var(--fr-accent-2)" />{t("Generate report")}
              </button>
              {canEditProject && (
                <button className="clk" onClick={openProjEdit} style={{ height: 42, padding: "0 18px", border: "none", borderRadius: 11, background: "var(--fr-accent-2)", color: "var(--fr-on-accent)", font: "700 13px Inter,sans-serif", display: "flex", alignItems: "center", gap: 8 }}>
                  <Icon name="edit" size={16} color="var(--fr-on-accent)" />{t("Edit")}
                </button>
              )}
            </div>
          </div>
        ) : (
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 20, marginBottom: 22 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12, minWidth: 0 }}>
              <h1 style={{ margin: 0, fontSize: 30, fontWeight: 800, letterSpacing: "-.7px", color: "var(--fr-text)" }}>{sectionLabel}</h1>
              {/* Recon total sits next to the section title; the toolbar below keeps
                  search on the left and filters on the right. */}
              {sec === "hosts" && !_hd && !_ipd && (
                <span style={{ display: "inline-flex", alignItems: "center", gap: 6, font: "600 12.5px Inter,sans-serif", color: "var(--fr-text-2)", background: "var(--fr-surface)", border: "1px solid var(--fr-border-strong)", borderRadius: 20, padding: "5px 13px" }}>{reconTotalLabel} <b className="mono" style={{ color: "var(--fr-text)" }}>{reconTotal}</b></span>
              )}
            </div>
            <div style={{ display: "flex", gap: 10, flex: "none" }}>
              {sec === "hosts" && rv === "hosts" && !state.hostImportOpen && !_hd && (
                <>
                  <button className="clk" onClick={() => openReconExport("hosts")} style={{ height: 42, padding: "0 16px", border: "1px solid var(--fr-border)", borderRadius: 10, background: "var(--fr-surface)", font: "700 13px Inter,sans-serif", color: "var(--fr-accent-2)", display: "inline-flex", alignItems: "center", gap: 7 }}>
                    <Icon name="download" size={16} sw={2.2} color="var(--fr-accent-2)" />{t("Export")}
                  </button>
                  <button className="addbtn clk" onClick={openHostImport} style={{ height: 42 }}>
                    <Icon name="plus" size={15} color="var(--fr-on-accent)" sw={2.6} />{t("Add hosts")}
                  </button>
                </>
              )}
              {/* On the open card the primary action becomes "Edit host" — it takes
                  the slot the "Add hosts"/"Add IPs" button held on the list. */}
              {sec === "hosts" && rv === "hosts" && _hd && (
                <button className="addbtn clk" onClick={() => openEditor("host", "edit", hosts.findIndex((x) => x.id === _hd.id))} style={{ height: 42 }}>
                  <Icon name="edit" size={15} color="var(--fr-on-accent)" sw={2.4} />{t("Edit host")}
                </button>
              )}
              {/* Each recon view adds the kind of object it lists; the totals row
                  below carries that view's filters. */}
              {sec === "hosts" && rv === "ips" && !state.ipImportOpen && !_ipd && (
                <>
                  <button className="clk" onClick={() => openReconExport("ips")} style={{ height: 42, padding: "0 16px", border: "1px solid var(--fr-border)", borderRadius: 10, background: "var(--fr-surface)", font: "700 13px Inter,sans-serif", color: "var(--fr-accent-2)", display: "inline-flex", alignItems: "center", gap: 7 }}>
                    <Icon name="download" size={16} sw={2.2} color="var(--fr-accent-2)" />{t("Export")}
                  </button>
                  <button className="addbtn clk" onClick={openIpImport} style={{ height: 42 }}>
                    <Icon name="plus" size={15} color="var(--fr-on-accent)" sw={2.6} />{t("Add IPs")}
                  </button>
                </>
              )}
              {/* The IP card edits the host the address belongs to. */}
              {sec === "hosts" && rv === "ips" && _ipd && (
                <button className="addbtn clk" onClick={() => openEditor("host", "edit", _ipd.hostIdx)} style={{ height: 42 }}>
                  <Icon name="edit" size={15} color="var(--fr-on-accent)" sw={2.4} />{t("Edit host")}
                </button>
              )}
              {sec === "hosts" && rv === "endpoints" && !state.epImportOpen && (
                <>
                  <button className="clk" onClick={() => openReconExport("endpoints")} style={{ height: 42, padding: "0 16px", border: "1px solid var(--fr-border)", borderRadius: 10, background: "var(--fr-surface)", font: "700 13px Inter,sans-serif", color: "var(--fr-accent-2)", display: "inline-flex", alignItems: "center", gap: 7 }}>
                    <Icon name="download" size={16} sw={2.2} color="var(--fr-accent-2)" />{t("Export")}
                  </button>
                  <button className="addbtn clk" onClick={openEpImport} style={{ height: 42 }}>
                    <Icon name="plus" size={15} color="var(--fr-on-accent)" sw={2.6} />{t("Add endpoints")}
                  </button>
                </>
              )}
              {/* Opens the domain picker rather than scanning straight away, so the
                  label says what the click does: choose what to scan. */}
              {/* Пути и секреты выгружаются раздельно: это разные артефакты и
                  разные потребители, один файл на двоих смысла не имеет. */}
              {sec === "hosts" && rv === "js" && !state.jsScanSetupOpen && !state.exportPageOpen && !_jsd && (
                <>
                  <button className="clk" onClick={() => openReconExport("js-endpoints")} style={{ height: 42, padding: "0 16px", border: "1px solid var(--fr-border)", borderRadius: 10, background: "var(--fr-surface)", font: "700 13px Inter,sans-serif", color: "var(--fr-accent-2)", display: "inline-flex", alignItems: "center", gap: 7 }}>
                    <Icon name="upload" size={15} sw={2.2} color="var(--fr-accent-2)" />{t("Export paths")}
                  </button>
                  <button className="clk" onClick={() => openReconExport("js-secrets")} style={{ height: 42, padding: "0 16px", border: "1px solid var(--fr-border)", borderRadius: 10, background: "var(--fr-surface)", font: "700 13px Inter,sans-serif", color: "var(--fr-accent-2)", display: "inline-flex", alignItems: "center", gap: 7 }}>
                    <Icon name="upload" size={15} sw={2.2} color="var(--fr-accent-2)" />{t("Export secrets")}
                  </button>
                  <button className="addbtn clk" onClick={openJsScanSetup} disabled={isFarmJobInFlight(state.jsFarmJob?.status ?? "")} style={{ height: 42, opacity: isFarmJobInFlight(state.jsFarmJob?.status ?? "") ? 0.6 : 1 }}>
                    <Icon name="search" size={15} color="var(--fr-on-accent)" sw={2.6} />{t("Select domains & scan")}
                  </button>
                </>
              )}
              {sec === "vulns" && state.openVulnId == null && (
                <button className="addbtn clk" onClick={() => openEditor("vuln", "add", -1)} style={{ height: 42 }}><Icon name="plus" size={15} color="var(--fr-on-accent)" sw={2.6} />{t("Add issue")}</button>
              )}
              {sec === "notes" && (
                <button className="addbtn clk" onClick={() => openNoteEditor("add", -1)} style={{ height: 42 }}><Icon name="plus" size={15} color="var(--fr-on-accent)" sw={2.6} />{t("Add note")}</button>
              )}
              {sec === "creds" && (
                <button className="addbtn clk" onClick={() => openEditor("cred", "add", -1)} style={{ height: 42 }}><Icon name="plus" size={15} color="var(--fr-on-accent)" sw={2.6} />{t("Add credential")}</button>
              )}
              {sec === "members" && canManageMembers && (
                <button className="addbtn clk" onClick={() => openEditor("member", "add", -1)} style={{ height: 42 }}><Icon name="plus" size={15} color="var(--fr-on-accent)" sw={2.6} />{t("Add member")}</button>
              )}
            </div>
          </div>
        )}

        <div style={{ width: "100%" }}>
          {sec === "overview" && renderOverview()}
          {sec === "hosts" && renderRecon()}
          {sec === "vulns" && renderVulns()}
          {sec === "notes" && (state.noteEditorOpen ? renderNoteEditor() : state.openNoteId != null ? renderNoteViewer() : renderNotes())}
          {sec === "creds" && renderCreds()}
          {sec === "members" &&
            (canViewMembers
              ? renderMembers()
              : renderNoAccessPage("The team roster is visible to the admin, the project lead and its creator."))}
          {sec === "activity" && renderActivity()}
        </div>
      </div>
    </div>
  );

  const renderNoAccess = (message: string) => (
    <div className="route" style={{ ...CARD, padding: "48px 24px", display: "flex", flexDirection: "column", alignItems: "center", textAlign: "center", gap: 12 }}>
      <div style={{ width: 48, height: 48, borderRadius: 12, background: "var(--fr-hover)", color: "var(--fr-text-faint)", display: "flex", alignItems: "center", justifyContent: "center" }}>
        <Icon name="lock" size={22} sw={1.9} />
      </div>
      <div style={{ font: "700 15px Inter,sans-serif", color: "var(--fr-text)" }}>{t("Restricted")}</div>
      <div style={{ fontSize: 13, color: "var(--fr-text-3)", maxWidth: 360 }}>{message}</div>
    </div>
  );

  /* Shown instead of a whole screen the user may not open: a project the backend
     refuses (403/404), or a section that is not theirs (workspace members, the
     project's team). 404 is folded in on purpose: "not found" and "not yours"
     must be indistinguishable, otherwise the id becomes an existence oracle. */
  const NO_ACCESS_PROJECT = "You don't have access to this project. It's visible to members only — ask an admin or lead to add you to the team.";
  const renderNoAccessPage = (message: string = NO_ACCESS_PROJECT) => (
    <div className="route" style={{ padding: "40px 48px 36px", width: "100%", display: "flex", justifyContent: "center" }}>
      <div style={{ ...CARD, padding: "56px 40px", maxWidth: 520, width: "100%", display: "flex", flexDirection: "column", alignItems: "center", textAlign: "center", gap: 14, marginTop: 40 }}>
        <div style={{ width: 64, height: 64, borderRadius: 16, background: "var(--fr-danger-soft)", color: "var(--fr-danger)", display: "flex", alignItems: "center", justifyContent: "center" }}>
          <Icon name="lock" size={28} sw={1.9} />
        </div>
        <h1 style={{ margin: 0, fontSize: 24, fontWeight: 800, letterSpacing: "-.5px", color: "var(--fr-text)" }}>{t("No access")}</h1>
        <div style={{ fontSize: 14, color: "var(--fr-text-3)", maxWidth: 380, lineHeight: 1.6 }}>{message}</div>
        <button
          className="clk"
          onClick={selProjects}
          style={{ marginTop: 10, height: 42, padding: "0 22px", border: "none", borderRadius: 11, background: "var(--fr-accent-2)", color: "var(--fr-on-accent)", font: "700 13.5px Inter,sans-serif", cursor: "pointer" }}
        >
          {t("Back to projects")}
        </button>
      </div>
    </div>
  );

  const renderOverview = () => (
    <div className="route">
      <div style={{ ...CARD, padding: "20px 22px", marginBottom: 18 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 14 }}>
          <div style={{ font: "700 14px Inter,sans-serif", color: "var(--fr-text)" }}>{t("Engagement timeline")}</div>
          <div className="mono" style={{ fontSize: 12, color: "var(--fr-text-3)" }}>{d.start} → {d.end}</div>
        </div>
        <div style={{ height: 10, borderRadius: 6, background: "var(--fr-bg)", overflow: "hidden" }}>
          <div style={{ width: `${d.progress}%`, height: "100%", background: "linear-gradient(90deg,var(--fr-accent-2),var(--fr-accent-2))", borderRadius: 6 }} />
        </div>
        <div style={{ display: "flex", justifyContent: "space-between", marginTop: 8 }}>
          <span className="mono" style={{ fontSize: 11, color: "var(--fr-text-faint)" }}>{t("Start")}</span>
          <span style={{ font: "600 12px Inter,sans-serif", color: "var(--fr-text-2)" }}>{d.progress}{t("% elapsed")}</span>
          <span className="mono" style={{ fontSize: 11, color: "var(--fr-text-faint)" }}>{t("End")}</span>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(3,minmax(0,1fr))", gap: 14, marginBottom: 18 }}>
        {(() => {
          // Cumulative sparklines over the engagement window — each add pushes the
          // line up. Open vulns / my findings chart the creation time of the very
          // findings that make up the shown count, so the curve lands on that total.
          const wStart = Date.parse(projRow?.startISO ?? "");
          const wEnd = Date.parse(projRow?.endISO ?? "");
          const openVulns = d.vulns.filter((v) => (VSTATUS_OPEN as readonly string[]).includes(v.status));
          const myVulns = d.vulns.filter((v) => v.author === me);
          return [
          { icon: "globe" as const, color: "var(--fr-accent-2)", label: "Hosts", value: hosts.length, spark: cumulativeSpark(hosts.map((h) => h.created), wStart, wEnd), stroke: "var(--fr-accent-2)", onClick: () => setSection("hosts") },
          { icon: "alert-triangle" as const, color: "var(--fr-danger)", label: "Open vulns", value: openVulnCount, spark: cumulativeSpark(openVulns.map((v) => v.created), wStart, wEnd), stroke: "var(--fr-danger)", onClick: goToOpenVulns },
          { icon: "star" as const, color: "var(--fr-purple)", label: "My findings", value: myFindingsCount, spark: cumulativeSpark(myVulns.map((v) => v.created), wStart, wEnd), stroke: "var(--fr-purple)", onClick: goToMyFindings },
          ];
        })().map((c) => (
          <div key={c.label} className="statc clk" onClick={c.onClick} style={{ ...CARD, padding: "16px 18px", cursor: "pointer" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--fr-text-3)", font: "600 11.5px Inter,sans-serif", letterSpacing: ".5px", textTransform: "uppercase" }}>
              <Icon name={c.icon} size={15} color={c.color} sw={2.1} />{c.label}
            </div>
            <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", marginTop: 8 }}>
              <div className="mono" style={{ fontWeight: 800, fontSize: 26, color: "var(--fr-text)", lineHeight: 1, letterSpacing: "-1px" }}>{c.value}</div>
              <svg height="30" viewBox="0 0 111 30" preserveAspectRatio="none" fill="none" style={{ flex: 1, minWidth: 0, width: "100%", maxWidth: 100, marginLeft: 14 }}>
                <polygon points={sparkArea(c.spark, 111)} fill={c.stroke} fillOpacity={0.15} />
                <polyline points={c.spark} stroke={c.stroke} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
              </svg>
            </div>
          </div>
        ))}
      </div>

      <div style={{ ...CARD, padding: "20px 22px", marginBottom: 18 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
          <div style={{ font: "700 14px Inter,sans-serif", color: "var(--fr-text)" }}>{t("Vulnerabilities across the project")}</div>
          <span className="clk" onClick={() => setSection("vulns")} style={{ font: "600 12px Inter,sans-serif", color: "var(--fr-accent-2)" }}>{t("View all →")}</span>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5,minmax(0,1fr))", gap: 12 }}>
          {sevBars.map((b) => (
            <div key={b.label} className="clk" onClick={b.onClick} style={{ border: "1px solid var(--fr-bg)", borderRadius: 13, padding: "15px 16px", background: b.tileBg, cursor: "pointer" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                <span style={{ width: 9, height: 9, borderRadius: 3, background: b.color }} />
                <span style={{ font: "700 10.5px Inter,sans-serif", textTransform: "uppercase", letterSpacing: ".5px", color: b.color }}>{b.label}</span>
              </div>
              <div className="mono" style={{ fontSize: 30, fontWeight: 800, color: "var(--fr-text)", marginTop: 10, lineHeight: 1 }}>{b.count}</div>
            </div>
          ))}
        </div>
      </div>

      {canViewMembers && (
        <div style={{ ...CARD, padding: "20px 22px", marginBottom: 18 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
            <div style={{ font: "700 14px Inter,sans-serif", color: "var(--fr-text)" }}>{t("Team")}</div>
            <span className="clk" onClick={() => setSection("members")} style={{ font: "600 12px Inter,sans-serif", color: "var(--fr-accent-2)" }}>{canManageMembers ? "Manage →" : "View all →"}</span>
          </div>
          {d.members.map((m, i) => (
            <div key={m.name + i} style={{ display: "flex", alignItems: "center", gap: 11, padding: "7px 0", borderTop: "1px solid var(--fr-divider)" }}>
              <span className="mono" style={{ width: 30, height: 30, flex: "none", borderRadius: "50%", background: m.color, color: "var(--fr-on-accent)", display: "flex", alignItems: "center", justifyContent: "center", font: "700 11px 'JetBrains Mono',monospace" }}>{m.initials}</span>
              <div style={{ minWidth: 0 }}>
                <div style={{ font: "600 13px Inter,sans-serif", color: "var(--fr-text)" }}>{m.name}</div>
                <div className="mono" style={{ fontSize: 11, color: "var(--fr-text-faint)" }}>{m.role}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );

  /* One pill per port holds BOTH the port and its status in a single highlight.
     A down host shows "down" per port; an up host shows the probed HTTP code. */
  const portPills = (ports: Host["ports"], hostDown = false) => (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
      {portPillsOf(ports).map((p, i) => {
        const statusText = hostDown ? "down" : p.http != null ? String(p.http) : null;
        const statusColor = hostDown ? "var(--fr-danger)" : p.http != null ? httpStatusColor(p.http) : undefined;
        return (
          <span key={i} className="mono" style={{ display: "inline-flex", alignItems: "center", gap: 5, fontSize: 11, fontWeight: 700, borderRadius: 6, padding: "2px 8px", background: p.bg, color: p.color }}>
            <span>{p.label}</span>
            {statusText != null && (
              <>
                <span style={{ opacity: 0.55 }}>-</span>
                <span style={{ color: statusColor }}>{statusText}</span>
              </>
            )}
          </span>
        );
      })}
      {/* A down host with no probed ports still shows a "down" chip in the ports column. */}
      {hostDown && ports.length === 0 && (
        <span className="mono" style={{ fontSize: 11, fontWeight: 700, borderRadius: 6, padding: "2px 8px", background: "var(--fr-danger-soft)", color: "var(--fr-danger)" }}>down</span>
      )}
    </div>
  );

  /** Признак Cloudflare чипом (трёхзначно): true подсвечен, false приглушён,
   *  null («unknown») — самый бледный: хост ещё пробится, признак не определён. */
  const cloudflarePill = (state: CfState) => (
    <span
      className="mono"
      style={{
        display: "inline-block",
        fontSize: 11,
        fontWeight: 700,
        borderRadius: 6,
        padding: "2px 8px",
        background: state === true ? "var(--fr-warn-soft)" : "var(--fr-elevated)",
        color:
          state === true ? "var(--fr-warn)" : state === null ? "var(--fr-text-faint)" : "var(--fr-text-3)",
      }}
    >
      {state === null ? "unknown" : String(state)}
    </span>
  );

  /* Имена, в которые резолвится адрес — серыми чипами по образцу портов: один
     адрес часто отдаёт несколько имён, и перечисление через запятую в узкой
     ячейке читается хуже, чем набор плашек. Неподтверждённые (PTR без обратного
     подтверждения) — приглушены и подписаны в title. */
  const hostnamePills = (names: { hostname: string; source: string; confirmed: boolean }[]) => {
    if (names.length === 0) return <span style={{ color: "var(--fr-text-faint)", fontSize: 12.5 }}>—</span>;
    return (
      <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
        {names.map((n) => (
          <span
            key={n.hostname}
            className="mono"
            title={n.confirmed ? undefined : t("unconfirmed")}
            style={{
              fontSize: 11,
              fontWeight: 700,
              borderRadius: 6,
              padding: "2px 8px",
              background: "var(--fr-elevated)",
              color: n.confirmed ? "var(--fr-text-2)" : "var(--fr-text-faint)",
              opacity: n.confirmed ? 1 : 0.75,
            }}
          >
            {n.hostname}
          </span>
        ))}
      </div>
    );
  };

  /* "Add hosts" is a full page (not a modal): paste a list, submit, and the server
     creates the hosts up front + probes them in the background. On submit we return
     to the list and statuses fill in live (see the poll effect + the probing banner). */
  /* One page, two farms. The IPs view used to open this very page verbatim, which
     is why "Add IPs" led to something titled "Add hosts" — the label was not the
     bug, the whole page was reused. Parameterised instead of copied so the two
     stay in step. */
  const renderImportPage = (cfg: {
    title: string;
    pasteLabel: string;
    placeholder: string;
    previewPlaceholder: string;
    raw: string;
    preview: string;
    busy: boolean;
    submitLabel?: string;
    busyLabel?: string;
    onRaw: (v: string) => void;
    onPreview: (v: string) => void;
    onCancel: () => void;
    onSubmit: () => void;
  }) => {
    const previewCount = cfg.preview.split(/\r?\n/).filter((l) => l.trim()).length;
    const fillArea: CSSProperties = { flex: 1, minHeight: 0, resize: "none", width: "100%", fontFamily: "ui-monospace,Menlo,monospace", fontSize: 13 };
    const paneCol: CSSProperties = { display: "flex", flexDirection: "column", minHeight: 0 };
    return (
      // Fills the whole section area: the two textareas grow to take all remaining height.
      <div className="route" style={{ ...CARD, padding: 0, overflow: "hidden", display: "flex", flexDirection: "column", height: "calc(100vh - 260px)" }}>
        <div style={{ flex: "none", display: "flex", alignItems: "center", gap: 10, padding: "16px 22px", borderBottom: "1px solid var(--fr-divider)" }}>
          <span className="clk" onClick={cfg.onCancel} style={{ display: "flex", color: "var(--fr-text-3)", cursor: "pointer" }}><Icon name="chevron-left" size={20} /></span>
          <h2 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: "var(--fr-text)" }}>{cfg.title}</h2>
        </div>
        <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", padding: "18px 22px 20px" }}>
          <div style={{ flex: 1, minHeight: 0, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            <div style={paneCol}>
              <label className="flabel">{cfg.pasteLabel}</label>
              <textarea className="finp" placeholder={cfg.placeholder} value={cfg.raw} onChange={(e) => cfg.onRaw(e.target.value)} style={fillArea} />
            </div>
            <div style={paneCol}>
              <label className="flabel">{t("Will be imported")}{previewCount ? ` (${previewCount})` : ""}</label>
              <textarea className="finp" placeholder={cfg.previewPlaceholder} value={cfg.preview} onChange={(e) => cfg.onPreview(e.target.value)} style={fillArea} />
            </div>
          </div>
          <div style={{ flex: "none", display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 16 }}>
            <button className="clk" onClick={cfg.onCancel} style={{ height: 42, padding: "0 20px", border: "1px solid var(--fr-border)", borderRadius: 11, background: "var(--fr-surface)", font: "700 13.5px Inter,sans-serif", color: "var(--fr-text-2)" }}>{t("Cancel")}</button>
            <button className="clk" onClick={cfg.onSubmit} style={{ height: 42, padding: "0 22px", border: "none", borderRadius: 11, background: "var(--fr-accent-2)", color: "var(--fr-on-accent)", font: "700 13.5px Inter,sans-serif" }}>{cfg.busy ? (cfg.busyLabel ?? t("Starting…")) : (cfg.submitLabel ?? t("Probe & add"))}</button>
          </div>
        </div>
      </div>
    );
  };

  const renderHostImport = () =>
    renderImportPage({
      title: t("Add hosts"),
      pasteLabel: t("Paste hosts"),
      placeholder: "https://example.com\nwww.example.com\napp.example.com\napi.example.com:8443\nadmin.acme-corp.com\nstaging.example.org",
      previewPlaceholder: t("parsed hosts appear here…"),
      raw: state.hostImportRaw,
      preview: state.hostImportPreview,
      busy: state.hostImportBusy,
      onRaw: (v) => setState({ hostImportRaw: v, hostImportPreview: normalizeHostList(v) }),
      onPreview: (v) => setState({ hostImportPreview: v }),
      onCancel: closeHostImport,
      onSubmit: submitHostImport,
    });

  const renderIpImport = () =>
    renderImportPage({
      title: t("Add IPs"),
      pasteLabel: t("Paste IPs"),
      placeholder: "1.2.3.4\n1.2.3.4:8443\nhttps://5.6.7.8:443",
      previewPlaceholder: t("parsed IPs appear here…"),
      raw: state.ipImportRaw,
      preview: state.ipImportPreview,
      busy: state.ipImportBusy,
      onRaw: (v) => setState({ ipImportRaw: v, ipImportPreview: normalizeIpList(v) }),
      onPreview: (v) => setState({ ipImportPreview: v }),
      onCancel: closeIpImport,
      onSubmit: submitIpImport,
    });

  const renderEpImport = () =>
    renderImportPage({
      title: t("Add endpoints"),
      pasteLabel: t("Paste endpoints"),
      placeholder: "https://api.example.com/v1/login\nhttps://example.com/admin\nPOST https://example.com/api/users",
      previewPlaceholder: t("parsed endpoints appear here…"),
      submitLabel: t("Add endpoints"),
      busyLabel: t("Adding…"),
      raw: state.epImportRaw,
      preview: state.epImportPreview,
      busy: state.epImportBusy,
      onRaw: (v) => setState({ epImportRaw: v, epImportPreview: normalizeEpList(v) }),
      onPreview: (v) => setState({ epImportPreview: v }),
      onCancel: closeEpImport,
      onSubmit: submitEpImport,
    });

  const searchBox = (placeholder: string, value: string, onChange: (v: string) => void, width: number | string = 280) => (
    <label className="fq" style={{ position: "relative", display: "flex", alignItems: "center", width }}>
      <svg style={{ position: "absolute", left: 13 }} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--fr-text-faint)" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="7" /><path d="M21 21l-4-4" /></svg>
      <input placeholder={placeholder} value={value} onChange={(e) => onChange(e.target.value)} />
    </label>
  );

  const filterPill = (label: string, on: boolean, onClick: () => void) => (
    <div key={label} className="clk" onClick={onClick} style={{ font: "600 12px Inter,sans-serif", padding: "6px 12px", borderRadius: 20, cursor: "pointer", ...vfPill(on) }}>{label}</div>
  );

  /** Группа пилюль Cloudflare — одна на таблицы хостов и IP. Выбор взаимо-
   *  исключающий: true и false вместе — это и есть All, поэтому повторный клик
   *  по активной пилюле возвращает в All. Метки — те же true/false, что в колонке. */
  const cfFilterGroup = (value: "" | "yes" | "no", onChange: (v: "" | "yes" | "no") => void) => (
    <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
      <span style={{ font: "700 11px Inter,sans-serif", letterSpacing: ".5px", textTransform: "uppercase", color: "var(--fr-text-faint)" }}>{t("Cloudflare")}</span>
      {filterPill(t("All"), value === "", () => onChange(""))}
      {filterPill("true", value === "yes", () => onChange(value === "yes" ? "" : "yes"))}
      {filterPill("false", value === "no", () => onChange(value === "no" ? "" : "no"))}
    </div>
  );

  /* The recon filter rows. The export page renders the same row as the view it
     exports — sharing one definition is what keeps the two from ever disagreeing
     about which rows are selected. Empty pill selection means All. */
  const reconFilterRow = (view: ReconView) => {
    if (view === "ips") {
      // One box matches either column of the row: the address or its host.
      return (
        <div style={{ display: "flex", alignItems: "center", gap: 9, marginBottom: 16, flexWrap: "wrap" }}>
          {searchBox(t("Filter by IP or host…"), state.ipQuery, (v) => setState({ ipQuery: v }))}
          <div style={{ flex: 1 }} />
          {cfFilterGroup(state.ipCfFilter, (v) => setState({ ipCfFilter: v }))}
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            <span style={{ font: "700 11px Inter,sans-serif", letterSpacing: ".5px", textTransform: "uppercase", color: "var(--fr-text-faint)" }}>{t("Status")}</span>
            {filterPill(t("All"), state.ipFilters.length === 0, () => setState({ ipFilters: [] }))}
            {STATUS_FILTER_KEYS.map((k) => filterPill(k, state.ipFilters.includes(k), () => setState((s) => ({ ipFilters: toggleIn(s.ipFilters, k) }))))}
          </div>
        </div>
      );
    }
    if (view === "endpoints") {
      /* Host and path get separate boxes: they are different questions ("everything
         on this host" vs "where is /login"), so one combined box would answer neither. */
      return (
        <div style={{ display: "flex", alignItems: "center", gap: 9, marginBottom: 16, flexWrap: "wrap" }}>
          {searchBox(t("Filter by host…"), state.epHostQuery, (v) => setState({ epHostQuery: v }), 190)}
          {searchBox(t("Filter by endpoint…"), state.epPathQuery, (v) => setState({ epPathQuery: v }), 190)}
          <div style={{ flex: 1 }} />
          {/* Подписан так же, как Status и Cloudflare, — иначе единственный ряд
             пилюль без заголовка читается как «непонятно что фильтрует». */}
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            <span style={{ font: "700 11px Inter,sans-serif", letterSpacing: ".5px", textTransform: "uppercase", color: "var(--fr-text-faint)" }}>{t("Method")}</span>
            {filterPill(t("All"), state.epMethods.length === 0, () => setState({ epMethods: [] }))}
            {FROST_METHODS.map((m) => filterPill(m, state.epMethods.includes(m), () => setState((s) => ({ epMethods: toggleIn(s.epMethods, m) }))))}
          </div>
        </div>
      );
    }
    if (view === "js") {
      return (
        <div style={{ display: "flex", alignItems: "center", gap: 9, marginBottom: 16, flexWrap: "wrap" }}>
          {searchBox(t("Filter by JS URL or host…"), state.jsQuery, (v) => setState({ jsQuery: v }))}
          <div style={{ flex: 1 }} />
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            <span style={{ font: "700 11px Inter,sans-serif", letterSpacing: ".5px", textTransform: "uppercase", color: "var(--fr-text-faint)" }}>{t("Secrets")}</span>
            {filterPill(t("All"), !state.jsSecretsOnly, () => setState({ jsSecretsOnly: false }))}
            {filterPill(t("With secrets"), state.jsSecretsOnly, () => setState({ jsSecretsOnly: true }))}
          </div>
        </div>
      );
    }
    return (
      <div style={{ display: "flex", alignItems: "center", gap: 9, marginBottom: 16, flexWrap: "wrap" }}>
        {searchBox(t("Filter by host…"), state.hostQuery, (v) => setState({ hostQuery: v }))}
        <div style={{ flex: 1 }} />
        {cfFilterGroup(state.hostCfFilter, (v) => setState({ hostCfFilter: v }))}
        {/* Label + pills share one flex gap so the spacing between filters is equal. */}
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          <span style={{ font: "700 11px Inter,sans-serif", letterSpacing: ".5px", textTransform: "uppercase", color: "var(--fr-text-faint)" }}>{t("Status")}</span>
          {filterPill(t("All"), state.hostFilters.length === 0, () => setState({ hostFilters: [] }))}
          {STATUS_FILTER_KEYS.map((k) => filterPill(k, state.hostFilters.includes(k), () => setState((s) => ({ hostFilters: toggleIn(s.hostFilters, k) }))))}
        </div>
      </div>
    );
  };

  /* Recon export: the same two-pane shape as "Add hosts". The left pane is the full
     list the filters leave on screen; the right pane is that list, editable. Deleting
     a row on the right drops it from the left too — the left only renders lines that
     survive on the right, so the two can't drift apart. The filter row sits above the
     card, where every other section keeps its filters, and it is the *same* row the
     list view renders: narrowing it there narrows what lands here. */
  const renderExport = () => {
    const scope = state.exportScope;
    const title =
      scope === "hosts" ? t("Export hosts")
      : scope === "ips" ? t("Export IP addresses")
      : scope === "js-endpoints" ? t("Export JS paths")
      : scope === "js-secrets" ? t("Export JS secrets")
      : t("Export endpoints");
    const kept = new Set(exportTextLines(state.exportText));
    const left = exportLinesFor(scope).filter((l) => kept.has(l));
    const keptCount = exportTextLines(state.exportText).length;
    const fillArea: CSSProperties = { flex: 1, minHeight: 0, resize: "none", width: "100%", fontFamily: "ui-monospace,Menlo,monospace", fontSize: 13 };
    const paneCol: CSSProperties = { display: "flex", flexDirection: "column", minHeight: 0 };
    return (
      <div className="route">
        {/* У JS-выгрузки из карточки файла набор задан самим файлом — фильтры
            списка к нему отношения не имеют и только сбивали бы с толку. */}
        {!(scope.startsWith("js-") && _jsd) &&
          reconFilterRow(
            scope === "ips" ? "ips"
            : scope === "endpoints" ? "endpoints"
            : scope.startsWith("js-") ? "js"
            : "hosts",
          )}
        {/* Height leaves room for the filter row the card now sits under. */}
        <div style={{ ...CARD, padding: 0, overflow: "hidden", display: "flex", flexDirection: "column", height: "calc(100vh - 318px)" }}>
          <div style={{ flex: "none", display: "flex", alignItems: "center", gap: 10, padding: "16px 22px", borderBottom: "1px solid var(--fr-divider)" }}>
            <span className="clk" onClick={closeReconExport} style={{ display: "flex", color: "var(--fr-text-3)", cursor: "pointer" }}><Icon name="chevron-left" size={20} /></span>
            <h2 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: "var(--fr-text)" }}>{title}</h2>
          </div>
          <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", padding: "18px 22px 20px" }}>
            <div style={{ flex: 1, minHeight: 0, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              <div style={paneCol}>
                <label className="flabel">{t("Found")}{left.length ? ` (${left.length})` : ""}</label>
                <textarea className="finp" readOnly value={left.join("\n")} style={{ ...fillArea, background: "var(--fr-sunken)", color: "var(--fr-text-2)" }} />
              </div>
              <div style={paneCol}>
                <label className="flabel">{t("Will be exported")}{keptCount ? ` (${keptCount})` : ""}</label>
                <textarea
                  className="finp"
                  value={state.exportText}
                  onChange={(e) => setState({ exportText: e.target.value })}
                  style={fillArea}
                />
              </div>
            </div>
            <div style={{ flex: "none", display: "flex", alignItems: "center", gap: 10, marginTop: 16 }}>
              {/* Endpoints can also go out as an OpenAPI doc, rebuilt from these lines. */}
              {scope === "endpoints" && (
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  {filterPill(t("List"), state.exportFormat === "list", () => setState({ exportFormat: "list" }))}
                  {filterPill(t("Swagger (OpenAPI 3)"), state.exportFormat === "openapi", () => setState({ exportFormat: "openapi" }))}
                </div>
              )}
              <div style={{ flex: 1 }} />
              <button className="clk" onClick={closeReconExport} style={{ height: 42, padding: "0 20px", border: "1px solid var(--fr-border)", borderRadius: 11, background: "var(--fr-surface)", font: "700 13.5px Inter,sans-serif", color: "var(--fr-text-2)" }}>{t("Cancel")}</button>
              <button className="clk" onClick={doReconExport} disabled={keptCount === 0} style={{ height: 42, padding: "0 22px", border: "none", borderRadius: 11, background: keptCount === 0 ? "var(--fr-accent-muted)" : "var(--fr-accent-2)", color: "var(--fr-on-accent)", font: "700 13.5px Inter,sans-serif", cursor: keptCount === 0 ? "default" : "pointer" }}>{t("Download")}</button>
            </div>
          </div>
        </div>
      </div>
    );
  };

  /* Domain picker shown before a JS scan — the same two-pane shape as the export
     page: the host filter row narrows the "Found" list, the editable right pane is
     the exact set that goes to the scan. Starting the scan sends that list verbatim. */
  const renderJsScanSetup = () => {
    const kept = new Set(exportTextLines(state.jsScanText));
    const found = jsScanDomains().filter((d) => kept.has(d));
    const keptCount = exportTextLines(state.jsScanText).length;
    const fillArea: CSSProperties = { flex: 1, minHeight: 0, resize: "none", width: "100%", fontFamily: "ui-monospace,Menlo,monospace", fontSize: 13 };
    const paneCol: CSSProperties = { display: "flex", flexDirection: "column", minHeight: 0 };
    return (
      <div className="route">
        {reconFilterRow("hosts")}
        <div style={{ ...CARD, padding: 0, overflow: "hidden", display: "flex", flexDirection: "column", height: "calc(100vh - 318px)" }}>
          <div style={{ flex: "none", display: "flex", alignItems: "center", gap: 10, padding: "16px 22px", borderBottom: "1px solid var(--fr-divider)" }}>
            <span className="clk" onClick={closeJsScanSetup} style={{ display: "flex", color: "var(--fr-text-3)", cursor: "pointer" }}><Icon name="chevron-left" size={20} /></span>
            <h2 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: "var(--fr-text)" }}>{t("Choose domains to scan")}</h2>
          </div>
          <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column", padding: "18px 22px 20px" }}>
            <div style={{ flex: 1, minHeight: 0, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              <div style={paneCol}>
                <label className="flabel">{t("Found")}{found.length ? ` (${found.length})` : ""}</label>
                <textarea className="finp" readOnly value={found.join("\n")} style={{ ...fillArea, background: "var(--fr-sunken)", color: "var(--fr-text-2)" }} />
              </div>
              <div style={paneCol}>
                <label className="flabel">{t("Will be scanned")}{keptCount ? ` (${keptCount})` : ""}</label>
                <textarea
                  className="finp"
                  placeholder={t("one domain per line…")}
                  value={state.jsScanText}
                  onChange={(e) => setState({ jsScanText: e.target.value })}
                  style={fillArea}
                />
              </div>
            </div>
            <div style={{ flex: "none", display: "flex", alignItems: "center", gap: 10, marginTop: 16 }}>
              <div style={{ flex: 1 }} />
              <button className="clk" onClick={closeJsScanSetup} style={{ height: 42, padding: "0 20px", border: "1px solid var(--fr-border)", borderRadius: 11, background: "var(--fr-surface)", font: "700 13.5px Inter,sans-serif", color: "var(--fr-text-2)" }}>{t("Cancel")}</button>
              <button className="clk" onClick={submitJsScan} disabled={keptCount === 0} style={{ height: 42, padding: "0 22px", border: "none", borderRadius: 11, background: keptCount === 0 ? "var(--fr-accent-muted)" : "var(--fr-accent-2)", color: "var(--fr-on-accent)", font: "700 13.5px Inter,sans-serif", cursor: keptCount === 0 ? "default" : "pointer", display: "inline-flex", alignItems: "center", gap: 8 }}>
                <Icon name="search" size={15} color="var(--fr-on-accent)" sw={2.6} />{t("Start scan")}
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  };

  const renderRecon = () => {
    if (state.exportPageOpen) return renderExport();
    if (rv === "js" && state.jsScanSetupOpen) return renderJsScanSetup();
    if (rv === "ips") {
      if (state.ipImportOpen) return renderIpImport();
      if (_ipd) return renderIpDetail(_ipd);
      const ipFarmRunning = isFarmJobInFlight(state.ipFarmJob?.status ?? "");
      // Grid shared by the header and every row — Status is gone, Cloudflare took its place.
      const ipGrid = "minmax(0,1fr) minmax(0,1.4fr) minmax(0,1fr) 104px 72px";
      return (
        <div className="route">
          {reconFilterRow("ips")}
          {/* Та же плашка, что у фермы хостов: синяя, со спиннером. */}
          {ipFarmRunning && (
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14, padding: "11px 16px", borderRadius: 12, background: "var(--fr-accent-soft)", color: "var(--fr-accent)", font: "600 12.5px Inter,sans-serif" }}>
              <span className="frost-spin" style={{ width: 14, height: 14, borderRadius: "50%", border: "2px solid var(--fr-accent)", borderTopColor: "transparent", display: "inline-block" }} />
              {t("Probing")} {state.ipFarmJob?.targets_total ?? ""} {t("IPs — hostnames and ports update automatically.")}
            </div>
          )}
          <div style={{ ...CARD, overflow: "hidden" }}>
            {/* No column headers over an empty table (same as the hosts table). */}
            {ipsRows.length > 0 && (
              <div style={{ display: "grid", gridTemplateColumns: ipGrid, gap: 14, padding: "13px 20px", borderBottom: "1px solid var(--fr-divider)", font: "700 11px Inter,sans-serif", letterSpacing: ".6px", color: "var(--fr-text-faint)", textTransform: "uppercase" }}>
                <div>{t("IP address")}</div><div>{t("Hostname")}</div><div>{t("Ports")}</div><div>{t("Cloudflare")}</div><div />
              </div>
            )}
            {ipsRows.map((i, idx) => (
              <div key={idx} className="prow clk" onClick={() => openIpDetail(i.ip)} style={{ display: "grid", gridTemplateColumns: ipGrid, gap: 14, alignItems: "center", padding: "14px 20px", borderBottom: "1px solid var(--fr-divider)" }}>
                <div style={{ minWidth: 0 }}>
                  <span className="mono hostname" style={{ font: "700 13.5px 'JetBrains Mono',monospace", color: "var(--fr-text)", cursor: "pointer" }}>{i.ip}</span>
                </div>
                {/* Every name the address resolves to, on the one row. Unconfirmed
                    names (PTR with no matching forward record) are dimmed, not hidden. */}
                <div style={{ minWidth: 0 }} title={i.names.map((n) => n.hostname).join(", ")}>{hostnamePills(i.names)}</div>
                <div style={{ minWidth: 0 }}>{portPills(i.ports, i.status === "down")}</div>
                <div>{cloudflarePill(i.cloudflare)}</div>
                <div style={{ display: "flex", justifyContent: "flex-end", gap: 2 }}>
                  <div className="actbtn" onClick={i.onEdit}><Icon name="edit" size={15} /></div>
                  <div className="actbtn del" onClick={i.onDelete}><Icon name="trash" size={15} /></div>
                </div>
              </div>
            ))}
            {ipsRows.length === 0 && <div style={{ padding: 52, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 14 }}>{t("No IPs found.")}</div>}
          </div>
        </div>
      );
    }
    if (rv === "endpoints") {
      if (state.epImportOpen) return renderEpImport();
      return (
        <div className="route">
          {reconFilterRow("endpoints")}
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {endpointGroups.map((g) => (
              <div key={g.host} style={{ background: "var(--fr-surface)", border: "1px solid var(--fr-border-light)", borderRadius: 14, overflow: "hidden" }}>
                <div className="prow clk" onClick={() => toggleEpGroup(g.host)} style={{ display: "flex", alignItems: "center", gap: 12, padding: "14px 18px" }}>
                  <Icon name="chevron-right" size={15} color="var(--fr-text-faint)" sw={2.4} style={{ transform: g.expanded ? "rotate(90deg)" : "none", transition: "transform .2s" }} />
                  <Icon name="globe2" size={16} color="var(--fr-text-3)" />
                  <span className="mono" style={{ font: "700 14px 'JetBrains Mono',monospace", color: "var(--fr-text)", flex: 1 }}>{g.host}</span>
                  <span className="mono" style={{ fontSize: 11.5, fontWeight: 700, color: "var(--fr-text-2)", background: "var(--fr-hover)", borderRadius: 7, padding: "3px 9px" }}>{g.count}</span>
                </div>
                {g.expanded && (
                  <div style={{ borderTop: "1px solid var(--fr-divider)", animation: "frost-fade .2s ease both" }}>
                    <div style={{ display: "grid", gridTemplateColumns: "72px minmax(0,1fr) 96px", gap: 10, padding: "11px 20px 11px 50px", borderBottom: "1px solid var(--fr-divider)", font: "700 10.5px Inter,sans-serif", letterSpacing: ".5px", color: "var(--fr-text-faint)", textTransform: "uppercase" }}>
                      <div>{t("Method")}</div><div>{t("Path")}</div><div />
                    </div>
                    {g.endpoints.map((e: Endpoint, i: number) => {
                      const m = METHOD[e.m] ?? PORT.closed;
                      return (
                        <div key={i} className="prow clk" onClick={() => openEndpoint({ method: e.m, path: e.p, host: g.host, hostId: g.hostId, endpointId: e.id })} style={{ display: "grid", gridTemplateColumns: "72px minmax(0,1fr) 96px", alignItems: "center", gap: 10, padding: "11px 20px 11px 50px", borderBottom: "1px solid var(--fr-elevated)" }}>
                          <span className="mono" style={{ justifySelf: "start", fontWeight: 700, borderRadius: 5, padding: "2px 8px", fontSize: 10.5, background: m.bg, color: m.color }}>{e.m}</span>
                          <div className="mono" style={{ fontSize: 12.5, color: "var(--fr-text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.p}</div>
                          <div style={{ display: "flex", justifyContent: "flex-end", gap: 2 }}>
                            <Tip label={t("Copy as cURL")}><div className="actbtn" onClick={(ev) => { ev.stopPropagation(); copyCurl({ method: e.m, path: e.p, host: g.host }); }}><Icon name="copy" size={15} /></div></Tip>
                            <Tip label={t("Delete endpoint")}><div className="actbtn del" onClick={(ev) => { ev.stopPropagation(); void deleteEndpoint(g.hostId, e.id); }}><Icon name="trash" size={15} /></div></Tip>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            ))}
            {endpointTotal === 0 && <div style={{ padding: 52, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 14, background: "var(--fr-surface)", border: "1px solid var(--fr-border-light)", borderRadius: 14 }}>{t("No endpoints discovered.")}</div>}
          </div>
        </div>
      );
    }
    if (rv === "js") {
      if (_jsd) return renderJsFileDetail(_jsd);
      const jsRunning = isFarmJobInFlight(state.jsFarmJob?.status ?? "");
      /* Та же сетка, что у таблицы хостов: домен — раскрывающаяся строка, файлы
         под ним — вложенные, как поддомены. Раньше это были отдельные карточки на
         домен, и раздел выпадал из общего стиля раздела Recon. */
      const jsGrid = "24px minmax(0,1.6fr) 96px 96px 96px";
      return (
        <div className="route">
          {reconFilterRow("js")}
          {/* Same blue in-flight banner as the host/IP farms. */}
          {jsRunning && (
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14, padding: "11px 16px", borderRadius: 12, background: "var(--fr-accent-soft)", color: "var(--fr-accent)", font: "600 12.5px Inter,sans-serif" }}>
              <span className="frost-spin" style={{ width: 14, height: 14, borderRadius: "50%", border: "2px solid var(--fr-accent)", borderTopColor: "transparent", display: "inline-block" }} />
              {t("Scanning")} {state.jsFarmJob?.targets_total ?? ""} {t("domains — secrets and paths appear as files are scanned.")}
            </div>
          )}
          <div style={{ ...CARD, overflow: "hidden" }}>
            {jsGroups.length > 0 && (
              <div style={{ display: "grid", gridTemplateColumns: jsGrid, gap: 14, padding: "12px 20px", borderBottom: "1px solid var(--fr-divider)", font: "700 11px Inter,sans-serif", letterSpacing: ".5px", color: "var(--fr-text-faint)", textTransform: "uppercase" }}>
                <div /><div>{t("Host")}</div><div>{t("Files")}</div><div>{t("Secrets")}</div><div />
              </div>
            )}
            {jsGroups.map((g) => {
              const exp = state.epExpanded.includes(`js:host:${g.host}`);
              const groupSecrets = g.files.reduce((n, f) => n + f.secrets.length, 0);
              return (
                <div key={g.host} style={{ borderBottom: "1px solid var(--fr-divider)" }}>
                  <div className="prow clk" onClick={() => toggleJsGroup(g.host)} style={{ display: "grid", gridTemplateColumns: jsGrid, alignItems: "center", gap: 14, padding: "15px 20px" }}>
                    <Icon name="chevron-right" size={15} color="var(--fr-text-faint)" sw={2.4} style={{ transform: exp ? "rotate(90deg)" : "none", transition: "transform .2s" }} />
                    <span className="mono hostname" style={{ font: "700 14px 'JetBrains Mono',monospace", color: "var(--fr-text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{g.host}</span>
                    <span className="mono" style={{ fontSize: 12, color: "var(--fr-text-2)" }}>{g.count} {t("files")}</span>
                    <span className="mono" style={{ fontSize: 12, fontWeight: 700, color: groupSecrets ? "var(--fr-danger)" : "var(--fr-text-faint)" }}>{groupSecrets}</span>
                    <div style={{ display: "flex", justifyContent: "flex-end", gap: 2 }}>
                      {/* Re-downloads this host's .js into a zip (files aren't stored). */}
                      <Tip label={t("Download JS archive")}><div className="actbtn" onClick={(ev) => { ev.stopPropagation(); downloadJsArchive(g.hostId, g.host); }}><Icon name="download" size={15} /></div></Tip>
                    </div>
                  </div>
                  {exp && (
                    <div style={{ background: "var(--fr-elevated)", animation: "frost-fade .2s ease both" }}>
                      {g.files.map((file) => (
                        <div key={file.id} className="prow clk" onClick={() => openJsFile(file.id)} style={{ display: "grid", gridTemplateColumns: jsGrid, alignItems: "center", gap: 14, padding: "13px 20px 13px 44px", borderTop: "1px solid var(--fr-divider)" }}>
                          <span />
                          <span className="mono hostname" title={file.url} style={{ font: "600 13px 'JetBrains Mono',monospace", color: file.status === "ok" ? "var(--fr-text)" : "var(--fr-text-faint)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", cursor: "pointer" }}>{fileBase(file.url)}</span>
                          <span className="mono" style={{ fontSize: 11.5, color: "var(--fr-text-3)" }}>{file.endpoints.length} {t("paths")}</span>
                          <span className="mono" style={{ fontSize: 11.5, fontWeight: 700, color: file.secrets.length ? "var(--fr-danger)" : "var(--fr-text-faint)" }}>{file.secrets.length}</span>
                          <span className="mono" style={{ fontSize: 11, color: "var(--fr-text-faint)", textAlign: "right" }}>{file.status === "ok" ? kb(file.size) : file.status}</span>
                        </div>
                      ))}
                      {g.files.length === 0 && (
                        <div style={{ padding: "13px 20px 13px 44px", borderTop: "1px solid var(--fr-divider)", font: "500 12.5px Inter,sans-serif", color: "var(--fr-text-faint)" }}>{t("No JS files on this host.")}</div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
            {state.apiJsFiles === null && <div style={{ padding: 52, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 14 }}>{t("Loading JS files…")}</div>}
            {state.apiJsFiles !== null && jsGroups.length === 0 && (
              <div style={{ padding: 52, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 14 }}>{t("No JS files yet — pick domains and scan.")}</div>
            )}
          </div>
        </div>
      );
    }
    // rv === "hosts"
    if (state.hostImportOpen) return renderHostImport();
    if (_hd) return renderHostDetail(_hd);
    const farmRunning = isFarmJobInFlight(state.hostFarmJob?.status ?? "");
    // Grid shared by the header, each host row and each nested subdomain row.
    const hostGrid = "24px minmax(0,1.25fr) minmax(0,1fr) 104px 72px";
    return (
      <div className="route">
        {/* While a probe job runs, statuses fill in live in the table below. */}
        {farmRunning && (
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14, padding: "11px 16px", borderRadius: 12, background: "var(--fr-accent-soft)", color: "var(--fr-accent)", font: "600 12.5px Inter,sans-serif" }}>
            <span className="frost-spin" style={{ width: 14, height: 14, borderRadius: "50%", border: "2px solid var(--fr-accent)", borderTopColor: "transparent", display: "inline-block" }} />
            {t("Probing")} {state.hostFarmJob?.targets_total ?? ""} {t("hosts — statuses update automatically.")}
          </div>
        )}
        {reconFilterRow("hosts")}
        <div style={{ ...CARD, overflow: "hidden" }}>
          {/* No column headers over an empty table — only show them with rows. */}
          {hostsList.length > 0 && (
            <div style={{ display: "grid", gridTemplateColumns: hostGrid, gap: 14, padding: "12px 20px", borderBottom: "1px solid var(--fr-divider)", font: "700 11px Inter,sans-serif", letterSpacing: ".5px", color: "var(--fr-text-faint)", textTransform: "uppercase" }}>
              <div /><div>{t("Host")}</div><div>{t("Ports")}</div><div>{t("Cloudflare")}</div><div />
            </div>
          )}
          {hostsList.map(({ h, idx }) => {
            const exp = state.expanded.includes(h.id);
            return (
              <div key={h.id} style={{ borderBottom: "1px solid var(--fr-divider)" }}>
                <div className="prow clk" onClick={() => toggleHost(h.id)} style={{ display: "grid", gridTemplateColumns: hostGrid, alignItems: "start", gap: 14, padding: "15px 20px" }}>
                  <Icon name="chevron-right" size={15} color="var(--fr-text-faint)" sw={2.4} style={{ marginTop: 3, transform: exp ? "rotate(90deg)" : "none", transition: "transform .2s" }} />
                  <div style={{ minWidth: 0 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0 }}>
                      <span style={{ width: 6, height: 6, flex: "none", borderRadius: "50%", background: STDOT[h.status] ?? STDOT.unknown }} />
                      <span className="clk" onClick={(ev) => { ev.stopPropagation(); openHostDetail(h.id); }} style={{ display: "inline-block", minWidth: 0 }}>
                        <span className="mono hostname" style={{ font: "700 14px 'JetBrains Mono',monospace", color: "var(--fr-text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", cursor: "pointer" }}>{h.host}</span>
                      </span>
                    </div>
                  </div>
                  <div style={{ minWidth: 0 }}>{portPills(h.ports, h.status === "down")}</div>
                  {/* True when any address of the host sits in a Cloudflare range. */}
                  <div style={{ marginTop: 1 }}>{cloudflarePill(h.cloudflare)}</div>
                  <div style={{ display: "flex", justifyContent: "flex-end", gap: 2 }}>
                    <div className="actbtn" onClick={(ev) => { ev.stopPropagation(); openEditor("host", "edit", idx); }}><Icon name="edit" size={15} /></div>
                    <div className="actbtn del" onClick={(ev) => { ev.stopPropagation(); askDelete("host", idx, h.host); }}><Icon name="trash" size={15} /></div>
                  </div>
                </div>
                {/* Expanding a host lists its subdomains — the addresses live in the IPs view. */}
                {exp && (
                  <div style={{ background: "var(--fr-elevated)", animation: "frost-fade .2s ease both" }}>
                    {visibleSubdomainsOf(h).map((sub) => (
                      <div key={sub.id} className="prow clk" onClick={(ev) => { ev.stopPropagation(); openHostDetail(sub.id); }} style={{ display: "grid", gridTemplateColumns: hostGrid, alignItems: "start", gap: 14, padding: "13px 20px 13px 44px", borderTop: "1px solid var(--fr-divider)" }}>
                        <span style={{ width: 6, height: 6, borderRadius: "50%", background: STDOT[sub.status] ?? STDOT.unknown, marginTop: 8, justifySelf: "end" }} />
                        <div style={{ minWidth: 0 }}>
                          <span className="mono hostname" style={{ font: "600 13px 'JetBrains Mono',monospace", color: "var(--fr-text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", display: "block", cursor: "pointer" }}>{sub.host}</span>
                        </div>
                        <div style={{ minWidth: 0 }}>{portPills(sub.ports, sub.status === "down")}</div>
                        <div style={{ marginTop: 1 }}>{cloudflarePill(sub.cloudflare)}</div>
                        <div style={{ display: "flex", justifyContent: "flex-end", gap: 2 }}>
                          <div className="actbtn" onClick={(ev) => { ev.stopPropagation(); openEditor("host", "edit", hosts.findIndex((x) => x.id === sub.id)); }}><Icon name="edit" size={15} /></div>
                          <div className="actbtn del" onClick={(ev) => { ev.stopPropagation(); askDelete("host", hosts.findIndex((x) => x.id === sub.id), sub.host); }}><Icon name="trash" size={15} /></div>
                        </div>
                      </div>
                    ))}
                    {visibleSubdomainsOf(h).length === 0 && (
                      <div style={{ padding: "13px 20px 13px 44px", borderTop: "1px solid var(--fr-divider)", font: "500 12.5px Inter,sans-serif", color: "var(--fr-text-faint)" }}>{t("No subdomains discovered.")}</div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
          {state.apiHosts === null && <div style={{ padding: 52, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 14 }}>{t("Loading hosts…")}</div>}
          {state.apiHosts !== null && hostsList.length === 0 && <div style={{ padding: 52, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 14 }}>{t("No hosts found.")}</div>}
        </div>
      </div>
    );
  };

  /* Карточка одного JS-файла — тот же приём, что у хоста и адреса: список
     остаётся списком, а разбор находок живёт на своей странице. Экспорт здесь
     ограничен этим файлом (см. exportLinesFor: открытая карточка задаёт источник),
     поэтому «Пути» и «Секреты» выгружаются ровно из него и по отдельности. */
  const renderJsFileDetail = (f: JsFileEntry) => (
    <div style={{ animation: "frost-fade .2s ease both" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 18 }}>
        <span className="clk" onClick={closeJsFile} style={{ display: "inline-flex", alignItems: "center", gap: 6, font: "600 12.5px Inter,sans-serif", color: "var(--fr-text-2)", background: "var(--fr-surface)", border: "1px solid var(--fr-border-light)", borderRadius: 20, padding: "7px 13px", cursor: "pointer" }}>
          <Icon name="chevron-left" size={15} />{t("All JS files")}
        </span>
        <div style={{ flex: 1 }} />
        <button className="clk" onClick={() => openReconExport("js-endpoints")} disabled={f.endpoints.length === 0} style={{ height: 38, padding: "0 14px", border: "1px solid var(--fr-border)", borderRadius: 10, background: "var(--fr-surface)", font: "700 12.5px Inter,sans-serif", color: f.endpoints.length ? "var(--fr-accent-2)" : "var(--fr-text-faint)", display: "inline-flex", alignItems: "center", gap: 7, cursor: f.endpoints.length ? "pointer" : "default" }}>
          <Icon name="upload" size={14} sw={2.2} color={f.endpoints.length ? "var(--fr-accent-2)" : "var(--fr-text-faint)"} />{t("Export paths")}
        </button>
        <button className="clk" onClick={() => openReconExport("js-secrets")} disabled={f.secrets.length === 0} style={{ height: 38, padding: "0 14px", border: "1px solid var(--fr-border)", borderRadius: 10, background: "var(--fr-surface)", font: "700 12.5px Inter,sans-serif", color: f.secrets.length ? "var(--fr-accent-2)" : "var(--fr-text-faint)", display: "inline-flex", alignItems: "center", gap: 7, cursor: f.secrets.length ? "pointer" : "default" }}>
          <Icon name="upload" size={14} sw={2.2} color={f.secrets.length ? "var(--fr-accent-2)" : "var(--fr-text-faint)"} />{t("Export secrets")}
        </button>
      </div>
      <div style={{ ...CARD, padding: "22px 24px", marginBottom: 16 }}>
        <div className="mono" style={{ font: "800 17px 'JetBrains Mono',monospace", color: "var(--fr-text)", wordBreak: "break-all" }}>{fileBase(f.url)}</div>
        <a className="mono" href={f.url} target="_blank" rel="noreferrer" style={{ display: "inline-block", marginTop: 8, fontSize: 12, color: "var(--fr-accent)", wordBreak: "break-all" }}>{f.url}</a>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 12 }}>
          <span className="mono" style={{ fontSize: 11, fontWeight: 600, color: "var(--fr-text-2)", background: "var(--fr-hover)", border: "1px solid var(--fr-border-light)", borderRadius: 6, padding: "3px 9px" }}>{f.host}</span>
          <span className="mono" style={{ fontSize: 11, fontWeight: 600, color: "var(--fr-text-2)", background: "var(--fr-hover)", border: "1px solid var(--fr-border-light)", borderRadius: 6, padding: "3px 9px" }}>{f.status === "ok" ? kb(f.size) : f.status}</span>
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
        <span style={{ font: "700 13px Inter,sans-serif", color: "var(--fr-text)" }}>{t("Secrets")} <span className="mono" style={{ color: "var(--fr-text-3)", fontWeight: 600 }}>{f.secrets.length}</span></span>
      </div>
      <div style={{ ...CARD, overflow: "hidden", marginBottom: 20 }}>
        {f.secrets.length > 0 && (
          <div style={{ display: "grid", gridTemplateColumns: "minmax(0,150px) minmax(0,1fr) minmax(0,1.2fr)", gap: 14, padding: "12px 20px", borderBottom: "1px solid var(--fr-divider)", font: "700 11px Inter,sans-serif", letterSpacing: ".5px", color: "var(--fr-text-faint)", textTransform: "uppercase" }}>
            <div>{t("Kind")}</div><div>{t("Match")}</div><div>{t("Snippet")}</div>
          </div>
        )}
        {f.secrets.map((sec, i) => {
          const c = SECRET_SEV[sec.severity] ?? SECRET_SEV.low;
          return (
            <div key={i} className="prow" style={{ display: "grid", gridTemplateColumns: "minmax(0,150px) minmax(0,1fr) minmax(0,1.2fr)", alignItems: "center", gap: 14, padding: "13px 20px", borderBottom: "1px solid var(--fr-divider)" }}>
              <span className="mono" style={{ justifySelf: "start", fontSize: 10.5, fontWeight: 700, borderRadius: 5, padding: "2px 8px", background: c.bg, color: c.color }}>{sec.kind}</span>
              <span className="mono" style={{ fontSize: 12, color: "var(--fr-text-2)", wordBreak: "break-all" }}>{sec.match}</span>
              <span className="mono" title={sec.snippet ?? ""} style={{ fontSize: 11.5, color: "var(--fr-text-faint)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{sec.snippet}</span>
            </div>
          );
        })}
        {f.secrets.length === 0 && (
          <div style={{ padding: 40, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 13.5 }}>{f.status === "ok" ? t("No secrets in this file.") : t("File could not be scanned.")}</div>
        )}
      </div>

      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
        <span style={{ font: "700 13px Inter,sans-serif", color: "var(--fr-text)" }}>{t("Paths")} <span className="mono" style={{ color: "var(--fr-text-3)", fontWeight: 600 }}>{f.endpoints.length}</span></span>
      </div>
      <div style={{ ...CARD, overflow: "hidden", marginBottom: 20 }}>
        {f.endpoints.map((path, i) => (
          <div key={i} className="prow" style={{ display: "flex", alignItems: "center", gap: 12, padding: "12px 20px", borderBottom: "1px solid var(--fr-divider)" }}>
            <span className="mono" style={{ fontSize: 12.5, color: "var(--fr-text)", wordBreak: "break-all" }}>{path}</span>
          </div>
        ))}
        {f.endpoints.length === 0 && (
          <div style={{ padding: 40, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 13.5 }}>{t("No paths in this file.")}</div>
        )}
      </div>
    </div>
  );

  const renderHostDetail = (h: Host) => {
    return (
      <div style={{ animation: "frost-fade .2s ease both" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 18 }}>
          <span className="clk" onClick={closeHostDetail} style={{ display: "inline-flex", alignItems: "center", gap: 6, font: "600 12.5px Inter,sans-serif", color: "var(--fr-text-2)", background: "var(--fr-surface)", border: "1px solid var(--fr-border-light)", borderRadius: 20, padding: "7px 13px", cursor: "pointer" }}>
            <Icon name="chevron-left" size={15} />{t("All hosts")}
          </span>
        </div>
        <div style={{ ...CARD, padding: "22px 24px", marginBottom: 16 }}>
          <div style={{ minWidth: 0 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{ width: 6, height: 6, flex: "none", borderRadius: "50%", background: STDOT[h.status] ?? STDOT.unknown }} />
              <span className="mono" style={{ font: "800 20px 'JetBrains Mono',monospace", color: "var(--fr-text)", wordBreak: "break-all" }}>{h.host}</span>
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 12 }}>
              {h.ips.map((ip, i) => (
                <span key={i} className="mono" style={{ fontSize: 11, fontWeight: 600, color: "var(--fr-text-2)", background: "var(--fr-hover)", border: "1px solid var(--fr-border-light)", borderRadius: 6, padding: "3px 9px" }}>{ip}</span>
              ))}
            </div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
          <span style={{ font: "700 13px Inter,sans-serif", color: "var(--fr-text)" }}>{t("Ports")} <span className="mono" style={{ color: "var(--fr-text-3)", fontWeight: 600 }}>{h.ports.length}</span></span>
        </div>
        <div style={{ ...CARD, overflow: "hidden", marginBottom: 20 }}>
          {h.ports.length > 0 && (
            <div style={{ display: "grid", gridTemplateColumns: "minmax(0,120px) minmax(0,1fr) 80px 110px", gap: 14, padding: "12px 20px", borderBottom: "1px solid var(--fr-divider)", font: "700 11px Inter,sans-serif", letterSpacing: ".5px", color: "var(--fr-text-faint)", textTransform: "uppercase" }}>
              <div>{t("Port")}</div><div>{t("Service")}</div><div>{t("HTTP")}</div><div>{t("State")}</div>
            </div>
          )}
          {h.ports.map((p, pi) => (
            <div key={pi} className="prow" style={{ display: "grid", gridTemplateColumns: "minmax(0,120px) minmax(0,1fr) 80px 110px", alignItems: "center", gap: 14, padding: "14px 20px", borderBottom: "1px solid var(--fr-divider)" }}>
              <span className="mono" style={{ font: "700 13px 'JetBrains Mono',monospace", color: "var(--fr-text)" }}>{p.n}/{p.proto}</span>
              {/* Весь стек технологий чипами (whatweb); пусто → unknown. */}
              {p.techs.length > 0 ? (
                <div style={{ display: "flex", flexWrap: "wrap", gap: 5, minWidth: 0 }}>
                  {p.techs.map((tech, ti) => (
                    <span key={ti} className="mono" title={tech.version ? `${tech.name} ${tech.version}` : tech.name} style={{ fontSize: 11, fontWeight: 700, borderRadius: 6, padding: "2px 8px", background: "var(--fr-elevated)", color: "var(--fr-text-2)" }}>
                      {tech.name}{tech.version ? ` ${tech.version}` : ""}
                    </span>
                  ))}
                </div>
              ) : (
                <span className="mono" style={{ fontSize: 12.5, color: "var(--fr-text-faint)" }}>{t("unknown")}</span>
              )}
              <span className="mono" style={{ fontSize: 12.5, fontWeight: 700, color: h.status === "down" ? "var(--fr-danger)" : p.http != null ? httpStatusColor(p.http) : "var(--fr-text-faint)" }}>{h.status === "down" ? "down" : p.http != null ? p.http : "—"}</span>
              <span className="mono" style={{ justifySelf: "start", fontSize: 11, fontWeight: 700, borderRadius: 6, padding: "3px 9px", ...(PORT[p.state] ?? PORT.closed) }}>{p.state}</span>
            </div>
          ))}
          {h.ports.length === 0 && <div style={{ padding: 40, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 13.5 }}>{t("No ports yet.")}</div>}
        </div>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
          <span style={{ font: "700 13px Inter,sans-serif", color: "var(--fr-text)" }}>{t("Endpoints")} <span className="mono" style={{ color: "var(--fr-text-3)", fontWeight: 600 }}>{h.endpoints.length}</span></span>
        </div>
        <div style={{ ...CARD, overflow: "hidden" }}>
          {h.endpoints.map((e, ei) => {
            const m = METHOD[e.m] ?? PORT.closed;
            return (
              <div key={ei} className="prow clk" onClick={() => openEndpoint({ method: e.m, path: e.p, host: h.host, hostId: h.id, endpointId: e.id })} style={{ display: "grid", gridTemplateColumns: "72px minmax(0,1fr) 96px", alignItems: "center", gap: 12, padding: "13px 20px", borderBottom: "1px solid var(--fr-divider)" }}>
                <span className="mono" style={{ justifySelf: "start", fontWeight: 700, borderRadius: 5, padding: "2px 8px", fontSize: 10.5, background: m.bg, color: m.color }}>{e.m}</span>
                <div className="mono" style={{ fontSize: 12.5, color: "var(--fr-text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{e.p}</div>
                <div style={{ display: "flex", justifyContent: "flex-end", gap: 2 }}>
                  <Tip label={t("Copy as cURL")}><div className="actbtn" onClick={(ev) => { ev.stopPropagation(); copyCurl({ method: e.m, path: e.p, host: h.host }); }}><Icon name="copy" size={15} /></div></Tip>
                  <Tip label={t("Delete endpoint")}><div className="actbtn del" onClick={(ev) => { ev.stopPropagation(); void deleteEndpoint(h.id, e.id); }}><Icon name="trash" size={15} /></div></Tip>
                </div>
              </div>
            );
          })}
          {h.endpoints.length === 0 && <div style={{ padding: 40, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 13.5 }}>{t("No endpoints yet.")}</div>}
        </div>
      </div>
    );
  };

  /* The IP card mirrors the host card: the address takes the host's place in the
     header, the names it resolves to take the host's IP chips, and the ports table
     is identical. IPs own no endpoints (those belong to a host), so there is no
     endpoints section — the resolved hostnames stand in as the address's context. */
  const renderIpDetail = (row: (typeof ipsRows)[number]) => {
    return (
      <div style={{ animation: "frost-fade .2s ease both" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 18 }}>
          <span className="clk" onClick={closeIpDetail} style={{ display: "inline-flex", alignItems: "center", gap: 6, font: "600 12.5px Inter,sans-serif", color: "var(--fr-text-2)", background: "var(--fr-surface)", border: "1px solid var(--fr-border-light)", borderRadius: 20, padding: "7px 13px", cursor: "pointer" }}>
            <Icon name="chevron-left" size={15} />{t("All IPs")}
          </span>
        </div>
        <div style={{ ...CARD, padding: "22px 24px", marginBottom: 16 }}>
          <div style={{ minWidth: 0 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
              <span style={{ width: 6, height: 6, flex: "none", borderRadius: "50%", background: STDOT[row.status] ?? STDOT.unknown }} />
              <span className="mono" style={{ font: "800 20px 'JetBrains Mono',monospace", color: "var(--fr-text)", wordBreak: "break-all" }}>{row.ip}</span>
              {row.cloudflare && (
                <span className="mono" style={{ fontSize: 11, fontWeight: 700, borderRadius: 6, padding: "3px 9px", background: "var(--fr-warn-soft)", color: "var(--fr-warn)" }}>{t("Cloudflare")}</span>
              )}
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 12 }}>
              <span style={{ font: "700 11px Inter,sans-serif", letterSpacing: ".5px", color: "var(--fr-text-faint)", textTransform: "uppercase" }}>{t("Hostnames")}</span>
              <span title={row.names.map((n) => n.hostname).join(", ")}>{hostnamePills(row.names)}</span>
            </div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
          <span style={{ font: "700 13px Inter,sans-serif", color: "var(--fr-text)" }}>{t("Ports")} <span className="mono" style={{ color: "var(--fr-text-3)", fontWeight: 600 }}>{row.ports.length}</span></span>
        </div>
        <div style={{ ...CARD, overflow: "hidden" }}>
          {row.ports.length > 0 && (
            <div style={{ display: "grid", gridTemplateColumns: "minmax(0,120px) minmax(0,1fr) 80px 110px", gap: 14, padding: "12px 20px", borderBottom: "1px solid var(--fr-divider)", font: "700 11px Inter,sans-serif", letterSpacing: ".5px", color: "var(--fr-text-faint)", textTransform: "uppercase" }}>
              <div>{t("Port")}</div><div>{t("Service")}</div><div>{t("HTTP")}</div><div>{t("State")}</div>
            </div>
          )}
          {row.ports.map((p, pi) => (
            <div key={pi} className="prow" style={{ display: "grid", gridTemplateColumns: "minmax(0,120px) minmax(0,1fr) 80px 110px", alignItems: "center", gap: 14, padding: "14px 20px", borderBottom: "1px solid var(--fr-divider)" }}>
              <span className="mono" style={{ font: "700 13px 'JetBrains Mono',monospace", color: "var(--fr-text)" }}>{p.n}/{p.proto}</span>
              {/* Весь стек технологий чипами (whatweb); пусто → unknown. */}
              {p.techs.length > 0 ? (
                <div style={{ display: "flex", flexWrap: "wrap", gap: 5, minWidth: 0 }}>
                  {p.techs.map((tech, ti) => (
                    <span key={ti} className="mono" title={tech.version ? `${tech.name} ${tech.version}` : tech.name} style={{ fontSize: 11, fontWeight: 700, borderRadius: 6, padding: "2px 8px", background: "var(--fr-elevated)", color: "var(--fr-text-2)" }}>
                      {tech.name}{tech.version ? ` ${tech.version}` : ""}
                    </span>
                  ))}
                </div>
              ) : (
                <span className="mono" style={{ fontSize: 12.5, color: "var(--fr-text-faint)" }}>{t("unknown")}</span>
              )}
              <span className="mono" style={{ fontSize: 12.5, fontWeight: 700, color: row.status === "down" ? "var(--fr-danger)" : p.http != null ? httpStatusColor(p.http) : "var(--fr-text-faint)" }}>{row.status === "down" ? "down" : p.http != null ? p.http : "—"}</span>
              <span className="mono" style={{ justifySelf: "start", fontSize: 11, fontWeight: 700, borderRadius: 6, padding: "3px 9px", ...(PORT[p.state] ?? PORT.closed) }}>{p.state}</span>
            </div>
          ))}
          {row.ports.length === 0 && <div style={{ padding: 40, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 13.5 }}>{t("No ports yet.")}</div>}
        </div>
      </div>
    );
  };

  const renderVulns = () => {
    if (state.openVulnId != null) return renderVulnDetail();
    return (
      <div className="route">
        {/* Панель фильтров: поиск по хосту и автору — слева (как в разделе
            «Эндпоинты»), пилюли статуса и критичности — справа, отодвинуты
            flex-распоркой. Счётчик уязвимостей переехал к заголовку секции. */}
        {/* Поиски слева; статус и критичность — справа, друг под другом. На узких
            экранах правый блок переносится под поиски, оставаясь выровненным по
            правому краю. */}
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 16, marginBottom: 16, flexWrap: "wrap" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 9, flexWrap: "wrap" }}>
            {searchBox(t("Filter by host…"), state.vulnFilterHost, (v) => setState({ vulnFilterHost: v }), 190)}
            {searchBox(t("Filter by author…"), state.vulnFilterAuthor, (v) => setState({ vulnFilterAuthor: v }), 190)}
          </div>
          {/* Status / severity are multi-select: pills toggle, several can be held at
              once, and clearing the last one falls back to "All". Driven by the token
              lists so they cannot drift from the backend's vocabularies. */}
          <div style={{ display: "flex", flexWrap: "wrap", gap: "8px 18px", alignItems: "flex-start", justifyContent: "flex-end", marginLeft: "auto" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", justifyContent: "flex-end" }}>
              <span className="mono" style={{ fontSize: 10.5, letterSpacing: 1, color: "var(--fr-text-faint)", fontWeight: 700 }}>{t("STATUS")}</span>
              {filterPill(t("All"), vfS.length === 0, () => setState({ vulnFilterStatuses: [] }))}
              {VSTATUS_ORDER.map((s) => filterPill(t(VSTATUS_LABEL[s]), vfS.includes(s), () => setState((st) => ({ vulnFilterStatuses: toggleIn(st.vulnFilterStatuses, s) }))))}
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", justifyContent: "flex-end" }}>
              <span className="mono" style={{ fontSize: 10.5, letterSpacing: 1, color: "var(--fr-text-faint)", fontWeight: 700 }}>{t("SEVERITY")}</span>
              {filterPill(t("All"), vfSev.length === 0, () => setState({ vulnFilterSeverities: [] }))}
              {(["critical", "high", "medium", "low", "info"] as Severity[]).map((s) => filterPill(cap(s), vfSev.includes(s), () => setState((st) => ({ vulnFilterSeverities: toggleIn(st.vulnFilterSeverities, s) }))))}
            </div>
          </div>
        </div>
        <div style={{ ...CARD, overflow: "hidden" }}>
          {vulns.length > 0 && (
            <div style={{ display: "grid", gridTemplateColumns: "48px minmax(0,1.8fr) minmax(0,1fr) 140px 110px 130px 120px 64px", gap: 10, padding: "13px 20px", borderBottom: "1px solid var(--fr-divider)", font: "700 11px Inter,sans-serif", letterSpacing: ".5px", color: "var(--fr-text-faint)", textTransform: "uppercase" }}>
              <div>#</div><div>{t("Title")}</div><div>{t("Asset")}</div><div>{t("Status")}</div><div>{t("Severity")}</div><div>{t("Author")}</div><div>{t("Updated")}</div><div />
            </div>
          )}
          {vulns.map((v) => (
            <div key={v.num} className="prow clk" onClick={v.onOpen} style={{ display: "grid", gridTemplateColumns: "48px minmax(0,1.8fr) minmax(0,1fr) 140px 110px 130px 120px 64px", alignItems: "center", gap: 10, padding: "14px 20px", borderBottom: "1px solid var(--fr-divider)" }}>
              <div className="mono" style={{ fontSize: 13, color: "var(--fr-text-faint)", fontWeight: 600 }}>{String(v.num).padStart(2, "0")}</div>
              <div style={{ font: "600 14px Inter,sans-serif", color: "var(--fr-text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{v.title}</div>
              <div className="mono" style={{ fontSize: 12, color: "var(--fr-text-3)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{v.host}</div>
              <div style={{ display: "flex", alignItems: "center", gap: 7, font: "600 12px Inter,sans-serif", color: VSTATUS[v.status] ?? "var(--fr-text-3)" }}><span style={{ width: 6, height: 6, flex: "none", borderRadius: "50%", background: VSTATUS[v.status] ?? "var(--fr-text-3)" }} />{t(VSTATUS_LABEL[v.status] ?? v.status)}</div>
              <span style={{ justifySelf: "start", font: "700 10.5px Inter,sans-serif", textTransform: "uppercase", letterSpacing: ".5px", borderRadius: 7, padding: "4px 9px", background: SEV[v.sev].bg, color: SEV[v.sev].color }}>{v.sev}</span>
              <div className="mono" style={{ fontSize: 12, color: "var(--fr-text-2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{v.author}</div>
              <div className="mono" style={{ fontSize: 11.5, color: "var(--fr-text-faint)" }}>{v.updated}</div>
              <div style={{ display: "flex", justifyContent: "flex-end", gap: 2 }}>
                <div className="actbtn" onClick={v.onEdit}><Icon name="edit" size={15} /></div>
                <div className="actbtn del" onClick={v.onDelete}><Icon name="trash" size={15} /></div>
              </div>
            </div>
          ))}
          {vulns.length === 0 && <div style={{ padding: 52, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 14 }}>{t("No findings match these filters.")}</div>}
        </div>
      </div>
    );
  };

  const renderVulnDetail = () => {
    // openVulnId is a backend id, not a list index — look the finding up by id.
    const original = state.openVulnId != null ? d.vulns.find((v) => v.id === state.openVulnId) : undefined;
    /* «Affected host» — тот же пикер хостов проекта, что и в форме создания уязвимости:
       ранжируем как combo редактора (совпадение по префиксу выше), режем до COMBO_MAX. */
    const vdHostQ = (vd.host || "").trim().toLowerCase();
    const vdHostSuggestions = hosts
      .map((h) => h.host)
      .flatMap((hn) => {
        if (!vdHostQ) return [{ v: hn, rank: 0 }];
        if (hn.toLowerCase().startsWith(vdHostQ)) return [{ v: hn, rank: 0 }];
        if (hn.toLowerCase().includes(vdHostQ)) return [{ v: hn, rank: 1 }];
        return [] as { v: string; rank: number }[];
      })
      .sort((a, b) => a.rank - b.rank)
      .slice(0, COMBO_MAX)
      .map((x) => x.v);
    const vdHostHi = Math.min(state.vdHostComboHi, Math.max(vdHostSuggestions.length - 1, 0));
    const vdHostPick = (v: string) =>
      setState((s) => ({ vulnDetailForm: { ...s.vulnDetailForm, host: v }, vdHostComboOpen: false, vdHostComboHi: 0 }));
    return (
      <div style={{ width: "100%" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, marginBottom: 18 }}>
          <span className="clk" onClick={closeVulnDetail} style={{ display: "inline-flex", alignItems: "center", gap: 6, font: "600 12.5px Inter,sans-serif", color: "var(--fr-text-2)", background: "var(--fr-surface)", border: "1px solid var(--fr-border-light)", borderRadius: 20, padding: "7px 13px", cursor: "pointer" }}>
            <Icon name="chevron-left" size={15} />{t("All findings")}
          </span>
        </div>
        <div style={{ ...CARD, padding: "26px 28px" }}>
          <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 16, marginBottom: 20 }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <label className="flabel">{t("Title")}</label>
              <input className="finp" value={vd.title || ""} onChange={(e) => updateVulnDetailForm("title", e.target.value)} style={{ font: "800 18px Inter,sans-serif" }} />
            </div>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 14 }}>
            <div>
              <label className="flabel">{t("Affected host")}</label>
              {/* Тот же пикер хостов проекта, что и в форме создания уязвимости —
                  подсказки при вводе; свободный ввод по-прежнему допускается. */}
              <div style={{ position: "relative" }}>
                <input
                  className="finp"
                  value={vd.host || ""}
                  placeholder={t("Start typing a hostname…")}
                  autoComplete="off"
                  onChange={(e) => { updateVulnDetailForm("host", e.target.value); setState({ vdHostComboOpen: true, vdHostComboHi: 0 }); }}
                  onFocus={() => setState({ vdHostComboOpen: true, vdHostComboHi: 0 })}
                  onBlur={() => setState({ vdHostComboOpen: false })}
                  onKeyDown={(e) => {
                    if (!state.vdHostComboOpen || vdHostSuggestions.length === 0) {
                      if (e.key === "ArrowDown") setState({ vdHostComboOpen: true, vdHostComboHi: 0 });
                      return;
                    }
                    if (e.key === "ArrowDown") { e.preventDefault(); setState({ vdHostComboHi: (vdHostHi + 1) % vdHostSuggestions.length }); }
                    else if (e.key === "ArrowUp") { e.preventDefault(); setState({ vdHostComboHi: (vdHostHi - 1 + vdHostSuggestions.length) % vdHostSuggestions.length }); }
                    else if (e.key === "Enter") { e.preventDefault(); vdHostPick(vdHostSuggestions[vdHostHi]); }
                    else if (e.key === "Escape") setState({ vdHostComboOpen: false });
                  }}
                />
                {state.vdHostComboOpen && vdHostSuggestions.length > 0 && (
                  <div style={{ position: "absolute", top: "calc(100% + 6px)", left: 0, right: 0, background: "var(--fr-surface)", border: "1px solid var(--fr-border-light)", borderRadius: 12, boxShadow: "0 18px 44px rgba(15,27,45,.16)", zIndex: 60, padding: 6, overflow: "hidden" }}>
                    {vdHostSuggestions.map((hn, i) => (
                      <div
                        key={hn}
                        className="clk"
                        /* mousedown, а не click: click после blur-а инпута уже не долетит (список размонтируется). */
                        onMouseDown={(e) => { e.preventDefault(); vdHostPick(hn); }}
                        style={{ display: "flex", flexDirection: "column", gap: 1, padding: "8px 10px", borderRadius: 9, background: i === vdHostHi ? "var(--fr-accent-soft)" : "transparent" }}
                      >
                        <span style={{ font: "600 13.5px Inter,sans-serif", color: i === vdHostHi ? "var(--fr-accent)" : "var(--fr-text)" }}>{hn}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
            <div><label className="flabel">{t("CWE ID")}</label><input className="finp mono" placeholder={t("e.g. CWE-89")} value={vd.cwe || ""} onChange={(e) => updateVulnDetailForm("cwe", e.target.value)} /></div>
          </div>
          <div style={{ marginBottom: 18 }}>
            <div style={{ display: "flex", alignItems: "flex-end", gap: 14 }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <label className="flabel">{t("CVSS 4.0 vector")}</label>
                <input className="finp mono" placeholder={t("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")} value={vd.vector || ""} onChange={(e) => updateVulnDetailForm("vector", e.target.value)} style={{ width: "100%", fontSize: 12.5 }} />
              </div>
              <div style={{ flex: "none", width: 150 }}>
                <label className="flabel">{t("Severity")}</label>
                <div className="finp" style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, cursor: "default" }}>
                  <span style={{ font: "700 11px Inter,sans-serif", textTransform: "uppercase", letterSpacing: ".5px", borderRadius: 6, padding: "3px 8px", background: SEV[vdSev].bg, color: SEV[vdSev].color }}>{vdSev}</span>
                  <span className="mono" style={{ fontSize: 12.5, color: "var(--fr-text-2)" }}>{vdScore}</span>
                </div>
              </div>
              <div style={{ flex: "none", width: 170 }}>
                <label className="flabel">{t("Status")}</label>
                <select className="finp" value={vd.status || "open"} onChange={(e) => updateVulnDetailForm("status", e.target.value as VStatus)}>
                  {VSTATUS_ORDER.map((s) => <option key={s} value={s}>{t(VSTATUS_LABEL[s])}</option>)}
                </select>
              </div>
            </div>
          </div>
          <div style={{ marginBottom: 18 }}>
            <label className="flabel">{t("Steps to reproduce")}</label>
            <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 6 }}>
              {(vd.stepsList ?? []).map((s, i) => {
                const imgs = (vd.stepImages ?? {})[i] ?? [];
                return (
                  <div key={i} style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                      <span className="mono" style={{ flex: "none", width: 26, height: 26, borderRadius: 8, background: "var(--fr-accent-soft)", color: "var(--fr-accent)", fontWeight: 700, fontSize: 12, display: "flex", alignItems: "center", justifyContent: "center" }}>{i + 1}</span>
                      <input className="finp" placeholder={t("Describe this step… (paste a screenshot to attach)")} value={s} onChange={(e) => updateVdStep(i, e.target.value)} onPaste={(e) => pasteVdStepImage(i, e)} style={{ flex: 1, fontFamily: "ui-monospace,Menlo,monospace", fontSize: 12.5 }} />
                      <div className="actbtn del" onClick={() => removeVdStep(i)}><Icon name="trash" size={15} /></div>
                    </div>
                    {imgs.length > 0 && (
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginLeft: 36 }}>
                        {imgs.map((src, ii) => (
                          <div key={ii} style={{ position: "relative" }}>
                            <img src={src} alt={`Step ${i + 1} screenshot ${ii + 1}`} title={t("Click to view")} onClick={() => setState({ lightboxSrc: src })} style={{ height: 78, borderRadius: 9, border: "1px solid var(--fr-border-strong)", display: "block", cursor: "zoom-in" }} />
                            <div className="clk" onClick={() => removeVdStepImage(i, ii)} style={{ position: "absolute", top: -7, right: -7, width: 20, height: 20, borderRadius: "50%", background: "var(--fr-danger)", color: "var(--fr-on-accent)", display: "flex", alignItems: "center", justifyContent: "center", font: "700 13px Inter,sans-serif", lineHeight: 1, cursor: "pointer", border: "2px solid var(--fr-surface)" }}>×</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
            <button className="clk" onClick={addVdStep} style={{ marginTop: 10, display: "inline-flex", alignItems: "center", gap: 6, height: 36, padding: "0 14px", border: "1px dashed var(--fr-border)", borderRadius: 10, background: "var(--fr-surface)", font: "700 12.5px Inter,sans-serif", color: "var(--fr-text-2)", cursor: "pointer" }}>
              <Icon name="plus" size={13} sw={2.4} />{t("Add step")}
            </button>
          </div>
          <div style={{ marginBottom: 18 }}><label className="flabel">{t("Impact")}</label><textarea className="finp" rows={2} placeholder={t("Business/security impact if exploited…")} value={vd.impact || ""} onChange={(e) => updateVulnDetailForm("impact", e.target.value)} /></div>
          <div><label className="flabel">{t("Remediation")}</label><textarea className="finp" rows={3} placeholder={t("How to fix or mitigate this vulnerability…")} value={vd.remediation || ""} onChange={(e) => updateVulnDetailForm("remediation", e.target.value)} /></div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 22, fontSize: 12, color: "var(--fr-text-faint)" }}>
            <span>{t("Reported by")} <b style={{ color: "var(--fr-text-3)" }}>{original?.author}</b> · {original?.updated}</span>
            <div style={{ display: "flex", gap: 10 }}>
              <button className="clk" onClick={closeVulnDetail} style={{ height: 40, padding: "0 18px", border: "1px solid var(--fr-border)", borderRadius: 10, background: "var(--fr-surface)", font: "700 13px Inter,sans-serif", color: "var(--fr-text-2)" }}>{t("Cancel")}</button>
              <button className="clk" onClick={saveVulnDetail} style={{ height: 40, padding: "0 20px", border: "none", borderRadius: 10, background: "var(--fr-accent-2)", color: "var(--fr-on-accent)", font: "700 13px Inter,sans-serif" }}>{t("Save changes")}</button>
            </div>
          </div>
        </div>
      </div>
    );
  };

  /** First non-empty line of the body, with Markdown syntax stripped — the card preview. */
  const notePreview = (md: string) => {
    const line = md.replace(/\r/g, "").split("\n").map((l) => l.trim()).find((l) => l && !/^[-*_]{3,}$/.test(l)) ?? "";
    return line
      .replace(/^#{1,6}\s+/, "")
      .replace(/^\s*[-*]\s+/, "")
      .replace(/\*\*([^*]+)\*\*/g, "$1")
      .replace(/\*([^*]+)\*/g, "$1")
      .replace(/`([^`]+)`/g, "$1")
      .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1");
  };

  /* The project credential vault: a shared table of username/password accounts.
     Passwords are masked by default; the eye reveals one row, the copy button
     lifts a value to the clipboard without revealing it. Everyone who can open
     the project can view and edit these, like notes. */
  // Fixed action column (not `auto`) so the header and every row share identical
  // column widths — otherwise the empty header cell and the 2-button rows compute
  // different 1fr widths and the "Password" header drifts off its column.
  const credCols = "34px minmax(0,1fr) minmax(0,1fr) minmax(0,1fr) 72px";
  // Fixed-width password box: the mask fills it, so nothing moves when a row is
  // revealed — the eye/copy buttons stay put (the shift bug). Long values ellipsize.
  const CRED_MASK = "••••••••••••••••";
  const renderCreds = () => {
    if (state.apiCreds === null) {
      return <div className="route" style={{ ...CARD, padding: 48, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 14 }}>{t("Loading credentials…")}</div>;
    }
    const monoCell: CSSProperties = { fontFamily: "ui-monospace,Menlo,monospace", fontSize: 13.5, color: "var(--fr-text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" };
    const empty = d.creds.length === 0;
    return (
      <div className="route" style={{ ...CARD, padding: 0, overflow: "hidden" }}>
        {/* Column headers only make sense with rows — hide them for an empty vault. */}
        {!empty && (
          <div className="mono" style={{ display: "grid", gridTemplateColumns: credCols, gap: 16, alignItems: "center", padding: "11px 20px", borderBottom: "1px solid var(--fr-divider)", background: "var(--fr-elevated)", fontSize: 11, letterSpacing: 0.4, textTransform: "uppercase", color: "var(--fr-text-faint)", fontWeight: 700 }}>
            <div>#</div>
            <div>{t("Username")}</div>
            <div>{t("Password")}</div>
            <div>{t("Host")}</div>
            <div />
          </div>
        )}
        {d.creds.map((c, idx) => {
          const revealed = state.revealedCredIds.includes(c.id);
          return (
            <div key={c.id} className="statc" style={{ display: "grid", gridTemplateColumns: credCols, gap: 16, alignItems: "center", padding: "11px 20px", borderBottom: "1px solid var(--fr-divider)" }}>
              {/* row index */}
              <div className="mono" style={{ fontSize: 13, fontWeight: 600, color: "var(--fr-text-faint)" }}>{String(idx + 1).padStart(2, "0")}</div>
              {/* username + copy — one line */}
              <div style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0 }}>
                <span style={{ ...monoCell, flex: "0 1 auto" }}>{c.username || <span style={{ color: "var(--fr-text-faint)" }}>—</span>}</span>
                {c.username && <div className="actbtn" title={t("Copy username")} onClick={() => copyText(c.username, "Username")}><Icon name="copy" size={14} /></div>}
              </div>
              {/* password (masked) + reveal + copy — the value box is a fixed width so
                  revealing never shifts the icons */}
              <div style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0 }}>
                <span style={{ ...monoCell, flex: "0 1 18ch" }}>{revealed ? c.password : CRED_MASK}</span>
                <div className="actbtn" title={revealed ? t("Hide password") : t("Reveal password")} onClick={() => toggleCredReveal(c.id)}><Icon name={revealed ? "lock" : "eye"} size={14} /></div>
                <div className="actbtn" title={t("Copy password")} onClick={() => copyText(c.password, "Password")}><Icon name="copy" size={14} /></div>
              </div>
              {/* host — which host these creds belong to */}
              <div style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0 }}>
                <span style={{ ...monoCell, flex: "0 1 auto" }}>{c.host || <span style={{ color: "var(--fr-text-faint)" }}>—</span>}</span>
                {c.host && <div className="actbtn" title={t("Copy host")} onClick={() => copyText(c.host, "Host")}><Icon name="copy" size={14} /></div>}
              </div>
              {/* row actions */}
              <div style={{ display: "flex", alignItems: "center", justifyContent: "flex-end", gap: 4 }}>
                <div className="actbtn" title={t("Edit")} onClick={() => openEditor("cred", "edit", idx)}><Icon name="edit" size={15} /></div>
                <div className="actbtn del" title={t("Delete")} onClick={() => askDelete("cred", idx, c.username || "credential")}><Icon name="trash" size={15} /></div>
              </div>
            </div>
          );
        })}
        {empty && (
          <div style={{ padding: 52, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 14 }}>
            {t("No credentials yet. Add a username and password for this project.")}
          </div>
        )}
      </div>
    );
  };

  const renderNotes = () => (
    <div className="route" style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      {d.notes.map((n, idx) => {
        const mine = n.author === me;
        return (
          // Clicking a note always opens it rendered — your own notes included.
          <div key={n.id} className="statc clk" onClick={() => openNoteViewer(n.id)} style={{ ...CARD, padding: "18px 20px" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
              <div style={{ font: "700 15px Inter,sans-serif", color: "var(--fr-text)" }}>{n.title}</div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flex: "none" }}>
                {mine && (
                  <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                    <div className="actbtn" onClick={(e) => { e.stopPropagation(); openNoteEditor("edit", idx); }}><Icon name="edit" size={15} /></div>
                    <div className="actbtn del" onClick={(e) => { e.stopPropagation(); askDelete("note", idx, n.title); }}><Icon name="trash" size={15} /></div>
                  </div>
                )}
                <span className="mono" style={{ fontSize: 11.5, color: "var(--fr-text-faint)" }}>{n.when}</span>
              </div>
            </div>
            <div style={{ fontSize: 13, color: "var(--fr-text-3)", marginTop: 6, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{notePreview(n.excerpt)}</div>
            <div className="mono" style={{ fontSize: 11.5, color: "var(--fr-text-3)", marginTop: 12 }}>{n.author}</div>
          </div>
        );
      })}
      {d.notes.length === 0 && <div style={{ ...CARD, padding: 52, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 14 }}>{t("No notes yet.")}</div>}
    </div>
  );

  /* The note deep link (/projects/{p}/notes/{n}) renders the body as Markdown.
     Your own notes get an Edit button here rather than opening raw on click. */
  const renderNoteViewer = () => {
    const idx = d.notes.findIndex((x) => x.id === state.openNoteId);
    const n = idx === -1 ? undefined : d.notes[idx];
    if (!n) {
      if (state.apiNotes === null) return <div className="route" style={{ ...CARD, padding: 48, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 14 }}>{t("Loading note…")}</div>;
      return renderNoAccess("Note not found.");
    }
    const mine = n.author === me;
    return (
      <div className="route" style={{ ...CARD, padding: 0, overflow: "hidden" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "16px 22px", borderBottom: "1px solid var(--fr-divider)" }}>
          <span className="clk" onClick={closeNoteViewer} style={{ display: "flex", color: "var(--fr-text-3)", cursor: "pointer" }}><Icon name="chevron-left" size={20} /></span>
          <h2 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: "var(--fr-text)" }}>{n.title}</h2>
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 10 }}>
            {mine ? (
              <button className="addbtn clk" onClick={() => openNoteEditor("edit", idx)} style={{ height: 36 }}>
                <Icon name="edit" size={15} color="var(--fr-on-accent)" sw={2.4} />{t("Edit note")}
              </button>
            ) : (
              <span style={{ display: "inline-flex", alignItems: "center", gap: 6, font: "600 11px Inter,sans-serif", color: "var(--fr-text-3)", background: "var(--fr-divider)", borderRadius: 20, padding: "5px 11px" }}>
                <Icon name="eye" size={12} />{t("Read only")}
              </span>
            )}
          </div>
        </div>
        <div style={{ padding: "24px 22px" }}>
          <div style={{ maxWidth: 720 }}>{renderMarkdown(n.excerpt)}</div>
          <div className="mono" style={{ fontSize: 11.5, color: "var(--fr-text-faint)", marginTop: 24, paddingTop: 16, borderTop: "1px solid var(--fr-elevated)" }}>{n.author} · {n.when}</div>
        </div>
      </div>
    );
  };

  const renderNoteEditor = () => (
    <div className="route" style={{ ...CARD, padding: 0, overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, padding: "16px 22px", borderBottom: "1px solid var(--fr-divider)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span className="clk" onClick={closeNoteEditor} style={{ display: "flex", color: "var(--fr-text-3)", cursor: "pointer" }}><Icon name="chevron-left" size={20} /></span>
          <h2 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: "var(--fr-text)" }}>{state.noteEditorMode === "add" ? "New note" : "Edit note"}</h2>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <button className="clk" onClick={closeNoteEditor} style={{ height: 38, padding: "0 16px", border: "1px solid var(--fr-border)", borderRadius: 10, background: "var(--fr-surface)", font: "700 13px Inter,sans-serif", color: "var(--fr-text-2)", cursor: "pointer" }}>{t("Cancel")}</button>
          <button className="clk" onClick={saveNote} style={{ height: 38, padding: "0 18px", border: "none", borderRadius: 10, background: "var(--fr-accent-2)", color: "var(--fr-on-accent)", font: "700 13px Inter,sans-serif", cursor: "pointer" }}>{t("Save note")}</button>
        </div>
      </div>
      <div style={{ padding: "22px 22px 8px" }}>
        <label className="flabel">{t("Title")}</label>
        <input className="finp" placeholder={t("Give this note a title…")} value={state.noteForm.title} onChange={(e) => updateNoteForm("title", e.target.value)} style={{ font: "700 16px Inter,sans-serif", height: 48, background: "var(--fr-elevated)" }} />
      </div>
      {/* Markdown renders as you type (### + space → heading, right in the line) —
          the note is still stored as Markdown, so the viewer and the reports read
          exactly what was typed. */}
      <div style={{ padding: "14px 22px 24px" }}>
        <label className="flabel">{t("Content")}</label>
        <Suspense fallback={<div className="frostmd" style={{ minHeight: 260, color: "var(--fr-text-faint)", font: "500 14px Inter,sans-serif" }}>{t("Loading editor…")}</div>}>
          <FrostMarkdownEditor
            value={state.noteForm.excerpt}
            onChange={(md) => updateNoteForm("excerpt", md)}
            placeholder={t("Write your note… «### » makes a heading, «- » a list")}
          />
        </Suspense>
      </div>
    </div>
  );

  const renderMembers = () => {
    const mq = state.memberQuery.trim().toLowerCase();
    const filtered = d.members
      .map((m, idx) => ({ m, idx }))
      .filter(({ m }) => (state.memberRoles.length === 0 || state.memberRoles.includes(m.role)) && (!mq || m.name.toLowerCase().includes(mq)));
    return (
      <div className="route">
        {/* search + role filter */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16, flexWrap: "wrap" }}>
          <label className="fq" style={{ position: "relative", display: "flex", alignItems: "center", width: 280 }}>
            <svg style={{ position: "absolute", left: 13 }} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--fr-text-faint)" strokeWidth="2" strokeLinecap="round"><circle cx="11" cy="11" r="7" /><path d="M21 21l-4-4" /></svg>
            <input placeholder={t("Search by username…")} value={state.memberQuery} onChange={(e) => setState({ memberQuery: e.target.value })} />
          </label>
          <div style={{ flex: 1 }} />
          {/* Every pill toggles; an empty selection means "All". */}
          <span className="mono" style={{ fontSize: 10.5, letterSpacing: 1, color: "var(--fr-text-faint)", fontWeight: 700 }}>{t("ROLE")}</span>
          <div className="clk" onClick={() => setState({ memberRoles: [] })} style={{ font: "600 12px Inter,sans-serif", padding: "6px 12px", borderRadius: 20, cursor: "pointer", ...vfPill(state.memberRoles.length === 0) }}>{t("All")}</div>
          {([{ label: "Lead", v: "lead" as const }, { label: "Pentester", v: "pentester" as const }]).map((o) => (
            <div key={o.v} className="clk" onClick={() => setState((s) => ({ memberRoles: toggleIn(s.memberRoles, o.v) }))} style={{ font: "600 12px Inter,sans-serif", padding: "6px 12px", borderRadius: 20, cursor: "pointer", ...vfPill(state.memberRoles.includes(o.v)) }}>{t(o.label)}</div>
          ))}
        </div>
        <div style={{ ...CARD, overflow: "hidden" }}>
          {filtered.map(({ m, idx }) => (
            <div key={m.name + idx} className="prow" style={{ display: "flex", alignItems: "center", gap: 13, padding: "15px 20px", borderBottom: "1px solid var(--fr-divider)" }}>
              <span className="mono" style={{ width: 38, height: 38, flex: "none", borderRadius: "50%", background: m.color, color: "var(--fr-on-accent)", display: "flex", alignItems: "center", justifyContent: "center", font: "700 13px 'JetBrains Mono',monospace" }}>{m.initials}</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ font: "600 14px Inter,sans-serif", color: "var(--fr-text)" }}>{m.name}</span>
                  <span style={{ font: "700 10px Inter,sans-serif", textTransform: "uppercase", letterSpacing: ".5px", borderRadius: 6, padding: "2px 8px", background: ROLE[m.role].bg, color: ROLE[m.role].color }}>{m.role}</span>
                </div>
                <div className="mono" style={{ fontSize: 12, color: "var(--fr-text-faint)", marginTop: 2 }}>{m.email}</div>
              </div>
              {canManageMembers && (
                <div style={{ display: "flex", gap: 2 }}>
                  <div className="actbtn del" onClick={() => askDelete("member", idx, m.name)}><Icon name="trash" size={15} /></div>
                </div>
              )}
            </div>
          ))}
          {filtered.length === 0 && <div style={{ padding: 44, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 14 }}>{t("No members match.")}</div>}
        </div>
      </div>
    );
  };

  /* UPDATE/DELETE audit rows carry no details, so the feed resolves the entity's
     name from the project data already loaded rather than printing "#12". */
  const resolveActivityName: ActivityResolver = (type, id) => {
    if (id == null) return null;
    if (type === "host") return hosts.find((h) => h.id === id)?.host ?? null;
    if (type === "vulnerability") return d.vulns.find((v) => v.id === id)?.title ?? null;
    if (type === "project_note" || type === "note") return d.notes.find((n) => n.id === id)?.title ?? null;
    if (type === "project") return projRow?.id === id ? projRow.name : null;
    if (type === "endpoint") {
      for (const h of hosts) {
        const e = h.endpoints.find((x) => x.id === id);
        if (e) return `${e.m} ${e.p}`;
      }
    }
    return null;
  };

  /* Grouped up-front rather than inside renderActivity: the tab's counter must
     match what the feed actually lists (cards, ports already dropped), and it has
     to be right before the tab is opened. */
  const activityGroups = groupActivity(state.activity ?? [], resolveActivityName);

  /** One line of the dark event panel: + text [SEVERITY]. */
  const activityLineRow = (l: ActivityLine, tone: ActTone) => (
    <div key={l.key} style={{ display: "flex", alignItems: "center", gap: 9, whiteSpace: "nowrap" }}>
      <span className="mono" style={{ flex: "none", width: 10, textAlign: "center", font: "700 12.5px 'JetBrains Mono',monospace", color: tone.color }}>
        {tone.mark}
      </span>
      <span style={{ font: "600 12.5px 'JetBrains Mono',monospace", color: "var(--fr-code-text)", textOverflow: "ellipsis", overflow: "hidden" }}>{l.text}</span>
      {/* Severity sits in a chip filled with that severity's own colour. */}
      {l.severity && (
        <span
          className="mono"
          style={{ flex: "none", font: "700 9.5px 'JetBrains Mono',monospace", letterSpacing: ".4px", textTransform: "uppercase", borderRadius: 4, padding: "3px 6px", background: ACT_SEV[l.severity], color: "var(--fr-on-accent)" }}
        >
          {l.severity}
        </span>
      )}
    </div>
  );

  /* Project activity: /projects/{id}/activity, visible to every project member.
     One white card per action per entity type, each listing exactly *what* was
     touched inside a dark panel. Long lists collapse to ACT_LINE_LIMIT rows and
     open in full in a modal. */
  const renderActivity = () => {
    const logs = state.activity ?? [];
    if (state.activityLoading && logs.length === 0)
      return <div className="route" style={{ ...CARD, padding: 48, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 14 }}>{t("Loading activity…")}</div>;
    if (state.activityError) return renderNoAccess(state.activityError);
    const groups = activityGroups;
    if (groups.length === 0)
      return <div className="route" style={{ ...CARD, padding: 48, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 14 }}>{t("No activity yet.")}</div>;
    return (
      <div className="route" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        {groups.map((g) => {
          const hidden = g.lines.length - ACT_LINE_LIMIT;
          const shown = hidden > 0 ? g.lines.slice(0, ACT_LINE_LIMIT) : g.lines;
          return (
            <div key={g.key} style={{ ...CARD, padding: "16px 18px", display: "flex", gap: 13 }}>
              <span
                className="mono"
                style={{ width: 32, height: 32, flex: "none", borderRadius: "50%", background: g.actor === "System" ? "var(--fr-accent-soft)" : "var(--fr-accent)", color: g.actor === "System" ? "var(--fr-accent-2)" : "var(--fr-on-accent)", display: "flex", alignItems: "center", justifyContent: "center", font: "700 11px 'JetBrains Mono',monospace" }}
              >
                {g.actor === "System" ? <Icon name="clock2" size={15} /> : initialsOf(g.actor)}
              </span>
              <div style={{ flex: 1, minWidth: 0 }}>
                {/* The count reads inline — "admin added 3 IP addresses" — rather
                    than as a separate badge repeating what the list already shows. */}
                <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
                  <div style={{ fontSize: 13.5, color: "var(--fr-text-2)", lineHeight: 1.5, flex: 1, minWidth: 0 }}>
                    <b className="mono" style={{ color: "var(--fr-text)" }}>{g.actor}</b> {g.verb} <b style={{ color: "var(--fr-text)" }}>{g.subject}</b>
                  </div>
                  <span className="mono" style={{ flex: "none", fontSize: 11.5, color: "var(--fr-text-faint)" }}>{g.time}</span>
                </div>
                <div style={{ marginTop: 11, background: "var(--fr-code-bg)", borderRadius: 10, padding: "11px 13px", display: "flex", flexDirection: "column", gap: 6, overflowX: "auto" }}>
                  {shown.map((l) => activityLineRow(l, g.tone))}
                  {hidden > 0 && (
                    <div
                      className="clk"
                      onClick={() => setState({ activityModalKey: g.key })}
                      style={{ marginTop: 3, font: "700 11.5px Inter,sans-serif", color: "var(--fr-accent-muted)", cursor: "pointer" }}
                    >
                      {t("Show more ·")} {hidden} {t("more")}
                    </div>
                  )}
                </div>
                {/* Findings link out from under the panel — the title itself is plain text. */}
                {g.vulnId != null && (
                  <div
                    className="clk"
                    onClick={() => openVulnDetail(g.vulnId as number)}
                    style={{ marginTop: 10, display: "inline-flex", alignItems: "center", gap: 5, font: "700 12px Inter,sans-serif", color: "var(--fr-accent-2)", cursor: "pointer" }}
                  >
                    {t("Show details")}<Icon name="chevron-right" size={13} sw={2.4} />
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    );
  };

  // ---------- Profile ----------
  const renderProfile = () => (
    <div className="route" style={{ padding: "40px 48px 36px", width: "100%" }}>
      {eyebrow([{ label: "Account", muted: true }, { label: "Profile settings", muted: true }])}
      <h1 style={{ margin: 0, fontSize: 30, fontWeight: 800, letterSpacing: "-.7px", color: "var(--fr-text)" }}>{t("Profile Settings")}</h1>
      <div style={{ fontSize: 13.5, color: "var(--fr-text-3)", marginTop: 6 }}>{t("Signed in as")} <b style={{ color: "var(--fr-text-2)" }}>{me}</b> · manage your account, security, integrations &amp; automation</div>

      <div style={{ display: "grid", gridTemplateColumns: "260px 1fr", gap: 22, alignItems: "start", marginTop: 26 }}>
        <div style={{ ...CARD, padding: 8 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "14px 12px 16px" }}>
            {meAvatar(44, 17, meInitials)}
            <div style={{ minWidth: 0 }}>
              <div style={{ font: "700 14px Inter,sans-serif", color: "var(--fr-text)" }}>{meDisplay}</div>
              <div style={{ display: "flex", alignItems: "center", gap: 5, marginTop: 3, font: "600 11.5px Inter,sans-serif", color: "var(--fr-success)" }}><Icon name="shield-check" size={12} sw={2.2} />{t("Active")}</div>
            </div>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <div className="clk" onClick={() => setState({ profileTab: "account" })} style={{ display: "flex", alignItems: "center", gap: 11, padding: "10px 12px", borderRadius: 10, cursor: "pointer", font: "600 13.5px Inter,sans-serif", ...pfNav("account") }}><Icon name="user1" size={17} />{t("Account")}</div>
            <div className="clk" onClick={() => setState({ profileTab: "security" })} style={{ display: "flex", alignItems: "center", gap: 11, padding: "10px 12px", borderRadius: 10, cursor: "pointer", font: "600 13.5px Inter,sans-serif", ...pfNav("security") }}>
              <Icon name="lock" size={17} /><span style={{ flex: 1 }}>{t("Security")}</span>
              {twoFAEnabled && <span className="mono" style={{ fontSize: 9.5, fontWeight: 700, letterSpacing: ".5px", color: "var(--fr-success)", background: "var(--fr-success-soft)", borderRadius: 6, padding: "2px 6px" }}>{t("2FA")}</span>}
            </div>
            <div className="clk" onClick={() => setState({ profileTab: "api" })} style={{ display: "flex", alignItems: "center", gap: 11, padding: "10px 12px", borderRadius: 10, cursor: "pointer", font: "600 13.5px Inter,sans-serif", ...pfNav("api") }}><Icon name="plug" size={17} />API &amp; Automation</div>
            <div className="clk" onClick={() => setState({ profileTab: "customizing" })} style={{ display: "flex", alignItems: "center", gap: 11, padding: "10px 12px", borderRadius: 10, cursor: "pointer", font: "600 13.5px Inter,sans-serif", ...pfNav("customizing") }}><Icon name={theme === "dark" ? "moon" : "sun"} size={17} />{t("Customizing")}</div>
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
          {state.profileTab === "account" && renderProfileAccount()}
          {state.profileTab === "security" && renderProfileSecurity()}
          {state.profileTab === "api" && renderProfileApi()}
          {state.profileTab === "customizing" && renderProfileCustomizing()}
        </div>
      </div>
    </div>
  );

  const cardHeader = (icon: Parameters<typeof Icon>[0]["name"], title: string, sub: string, right?: ReactNode) => (
    <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 14, marginBottom: 18 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ width: 38, height: 38, flex: "none", borderRadius: 10, background: "var(--fr-accent-soft)", color: "var(--fr-accent)", display: "flex", alignItems: "center", justifyContent: "center" }}><Icon name={icon} size={19} /></div>
        <div><div style={{ font: "700 15px Inter,sans-serif", color: "var(--fr-text)" }}>{title}</div><div style={{ fontSize: 12.5, color: "var(--fr-text-3)", marginTop: 2 }}>{sub}</div></div>
      </div>
      {right}
    </div>
  );

  const renderProfileAccount = () => (
    <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
      <div style={{ ...CARD, padding: "22px 24px" }}>
        {cardHeader("image", "Profile Picture", "Shown next to your name across the workspace")}
        <div style={{ display: "flex", alignItems: "center", gap: 28 }}>
          {meAvatar(84, 30, meInitials[0], avatarPreview || (authUser?.avatar_url ?? null))}
          <div style={{ flex: 1 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <input id="pfFileInput" type="file" accept="image/png,image/jpeg,image/webp,image/gif" style={{ display: "none" }} onChange={onAvatarPick} />
              <label htmlFor="pfFileInput" className="clk" style={{ display: "inline-flex", alignItems: "center", gap: 8, height: 42, padding: "0 18px", border: "1px solid var(--fr-border)", borderRadius: 11, background: "var(--fr-surface)", font: "700 13px Inter,sans-serif", color: "var(--fr-text-2)", cursor: "pointer" }}><Icon name="image" size={15} />{t("Choose file")}</label>
              <button className="clk" disabled={!avatarFile || avatarUploading} onClick={submitAvatar} style={{ display: "inline-flex", alignItems: "center", gap: 8, height: 42, padding: "0 18px", border: "none", borderRadius: 11, background: !avatarFile || avatarUploading ? "var(--fr-accent-muted)" : "var(--fr-accent)", color: "var(--fr-on-accent)", font: "700 13px Inter,sans-serif", cursor: !avatarFile || avatarUploading ? "not-allowed" : "pointer" }}><Icon name="upload" size={15} color="var(--fr-on-accent)" />{avatarUploading ? "Uploading…" : "Upload"}</button>
              {avatarFile && !avatarUploading && (
                <button className="clk" onClick={clearAvatarPick} style={{ display: "inline-flex", alignItems: "center", height: 42, padding: "0 14px", border: "1px solid var(--fr-border)", borderRadius: 11, background: "var(--fr-surface)", font: "700 13px Inter,sans-serif", color: "var(--fr-text-3)", cursor: "pointer" }}>{t("Cancel")}</button>
              )}
            </div>
            <div style={{ fontSize: 12.5, color: "var(--fr-text-faint)", marginTop: 12 }}>
              {avatarFile ? (
                <span style={{ color: "var(--fr-text-2)" }}>{t("Selected:")} <b>{avatarFile.name}</b> {t("— press Upload to save.")}</span>
              ) : (
                <>{t("PNG / JPEG / WEBP / GIF, up to")} <b style={{ color: "var(--fr-text-3)" }}>{t("5 MB")}</b>{t(". Square images look best.")}</>
              )}
            </div>
          </div>
        </div>
      </div>

      <div style={{ ...CARD, padding: "22px 24px" }}>
        {cardHeader("idcard", "Account identity", "Read-only — managed by your administrator", <span style={{ font: "700 11px Inter,sans-serif", color: "var(--fr-text-2)", background: "var(--fr-hover)", border: "1px solid var(--fr-border-light)", borderRadius: 8, padding: "5px 11px" }}>{t("Active")}</span>)}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", border: "1px solid var(--fr-divider)", borderRadius: 12, overflow: "hidden" }}>
          {[
            { label: "Username", value: me, mono: true, color: "var(--fr-text)" },
            { label: "Email", value: meEmail, mono: true, color: "var(--fr-text)", small: true },
            { label: "Role", value: meRoleLabel, mono: false, color: "var(--fr-accent)" },
            { label: "User ID", value: String(meId), mono: true, color: "var(--fr-accent-2)", last: true },
          ].map((c, i) => (
            <div key={i} style={{ padding: "15px 18px", borderRight: c.last ? "none" : "1px solid var(--fr-divider)" }}>
              <div className="mono" style={{ fontSize: 10, letterSpacing: ".8px", color: "var(--fr-text-faint)", fontWeight: 700, textTransform: "uppercase" }}>{c.label}</div>
              <div className={c.mono ? "mono" : undefined} style={{ fontSize: c.small ? 13 : 14, color: c.color, fontWeight: c.mono ? 600 : 700, marginTop: 7, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", ...(c.mono ? {} : { font: "700 13px Inter,sans-serif" }) }}>{c.value}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  const renderProfileCustomizing = () => {
    // One selectable option tile, shared by the Appearance and Language cards.
    const tile = (key: string, active: boolean, onClick: () => void, icon: Parameters<typeof Icon>[0]["name"], title: string, desc: string) => (
      <div
        key={key}
        className="clk"
        onClick={onClick}
        style={{
          display: "flex",
          alignItems: "flex-start",
          gap: 13,
          padding: "16px 18px",
          border: `1.5px solid ${active ? "var(--fr-accent)" : "var(--fr-border-light)"}`,
          borderRadius: 14,
          background: active ? "var(--fr-accent-soft)" : "var(--fr-surface)",
          cursor: "pointer",
          transition: "border-color .12s, background .12s",
        }}
      >
        <div style={{ width: 38, height: 38, flex: "none", borderRadius: 10, background: active ? "var(--fr-surface)" : "var(--fr-hover)", color: active ? "var(--fr-accent)" : "var(--fr-text-2)", display: "flex", alignItems: "center", justifyContent: "center" }}>
          <Icon name={icon} size={19} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ font: "700 14px Inter,sans-serif", color: active ? "var(--fr-accent)" : "var(--fr-text)" }}>{title}</span>
            {active && <Icon name="check-circle" size={15} color="var(--fr-accent)" sw={2.2} />}
          </div>
          <div style={{ fontSize: 12.5, color: "var(--fr-text-3)", marginTop: 4, lineHeight: 1.45 }}>{desc}</div>
        </div>
      </div>
    );
    const grid: CSSProperties = { display: "grid", gridTemplateColumns: "repeat(2,1fr)", gap: 14 };
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
        {/* Appearance / theme */}
        <div style={{ ...CARD, padding: "22px 24px" }}>
          {cardHeader("sun", t("Appearance"), t("Choose how FROST looks — saved on this browser"))}
          <div style={grid}>
            {tile("light", theme === "light", () => setTheme("light"), "sun", t("Light"), t("Bright interface — the FROST default."))}
            {tile("dark", theme === "dark", () => setTheme("dark"), "moon", t("Dark"), t("Dimmed palette, easier on the eyes in low light."))}
          </div>
        </div>
        {/* Language */}
        <div style={{ ...CARD, padding: "22px 24px" }}>
          {cardHeader("globe", t("Language"), t("Language of the interface — saved on this browser"))}
          <div style={grid}>
            {tile("en", lang === "en", () => setLang("en"), "globe", "English", t("Interface in English."))}
            {tile("ru", lang === "ru", () => setLang("ru"), "globe2", "Русский", t("Interface in Russian."))}
          </div>
        </div>
      </div>
    );
  };

  const renderProfileSecurity = () => {
    const pwReady = state.pwCurrent.length > 0 && state.pwNew.length >= PW_MIN && state.pwConfirm.length > 0;
    return (
    <>
    <div style={{ ...CARD, padding: "22px 24px", marginBottom: 16 }}>
      {cardHeader("lock", t("Password"), t("Changing it signs out every session, including this one"))}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(220px,1fr))", gap: 12 }}>
        <div>
          <label className="flabel">{t("Current password")}</label>
          <PasswordInput value={state.pwCurrent} onChange={(v) => setState({ pwCurrent: v, pwError: null })} autoComplete="current-password" placeholder={t("Current password")} />
        </div>
        <div>
          <label className="flabel">{t("New password")}</label>
          <PasswordInput value={state.pwNew} onChange={(v) => setState({ pwNew: v, pwError: null })} autoComplete="new-password" placeholder={t("At least 8 characters")} />
        </div>
        <div>
          <label className="flabel">{t("Repeat new password")}</label>
          <PasswordInput value={state.pwConfirm} onChange={(v) => setState({ pwConfirm: v, pwError: null })} autoComplete="new-password" placeholder={t("Repeat new password")} />
        </div>
      </div>
      {state.pwError && (
        <div style={{ marginTop: 12, font: "600 12.5px Inter,sans-serif", color: "var(--fr-danger)" }}>{state.pwError}</div>
      )}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 16 }}>
        <button className="clk" onClick={changeOwnPassword} disabled={!pwReady || state.pwBusy} style={{ height: 44, padding: "0 18px", border: "none", borderRadius: 11, background: !pwReady || state.pwBusy ? "var(--fr-accent-muted)" : "var(--fr-accent)", color: "var(--fr-on-accent)", font: "700 13px Inter,sans-serif", cursor: !pwReady || state.pwBusy ? "not-allowed" : "pointer" }}>
          {state.pwBusy ? t("Changing…") : t("Change password")}
        </button>
        <span style={{ font: "500 12.5px Inter,sans-serif", color: "var(--fr-text-faint)" }}>{t("You will be asked to sign in again.")}</span>
      </div>
    </div>
    <div style={{ ...CARD, padding: "22px 24px" }}>
      {cardHeader("lock", "Two-factor authentication", "Protect sign-in with a Google Authenticator code")}
      {twoFAEnabled ? (
        state.twoFADisableOpen ? (
          <div style={{ border: "1px solid var(--fr-divider)", borderRadius: 12, padding: 18 }}>
            <div style={{ font: "600 13px Inter,sans-serif", color: "var(--fr-text)", marginBottom: 12 }}>{t("Confirm your account password to disable 2FA")}</div>
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
              <input className="finp" type="password" autoComplete="current-password" placeholder={t("Account password")} value={state.twoFADisablePassword} onChange={(e) => setState({ twoFADisablePassword: e.target.value })} style={{ maxWidth: 240 }} />
              <button className="clk" onClick={disableTwoFA} disabled={!state.twoFADisablePassword || state.twoFABusy} style={{ height: 44, padding: "0 18px", border: "none", borderRadius: 11, background: !state.twoFADisablePassword || state.twoFABusy ? "var(--fr-danger-muted)" : "var(--fr-danger)", color: "var(--fr-on-accent)", font: "700 13px Inter,sans-serif", cursor: !state.twoFADisablePassword || state.twoFABusy ? "not-allowed" : "pointer" }}>{state.twoFABusy ? "Disabling…" : "Disable 2FA"}</button>
              <button className="clk" onClick={cancelDisableTwoFA} style={{ height: 44, padding: "0 16px", border: "1px solid var(--fr-border)", borderRadius: 11, background: "var(--fr-surface)", font: "700 13px Inter,sans-serif", color: "var(--fr-text-2)", cursor: "pointer" }}>{t("Cancel")}</button>
            </div>
          </div>
        ) : (
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 14, border: "1px solid var(--fr-success-soft)", background: "var(--fr-success-soft)", borderRadius: 12, padding: "14px 16px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}><Icon name="check-circle" size={18} color="var(--fr-success)" sw={2.2} /><span style={{ font: "600 13.5px Inter,sans-serif", color: "var(--fr-text)" }}>{t("Enabled via authenticator app")}</span></div>
            <button className="clk" onClick={openDisableTwoFA} style={{ height: 38, padding: "0 16px", border: "1px solid var(--fr-border)", borderRadius: 10, background: "var(--fr-surface)", font: "700 12.5px Inter,sans-serif", color: "var(--fr-danger)", cursor: "pointer" }}>{t("Disable")}</button>
          </div>
        )
      ) : state.twoFASetupOpen ? (
        <div style={{ border: "1px solid var(--fr-divider)", borderRadius: 12, padding: 18 }}>
          <div style={{ font: "600 13px Inter,sans-serif", color: "var(--fr-text)", marginBottom: 14 }}>{t("1. Scan this QR in your authenticator app")}</div>
          <div style={{ display: "flex", gap: 20, alignItems: "center", flexWrap: "wrap" }}>
            {state.twoFAQr ? (
              <img src={state.twoFAQr} alt="TOTP QR code" width={120} height={120} style={{ flex: "none", borderRadius: 10, border: "1px solid var(--fr-divider)", imageRendering: "pixelated" }} />
            ) : (
              <div style={{ width: 120, height: 120, flex: "none", borderRadius: 10, background: "var(--fr-hover)", border: "1px solid var(--fr-divider)" }} />
            )}
            <div>
              <div style={{ font: "600 13px Inter,sans-serif", color: "var(--fr-text)", marginBottom: 6 }}>{t("Or enter this key manually")}</div>
              <div className="mono" style={{ fontSize: 13, letterSpacing: 1, background: "var(--fr-hover)", border: "1px solid var(--fr-divider)", borderRadius: 8, padding: "8px 12px", display: "inline-block", whiteSpace: "nowrap", maxWidth: "100%", overflowX: "auto" }}>{state.twoFASecret || "…"}</div>
            </div>
          </div>
          <div style={{ font: "600 13px Inter,sans-serif", color: "var(--fr-text)", margin: "18px 0 10px" }}>{t("2. Enter the 6-digit code")}</div>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <input className="finp" inputMode="numeric" maxLength={6} placeholder="000000" value={state.twoFACode} onChange={(e) => setState({ twoFACode: e.target.value.replace(/\D/g, "") })} style={{ maxWidth: 160, font: "700 16px 'JetBrains Mono',monospace", letterSpacing: 4, textAlign: "center" }} />
            <button className="clk" onClick={confirmTwoFA} disabled={state.twoFACode.trim().length < 6 || state.twoFABusy} style={{ height: 44, padding: "0 18px", border: "none", borderRadius: 11, background: state.twoFACode.trim().length < 6 || state.twoFABusy ? "var(--fr-accent-muted)" : "var(--fr-accent)", color: "var(--fr-on-accent)", font: "700 13px Inter,sans-serif", cursor: state.twoFACode.trim().length < 6 || state.twoFABusy ? "not-allowed" : "pointer" }}>{state.twoFABusy ? "Verifying…" : "Verify & enable"}</button>
            <button className="clk" onClick={cancelTwoFA} style={{ height: 44, padding: "0 16px", border: "1px solid var(--fr-border)", borderRadius: 11, background: "var(--fr-surface)", font: "700 13px Inter,sans-serif", color: "var(--fr-text-2)", cursor: "pointer" }}>{t("Cancel")}</button>
          </div>
        </div>
      ) : (
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 14, border: "1px solid var(--fr-divider)", borderRadius: 12, padding: "14px 16px" }}>
          <span style={{ font: "600 13.5px Inter,sans-serif", color: "var(--fr-text-2)" }}>{t("Two-factor authentication is currently disabled.")}</span>
          <button className="clk" onClick={startTwoFA} disabled={state.twoFABusy} style={{ height: 38, padding: "0 16px", border: "none", borderRadius: 10, background: state.twoFABusy ? "var(--fr-accent-muted)" : "var(--fr-accent)", color: "var(--fr-on-accent)", font: "700 12.5px Inter,sans-serif", cursor: state.twoFABusy ? "not-allowed" : "pointer" }}>{state.twoFABusy ? "Preparing…" : "Enable 2FA"}</button>
        </div>
      )}
    </div>
    </>
    );
  };

  const renderProfileApi = () => (
    <div style={{ ...CARD, padding: "22px 24px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
        <div><div style={{ font: "700 15px Inter,sans-serif", color: "var(--fr-text)" }}>{t("API keys")}</div><div style={{ fontSize: 12.5, color: "var(--fr-text-3)", marginTop: 2 }}>{t("Scoped tokens for CI, bots and automation — no interactive login")}</div></div>
        <button className="clk" onClick={openApiKeyModal} style={{ display: "inline-flex", alignItems: "center", gap: 7, height: 40, padding: "0 16px", border: "none", borderRadius: 10, background: "var(--fr-accent)", color: "var(--fr-on-accent)", font: "700 13px Inter,sans-serif", cursor: "pointer" }}><Icon name="plus" size={14} color="var(--fr-on-accent)" sw={2.2} />{t("Generate new key")}</button>
      </div>
      <div style={{ marginTop: 14, border: "1px solid var(--fr-divider)", borderRadius: 12, overflow: "hidden" }}>
        {state.apiKeys.map((k) => (
          <div key={k.id} style={{ display: "flex", alignItems: "center", gap: 14, padding: "14px 16px", borderTop: "1px solid var(--fr-divider)" }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ font: "600 13.5px Inter,sans-serif", color: "var(--fr-text)" }}>{k.name}</div>
              <div className="mono" style={{ fontSize: 12, color: "var(--fr-text-3)", marginTop: 4 }}>{k.key}</div>
              <div style={{ fontSize: 11, color: "var(--fr-text-faint)", marginTop: 4 }}>
                {k.allProjects ? t("All projects") : `${t("Projects:")} ${k.projectCount ?? 0}`}
                {" · "}
                {k.expires ? `until ${k.expires}` : "no expiry"}
              </div>
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 5, maxWidth: 280, justifyContent: "flex-end" }}>
              {k.scopes.map((sc) => <span key={sc} className="mono" style={{ fontSize: 10, fontWeight: 700, color: "var(--fr-accent)", background: "var(--fr-accent-soft)", borderRadius: 6, padding: "3px 8px" }}>{sc}</span>)}
            </div>
            <div className="mono" style={{ fontSize: 11.5, color: "var(--fr-text-faint)", width: 80, textAlign: "right" }}>{k.created}</div>
            <div className="actbtn del" onClick={() => revokeApiKey(k.id)} style={{ flex: "none" }}><Icon name="trash" size={15} /></div>
          </div>
        ))}
        {state.apiKeys.length === 0 && <div style={{ padding: "22px 16px", textAlign: "center", color: "var(--fr-text-faint)", fontSize: 13 }}>{t("No API keys yet.")}</div>}
      </div>
    </div>
  );

  // ---------- Modals ----------
  const modalShell = (open: boolean, onClose: () => void, zIndex: number, width: number, children: ReactNode, align: "center" | "flex-start" = "center", pad = "24px") => (
    <div className={`modalback ${open ? "open" : ""}`} onClick={onClose} style={{ position: "absolute", inset: 0, zIndex, background: "rgba(20,28,40,.42)", display: "flex", alignItems: align, justifyContent: "center", padding: pad, overflow: align === "flex-start" ? "auto" : undefined }}>
      <div className="modalcard" onClick={stop} style={{ width, maxWidth: "100%", background: "var(--fr-surface)", borderRadius: 20, boxShadow: "0 30px 80px rgba(15,27,45,.3)", padding: "28px 28px 24px" }}>
        {children}
      </div>
    </div>
  );

  const modalFooter = (onCancel: () => void, onSave: () => void, saveLabel: string, saveBg = "var(--fr-accent-2)") => (
    <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 24 }}>
      <button className="clk" onClick={onCancel} style={{ height: 42, padding: "0 20px", border: "1px solid var(--fr-border)", borderRadius: 11, background: "var(--fr-surface)", font: "700 13.5px Inter,sans-serif", color: "var(--fr-text-2)" }}>{t("Cancel")}</button>
      <button className="clk" onClick={onSave} style={{ height: 42, padding: "0 22px", border: "none", borderRadius: 11, background: saveBg, color: "var(--fr-on-accent)", font: "700 13.5px Inter,sans-serif" }}>{saveLabel}</button>
    </div>
  );

  return (
    <div className="frost" style={{ height: "100vh", display: "flex", flexDirection: "column", overflow: "hidden", background: "var(--fr-bg)", position: "relative" }}>
      {/* top app bar */}
      <header style={{ height: 58, flex: "none", display: "flex", alignItems: "center", gap: 14, padding: "0 22px", background: "var(--fr-surface)", borderBottom: "1px solid var(--fr-border-light)", zIndex: 30 }}>
        {/* Зона логотипа = прямоугольник от края экрана (x=0) до делителя (x=76,
            правый край свёрнутого сайдбара). Отрицательный marginLeft гасит
            паддинг хедера (22px), лого центрируется в этом прямоугольнике — ровно
            над иконками свёрнутой панели, делитель над её краем. */}
        <div style={{ display: "flex", alignItems: "center" }}>
          <div style={{ marginLeft: -22, width: 76, display: "flex", alignItems: "center", justifyContent: "center", flex: "none" }}>
            <FrostMark size={30} />
          </div>
          <div style={{ width: 1, height: 22, background: "var(--fr-border-strong)", flex: "none" }} />
          <div className="mono" style={{ marginLeft: 16, fontSize: 10.5, letterSpacing: 1.6, color: "var(--fr-text-faint)", fontWeight: 600 }}>FINDINGS, RESEARCH &amp; OFFENSIVE SECURITY TESTING</div>
        </div>
        <div style={{ flex: 1 }} />
        <div className="clk nav iconbtn" onClick={() => toggle("notifOpen")} style={{ width: 40, height: 40, borderRadius: 11, display: "flex", alignItems: "center", justifyContent: "center", position: "relative" }}>
          <Icon name="bell" size={19} color="var(--fr-text-3)" />
          {hasUnread && <span style={{ position: "absolute", top: 6, right: 7, width: 8, height: 8, borderRadius: "50%", background: "var(--fr-danger)", border: "2px solid var(--fr-surface)" }} />}
        </div>
        <div className="clk" onClick={() => toggle("userMenuOpen")} style={{ display: "flex", alignItems: "center", gap: 9, padding: 4, borderRadius: 24 }}>
          {meAvatar(34, 12.5, meInitials)}
          <Icon name="chevron-down" size={15} color="var(--fr-text-faint)" sw={2.2} style={{ transform: state.userMenuOpen ? "rotate(180deg)" : "none", transition: "transform .2s" }} />
        </div>
      </header>

      {/* user menu */}
      {state.userMenuOpen && <div onClick={() => setState({ userMenuOpen: false })} style={{ position: "absolute", inset: 0, zIndex: 40 }} />}
      <div className={`menu ${state.userMenuOpen ? "open" : ""}`} style={{ position: "absolute", top: 56, right: 16, width: 270, background: "var(--fr-surface)", border: "1px solid var(--fr-border-light)", borderRadius: 16, boxShadow: "0 20px 54px rgba(15,27,45,.18)", zIndex: 50, overflow: "hidden" }}>
        <div style={{ padding: "22px 20px 16px", textAlign: "center", borderBottom: "1px solid var(--fr-elevated)" }}>
          <div style={{ width: 60, height: 60, margin: "0 auto 12px", display: "flex", alignItems: "center", justifyContent: "center" }}>{meAvatar(60, 22, meInitials)}</div>
          <div style={{ fontWeight: 700, fontSize: 16, color: "var(--fr-text)" }}>{meDisplay}</div>
          <div className="mono" style={{ fontSize: 12, color: "var(--fr-text-faint)", marginTop: 3 }}>{meEmail}</div>
        </div>
        <div style={{ padding: 8 }}>
          <div className="nav clk" onClick={openProfile} style={{ display: "flex", alignItems: "center", gap: 12, padding: "11px 12px", borderRadius: 10, font: "600 13.5px Inter,sans-serif", color: "var(--fr-text)" }}><Icon name="user" size={18} color="var(--fr-text-3)" />{t("Profile")}</div>
          <div style={{ height: 1, background: "var(--fr-elevated)", margin: "6px 4px" }} />
          <div className="nav clk" onClick={() => { setState({ userMenuOpen: false }); void signOut(); }} style={{ display: "flex", alignItems: "center", gap: 12, padding: "11px 12px", borderRadius: 10, font: "600 13.5px Inter,sans-serif", color: "var(--fr-danger)" }}><Icon name="logout" size={18} color="currentColor" />{t("Logout")}</div>
        </div>
      </div>

      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
        {/* sidebar */}
        <aside className={`sb ${state.sidebarCollapsed ? "collapsed" : ""}`} style={{ width: sideW, flex: "none", background: "var(--fr-surface)", borderRight: "1px solid var(--fr-border-light)", display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <div className="sbhead" style={{ display: "flex", alignItems: "center", justifyContent: state.sidebarCollapsed ? "center" : "space-between", padding: state.sidebarCollapsed ? "20px 12px 18px 12px" : "20px 14px 18px 18px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, overflow: "hidden" }}>
              <span className="lbl"><FrostWordmark size={18} spacing={3} /></span>
            </div>
            <div className="clk nav iconbtn" onClick={() => toggle("sidebarCollapsed")} style={{ width: 40, height: 40, flex: "none", borderRadius: 11, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--fr-text-faint)" }}>
              <Icon name="chevrons-left" size={18} color="currentColor" sw={2.4} style={{ transform: state.sidebarCollapsed ? "rotate(180deg)" : "none", transition: "transform .26s ease" }} />
            </div>
          </div>
          <div className="lbl mono" style={{ padding: "0 20px 8px", fontSize: 10, letterSpacing: 1.5, color: "var(--fr-text-faint)", fontWeight: 700 }}>{t("WORKSPACE")}</div>
          <nav style={{ padding: "0 12px", display: "flex", flexDirection: "column", gap: 3 }}>
            {([
              { id: "projects" as const, icon: "folder" as const, label: "Projects", onClick: selProjects },
              { id: "tasks" as const, icon: "check-square" as const, label: "Tasks", onClick: () => setState({ nav: "tasks", view: "list" }) },
              { id: "mine" as const, icon: "user1" as const, label: "My Tasks", onClick: () => setState({ nav: "mine", view: "list" }) },
              { id: "docs" as const, icon: "doc" as const, label: "Docs", onClick: () => setState({ nav: "docs", view: "list" }) },
              ...(isAdmin ? [{ id: "members" as const, icon: "users" as const, label: "Members", onClick: selWSMembers }] : []),
            ]).map((it) => (
              <div key={it.id} className="nav clk" onClick={it.onClick} style={{ display: "flex", alignItems: "center", gap: 13, padding: "10px 12px", borderRadius: 11, font: "600 14px Inter,sans-serif", color: navColor(it.id), background: navBg(it.id) }}>
                <Icon name={it.icon} size={19} color="currentColor" style={{ flex: "none" }} />
                <span className="lbl">{t(it.label)}</span>
              </div>
            ))}
          </nav>
        </aside>

        {/* main column */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", minWidth: 0, overflow: "hidden" }}>
          <main style={{ flex: 1, overflow: "auto", paddingBottom: 48 }}>
            {isList && renderProjects()}
            {isDocs && (
              <Suspense fallback={<div className="route" style={{ padding: "40px 48px", color: "var(--fr-text-faint)", font: "500 14px Inter,sans-serif" }}>{t("Loading docs…")}</div>}>
                <FrostDocs isAdmin={isAdmin} onNavigateWorkspace={selProjects} />
              </Suspense>
            )}
            {isStub && renderStub()}
            {/* /members is admin-only (GET /users is too) — say so rather than
                quietly showing the projects list instead. */}
            {state.view === "workspaceMembers" &&
              (isAdmin
                ? renderWorkspaceMembers()
                : renderNoAccessPage("The Members section is admin-only — this is where users are created and roles assigned."))}
            {state.view === "detail" && (state.accessDenied ? renderNoAccessPage() : renderDetail())}
            {state.view === "profile" && renderProfile()}
          </main>
        </div>
      </div>
      <footer style={{ position: "absolute", bottom: 0, left: 0, right: 0, display: "flex", alignItems: "center", justifyContent: "center", gap: 8, padding: 16, fontSize: 12.5, color: "var(--fr-text-faint)", flexWrap: "wrap", pointerEvents: "none" }}>
        <FrostWordmark size={13} spacing={2} /><span>·</span><span>{t("Copyright © 2026. All rights reserved.")}</span>
      </footer>

      {/* ===== modals ===== */}
      {/* workspace user editor */}
      {modalShell(
        state.wsUserModalOpen,
        closeWSUserEditor,
        60,
        440,
        <>
          <h2 style={{ margin: 0, fontSize: 21, fontWeight: 800, color: "var(--fr-text)", letterSpacing: "-.4px" }}>{state.wsUserMode === "add" ? "Invite member" : "Edit member"}</h2>
          {state.wsUserMode === "add" ? (
            <>
              <div style={{ marginTop: 16 }}><label className="flabel">{t("Email")}</label><input className="finp" placeholder={t("user@company.com")} value={state.wsUserEmail} onChange={(e) => setState({ wsUserEmail: e.target.value })} /></div>
            </>
          ) : (
            <>
              {/* Юзернейм неизменяем (даже админом) — как и email: только для чтения. */}
              <div style={{ marginTop: 20 }}><label className="flabel">{t("Username")}</label><input className="finp" value={state.wsUserName} disabled style={{ background: "var(--fr-elevated)", color: "var(--fr-text-3)" }} /></div>
              <div style={{ marginTop: 16 }}><label className="flabel">{t("Email")}</label><input className="finp" placeholder={t("user@company.com")} value={state.wsUserEmail} disabled style={{ background: "var(--fr-elevated)", color: "var(--fr-text-3)" }} /></div>
            </>
          )}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginTop: 16 }}>
            <div>
              <label className="flabel">{t("Workspace role")}</label>
              <FrostSelect
                value={state.wsUserRole}
                onChange={(v) => setState({ wsUserRole: v as WsRole })}
                options={[
                  { value: "user", label: "User", dot: WS_ROLE.user.color, desc: "Works on assigned projects" },
                  { value: "admin", label: "Admin", dot: WS_ROLE.admin.color, desc: "Manages the whole workspace" },
                ]}
              />
            </div>
            <div>
              <label className="flabel">{t("Project role")}</label>
              <FrostSelect
                value={state.wsUserProjectRole}
                onChange={(v) => setState({ wsUserProjectRole: v as Role })}
                options={[
                  { value: "lead", label: "Lead", dot: ROLE.lead.color, desc: "Leads the project team" },
                  { value: "pentester", label: "Pentester", dot: ROLE.pentester.color, desc: "Tests and reports findings" },
                ]}
              />
            </div>
          </div>
          {modalFooter(closeWSUserEditor, saveWSUser, state.wsUserMode === "add" ? t("Send invite") : t("Save"), "var(--fr-accent)")}
        </>
      )}

      {/* generate API key */}
      {modalShell(
        state.apiKeyModalOpen,
        closeApiKeyModal,
        60,
        460,
        <>
          <h2 style={{ margin: 0, fontSize: 21, fontWeight: 800, color: "var(--fr-text)", letterSpacing: "-.4px" }}>{t("Generate API key")}</h2>
          <div style={{ marginTop: 20 }}><label className="flabel">{t("Key name")}</label><input className="finp" placeholder={t("e.g. CI pipeline")} value={state.apiKeyName} onChange={(e) => setState({ apiKeyName: e.target.value })} /></div>
          <div style={{ marginTop: 16 }}>
            <label className="flabel">{t("Permissions")}</label>
            <div style={{ display: "flex", flexDirection: "column", gap: 2, border: "1px solid var(--fr-divider)", borderRadius: 11, overflow: "hidden", marginTop: 6 }}>
              {API_SCOPES.map((s) => {
                const checked = !!state.apiKeyScopes[s];
                return (
                  <div key={s} className="clk" onClick={() => toggleApiScope(s)} style={{ display: "flex", alignItems: "center", gap: 10, padding: "11px 14px", borderTop: "1px solid var(--fr-divider)", cursor: "pointer" }}>
                    <span style={{ width: 18, height: 18, flex: "none", borderRadius: 5, border: `1.5px solid ${checked ? "var(--fr-accent)" : "var(--fr-border)"}`, background: checked ? "var(--fr-accent)" : "var(--fr-surface)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                      {checked && <Icon name="check" size={12} color="var(--fr-on-accent)" sw={3} />}
                    </span>
                    <span className="mono" style={{ fontSize: 12, color: "var(--fr-text)", flex: "none" }}>{s}</span>
                    <span style={{ fontSize: 12, color: "var(--fr-text-3)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{API_SCOPE_LABELS[s]}</span>
                  </div>
                );
              })}
            </div>
          </div>
          <div style={{ marginTop: 16 }}>
            <label className="flabel">{t("Project access")}</label>
            <div style={{ display: "flex", gap: 8, marginTop: 6 }}>
              <div className="clk" onClick={() => setState({ apiKeyAllProjects: true })} style={{ font: "600 12.5px Inter,sans-serif", padding: "7px 13px", borderRadius: 9, cursor: "pointer", ...vfPill(state.apiKeyAllProjects) }}>{t("All my projects")}</div>
              <div className="clk" onClick={() => setState({ apiKeyAllProjects: false })} style={{ font: "600 12.5px Inter,sans-serif", padding: "7px 13px", borderRadius: 9, cursor: "pointer", ...vfPill(!state.apiKeyAllProjects) }}>{t("Selected projects")}</div>
            </div>
            {!state.apiKeyAllProjects && (
              <div style={{ marginTop: 8, border: "1px solid var(--fr-divider)", borderRadius: 11, maxHeight: 168, overflow: "auto" }}>
                {(state.apiProjects ?? []).map((p) => {
                  const checked = state.apiKeyProjectIds.includes(p.id);
                  return (
                    <div key={p.id} className="clk" onClick={() => toggleApiProject(p.id)} style={{ display: "flex", alignItems: "center", gap: 10, padding: "9px 12px", borderTop: "1px solid var(--fr-divider)", cursor: "pointer" }}>
                      <span style={{ width: 18, height: 18, flex: "none", borderRadius: 5, border: `1.5px solid ${checked ? "var(--fr-accent)" : "var(--fr-border)"}`, background: checked ? "var(--fr-accent)" : "var(--fr-surface)", display: "flex", alignItems: "center", justifyContent: "center" }}>
                        {checked && <Icon name="check" size={12} color="var(--fr-on-accent)" sw={3} />}
                      </span>
                      <span style={{ fontSize: 12.5, color: "var(--fr-text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{p.name}</span>
                    </div>
                  );
                })}
                {(state.apiProjects ?? []).length === 0 && <div style={{ padding: 16, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 12.5 }}>{t("No projects available.")}</div>}
              </div>
            )}
          </div>
          <div style={{ marginTop: 16 }}>
            <label className="flabel">{t("Expiry")}</label>
            <FrostDatePicker value={state.apiKeyExpiry} onChange={(v) => setState({ apiKeyExpiry: v })} min={new Date().toISOString().slice(0, 10)} placeholder={t("No expiry")} />
          </div>
          {modalFooter(closeApiKeyModal, createApiKey, t("Generate key"), "var(--fr-accent)")}
        </>
      )}

      {/* new project */}
      {modalShell(
        state.modalOpen,
        () => setState({ modalOpen: false, newName: "", newDesc: "", newStart: "", newEnd: "" }),
        60,
        480,
        <>
          <h2 style={{ margin: 0, fontSize: 22, fontWeight: 800, color: "var(--fr-text)", letterSpacing: "-.4px" }}>{t("New project")}</h2>
          <div style={{ fontSize: 13.5, color: "var(--fr-text-3)", marginTop: 6 }}>{t("Create a project workspace for a new engagement.")}</div>
          <div style={{ marginTop: 22 }}><label className="flabel">{t("Project name")}</label><input className="finp" placeholder={t("e.g. Acme Corp — External Perimeter")} value={state.newName} onChange={(e) => setState({ newName: e.target.value })} /></div>
          <div style={{ marginTop: 16 }}><label className="flabel">{t("Description")}</label><textarea className="finp" rows={3} placeholder={t("Short summary of the engagement scope…")} value={state.newDesc} onChange={(e) => setState({ newDesc: e.target.value })} /></div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginTop: 16 }}>
            {/* min/max keep the pickers themselves from offering an inverted range. */}
            <div><label className="flabel">{t("Start date")}</label><FrostDatePicker value={state.newStart} onChange={(v) => setState({ newStart: v })} max={state.newEnd || undefined} /></div>
            <div><label className="flabel">{t("End date")}</label><FrostDatePicker value={state.newEnd} onChange={(v) => setState({ newEnd: v })} min={state.newStart || undefined} /></div>
          </div>
          {datesInvalid(state.newStart, state.newEnd) && (
            <div style={{ marginTop: 8, font: "600 12px Inter,sans-serif", color: "var(--fr-danger)" }}>{DATES_ERROR}</div>
          )}
          {modalFooter(() => setState({ modalOpen: false, newName: "", newDesc: "", newStart: "", newEnd: "" }), createProject, "Create project")}
        </>
      )}

      {/* edit project */}
      {modalShell(
        state.projEditOpen,
        closeProjEdit,
        60,
        480,
        <>
          <h2 style={{ margin: 0, fontSize: 22, fontWeight: 800, color: "var(--fr-text)", letterSpacing: "-.4px" }}>{t("Edit project")}</h2>
          <div style={{ marginTop: 20 }}><label className="flabel">{t("Project name")}</label><input className="finp" value={state.projEditName} onChange={(e) => setState({ projEditName: e.target.value })} /></div>
          <div style={{ marginTop: 16 }}><label className="flabel">{t("Description")}</label><textarea className="finp" rows={3} value={state.projEditDesc} onChange={(e) => setState({ projEditDesc: e.target.value })} /></div>
          <div style={{ marginTop: 16 }}>
            <label className="flabel">{t("Status")}</label>
            <select className="finp" value={state.projEditStatus} onChange={(e) => setState({ projEditStatus: e.target.value as ProjectStatus })}>
              {PROJECT_STATUS_ORDER.map((s) => <option key={s} value={s}>{t(PROJ_STATUS[s]?.label ?? s)}</option>)}
            </select>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginTop: 16 }}>
            <div><label className="flabel">{t("Start date")}</label><FrostDatePicker value={state.projEditStart} onChange={(v) => setState({ projEditStart: v })} max={state.projEditEnd || undefined} /></div>
            <div><label className="flabel">{t("End date")}</label><FrostDatePicker value={state.projEditEnd} onChange={(v) => setState({ projEditEnd: v })} min={state.projEditStart || undefined} /></div>
          </div>
          {datesInvalid(state.projEditStart, state.projEditEnd) && (
            <div style={{ marginTop: 8, font: "600 12px Inter,sans-serif", color: "var(--fr-danger)" }}>{DATES_ERROR}</div>
          )}
          {modalFooter(closeProjEdit, saveProjEdit, t("Save"))}
        </>
      )}

      {/* activity: the full list behind a card's "Show more" */}
      {(() => {
        const g = state.activityModalKey ? activityGroups.find((x) => x.key === state.activityModalKey) : undefined;
        const close = () => setState({ activityModalKey: null });
        return modalShell(
          !!g,
          close,
          60,
          620,
          <>
            <h2 style={{ margin: 0, fontSize: 20, fontWeight: 800, color: "var(--fr-text)", letterSpacing: "-.4px" }}>
              {g ? `${g.actor} ${g.verb} ${g.subject}` : ""}
            </h2>
            {g && <div className="mono" style={{ marginTop: 6, fontSize: 11.5, color: "var(--fr-text-faint)" }}>{g.time}</div>}
            <div style={{ marginTop: 16, background: "var(--fr-code-bg)", borderRadius: 10, padding: "12px 13px", display: "flex", flexDirection: "column", gap: 6, maxHeight: 420, overflow: "auto" }}>
              {g?.lines.map((l) => activityLineRow(l, g.tone))}
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 20 }}>
              <button className="clk" onClick={close} style={{ height: 40, padding: "0 20px", border: "1px solid var(--fr-border)", borderRadius: 10, background: "var(--fr-surface)", font: "700 13px Inter,sans-serif", color: "var(--fr-text-2)", cursor: "pointer" }}>{t("Close")}</button>
            </div>
          </>
        );
      })()}

      {/* export: Word report generation (backend templates szi / pp) */}
      {modalShell(
        state.exportModalOpen && state.exportScope === "report",
        closeExportModal,
        60,
        480,
        <>
          <h2 style={{ margin: 0, fontSize: 21, fontWeight: 800, color: "var(--fr-text)", letterSpacing: "-.4px" }}>{t("Export report")}</h2>
          <div style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 18 }}>
            {REPORT_KINDS.map((r) => {
              const on = state.exportKind === r.kind;
              return (
                <div
                  key={r.kind}
                  className="clk"
                  onClick={() => setState({ exportKind: r.kind })}
                  style={{ display: "flex", alignItems: "flex-start", gap: 12, padding: "14px 16px", borderRadius: 12, cursor: "pointer", border: `1.5px solid ${on ? "var(--fr-accent-2)" : "var(--fr-border-light)"}`, background: on ? "var(--fr-accent-soft)" : "var(--fr-surface)" }}
                >
                  <span style={{ width: 18, height: 18, flex: "none", marginTop: 2, borderRadius: "50%", border: `1.5px solid ${on ? "var(--fr-accent)" : "var(--fr-border)"}`, display: "flex", alignItems: "center", justifyContent: "center", background: on ? "var(--fr-accent)" : "var(--fr-surface)" }}>
                    {on && <span style={{ width: 7, height: 7, borderRadius: "50%", background: "var(--fr-surface)" }} />}
                  </span>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ font: "700 13.5px Inter,sans-serif", color: "var(--fr-text)" }}>{t(r.title)}</div>
                    <div style={{ fontSize: 12.5, color: "var(--fr-text-3)", marginTop: 3, lineHeight: 1.5 }}>{t(r.desc)}</div>
                  </div>
                </div>
              );
            })}
          </div>
          <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, marginTop: 22 }}>
            <button className="clk" onClick={closeExportModal} style={{ height: 42, padding: "0 20px", border: "1px solid var(--fr-border)", borderRadius: 11, background: "var(--fr-surface)", font: "700 13.5px Inter,sans-serif", color: "var(--fr-text-2)" }}>{t("Cancel")}</button>
            <button className="clk" onClick={doExport} disabled={state.exportBusy} style={{ height: 42, padding: "0 22px", border: "none", borderRadius: 11, background: state.exportBusy ? "var(--fr-accent-muted)" : "var(--fr-accent-2)", color: "var(--fr-on-accent)", font: "700 13.5px Inter,sans-serif", cursor: state.exportBusy ? "default" : "pointer" }}>
              {state.exportBusy ? t("Generating…") : t("Download .docx")}
            </button>
          </div>
        </>
      )}

      {/* entity editor */}
      {modalShell(
        state.editorOpen,
        closeEditor,
        60,
        480,
        <>
          <h2 style={{ margin: 0, fontSize: 21, fontWeight: 800, color: "var(--fr-text)", letterSpacing: "-.4px", textTransform: "capitalize" }}>{`${state.editorMode === "add" ? t("Add") : t("Edit")} ${t(TYPELABEL[state.editorType])}`}</h2>
          <div style={{ display: "flex", flexDirection: "column", gap: 15, marginTop: 22 }}>
            {editorFields.map((f) => (
              <div key={f.key}>
                <label className="flabel">{t(f.label)}</label>
                {f.isText && <input className="finp" placeholder={t(f.placeholder)} value={f.value} onChange={f.onInput} />}
                {f.isTextarea && <textarea className="finp" rows={3} placeholder={t(f.placeholder)} value={f.value} onChange={f.onInput} />}
                {f.isSelect && (
                  <select className="esel" value={f.value} onChange={f.onInput}>
                    {f.value === "" && <option value="" disabled>{t("Select…")}</option>}
                    {f.options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                )}
                {/* Type-to-search over a long option list (hosts, workspace users).
                    A native datalist renders as an unstyleable OS popup, so the
                    suggestions are drawn here instead — top COMBO_MAX matches,
                    prefix hits first. Free text is still accepted. */}
                {f.isCombo && (
                  <div style={{ position: "relative" }}>
                    <input
                      className="finp"
                      placeholder={t(f.placeholder)}
                      value={f.value}
                      onChange={f.onComboInput}
                      onFocus={f.onComboFocus}
                      onBlur={f.onComboBlur}
                      onKeyDown={f.onComboKeyDown}
                      autoComplete="off"
                    />
                    {f.comboOpen && (
                      <div style={{ position: "absolute", top: "calc(100% + 6px)", left: 0, right: 0, background: "var(--fr-surface)", border: "1px solid var(--fr-border-light)", borderRadius: 12, boxShadow: "0 18px 44px rgba(15,27,45,.16)", zIndex: 60, padding: 6, overflow: "hidden" }}>
                        {f.suggestions.map((o) => (
                          <div
                            key={o.value}
                            className="clk"
                            /* mousedown would blur the input and unmount the list
                               before the click lands, so pick on mousedown. */
                            onMouseDown={(e) => {
                              e.preventDefault();
                              o.onPick();
                            }}
                            style={{ display: "flex", flexDirection: "column", gap: 1, padding: "8px 10px", borderRadius: 9, background: o.active ? "var(--fr-accent-soft)" : "transparent" }}
                          >
                            <span style={{ font: "600 13.5px Inter,sans-serif", color: o.active ? "var(--fr-accent)" : "var(--fr-text)" }}>{o.label}</span>
                            {o.sub && <span className="mono" style={{ fontSize: 11.5, color: "var(--fr-text-3)" }}>{o.sub}</span>}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
                {f.isTags && (
                  <div>
                    {f.tags.length > 0 && (
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 8 }}>
                        {f.tags.map((t, ti) => (
                          <span key={ti} className="mono" style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11.5, fontWeight: 600, color: "var(--fr-text-2)", background: "var(--fr-hover)", border: "1px solid var(--fr-border-light)", borderRadius: 7, padding: "4px 6px 4px 9px" }}>
                            {t.value}
                            <span className="clk" onClick={t.onRemove} style={{ display: "flex", color: "var(--fr-text-faint)" }}><Icon name="close" size={12} sw={2.4} /></span>
                          </span>
                        ))}
                      </div>
                    )}
                    <input className="finp" placeholder={t(f.placeholder)} value={f.tagDraft} onChange={f.onTagDraft} onKeyDown={f.onTagKeyDown} />
                  </div>
                )}
              </div>
            ))}
          </div>
          {modalFooter(closeEditor, saveEditor, state.editorMode === "add" ? t("Create") : t("Save changes"))}
        </>
      )}

      {/* delete confirm */}
      {modalShell(
        state.confirmOpen,
        closeConfirm,
        65,
        420,
        state.confirmUserId != null ? (
          /* Пользователя не удаляем, а деактивируем — формулировки об этом и говорят
             (действие обратимо: разблокировать можно тут же на странице участников). */
          <>
            <div style={{ display: "flex", alignItems: "center", gap: 13, marginBottom: 14 }}>
              <span style={{ width: 42, height: 42, flex: "none", borderRadius: "50%", background: "var(--fr-danger-soft)", color: "var(--fr-danger)", display: "flex", alignItems: "center", justifyContent: "center" }}><Icon name="lock" size={20} /></span>
              <h2 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: "var(--fr-text)" }}>{t("Block user")}</h2>
            </div>
            <div style={{ fontSize: 14, color: "var(--fr-text-2)", lineHeight: 1.55 }}>
              <b style={{ color: "var(--fr-text)" }}>{state.confirmLabel}</b> {t("will lose access, but their projects, findings and notes stay. You can reactivate them here later.")}
            </div>
            {modalFooter(closeConfirm, confirmDelete, t("Block"), "var(--fr-danger)")}
          </>
        ) : (
          <>
            <div style={{ display: "flex", alignItems: "center", gap: 13, marginBottom: 14 }}>
              <span style={{ width: 42, height: 42, flex: "none", borderRadius: "50%", background: "var(--fr-danger-soft)", color: "var(--fr-danger)", display: "flex", alignItems: "center", justifyContent: "center" }}><Icon name="trash" size={20} /></span>
              <h2 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: "var(--fr-text)" }}>{t("Confirm deletion")}</h2>
            </div>
            <div style={{ fontSize: 14, color: "var(--fr-text-2)", lineHeight: 1.55 }}>{t("Are you sure you want to delete")} <b style={{ color: "var(--fr-text)" }}>{state.confirmLabel}</b>{t("? This action cannot be undone.")}</div>
            {modalFooter(closeConfirm, confirmDelete, t("Delete"), "var(--fr-danger)")}
          </>
        )
      )}

      {/* endpoint detail */}
      <div className={`modalback ${state.epOpen ? "open" : ""}`} onClick={closeEndpoint} style={{ position: "absolute", inset: 0, zIndex: 66, background: "rgba(20,28,40,.42)", display: "flex", alignItems: "flex-start", justifyContent: "center", padding: "40px 24px", overflow: "auto" }}>
        <div className="modalcard" onClick={stop} style={{ width: 820, maxWidth: "100%", background: "var(--fr-surface)", borderRadius: 20, boxShadow: "0 30px 80px rgba(15,27,45,.3)", padding: "24px 26px 22px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 20 }}>
            <span className="mono" style={{ fontWeight: 700, borderRadius: 6, padding: "3px 10px", fontSize: 12, background: (METHOD[state.epData.method] ?? PORT.closed).bg, color: (METHOD[state.epData.method] ?? PORT.closed).color }}>{state.epData.method}</span>
            <span className="mono" style={{ font: "700 15px 'JetBrains Mono',monospace", color: "var(--fr-text)" }}>{state.epData.path}</span>
            <span className="mono" style={{ fontSize: 12, color: "var(--fr-text-3)", background: "var(--fr-hover)", borderRadius: 6, padding: "3px 9px" }}>{state.epData.host}</span>
            <div style={{ flex: 1 }} />
            <div className="clk actbtn" onClick={closeEndpoint}><Icon name="close" size={18} /></div>
          </div>
          {/* Full-width request box (the response scratchpad was removed). The copy
              control builds a ready cURL for this endpoint; the raw request below is
              still editable and stored on the endpoint. */}
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
              <div className="mono" style={{ fontSize: 10.5, letterSpacing: 1, color: "var(--fr-text-faint)", fontWeight: 700 }}>{t("REQUEST")}</div>
              <div style={{ flex: 1 }} />
              <Tip label={t("Copy cURL request")}>
                <span className="clk" onClick={() => copyCurl(state.epData)} style={{ display: "inline-flex", alignItems: "center", gap: 5, font: "700 11.5px Inter,sans-serif", color: "var(--fr-accent-2)", cursor: "pointer" }}>
                  <Icon name="copy" size={13} />{t("Copy cURL")}
                </span>
              </Tip>
            </div>
            <textarea className="finp mono" rows={9} style={{ fontSize: 12, lineHeight: 1.6, resize: "vertical" }} value={state.epRequest} onChange={(e) => setState({ epRequest: e.target.value })} placeholder={`${state.epData.method} ${state.epData.path} HTTP/1.1`} />
          </div>
          <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 14 }}>
            <button className="clk" onClick={() => copyText(state.epRequest, "Request")} style={{ display: "flex", alignItems: "center", gap: 8, height: 40, padding: "0 18px", border: "none", borderRadius: 10, background: "var(--fr-accent-2)", color: "var(--fr-on-accent)", font: "700 13px Inter,sans-serif", cursor: "pointer" }}>
              <Icon name="copy" size={15} color="var(--fr-on-accent)" />{t("Copy request")}
            </button>
          </div>
          <div style={{ height: 1, background: "var(--fr-divider)", margin: "22px 0 18px" }} />
          <div className="mono" style={{ fontSize: 10.5, letterSpacing: 1, color: "var(--fr-text-faint)", fontWeight: 700, marginBottom: 10 }}>{t("DISCUSSION")}</div>
          <div style={{ background: "var(--fr-hover)", border: "1px solid var(--fr-divider)", borderRadius: 12, padding: 16, fontSize: 13, color: "var(--fr-text-3)", marginBottom: 12 }}>{t("No comments yet — start the discussion.")}</div>
          <textarea className="finp" rows={3} placeholder={t("Share progress, blockers, or review notes…")} />
          <div style={{ display: "flex", justifyContent: "flex-end", alignItems: "center", marginTop: 12 }}>
            <button className="clk" onClick={closeEndpoint} style={{ height: 40, padding: "0 18px", border: "none", borderRadius: 10, background: "var(--fr-accent-2)", color: "var(--fr-on-accent)", font: "700 13px Inter,sans-serif" }}>{t("Post comment")}</button>
          </div>
        </div>
      </div>

      {/* notifications panel */}
      <div className={`notifback ${state.notifOpen ? "open" : ""}`} onClick={() => setState({ notifOpen: false })} style={{ position: "absolute", inset: 0, zIndex: 60, background: "rgba(20,28,40,.3)", display: "flex", justifyContent: "flex-end" }}>
        <div className="notifpanel" onClick={stop} style={{ width: 390, maxWidth: "90%", height: "100%", background: "var(--fr-surface)", boxShadow: "-20px 0 60px rgba(15,27,45,.2)", display: "flex", flexDirection: "column" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 11, padding: "22px 24px 18px", borderBottom: "1px solid var(--fr-divider)" }}>
            <div style={{ fontWeight: 800, fontSize: 18, color: "var(--fr-text)" }}>{t("Notifications")}</div>
            <span className="mono" style={{ padding: "3px 9px", borderRadius: 8, background: "var(--fr-accent-soft)", color: "var(--fr-accent)", fontSize: 11, fontWeight: 700 }}>{newCount} {t("new")}</span>
            <div style={{ flex: 1 }} />
            <div className="clk" onClick={markAllNotifsRead} style={{ font: "600 13px Inter,sans-serif", color: "var(--fr-accent-2)" }}>{t("Mark all read")}</div>
          </div>
          <div style={{ flex: 1, overflow: "auto", padding: 6 }}>
            {notifs.map((n) => (
              <div key={n.key} className="notifitem clk" onClick={n.onClick} style={{ display: "flex", gap: 13, padding: "14px 16px", borderRadius: 12, alignItems: "flex-start" }}>
                <div style={{ width: 36, height: 36, flex: "none", borderRadius: "50%", background: n.avBg, color: "var(--fr-on-accent)", display: "flex", alignItems: "center", justifyContent: "center", font: "700 12px 'JetBrains Mono',monospace" }}>{n.initials}</div>
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div style={{ fontSize: 13.5, color: "var(--fr-text)", lineHeight: 1.45 }}>
                    <span className="mono" style={{ color: "var(--fr-accent)", fontWeight: 600 }}>{n.user}</span> {n.action}{" "}
                    <span style={{ fontWeight: 700, color: "var(--fr-text)" }}>{n.where}</span>
                  </div>
                  <div className="mono" style={{ fontSize: 11, color: "var(--fr-text-faint)", marginTop: 5 }}>{n.meta}</div>
                </div>
                {n.unread && <span style={{ width: 8, height: 8, flex: "none", borderRadius: "50%", background: "var(--fr-accent-2)", marginTop: 5 }} />}
              </div>
            ))}
            {notifs.length === 0 && <div style={{ padding: 48, textAlign: "center", color: "var(--fr-text-faint)", fontSize: 13.5 }}>{t("No notifications.")}</div>}
          </div>
        </div>
      </div>

      {/* image lightbox — click a step screenshot to view it full-size */}
      {state.lightboxSrc && (
        <div onClick={() => setState({ lightboxSrc: null })} style={{ position: "fixed", inset: 0, zIndex: 90, background: "rgba(10,16,26,.82)", display: "flex", alignItems: "center", justifyContent: "center", padding: 40, cursor: "zoom-out", animation: "frost-fade .18s ease both" }}>
          <img src={state.lightboxSrc} alt="Step screenshot" onClick={stop} style={{ maxWidth: "100%", maxHeight: "100%", borderRadius: 12, boxShadow: "0 30px 80px rgba(0,0,0,.5)", display: "block", cursor: "default" }} />
          <div className="clk" onClick={() => setState({ lightboxSrc: null })} style={{ position: "fixed", top: 22, right: 24, width: 40, height: 40, borderRadius: "50%", background: "rgba(255,255,255,.12)", color: "var(--fr-on-accent)", display: "flex", alignItems: "center", justifyContent: "center", cursor: "pointer" }}>
            <Icon name="close" size={20} color="var(--fr-on-accent)" />
          </div>
        </div>
      )}
    </div>
  );
}
