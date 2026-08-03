import axios from "axios";
import type {
  AuthLoginResponse,
  TwoFASetupResponse,
  VulnerabilityComment,
  VulnerabilityDetails,
  VulnerabilityFile,
  Endpoint,
  EndpointRequestHeader,
  Service,
  AuditLog,
  Host,
  HostDetails,
  HostFarmJob,
  IpFarmJob,
  JsFarmJob,
  JsFile,
  ImportResult,
  OpenApiImportResult,
  Invitation,
  InvitationInfo,
  InvitationSentResult,
  Notification,
  OsType,
  PaginatedResponse,
  PasswordResetInfo,
  ReactivationInfo,
  Port,
  Project,
  ProjectActivityItem,
  ProjectFolder,
  ProjectMember,
  ProjectStats,
  PasswordResetResult,
  User,
  ProjectNote,
  ProjectNoteComment,
  ProjectCredential,
  Vulnerability,
  VulnerabilityAsset,
  AgentApiToken,
  JiraIssueLink,
  ProjectJiraLink,
  JiraConfig,
} from "./types";

const api = axios.create({
  baseURL: "/api/v1",
  withCredentials: true,
});

const isBlank = (value: string | null | undefined): boolean => !value || value.trim().length === 0;

const assertRequired = (value: string | null | undefined, label: string): void => {
  if (isBlank(value)) {
    throw new Error(`Field "${label}" is required`);
  }
};

const normalizeDetailMessage = (detail: unknown): string | null => {
  if (typeof detail === "string" && detail.trim()) {
    return detail.trim();
  }
  if (Array.isArray(detail)) {
    const messages = detail.map((item) => normalizeDetailMessage(item)).filter((item): item is string => Boolean(item));
    return messages.length ? messages.join("; ") : null;
  }
  if (detail && typeof detail === "object") {
    if ("detail" in detail) {
      return normalizeDetailMessage((detail as { detail?: unknown }).detail);
    }
    if ("message" in detail) {
      return normalizeDetailMessage((detail as { message?: unknown }).message);
    }
  }
  return null;
};

/** HTTP-статус ошибки axios, если он есть (403 → показываем экран «нет доступа»). */
export const getApiErrorStatus = (error: unknown): number | null =>
  axios.isAxiosError(error) ? (error.response?.status ?? null) : null;

export const getApiErrorMessage = (error: unknown, fallback: string): string => {
  if (axios.isAxiosError(error)) {
    const detail = normalizeDetailMessage(error.response?.data);
    const status = error.response?.status;

    // Нет ответа вовсе — сеть/прокси/бэкенд недоступен. Самый частый случай при
    // локальном `npm run dev`, когда прокси указывает на несуществующий хост.
    if (!error.response) {
      if (error.code === "ECONNABORTED" || error.code === "ETIMEDOUT") {
        return "The server response timed out.";
      }
      return "Server unavailable — couldn't connect to the backend. Make sure the backend is running.";
    }

    if (status === 401) return detail || "Invalid username or password.";
    if (status === 403) return detail || "You don't have permission for this action.";
    if (status === 404) return detail || "The requested resource was not found.";
    if (status === 409) return detail || "Conflict: the resource already exists or was changed.";
    if (status === 422) return detail || "Check the form fields.";
    if (status === 429) return detail || "Too many attempts. Try again later.";
    if (status && status >= 500) {
      // 500/502/503/504 — на сервере/прокси. Если это заглушка прокси Vite,
      // тела с detail обычно нет, поэтому даём понятную подсказку.
      const isGeneric = !detail || detail === "Internal Server Error";
      return isGeneric
        ? `Server error (${status}). The backend may be down or unavailable.`
        : `Server error (${status}): ${detail}`;
    }

    return detail || normalizeDetailMessage(error.message) || fallback;
  }
  if (error instanceof Error && error.message.trim()) {
    return error.message;
  }
  return fallback;
};

let isRefreshing = false;
let waitingQueue: Array<{ resolve: () => void; reject: (error: unknown) => void }> = [];

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    const requestUrl = String(originalRequest?.url ?? "");
    // /auth/login и /auth/refresh — сами по себе попытки аутентификации;
    // 401 здесь = «неверные креды / refresh-токен», а не «сессия истекла»,
    // повторный refresh замаскирует настоящую ошибку.
    // /users/me на старте — проверка наличия сессии: 401 ожидаем, без авторефреша.
    const shouldSkipRefresh =
      requestUrl.includes("/auth/login") ||
      requestUrl.includes("/auth/2fa/verify") ||
      requestUrl.includes("/auth/refresh") ||
      // Публичные эндпоинты активации приглашения — вызываются без сессии,
      // 401 тут «токен активации недействителен», а не «сессия истекла».
      requestUrl.includes("/auth/invitations") ||
      requestUrl.includes("/auth/password-reset") ||
      requestUrl.includes("/auth/reactivate") ||
      requestUrl.includes("/users/me");
    if (error.response?.status === 401 && !originalRequest?._retry && !shouldSkipRefresh) {
      originalRequest._retry = true;
      if (isRefreshing) {
        return new Promise<void>((resolve, reject) => waitingQueue.push({ resolve, reject })).then(() => api(originalRequest));
      }
      isRefreshing = true;
      try {
        await api.post("/auth/refresh");
        waitingQueue.forEach((entry) => entry.resolve());
        waitingQueue = [];
        return api(originalRequest);
      } catch (refreshError) {
        waitingQueue.forEach((entry) => entry.reject(refreshError));
        waitingQueue = [];
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }
    return Promise.reject(error);
  }
);

export async function login(username: string, password: string): Promise<AuthLoginResponse> {
  assertRequired(username, "Username");
  assertRequired(password, "Password");
  const { data } = await api.post<AuthLoginResponse>("/auth/login", { username, password });
  return data;
}

export async function verifyTwoFactor(code: string): Promise<AuthLoginResponse> {
  assertRequired(code, "Verification code");
  const { data } = await api.post<AuthLoginResponse>("/auth/2fa/verify", { code: code.trim() });
  return data;
}

export async function setupTwoFactor(): Promise<TwoFASetupResponse> {
  const { data } = await api.post<TwoFASetupResponse>("/users/me/2fa/setup");
  return data;
}

export async function confirmTwoFactor(code: string): Promise<User> {
  assertRequired(code, "Verification code");
  const { data } = await api.post<User>("/users/me/2fa/confirm", { code: code.trim() });
  return data;
}

export async function disableTwoFactor(password: string): Promise<User> {
  assertRequired(password, "Password");
  const { data } = await api.post<User>("/users/me/2fa/disable", { password });
  return data;
}

export async function logout(): Promise<void> {
  await api.post("/auth/logout");
}

/* ── Восстановление пароля («забыли пароль») ─────────────────────────────
   Все три вызова публичные: выполняются без сессии. */

/** Запрашивает ссылку сброса. Отвечает 200 всегда — есть такой email или нет,
 *  бэкенд намеренно не сообщает, чтобы форму нельзя было использовать для
 *  перебора существующих адресов. */
export async function requestPasswordReset(email: string): Promise<{ ok: boolean; mail_preview_url: string | null }> {
  assertRequired(email, "Email");
  const { data } = await api.post<{ ok: boolean; mail_preview_url: string | null }>(
    "/auth/password-reset/request",
    { email }
  );
  return data;
}

export async function getPasswordResetInfo(token: string): Promise<PasswordResetInfo> {
  const { data } = await api.get<PasswordResetInfo>(`/auth/password-reset/${encodeURIComponent(token)}`);
  return data;
}

export async function confirmPasswordReset(token: string, password: string): Promise<void> {
  assertRequired(password, "Пароль");
  await api.post(`/auth/password-reset/${encodeURIComponent(token)}`, { password });
}

export async function getMe(): Promise<User> {
  const { data } = await api.get<User>("/users/me");
  return data;
}

export async function getUsers(page = 1, size = 200): Promise<PaginatedResponse<User>> {
  const { data } = await api.get<PaginatedResponse<User>>("/users", { params: { page, size } });
  return data;
}

/**
 * @deprecated Прямое создание пользователя с паролем убрано в пользу приглашений
 * ({@link createInvitation}). Функция оставлена только чтобы типизировалась
 * устаревшая, НЕ подключённая к роутингу страница `pages/UsersAdminPage.tsx`
 * (живой UI — Storm — её не использует). Реального эндпоинта на бэкенде больше нет.
 */
export async function createUser(_payload: {
  username: string;
  email: string;
  full_name?: string;
  password?: string;
  role: User["role"];
  project_role?: User["project_role"];
  send_invite_email?: boolean;
}): Promise<User> {
  throw new Error("Direct user creation is disabled — use invitations (invite flow)");
}

/* ── Приглашения (invite-flow) ────────────────────────────────────────────
   Пользователей больше не создаём напрямую: админ шлёт приглашение по email,
   а username/пароль приглашённый задаёт сам на странице активации. */

export async function createInvitation(payload: {
  email: string;
  full_name?: string;
  role: User["role"];
  project_role?: User["project_role"];
}): Promise<InvitationSentResult> {
  assertRequired(payload.email, "Email");
  const { data } = await api.post<InvitationSentResult>("/users/invitations", payload);
  return data;
}

export async function getInvitations(): Promise<Invitation[]> {
  const { data } = await api.get<Invitation[]>("/users/invitations");
  return data;
}

export async function resendInvitation(invitationId: number): Promise<InvitationSentResult> {
  const { data } = await api.post<InvitationSentResult>(`/users/invitations/${invitationId}/resend`);
  return data;
}

export async function revokeInvitation(invitationId: number): Promise<void> {
  await api.delete(`/users/invitations/${invitationId}`);
}

/* Публичные вызовы страницы активации (без сессии). */

export async function getInvitationInfo(token: string): Promise<InvitationInfo> {
  const { data } = await api.get<InvitationInfo>(`/auth/invitations/${encodeURIComponent(token)}`);
  return data;
}

export async function checkInvitationUsername(token: string, username: string): Promise<boolean> {
  const { data } = await api.get<{ available: boolean }>(
    `/auth/invitations/${encodeURIComponent(token)}/username-available`,
    { params: { username } }
  );
  return data.available;
}

export async function acceptInvitation(
  token: string,
  payload: { username: string; password: string }
): Promise<AuthLoginResponse> {
  assertRequired(payload.username, "Username");
  assertRequired(payload.password, "Password");
  const { data } = await api.post<AuthLoginResponse>(
    `/auth/invitations/${encodeURIComponent(token)}/accept`,
    payload
  );
  return data;
}

export async function updateUser(
  userId: number,
  payload: {
    username?: string;
    full_name?: string;
    role?: User["role"];
    project_role?: User["project_role"];
    is_active?: boolean;
  }
): Promise<User> {
  const { data } = await api.put<User>(`/users/${userId}`, payload);
  return data;
}

/** Возврат деактивированного пользователя: шлёт ему письмо со ссылкой-возвратом.
 *  Аккаунт разблокируется, только когда пользователь сам перейдёт по ссылке. */
export async function reactivateUser(userId: number): Promise<PasswordResetResult> {
  const { data } = await api.post<PasswordResetResult>(`/users/${userId}/reactivate`);
  return data;
}

/* ── Возврат по ссылке из письма (страница /reactivate, без сессии) ──────── */

export async function getReactivationInfo(token: string): Promise<ReactivationInfo> {
  const { data } = await api.get<ReactivationInfo>(`/auth/reactivate/${encodeURIComponent(token)}`);
  return data;
}

/** Разблокирует аккаунт по ссылке и сразу выдаёт сессию (cookie ставит бэкенд). */
export async function completeReactivation(token: string): Promise<AuthLoginResponse> {
  const { data } = await api.post<AuthLoginResponse>(`/auth/reactivate/${encodeURIComponent(token)}`);
  return data;
}

export async function resetUserPassword(userId: number): Promise<PasswordResetResult> {
  const { data } = await api.patch<PasswordResetResult>(`/users/${userId}/password`);
  return data;
}

export async function deleteUser(userId: number): Promise<void> {
  await api.delete(`/users/${userId}`);
}

export async function updateMyProfile(payload: {
  username?: string;
  email?: string;
  full_name?: string;
}): Promise<User> {
  const { data } = await api.patch<User>("/users/me", payload);
  return data;
}

export async function changeMyPassword(payload: { current_password: string; new_password: string }): Promise<User> {
  assertRequired(payload.current_password, "Current password");
  assertRequired(payload.new_password, "New password");
  const { data } = await api.patch<User>("/users/me/password", payload);
  return data;
}

export async function uploadMyAvatar(file: File): Promise<User> {
  if (!file) {
    throw new Error("An avatar file is required");
  }
  const formData = new FormData();
  formData.append("avatar", file);
  const { data } = await api.post<User>("/users/me/avatar", formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return data;
}

export async function getProjects(page = 1, size = 20, status?: Project["status"]): Promise<PaginatedResponse<Project>> {
  const { data } = await api.get<PaginatedResponse<Project>>("/projects", { params: { page, size, status } });
  return data;
}

export async function getProjectStats(): Promise<ProjectStats[]> {
  const { data } = await api.get<ProjectStats[]>("/projects/stats");
  return data;
}

export async function getProjectFolders(): Promise<ProjectFolder[]> {
  const { data } = await api.get<ProjectFolder[]>("/projects/folders");
  return data;
}

export async function createProjectFolder(payload: { name: string; parent_id?: number | null }): Promise<ProjectFolder> {
  assertRequired(payload.name, "Folder name");
  const { data } = await api.post<ProjectFolder>("/projects/folders", payload);
  return data;
}

export async function moveProjectFolder(folderId: number, payload: { parent_id?: number | null }): Promise<ProjectFolder> {
  const { data } = await api.patch<ProjectFolder>(`/projects/folders/${folderId}/move`, payload);
  return data;
}

export interface DeleteProjectFolderResult {
  path: string;
  deleted_folders: number;
  deleted_projects: number;
}

export async function deleteProjectFolder(folderId: number): Promise<DeleteProjectFolderResult> {
  const { data } = await api.delete<DeleteProjectFolderResult>(`/projects/folders/${folderId}`);
  return data;
}

export async function createProject(payload: {
  name: string;
  folder?: string;
  description?: string;
  start_date?: string;
  end_date?: string;
}): Promise<Project> {
  assertRequired(payload.name, "Project name");
  const { data } = await api.post<Project>("/projects", payload);
  return data;
}

export async function getProject(projectId: number): Promise<Project> {
  const { data } = await api.get<Project>(`/projects/${projectId}`);
  return data;
}

export async function updateProject(
  projectId: number,
  payload: {
    name?: string;
    folder?: string;
    description?: string;
    start_date?: string;
    end_date?: string;
    status?: Project["status"];
  }
): Promise<Project> {
  const { data } = await api.put<Project>(`/projects/${projectId}`, payload);
  return data;
}

export async function getProjectMembers(projectId: number): Promise<ProjectMember[]> {
  const { data } = await api.get<ProjectMember[]>(`/projects/${projectId}/members`);
  return data;
}

export async function addProjectMember(projectId: number, userId: number): Promise<void> {
  if (!userId) {
    throw new Error("Select a user");
  }
  await api.post(`/projects/${projectId}/members`, { user_id: userId });
}

export async function removeProjectMember(projectId: number, userId: number): Promise<void> {
  await api.delete(`/projects/${projectId}/members/${userId}`);
}

/** Лента активности проекта — доступна любому участнику (в отличие от админского /audit-logs). */
export async function getProjectActivity(projectId: number, limit = 50): Promise<ProjectActivityItem[]> {
  const { data } = await api.get<ProjectActivityItem[]>(`/projects/${projectId}/activity`, { params: { limit } });
  return data;
}

export async function listProjectNotes(projectId: number): Promise<ProjectNote[]> {
  const { data } = await api.get<ProjectNote[]>(`/projects/${projectId}/notes`);
  return data;
}

export type ProjectNoteActivity = {
  id: number;
  action: "CREATE" | "UPDATE" | "DELETE";
  note_id: number | null;
  note_title: string | null;
  user_id: number | null;
  username: string | null;
  created_at: string;
};

export async function listProjectNotesActivity(
  projectId: number,
  limit = 30,
): Promise<ProjectNoteActivity[]> {
  const { data } = await api.get<ProjectNoteActivity[]>(
    `/projects/${projectId}/notes-activity`,
    { params: { limit } },
  );
  return data;
}

export async function getProjectNote(projectId: number, noteId: number): Promise<ProjectNote> {
  const { data } = await api.get<ProjectNote>(`/projects/${projectId}/notes/${noteId}`);
  return data;
}

export async function createProjectNote(
  projectId: number,
  payload: { title: string; parent_id?: number | null; content?: string | null }
): Promise<ProjectNote> {
  assertRequired(payload.title, "Page title");
  const { data } = await api.post<ProjectNote>(`/projects/${projectId}/notes`, payload);
  return data;
}

export async function updateProjectNote(
  projectId: number,
  noteId: number,
  payload: { title?: string; content?: string | null }
): Promise<ProjectNote> {
  if (payload.title !== undefined) {
    assertRequired(payload.title, "Page title");
  }
  const { data } = await api.put<ProjectNote>(`/projects/${projectId}/notes/${noteId}`, payload);
  return data;
}

export async function moveProjectNote(
  projectId: number,
  noteId: number,
  payload: { parent_id?: number | null }
): Promise<ProjectNote> {
  const { data } = await api.patch<ProjectNote>(`/projects/${projectId}/notes/${noteId}/move`, payload);
  return data;
}

export async function reorderProjectNotes(
  projectId: number,
  payload: { parent_id?: number | null; items: Array<{ id: number; sort_order: number }> }
): Promise<ProjectNote[]> {
  if (!payload.items.length) {
    throw new Error("Provide at least one page to sort");
  }
  const { data } = await api.patch<ProjectNote[]>(`/projects/${projectId}/notes/reorder`, payload);
  return data;
}

export async function deleteProjectNote(projectId: number, noteId: number): Promise<void> {
  await api.delete(`/projects/${projectId}/notes/${noteId}`);
}

// ---- project credentials (accounts & access tokens) ----

export async function listProjectCredentials(projectId: number): Promise<ProjectCredential[]> {
  const { data } = await api.get<ProjectCredential[]>(`/projects/${projectId}/credentials`);
  return data;
}

export async function createProjectCredential(
  projectId: number,
  payload: { username?: string | null; password: string; host?: string | null }
): Promise<ProjectCredential> {
  assertRequired(payload.password, "Password");
  const { data } = await api.post<ProjectCredential>(`/projects/${projectId}/credentials`, payload);
  return data;
}

export async function updateProjectCredential(
  projectId: number,
  credentialId: number,
  // Пустой/опущенный password означает «оставить прежний» — форма правки не
  // присылает существующий пароль обратно.
  payload: { username?: string | null; password?: string; host?: string | null }
): Promise<ProjectCredential> {
  const { data } = await api.put<ProjectCredential>(`/projects/${projectId}/credentials/${credentialId}`, payload);
  return data;
}

export async function deleteProjectCredential(projectId: number, credentialId: number): Promise<void> {
  await api.delete(`/projects/${projectId}/credentials/${credentialId}`);
}

export async function listProjectNoteComments(projectId: number, noteId: number): Promise<PaginatedResponse<ProjectNoteComment>> {
  const { data } = await api.get<PaginatedResponse<ProjectNoteComment>>(`/projects/${projectId}/notes/${noteId}/comments`, {
    params: { page: 1, size: 100 },
  });
  return data;
}

export async function createProjectNoteComment(
  projectId: number,
  noteId: number,
  content: string
): Promise<ProjectNoteComment> {
  assertRequired(content, "Comment");
  const { data } = await api.post<ProjectNoteComment>(`/projects/${projectId}/notes/${noteId}/comments`, { content });
  return data;
}

export async function updateProjectNoteComment(
  projectId: number,
  noteId: number,
  commentId: number,
  content: string
): Promise<ProjectNoteComment> {
  assertRequired(content, "Comment");
  const { data } = await api.put<ProjectNoteComment>(`/projects/${projectId}/notes/${noteId}/comments/${commentId}`, { content });
  return data;
}

export async function deleteProjectNoteComment(projectId: number, noteId: number, commentId: number): Promise<void> {
  await api.delete(`/projects/${projectId}/notes/${noteId}/comments/${commentId}`);
}

export async function deleteProject(projectId: number): Promise<void> {
  await api.delete(`/projects/${projectId}`);
}

export async function getHosts(projectId: number): Promise<PaginatedResponse<Host>> {
  // origin=all — один запрос кормит и таблицу хостов, и таблицу IP: строки
  // origin='ip' отфильтровываются на клиенте (см. hostsList в StormApp).
  const { data } = await api.get<PaginatedResponse<Host>>(`/projects/${projectId}/hosts`, {
    params: { page: 1, size: 100, origin: "all" },
  });
  return data;
}

export async function createHost(
  projectId: number,
  payload: {
    ip_address?: string;
    ip_addresses?: string[];
    hostname?: string;
    notes?: string;
    status?: "up" | "down" | "unknown";
    os_type?: OsType;
  }
): Promise<Host> {
  if (isBlank(payload.ip_address) && isBlank(payload.hostname)) {
    throw new Error('Provide at least "IP address" or "Hostname"');
  }
  const { data } = await api.post<Host>(`/projects/${projectId}/hosts`, payload);
  return data;
}

export async function getHost(projectId: number, hostId: number): Promise<HostDetails> {
  const { data } = await api.get<HostDetails>(`/projects/${projectId}/hosts/${hostId}`);
  return data;
}

export async function updateHost(
  projectId: number,
  hostId: number,
  payload: {
    ip_address?: string;
    ip_addresses?: Array<{ ip_address: string; label?: string | null; is_primary?: boolean }>;
    hostname?: string;
    notes?: string | null;
    status?: "up" | "down" | "unknown";
    os_type?: OsType;
  }
): Promise<Host> {
  const { data } = await api.put<Host>(`/projects/${projectId}/hosts/${hostId}`, payload);
  return data;
}

export async function deleteHost(projectId: number, hostId: number): Promise<void> {
  await api.delete(`/projects/${projectId}/hosts/${hostId}`);
}

/* ── Скрытые IP: «удаление» адреса из вкладки IP без разрыва привязки к хостам ──
   Список адресов, скрытых из вкладки IP. Фронт фильтрует по нему ipsRows. */
export async function getHiddenIps(projectId: number): Promise<string[]> {
  const { data } = await api.get<string[]>(`/projects/${projectId}/hidden-ips`);
  return data;
}

/** Скрывает адрес из списка IP (сносит отдельную IP-запись, привязку к хостам хранит). */
export async function hideIp(projectId: number, ip: string): Promise<void> {
  await api.post(`/projects/${projectId}/hidden-ips`, { ip_address: ip });
}

/** Возвращает адрес в список IP. */
export async function unhideIp(projectId: number, ip: string): Promise<void> {
  await api.delete(`/projects/${projectId}/hidden-ips/${encodeURIComponent(ip)}`);
}

// ---- recon farm: серверный пробив вставленных списков хостов и IP ----

/** Запускает фоновый пробив вставленного списка; возвращает созданную задачу. */
export async function startHostFarm(projectId: number, raw: string): Promise<HostFarmJob> {
  assertRequired(raw, "Hosts");
  const { data } = await api.post<HostFarmJob>(`/projects/${projectId}/host-farm`, { raw });
  return data;
}

/** Статус задачи фермы — фронт опрашивает до status === "done" | "failed". */
export async function getHostFarmJob(projectId: number, jobId: number): Promise<HostFarmJob> {
  const { data } = await api.get<HostFarmJob>(`/projects/${projectId}/host-farm/jobs/${jobId}`);
  return data;
}

/** Запускает обратный резолв + пробив вставленного списка IP-адресов. */
export async function startIpFarm(projectId: number, raw: string): Promise<IpFarmJob> {
  assertRequired(raw, "IPs");
  const { data } = await api.post<IpFarmJob>(`/projects/${projectId}/ip-farm`, { raw });
  return data;
}

/** Статус задачи фермы IP — фронт опрашивает до status === "done" | "failed". */
export async function getIpFarmJob(projectId: number, jobId: number): Promise<IpFarmJob> {
  const { data } = await api.get<IpFarmJob>(`/projects/${projectId}/ip-farm/jobs/${jobId}`);
  return data;
}

/** Запускает скан JS всех доменов проекта (raw пусто) или переданного списка. */
export async function startJsScan(projectId: number, raw = ""): Promise<JsFarmJob> {
  const { data } = await api.post<JsFarmJob>(`/projects/${projectId}/js-farm`, { raw });
  return data;
}

/** Статус задачи фермы JS — фронт опрашивает до status === "done" | "failed". */
export async function getJsScanJob(projectId: number, jobId: number): Promise<JsFarmJob> {
  const { data } = await api.get<JsFarmJob>(`/projects/${projectId}/js-farm/jobs/${jobId}`);
  return data;
}

/** JS-файлы проекта с находками — раздел JS группирует их по хосту. */
export async function getJsFiles(projectId: number): Promise<JsFile[]> {
  const { data } = await api.get<JsFile[]>(`/projects/${projectId}/js-files`);
  return data;
}

/** Zip найденных .js. `hostId` сужает архив до одного хоста; без него — весь проект.
 *  Файлы не хранятся, поэтому бэкенд докачивает их по URL по требованию. */
export async function downloadJsArchive(projectId: number, hostId?: number): Promise<Blob> {
  const { data } = await api.get(`/projects/${projectId}/js-files/archive`, {
    params: hostId != null ? { host_id: hostId } : {},
    responseType: "blob",
  });
  return data as Blob;
}

export async function getPorts(projectId: number, hostId: number): Promise<Port[]> {
  const { data } = await api.get<Port[]>(`/projects/${projectId}/hosts/${hostId}/ports`);
  return data;
}

export async function createPort(
  projectId: number,
  hostId: number,
  payload: {
    ip_address_id: number;
    port_number: number;
    protocol?: "tcp" | "udp";
    state?: "open" | "closed" | "filtered";
  }
): Promise<Port> {
  if (!Number.isFinite(payload.port_number)) {
    throw new Error("Port must be a number");
  }
  if (!payload.ip_address_id) {
    throw new Error("No IP address selected");
  }
  const { data } = await api.post<Port>(`/projects/${projectId}/hosts/${hostId}/ports`, payload);
  return data;
}

export async function updatePort(
  projectId: number,
  hostId: number,
  portId: number,
  payload: {
    ip_address_id?: number;
    port_number?: number;
    protocol?: "tcp" | "udp";
    state?: "open" | "closed" | "filtered";
  }
): Promise<Port> {
  const { data } = await api.put<Port>(`/projects/${projectId}/hosts/${hostId}/ports/${portId}`, payload);
  return data;
}

export async function deletePort(projectId: number, hostId: number, portId: number): Promise<void> {
  await api.delete(`/projects/${projectId}/hosts/${hostId}/ports/${portId}`);
}

export async function getServices(projectId: number, hostId: number, portId: number): Promise<Service[]> {
  const { data } = await api.get<Service[]>(`/projects/${projectId}/hosts/${hostId}/ports/${portId}/services`);
  return data;
}

export async function createService(
  projectId: number,
  hostId: number,
  portId: number,
  payload: { name: string; version?: string; banner?: string }
): Promise<Service> {
  assertRequired(payload.name, "Service name");
  const { data } = await api.post<Service>(`/projects/${projectId}/hosts/${hostId}/ports/${portId}/services`, payload);
  return data;
}

export async function updateService(
  projectId: number,
  hostId: number,
  portId: number,
  serviceId: number,
  payload: { name?: string; version?: string; banner?: string }
): Promise<Service> {
  if (payload.name !== undefined) {
    assertRequired(payload.name, "Service name");
  }
  const { data } = await api.put<Service>(`/projects/${projectId}/hosts/${hostId}/ports/${portId}/services/${serviceId}`, payload);
  return data;
}

export async function deleteService(projectId: number, hostId: number, portId: number, serviceId: number): Promise<void> {
  await api.delete(`/projects/${projectId}/hosts/${hostId}/ports/${portId}/services/${serviceId}`);
}

export async function getEndpoints(projectId: number, hostId: number): Promise<Endpoint[]> {
  const { data } = await api.get<Endpoint[]>(`/projects/${projectId}/hosts/${hostId}/endpoints`);
  return data;
}

export async function createEndpoint(
  projectId: number,
  hostId: number,
  payload: {
    path?: string;
    method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "QUERY";
    description?: string | null;
    request_raw?: string;
    query_params?: { name: string; value?: string | null; required?: boolean; description?: string | null }[];
    request_body?: string | null;
    request_content_type?: string | null;
    request_headers?: EndpointRequestHeader[];
  }
): Promise<Endpoint> {
  if (isBlank(payload.path) && isBlank(payload.request_raw)) {
    throw new Error('Provide at least "Path" or "Raw request"');
  }
  const { data } = await api.post<Endpoint>(`/projects/${projectId}/hosts/${hostId}/endpoints`, payload);
  return data;
}

export async function updateEndpoint(
  projectId: number,
  hostId: number,
  endpointId: number,
  payload: {
    path?: string;
    method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "QUERY";
    description?: string | null;
    request_raw?: string;
    query_params?: { name: string; value?: string | null; required?: boolean; description?: string | null }[];
    request_body?: string | null;
    request_content_type?: string | null;
    request_headers?: EndpointRequestHeader[];
  }
): Promise<Endpoint> {
  if (payload.path !== undefined && isBlank(payload.path) && isBlank(payload.request_raw)) {
    throw new Error('Provide at least "Path" or "Raw request"');
  }
  const { data } = await api.put<Endpoint>(`/projects/${projectId}/hosts/${hostId}/endpoints/${endpointId}`, payload);
  return data;
}

export async function deleteEndpoint(projectId: number, hostId: number, endpointId: number): Promise<void> {
  await api.delete(`/projects/${projectId}/hosts/${hostId}/endpoints/${endpointId}`);
}

export async function getVulnerabilities(projectId: number): Promise<PaginatedResponse<Vulnerability>> {
  const { data } = await api.get<PaginatedResponse<Vulnerability>>(`/projects/${projectId}/vulnerabilities`, {
    params: { page: 1, size: 100 },
  });
  return data;
}

export async function createVulnerability(
  projectId: number,
  payload: {
    host_id: number;
    title: string;
    description?: string | null;
    // Необязательно: бэкенд по умолчанию ставит "unknown" (критичность не определена).
    severity?: "critical" | "high" | "medium" | "low" | "info";
    cvss_version?: "4.0" | null;
    cvss_score?: number | null;
    cvss_vector?: string | null;
    cwe_id?: string | null;
    status?: "open" | "in_progress" | "fixed" | "wont_fix" | "accepted_risk";
    workflow_steps?: Array<{
      id: string;
      description?: string | null;
      image_file_ids?: number[];
      endpoint_id?: number | null;
      endpoint_request_raw?: string | null;
    }>;
    steps_to_reproduce?: string | null;
    impact?: string | null;
    recommendations?: string | null;
  }
): Promise<Vulnerability> {
  if (!payload.host_id) {
    throw new Error("Select a host");
  }
  assertRequired(payload.title, "Vulnerability title");
  const { data } = await api.post<Vulnerability>(`/projects/${projectId}/vulnerabilities`, payload);
  return data;
}

export async function updateVulnerability(
  projectId: number,
  vulnerabilityId: number,
  payload: {
    title?: string;
    description?: string | null;
    severity?: "critical" | "high" | "medium" | "low" | "info";
    cvss_version?: "4.0" | null;
    cvss_score?: number | null;
    cvss_vector?: string | null;
    cwe_id?: string | null;
    status?: "open" | "in_progress" | "fixed" | "wont_fix" | "accepted_risk";
    workflow_steps?: Array<{
      id: string;
      description?: string | null;
      image_file_ids?: number[];
      endpoint_id?: number | null;
      endpoint_request_raw?: string | null;
    }>;
    steps_to_reproduce?: string | null;
    impact?: string | null;
    recommendations?: string | null;
  }
): Promise<Vulnerability> {
  if (payload.title !== undefined) {
    assertRequired(payload.title, "Vulnerability title");
  }
  const { data } = await api.put<Vulnerability>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}`, payload);
  return data;
}

export async function deleteVulnerability(projectId: number, vulnerabilityId: number): Promise<void> {
  await api.delete(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}`);
}

export async function getVulnerabilityJiraLink(projectId: number, vulnerabilityId: number): Promise<JiraIssueLink | null> {
  const { data } = await api.get<JiraIssueLink | null>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/jira`);
  return data;
}

export async function exportVulnerabilityToJira(projectId: number, vulnerabilityId: number): Promise<JiraIssueLink> {
  const { data } = await api.post<JiraIssueLink>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/jira/export`);
  return data;
}

export async function getProjectJiraLink(projectId: number): Promise<ProjectJiraLink | null> {
  const { data } = await api.get<ProjectJiraLink | null>(`/projects/${projectId}/jira-link`);
  return data;
}

export async function saveProjectJiraLink(projectId: number, jiraProjectKey: string): Promise<ProjectJiraLink> {
  assertRequired(jiraProjectKey, "Jira project key");
  const { data } = await api.put<ProjectJiraLink>(`/projects/${projectId}/jira-link`, { jira_project_key: jiraProjectKey });
  return data;
}

export async function getJiraConfig(): Promise<JiraConfig | null> {
  const { data } = await api.get<JiraConfig | null>("/jira/config");
  return data;
}

export async function saveJiraConfig(payload: {
  base_url: string;
  email: string;
  api_token?: string;
  default_issue_type?: string;
  is_enabled?: boolean;
}): Promise<JiraConfig> {
  assertRequired(payload.base_url, "Jira base URL");
  assertRequired(payload.email, "Email");
  const { data } = await api.put<JiraConfig>("/jira/config", { name: "default", ...payload });
  return data;
}

export async function getVulnerability(projectId: number, vulnerabilityId: number): Promise<VulnerabilityDetails> {
  const { data } = await api.get<VulnerabilityDetails>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}`);
  return data;
}

export async function getHostVulnerabilities(projectId: number, hostId: number): Promise<PaginatedResponse<Vulnerability>> {
  const { data } = await api.get<PaginatedResponse<Vulnerability>>(`/projects/${projectId}/hosts/${hostId}/vulnerabilities`, {
    params: { page: 1, size: 100 },
  });
  return data;
}

export async function addVulnerabilityAsset(
  projectId: number,
  vulnerabilityId: number,
  payload: {
    asset_type: "host" | "port" | "service" | "endpoint";
    asset_id: number;
  }
): Promise<VulnerabilityAsset> {
  const { data } = await api.post<VulnerabilityAsset>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/assets`, payload);
  return data;
}

export async function deleteVulnerabilityAsset(projectId: number, vulnerabilityId: number, assetLinkId: number): Promise<void> {
  await api.delete(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/assets/${assetLinkId}`);
}

export async function listVulnerabilityFiles(projectId: number, vulnerabilityId: number): Promise<VulnerabilityFile[]> {
  const { data } = await api.get<VulnerabilityFile[]>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/files`);
  return data;
}

export async function uploadVulnerabilityFile(projectId: number, vulnerabilityId: number, file: File): Promise<VulnerabilityFile> {
  if (!file) {
    throw new Error("Select a file");
  }
  const formData = new FormData();
  formData.append("file", file);
  const { data } = await api.post<VulnerabilityFile>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/files`, formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return data;
}

export async function deleteVulnerabilityFile(projectId: number, vulnerabilityId: number, fileId: number): Promise<void> {
  await api.delete(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/files/${fileId}`);
}

export async function listVulnerabilityComments(projectId: number, vulnerabilityId: number): Promise<PaginatedResponse<VulnerabilityComment>> {
  const { data } = await api.get<PaginatedResponse<VulnerabilityComment>>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/comments`, {
    params: { page: 1, size: 100 },
  });
  return data;
}

export async function createVulnerabilityComment(projectId: number, vulnerabilityId: number, content: string): Promise<VulnerabilityComment> {
  assertRequired(content, "Comment");
  const { data } = await api.post<VulnerabilityComment>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/comments`, { content });
  return data;
}

export async function updateVulnerabilityComment(
  projectId: number,
  vulnerabilityId: number,
  commentId: number,
  content: string
): Promise<VulnerabilityComment> {
  assertRequired(content, "Comment");
  const { data } = await api.put<VulnerabilityComment>(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/comments/${commentId}`, { content });
  return data;
}

export async function deleteVulnerabilityComment(projectId: number, vulnerabilityId: number, commentId: number): Promise<void> {
  await api.delete(`/projects/${projectId}/vulnerabilities/${vulnerabilityId}/comments/${commentId}`);
}

export async function importProjectData(projectId: number, file: File): Promise<ImportResult> {
  const formData = new FormData();
  formData.append("file", file);
  const { data } = await api.post<ImportResult>(`/projects/${projectId}/import`, formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return data;
}

export async function importOpenApiFile(projectId: number, hostId: number, file: File): Promise<OpenApiImportResult> {
  if (!file) {
    throw new Error("Select a Swagger/OpenAPI file");
  }
  const formData = new FormData();
  formData.append("file", file);
  const { data } = await api.post<OpenApiImportResult>(`/projects/${projectId}/hosts/${hostId}/import-openapi`, formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return data;
}

export async function exportOpenApiFile(projectId: number, hostId: number): Promise<Blob> {
  const { data } = await api.get(`/projects/${projectId}/hosts/${hostId}/export-openapi`, {
    responseType: "blob",
  });
  return data as Blob;
}

export async function downloadProjectCertificationReport(projectId: number): Promise<Blob> {
  const { data } = await api.post(`/projects/${projectId}/reports/szi`, null, {
    responseType: "blob",
  });
  return data as Blob;
}

export async function downloadProjectAcceptanceReport(projectId: number): Promise<Blob> {
  const { data } = await api.post(`/projects/${projectId}/reports/pp`, null, {
    responseType: "blob",
  });
  return data as Blob;
}

export async function listAgentTokens(): Promise<AgentApiToken[]> {
  const { data } = await api.get<AgentApiToken[]>("/agent-tokens");
  return data;
}

export async function createAgentToken(payload: {
  name: string;
  scopes: string[];
  project_ids: number[];
  all_projects: boolean;
  expires_at?: string | null;
}): Promise<AgentApiToken & { token: string }> {
  const { data } = await api.post<AgentApiToken & { token: string }>("/agent-tokens", payload);
  return data;
}

export async function revokeAgentToken(tokenId: number): Promise<void> {
  await api.delete(`/agent-tokens/${tokenId}`);
}

export async function listNotifications(options?: { is_read?: boolean }): Promise<PaginatedResponse<Notification>> {
  const params: Record<string, number | boolean> = { page: 1, size: 20 };
  if (options?.is_read !== undefined) {
    params.is_read = options.is_read;
  }
  const { data } = await api.get<PaginatedResponse<Notification>>("/notifications", { params });
  return data;
}

export async function unreadCount(): Promise<number> {
  const { data } = await api.get<{ count: number }>("/notifications/unread-count");
  return data.count;
}

export async function markNotificationRead(notificationId: number): Promise<void> {
  await api.patch(`/notifications/${notificationId}/read`);
}

export async function markAllNotificationsRead(): Promise<void> {
  await api.patch("/notifications/read-all");
}

export async function getAuditLogs(
  page = 1,
  size = 50,
  filters?: {
    user_id?: string;
    username?: string;
    action?: string;
    entity_type?: string;
    entity_id?: string;
    ip_address?: string;
    query?: string;
    created_from?: string;
    created_to?: string;
  }
): Promise<PaginatedResponse<AuditLog>> {
  const { data } = await api.get<PaginatedResponse<AuditLog>>("/audit-logs", {
    params: { page, size, ...filters },
  });
  return data;
}
