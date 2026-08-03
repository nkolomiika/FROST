// Пользовательская документация Storm, рендерится in-app на /docs.
// Тела глав хранятся рядом в .md-файлах (импорт через Vite `?raw`), а этот
// модуль задаёт их порядок, заголовки и целевую роль (audience). Ролевую
// видимость применяет StormDocs: `user` видят все, `admin`/`agent` — только
// администратор.

import userGettingStarted from "./user-getting-started.md?raw";
import userProjects from "./user-projects.md?raw";
import userHosts from "./user-hosts.md?raw";
import userVulnerabilities from "./user-vulnerabilities.md?raw";
import userNotes from "./user-notes.md?raw";
import userReports from "./user-reports.md?raw";
import userNotifications from "./user-notifications.md?raw";
import userProfile from "./user-profile.md?raw";
import userTeamLead from "./user-team-lead.md?raw";
import adminOverview from "./admin-overview.md?raw";
import adminUsers from "./admin-users.md?raw";
import adminProjects from "./admin-projects.md?raw";
import agentOverview from "./agent-overview.md?raw";
import agentTokens from "./agent-tokens.md?raw";
import agentUsage from "./agent-usage.md?raw";

/** Целевая роль документа. `user` виден всем; `admin` и `agent` — только администратору. */
export type DocAudience = "user" | "admin" | "agent";

export interface DocChapter {
  /** Стабильный id для выбора активной главы. */
  id: string;
  /** Заголовок в оглавлении. */
  title: string;
  /** Кому видна глава. */
  audience: DocAudience;
  /** Тело главы в Markdown. */
  body: string;
}

export interface DocGroup {
  audience: DocAudience;
  /** Название документа в оглавлении. */
  title: string;
}

/** Три документа, на которые делится документация (порядок — как в оглавлении). */
export const DOC_GROUPS: DocGroup[] = [
  { audience: "user", title: "Пользователь" },
  { audience: "admin", title: "Администратор" },
  { audience: "agent", title: "Agent API" },
];

/** Главы в порядке отображения. Группируются по `audience` через DOC_GROUPS. */
export const DOC_CHAPTERS: DocChapter[] = [
  { id: "user-getting-started", title: "Начало работы", audience: "user", body: userGettingStarted },
  { id: "user-projects", title: "Проекты", audience: "user", body: userProjects },
  { id: "user-hosts", title: "Хосты и активы", audience: "user", body: userHosts },
  { id: "user-vulnerabilities", title: "Уязвимости", audience: "user", body: userVulnerabilities },
  { id: "user-notes", title: "Заметки проекта", audience: "user", body: userNotes },
  { id: "user-reports", title: "Отчёты", audience: "user", body: userReports },
  { id: "user-notifications", title: "Уведомления", audience: "user", body: userNotifications },
  { id: "user-profile", title: "Профиль и безопасность", audience: "user", body: userProfile },
  { id: "user-team-lead", title: "Работа тимлида", audience: "user", body: userTeamLead },
  { id: "admin-overview", title: "Роль администратора", audience: "admin", body: adminOverview },
  { id: "admin-users", title: "Управление пользователями", audience: "admin", body: adminUsers },
  { id: "admin-projects", title: "Проекты", audience: "admin", body: adminProjects },
  { id: "agent-overview", title: "Обзор Agent API", audience: "agent", body: agentOverview },
  { id: "agent-tokens", title: "Токены и права доступа", audience: "agent", body: agentTokens },
  { id: "agent-usage", title: "Аутентификация и эндпоинты", audience: "agent", body: agentUsage },
];

/**
 * Главы, доступные роли. Администратор видит всё; обычный пользователь видит
 * «Пользователь» и «Agent API» (токены выпускает любой в рамках своих прав),
 * но не «Администратор» (`audience: "admin"`).
 */
export function chaptersForRole(isAdmin: boolean): DocChapter[] {
  return isAdmin ? DOC_CHAPTERS : DOC_CHAPTERS.filter((c) => c.audience !== "admin");
}
