/* Lightweight i18n for the STORM app.

   The UI is authored in English; `t("English source")` returns the Russian
   translation when the language is set to RU, and falls back to the English
   source otherwise (so an un-translated string simply stays English). The
   preference is persisted and toggled in Profile → Customizing.

   `t()` reads the current language from the store at call time; components
   re-render because StormApp subscribes to `useLangStore` once at the top, so
   the whole tree re-evaluates its `t()` calls when the language flips.

   The login / activation / reset screens are intentionally NOT translated —
   they always render in English (and light theme). */

import { create } from "zustand";

export type Lang = "en" | "ru";

const STORAGE_KEY = "storm.lang";

function readStored(): Lang {
  if (typeof window === "undefined") return "en";
  try {
    return window.localStorage.getItem(STORAGE_KEY) === "ru" ? "ru" : "en";
  } catch {
    return "en";
  }
}

interface LangState {
  lang: Lang;
  setLang: (lang: Lang) => void;
}

export const useLangStore = create<LangState>((set) => ({
  lang: readStored(),
  setLang: (lang) => {
    try {
      window.localStorage.setItem(STORAGE_KEY, lang);
    } catch {
      /* storage unavailable — keep in memory */
    }
    set({ lang });
  },
}));

/* English source → Russian. A missing key falls back to the English source, so
   partial coverage is safe. Russian infosec idiom + accepted anglicisms
   (хост, эндпоинт, воркспейс, пентест) — deliberately, per product preference. */
const RU: Record<string, string> = {
  // ── navigation / sections ──
  Projects: "Проекты",
  Tasks: "Задачи",
  "My Tasks": "Мои задачи",
  Docs: "Документация",
  Team: "Команда",
  Overview: "Обзор",
  Recon: "Разведка",
  Vulnerabilities: "Уязвимости",
  Notes: "Заметки",
  Creds: "Учётки",
  Members: "Участники",
  Activity: "Активность",
  Endpoints: "Эндпоинты",
  Ports: "Порты",
  Host: "Хост",
  Hosts: "Хосты",

  // ── top bar / profile menu ──
  Profile: "Профиль",
  Logout: "Выйти",
  Notifications: "Уведомления",
  "No notifications.": "Нет уведомлений.",
  "Mark all read": "Отметить все прочитанными",
  "View all →": "Показать все →",
  new: "новые",

  // ── projects list ──
  "New project": "Новый проект",
  "Filter projects…": "Фильтр проектов…",
  // Kept short so the projects-table column stays on one line.
  "Last updated": "Обновлено",
  "First updated": "Сначала старые",
  "No projects found.": "Проекты не найдены.",
  "No projects available.": "Нет доступных проектов.",
  "Loading projects…": "Загрузка проектов…",
  "Create a project workspace for a new engagement.": "Создайте рабочее пространство для нового проекта.",
  Findings: "Уязвимости",
  // Project statuses (Active / Archived / Freeze / …) are intentionally NOT
  // translated — they stay English by product preference (t() → fallback).
  "Showing active projects": "Показаны активные проекты",
  "Showing archived projects": "Показаны архивные проекты",
  active: "активных",
  archived: "в архиве",

  // ── project detail: header / tabs / buttons ──
  "Back to projects": "Назад к проектам",
  "Back to Projects": "Назад к проектам",
  "Generate report": "Сгенерировать отчёт",
  "Edit project": "Изменить проект",
  "Engagement timeline": "Сроки проекта",
  "Vulnerabilities across the project": "Уязвимости по проекту",
  "Show details": "Подробнее",
  "Show more ·": "Показать ещё ·",
  "more": "ещё",

  // ── recon (hosts / ips / endpoints) ──
  RECON: "РАЗВЕДКА",
  "Add host": "Добавить хост",
  "Add IPs": "Добавить IP",
  "Add endpoint": "Добавить эндпоинт",
  "Add endpoints": "Добавить эндпоинты",
  "Paste endpoints": "Вставьте эндпоинты",
  "parsed endpoints appear here…": "здесь появятся эндпоинты…",
  "Adding…": "Добавляем…",
  "Paste at least one endpoint": "Вставьте хотя бы один эндпоинт",
  "skipped (host not found)": "пропущено (хост не найден)",
  endpoints: "эндпоинтов",
  "Edit host": "Изменить хост",
  "Copy host": "Скопировать хост",
  "Copy as cURL": "Скопировать как cURL",
  "Copy cURL": "Скопировать cURL",
  "Copy cURL request": "Скопировать cURL-запрос",
  "cURL copied": "cURL скопирован",
  "Delete endpoint": "Удалить эндпоинт",
  "Search by host…": "Поиск по хосту…",
  "Search by IP or host…": "Поиск по IP или хосту…",
  "Search by endpoint…": "Поиск по эндпоинту…",
  // The recon rows narrow a list in place rather than searching, so they say "filter".
  "Filter by IP or host…": "Фильтр по IP или хосту…",
  "Filter by endpoint…": "Фильтр по эндпоинту…",
  "Filter by host…": "Фильтр по хосту…",
  "Filter by author…": "Фильтр по автору…",
  "All hosts": "Все хосты",
  "All IPs": "Все IP",
  "Hostnames": "Имена хостов",
  "No hostnames.": "Имён хостов нет.",
  "No hosts found.": "Хосты не найдены.",
  "No IPs found.": "IP не найдены.",
  "No endpoints discovered.": "Эндпоинты не обнаружены.",
  "No endpoints yet.": "Пока нет эндпоинтов.",
  "No ports yet.": "Пока нет портов.",
  "No subdomains discovered.": "Поддомены не обнаружены.",
  "Loading hosts…": "Загрузка хостов…",
  Port: "Порт",
  Service: "Сервис",
  State: "Состояние",
  Method: "Метод",
  Path: "Путь",
  "IP address": "IP-адрес",
  Hostname: "Имя хоста",

  // ── vulnerabilities ──
  "Add issue": "Добавить уязвимость",
  "All findings": "Все уязвимости",
  "No findings match these filters.": "Нет уязвимостей по этим фильтрам.",
  "findings on this page": "уязвимостей на этой странице",
  Asset: "Актив",
  Title: "Название",
  Severity: "Критичность",
  SEVERITY: "КРИТИЧНОСТЬ",
  Status: "Статус",
  STATUS: "СТАТУС",
  HOST: "ХОСТ",
  Author: "Автор",
  AUTHOR: "АВТОР",
  Updated: "Обновлено",
  Impact: "Влияние",
  Remediation: "Исправление",
  "Steps to reproduce": "Шаги воспроизведения",
  "Add step": "Добавить шаг",
  "Affected host": "Затронутый хост",
  "CVSS 4.0 vector": "Вектор CVSS 4.0",
  "Reported by": "Автор находки",
  "Business/security impact if exploited…": "Влияние на бизнес/безопасность при эксплуатации…",
  "How to fix or mitigate this vulnerability…": "Как исправить или снизить риск этой уязвимости…",
  "Describe this step… (paste a screenshot to attach)": "Опишите шаг… (вставьте скриншот, чтобы прикрепить)",
  // Vulnerability statuses (Open / In progress / Fixed / Won't fix / Accepted
  // risk) are intentionally left untranslated — they stay in English by product
  // preference, so no VSTATUS_LABEL entries here (t() falls back to English).

  // ── discussion / comments ──
  DISCUSSION: "ОБСУЖДЕНИЕ",
  "Post comment": "Отправить комментарий",
  "No comments yet — start the discussion.": "Пока нет комментариев — начните обсуждение.",
  "Use comments to coordinate review, blockers, and follow-ups.": "Используйте комментарии для координации ревью, блокеров и последующих шагов.",
  "Share progress, blockers, or review notes…": "Поделитесь прогрессом, блокерами или замечаниями…",

  // ── notes ──
  "Add note": "Добавить заметку",
  "Edit note": "Изменить заметку",
  "Save note": "Сохранить заметку",
  "No notes yet.": "Пока нет заметок.",
  "Loading note…": "Загрузка заметки…",
  "Loading editor…": "Загрузка редактора…",
  "Give this note a title…": "Название заметки…",
  "Write your note… «### » makes a heading, «- » a list": "Пишите заметку… «### » — заголовок, «- » — список",
  Content: "Содержание",

  // ── credentials ──
  "Add credential": "Добавить учётку",
  "Copy username": "Скопировать логин",
  "Copy password": "Скопировать пароль",
  "No credentials yet. Add a username and password for this project.": "Пока нет учёток. Добавьте логин и пароль для этого проекта.",
  "Loading credentials…": "Загрузка учёток…",

  // ── members ──
  "Add member": "Добавить участника",
  "Invite member": "Пригласить участника",
  "Invite people by email — they set their own username and password from the link":
    "Приглашайте людей по email — логин и пароль они задают сами по ссылке",
  "No members match.": "Нет подходящих участников.",
  // Деактивация участника (мягкое удаление, is_locked). «Удаление» больше не
  // стирает пользователя — блокирует, и его можно разблокировать тут же.
  Deactivated: "Деактивирован",
  "Deactivate user": "Деактивировать пользователя",
  "Reactivate user": "Вернуть пользователя (письмо со ссылкой)",
  Deactivate: "Деактивировать",
  // Диалог блокировки участника: заголовок и кнопка на «block»-терминологии
  // (таб «Blocked»). Сторона возврата остаётся reactivate/return-потоком выше.
  "Block user": "Заблокировать пользователя",
  Block: "Заблокировать",
  "will lose access, but their projects, findings and notes stay. You can reactivate them here later.":
    "потеряет доступ, но его проекты, находки и заметки останутся. Вернуть его можно здесь же позже.",
  "Couldn't deactivate user": "Не удалось деактивировать пользователя",
  "Couldn't block user": "Не удалось заблокировать пользователя",
  // Backend error messages (canonical English → RU). getApiErrorMessage runs the
  // server's `detail` through t(), so these render English in the English locale
  // and Russian here.
  "You can't block yourself": "Нельзя заблокировать самого себя",
  "Username or email is already taken": "Логин или email уже заняты",
  "User not found": "Пользователь не найден",
  "Provide a password or enable sending an email invitation": "Укажите пароль или включите отправку приглашения по email",
  "A user with this email already exists": "Пользователь с таким email уже существует",
  "The user is not deactivated": "Пользователь не деактивирован",
  "An admin can't change a user's email — the user must change it themselves":
    "Администратор не может менять email пользователя — пользователь должен изменить его сам",
  "The username can't be changed — it's tied to the user": "Юзернейм менять нельзя — он закреплён за пользователем",
  "Reactivation link sent to": "Ссылка возврата отправлена на",
  "No deactivated members.": "Нет деактивированных участников.",
  "Search by username…": "Поиск по логину…",
  "Pending invitations ·": "Ожидают активации ·",
  "Resend": "Отправить снова",
  "Revoke invitation": "Отозвать приглашение",
  Role: "Роль",
  ROLE: "РОЛЬ",
  "Workspace role": "Роль в воркспейсе",
  "Project role": "Роль в проекте",
  WORKSPACE: "ВОРКСПЕЙС",
  PROJECT: "ПРОЕКТ",
  Workspace: "Воркспейс",
  Admin: "Админ",
  User: "Пользователь",
  Lead: "Лид",
  Pentester: "Пентестер",
  // host-status tiles (HSTAT labels)
  Up: "Онлайн",
  Down: "Офлайн",
  Unknown: "Неизвестно",

  // ── activity ──
  "No activity yet.": "Пока нет активности.",
  "Loading activity…": "Загрузка активности…",

  // ── export / jira ──
  Export: "Экспорт",
  Exporting: "Экспорт",
  "Export report": "Экспорт отчёта",
  "Export to Jira": "Экспорт в Jira",
  "Export all to Jira": "Экспортировать всё в Jira",
  "Export finished": "Экспорт завершён",
  "Open in Jira": "Открыть в Jira",
  "Open Jira": "Открыть Jira",
  "Checking status…": "Проверка статуса…",
  "Already exported:": "Уже выгружено:",
  "Already linked (skipped):": "Уже связано (пропущено):",
  "Failed:": "Ошибок:",
  "Selected:": "Выбрано:",
  "% elapsed": "% прошло",
  "A Jira issue (": "Задача в Jira (",
  ") will be created in To Do with the finding details, a start date of today and a due date in 2 weeks.":
    ") будет создана в To Do с деталями уязвимости, датой начала сегодня и сроком через 2 недели.",
  "This will create a Jira issue (in To Do) for each of the": "Будет создана задача в Jira (в To Do) для каждой из",
  "Exports whatever is left after the page filters —": "Выгружает всё, что осталось после фильтров страницы —",
  "(page filters apply). Already-linked findings are skipped.":
    "(с учётом фильтров страницы). Уже связанные уязвимости пропускаются.",
  ". To export something else, change the filters and reopen the export.":
    ". Чтобы выгрузить другое, измените фильтры и откройте экспорт заново.",

  // ── profile / settings ──
  "Profile Settings": "Настройки профиля",
  Account: "Аккаунт",
  Security: "Безопасность",
  Customizing: "Кастомизация",
  "Signed in as": "Вы вошли как",
  Name: "Имя",
  Email: "Email",
  Username: "Логин",
  Password: "Пароль",
  "Account password": "Пароль аккаунта",
  "Choose file": "Выбрать файл",
  ". Square images look best.": ". Лучше всего смотрятся квадратные изображения.",
  "— press Upload to save.": "— нажмите «Загрузить», чтобы сохранить.",
  "PNG / JPEG / WEBP / GIF, up to": "PNG / JPEG / WEBP / GIF, до",

  // ── 2FA ──
  "Two-factor authentication is currently disabled.": "Двухфакторная аутентификация сейчас отключена.",
  "Enabled via authenticator app": "Включена через приложение-аутентификатор",
  "Confirm your account password to disable 2FA": "Подтвердите пароль аккаунта, чтобы отключить 2FA",
  "1. Scan this QR in your authenticator app": "1. Отсканируйте QR в приложении-аутентификаторе",
  "2. Enter the 6-digit code": "2. Введите 6-значный код",
  "Or enter this key manually": "Или введите этот ключ вручную",

  // ── API keys ──
  "API keys": "API-ключи",
  "Generate API key": "Сгенерировать API-ключ",
  "Generate new key": "Сгенерировать новый ключ",
  "No API keys yet.": "Пока нет API-ключей.",
  "Key name": "Название ключа",
  Expiry: "Срок действия",
  "No expiry": "Без срока",
  Permissions: "Права",
  "Read only": "Только чтение",
  "Project access": "Доступ к проектам",
  "Selected projects": "Выбранные проекты",
  "All my projects": "Все мои проекты",
  Restricted: "Ограничено",
  "Scoped tokens for CI, bots and automation — no interactive login":
    "Токены с ограниченными правами для CI, ботов и автоматизации — без интерактивного входа",
  "e.g. CI pipeline": "напр. CI-пайплайн",

  // ── requests / responses view ──
  REQUEST: "ЗАПРОС",
  RESPONSE: "ОТВЕТ",
  "Copy request": "Скопировать запрос",
  "Copy response": "Скопировать ответ",

  // ── generic form / modal ──
  Cancel: "Отмена",
  Close: "Закрыть",
  Delete: "Удалить",
  Edit: "Изменить",
  Download: "Скачать",
  Disable: "Отключить",
  Done: "Готово",
  Save: "Сохранить",
  Create: "Создать",
  "Send invite": "Отправить приглашение",
  "Generate key": "Сгенерировать ключ",
  "Save changes": "Сохранить изменения",
  "Confirm deletion": "Подтвердите удаление",
  "Are you sure you want to delete": "Вы уверены, что хотите удалить",
  "? This action cannot be undone.": "? Это действие нельзя отменить.",
  "Select…": "Выбрать…",
  All: "Все",
  Description: "Описание",
  "Project name": "Название проекта",
  "Short summary of the engagement scope…": "Кратко опишите скоуп работ…",
  "e.g. Acme Corp — External Perimeter": "напр. Acme Corp — внешний периметр",
  "e.g. i.volkov": "напр. i.volkov",
  "e.g. CWE-89": "напр. CWE-89",
  Start: "Начало",
  End: "Конец",
  "Start date": "Дата начала",
  "End date": "Дата окончания",
  Created: "Создан",
  "Created:": "Создан:",
  Actions: "Действия",
  Project: "Проект",
  "Click to view": "Нажмите для просмотра",

  // ── entity editor (modal title = "Add/Edit " + TYPELABEL; field labels + ph) ──
  Add: "Добавить",
  host: "хост",
  endpoint: "эндпоинт",
  vulnerability: "уязвимость",
  note: "заметка",
  member: "участник",
  credential: "учётка",
  "e.g. app.acme-corp.com": "напр. app.acme-corp.com",
  "e.g. 10.0.0.7": "напр. 10.0.0.7",
  "e.g. 443/tcp — press Enter": "напр. 443/tcp — Enter",
  "Start typing a hostname…": "Начните вводить имя хоста…",
  "e.g. /api/users": "напр. /api/users",
  "e.g. Stored XSS in comments": "напр. Хранимая XSS в комментариях",
  "Note title": "Название заметки",
  "Write your note…": "Напишите заметку…",
  "Start typing a username…": "Начните вводить логин…",
  "account username": "логин учётной записи",
  "account password": "пароль учётной записи",

  // ── misc empty / stub states ──
  "No access": "Нет доступа",
  "Coming soon": "Скоро",
  "This area is under construction. Head back to Projects to continue your work.":
    "Этот раздел в разработке. Вернитесь к «Проектам», чтобы продолжить работу.",
  "Loading docs…": "Загрузка документации…",

  // ── customizing tab ──
  Appearance: "Оформление",
  "Choose how STORM looks — saved on this browser": "Как выглядит STORM — сохраняется в этом браузере",
  Light: "Светлая",
  Dark: "Тёмная",
  "Bright interface — the STORM default.": "Светлый интерфейс — по умолчанию в STORM.",
  "Dimmed palette, easier on the eyes in low light.": "Приглушённая палитра, комфортнее для глаз в темноте.",
  Language: "Язык",
  "Language of the interface — saved on this browser": "Язык интерфейса — сохраняется в этом браузере",
  "Interface in English.": "Интерфейс на английском.",
  "Interface in Russian.": "Интерфейс на русском.",

  // ── misc computed labels ──
  Administrator: "Администратор",
  "Profile settings": "Настройки профиля",
  IPs: "IP",
  "Total hosts": "Всего хостов",
  "Total IPs": "Всего IP",
  "Total endpoints": "Всего эндпоинтов",
  "No open": "Нет открытых",
  "No findings": "Нет находок",
  open: "открытых",
  "Hide password": "Скрыть пароль",
  "Reveal password": "Показать пароль",
  "All projects": "Все проекты",
  "Projects:": "Проекты:",
  "Export hosts": "Экспорт хостов",
  "Export IP addresses": "Экспорт IP-адресов",
  "Export endpoints": "Экспорт эндпоинтов",
  "Exporting…": "Экспорт…",
  "Track and assign engagement tasks across the team.": "Отслеживайте и назначайте задачи по проекту в команде.",
  "Your personally assigned tasks and reviews.": "Ваши личные задачи и ревью.",

  // ── report export ──
  "Certification report": "Отчёт для сертификации",
  "Security-system test report — for certification testing.": "Отчёт об испытаниях системы защиты информации — для сертификационных испытаний.",
  "Internal acceptance report": "Отчёт о внутренней приёмке",
  "Acceptance protocol — for internal acceptance of the work.": "Протокол приёмки — для внутренней приёмки работ.",
  "Download .docx": "Скачать .docx",
  "Generating…": "Генерация…",

  // ── recon farm: add hosts / add IPs ──
  "Add hosts": "Добавить хосты",
  "Add more": "Добавить ещё",
  "Paste hosts": "Вставьте хосты",
  "Paste IPs": "Вставьте IP-адреса",
  "Will be imported": "Будет импортировано",
  "parsed hosts appear here…": "здесь появятся разобранные хосты…",
  "parsed IPs appear here…": "здесь появятся разобранные адреса…",
  "Paste at least one host": "Вставьте хотя бы один хост",
  "Paste at least one IP": "Вставьте хотя бы один IP-адрес",
  "Couldn't start host import": "Не удалось запустить импорт хостов",
  "Couldn't start IP import": "Не удалось запустить импорт IP",
  "Probe done": "Проверка завершена",
  hosts: "хостов",
  hostnames: "имён",
  up: "доступно",
  down: "недоступно",
  added: "добавлено",
  skipped: "пропущено",
  "hosts — statuses update automatically.": "хостов — статусы обновляются автоматически.",
  "IPs — hostnames and ports update automatically.": "IP — имена и порты обновляются автоматически.",
  // Имя из PTR, чей прямой резолв не вернул этот адрес: показываем приглушённо.
  unconfirmed: "не подтверждено прямым резолвом",
  Cloudflare: "Cloudflare",
  unknown: "unknown",
  // ── recon farm: JS ──
  JS: "JS",
  "Scan JS": "Сканировать JS",
  "Select domains & scan": "Выбрать домены и сканировать",
  "Choose domains": "Выбор доменов",
  "Choose domains to scan": "Выберите домены для скана",
  "Will be scanned": "Будет просканировано",
  "one domain per line…": "по одному домену в строке…",
  "Start scan": "Запустить скан",
  "Pick at least one domain to scan.": "Выберите хотя бы один домен для скана.",
  "Total JS files": "Всего JS-файлов",
  Scanning: "Сканируем",
  "domains…": "доменов…",
  "domains — secrets and paths appear as files are scanned.": "доменов — секреты и пути появляются по мере скана.",
  "Scan done": "Скан завершён",
  "Scan failed": "Скан не удался",
  "Couldn't start JS scan": "Не удалось запустить скан JS",
  Archive: "Архив",
  "Download JS archive": "Скачать архив JS",
  "Preparing JS archive…": "Готовим архив JS…",
  "Couldn't download JS archive.": "Не удалось скачать архив JS.",
  secrets: "секретов",
  paths: "путей",
  Secrets: "Секреты",
  Paths: "Пути",
  "With secrets": "С секретами",
  "Filter by JS URL or host…": "Фильтр по URL или хосту…",
  "No JS files yet — pick domains and scan.": "Пока нет JS-файлов — выберите домены и запустите скан.",
  "Loading JS files…": "Загрузка JS-файлов…",
  "Nothing found in this file.": "В этом файле ничего не найдено.",
  "File could not be scanned.": "Файл не удалось просканировать.",
  "Paste hosts — with or without scheme/port. The server probes web ports and adds each host with its status.":
    "Вставьте хосты — со схемой/портом или без. Сервер проверит веб-порты и добавит каждый хост с его статусом.",
  "hosts…": "хостов…",
  "ports added": "портов добавлено",
  Probing: "Проверяем",
  "Runs in the background — you can keep working; results appear here.":
    "Выполняется в фоне — можно продолжать работу; результаты появятся здесь.",
  "Starting…": "Запуск…",
  "Probe & add": "Проверить и добавить",
  "Probe failed": "Проверка не удалась",
  "Try again": "Повторить",
  Added: "Добавлено",
  Online: "Онлайн",
  Offline: "Офлайн",
  "host(s) updated": "хостов обновлено",
  // Recon export page (two panes: what was found vs what will be written out).
  Found: "Найдено",
  "Will be exported": "Будет выгружено",
  List: "Список",
  "Swagger (OpenAPI 3)": "Swagger (OpenAPI 3)",
};

/** Translate an English source string to the active language (RU or EN). */
export function t(s: string): string {
  if (useLangStore.getState().lang !== "ru") return s;
  return RU[s] ?? s;
}
