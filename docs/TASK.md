# TASK — STORM

Чек-лист реализованных задач (отмечено `[x]`) и backlog (`[ ]`), сгруппированный по
эпикам/модулям. Источник истины — текущий код `backend/app` и `frontend/src`.

---

## Эпик 1. Аутентификация, сессии и безопасность

- [x] Cookie-аутентификация с парой `access_token` (JWT) + `refresh_token` (хэш в БД)
- [x] `POST /api/v1/auth/login` (CSRF-cookie + Double Submit)
- [x] `POST /api/v1/auth/refresh` с ротацией refresh-токена
- [x] `POST /api/v1/auth/logout` (отзыв всех refresh-токенов, очистка cookie)
- [x] CSRF-защита всех мутирующих эндпоинтов через `enforce_csrf`
- [x] Проверка `is_active` пользователя на каждом запросе
- [x] Извлечение реального IP клиента (`get_client_ip`) для audit
- [x] Хранение refresh-токенов как хэшей с TTL и `revoked_at`
- [x] 2FA (TOTP, RFC 6238) — опциональна, подключается в личном кабинете; логин в два шага (`POST /api/v1/auth/2fa/verify`), секрет зашифрован (Fernet), сброс админом `POST /api/v1/users/{id}/2fa/reset`
- [ ] Обязательное 2FA для admin (принудительный enrollment)
- [ ] WebAuthn / Passkey

## Эпик 2. Управление пользователями

- [x] Аккаунтная роль `admin` / `pentester` (`UserRole`) и проектная `lead` / `pentester` (`ProjectRole`, глобальная)
- [x] CRUD пользователей (только admin): `GET/POST/PUT/DELETE /api/v1/users`
- [x] `GET /api/v1/users/me` и расширенный `GET /api/v1/users/me/profile`
- [x] `PATCH /api/v1/users/me` (full_name, email, tags)
- [x] `PATCH /api/v1/users/me/password` (требует current_password)
- [x] Загрузка/скачивание аватара пользователя (MinIO; URL версионируется)
- [x] Сброс пароля админом с генерацией временного и письмом по email
- [x] In-app превью писем через Mailpit (`mail_preview_url` в ответе)
- [x] Теги (`tags: list[str]`) на уровне пользователя
- [ ] Self-service запрос «забыли пароль» (без admin)
- [ ] Soft-delete пользователей и история ролей

## Эпик 3. Проекты и иерархия

- [x] CRUD проектов (создание/обновление/удаление — только admin)
- [x] Статусы: `active`, `handover_to_development`, `vulnerability_recheck`, `completed`, `archived`
- [x] Поля `start_date`, `end_date`, `timeline_frozen_at`, `description`
- [x] Иерархия папок (`project_folders`) с `path` и `parent_id`
- [x] `POST /api/v1/projects/folders`, `PATCH .../folders/{id}/move`
- [x] Плоский ответ дерева папок + drag&drop в UI
- [x] Управление участниками: `GET/POST/DELETE /api/v1/projects/{id}/members`
- [x] Изоляция доступа через `require_project_access` (admin видит всё)
- [x] WebSocket `/ws/projects-index` для real-time обновления списка
- [ ] Архивирование с автоматическим reset членства

## Эпик 4. Хосты, порты, сервисы, endpoints

- [x] Хост может иметь несколько IP (`host_ip_addresses`, `is_primary`) и/или hostname
- [x] CRUD хостов с пагинацией и фильтром по статусу
- [x] Порты (TCP/UDP, состояния open/closed/filtered, диапазон 1..65535, уникальность)
- [x] Сервисы (имя, версия, баннер) на уровне порта
- [x] HTTP endpoints: метод, path, query_params, request_headers, request_body, content_type
- [x] Парсинг raw HTTP-запроса в форме endpoint (фронт)
- [x] Импорт OpenAPI/Swagger (JSON и YAML) в endpoints хоста
- [x] Экспорт endpoints хоста в OpenAPI 3.0 JSON
- [ ] Discovery сервиса по баннеру / fingerprinting
- [ ] Сетевые домены/подсети как отдельная сущность

## Эпик 5. Уязвимости

- [x] CRUD уязвимостей с пагинацией, фильтрами по severity и status
- [x] Severity: critical / high / medium / low / info
- [x] Status: open / in_progress / fixed / wont_fix / accepted_risk
- [x] CVSS v3.1 и v4.0: версия + вектор + автоматический расчёт `cvss_score`
- [x] Поле `cwe_id`
- [x] `workflow_steps` (массив этапов, JSON)
- [x] Поля `description`, `steps_to_reproduce`, `impact`, `recommendations`
- [x] Полиморфная привязка к активам (host/port/service/endpoint) через `vulnerability_assets`
- [x] Отдельный эндпоинт `PATCH .../vulnerabilities/{vid}/status`
- [x] Список уязвимостей хоста: `GET .../hosts/{hid}/vulnerabilities`
- [x] Подробная карточка с `assets`, `files`, `comments_count`
- [ ] Шаблоны уязвимостей (создание из библиотеки)
- [ ] CVSS v2 (legacy импорт)

## Эпик 6. Файлы доказательной базы

- [x] Загрузка файлов в MinIO, до 50 МБ, whitelist mime
- [x] CRUD файлов уязвимости (`/projects/{pid}/vulnerabilities/{vid}/files`)
- [x] Скачивание `GET /api/v1/files/{file_id}/download` (inline для image/*)
- [x] Доступ контролируется по членству в проекте
- [ ] Антивирусное сканирование загружаемых файлов
- [ ] Watermark / превью изображений на лету

## Эпик 7. Комментарии и уведомления

- [x] Комментарии к уязвимостям (CRUD)
- [x] Парсинг `@username` и создание `comment_mentions`
- [x] In-app `notifications` (тип `mention`)
- [x] `GET /api/v1/notifications` с фильтром `is_read`, пагинация
- [x] `GET /api/v1/notifications/unread-count`
- [x] `PATCH /notifications/{id}/read` и `PATCH /read-all`
- [x] WebSocket `/ws/notifications` — push новых уведомлений
- [x] Тосты в UI и бейдж непрочитанных
- [x] Комментарии к страницам заметок проекта (`project_note_comments`)
- [ ] Email-нотификация при упоминании
- [ ] Подписка на изменения уязвимости без упоминания

## Эпик 8. Заметки проекта (Confluence-like)

- [x] Дерево заметок (`project_notes`) с `parent_id` и `sort_order`
- [x] CRUD заметок проекта
- [x] Перемещение `PATCH .../notes/{id}/move` и reorder `PATCH .../notes/reorder`
- [x] Markdown-контент в `content`
- [x] Уникальность title в пределах sibling-уровня
- [x] Комментарии к заметкам (CRUD)
- [x] Логирование `updated_by`
- [ ] Версионирование заметок (история изменений)
- [ ] Real-time совместное редактирование

## Эпик 9. Импорт данных

- [x] Импорт PCF JSON-дампа в проект (`POST .../projects/{id}/import`)
- [x] Импорт OpenAPI/Swagger в endpoints хоста (`POST .../hosts/{hid}/import-openapi`)
- [x] Возврат `ImportResult` со счётчиками и предупреждениями
- [ ] Импорт Burp Suite XML
- [ ] Импорт Nessus / nmap / OpenVAS XML

## Эпик 10. Отчёты Word

- [x] Шаблон «План пентеста» (ПП) — `POST .../reports/pp`
- [x] Шаблон «Состояние защищённости» (СЗИ) — `POST .../reports/szi`
- [x] Подстановка данных проекта/уязвимостей в `.docx` шаблоны
- [x] Корректное `Content-Disposition` с UTF-8 именем файла
- [ ] PDF-экспорт
- [ ] Кастомные шаблоны отчётов на стороне admin

## Эпик 11. Интеграция с Jira

- [x] Глобальный конфиг Jira (`jira_instances`): URL, email, API-токен (шифрование at rest)
- [x] `GET/PUT /api/v1/jira/config` (admin)
- [x] Привязка проекта STORM к Jira project key (`project_jira_links`)
- [x] `POST .../vulnerabilities/{vid}/jira/export` — создание Jira issue
- [x] Хранение `JiraIssueLink` (key, URL, status, last_error)
- [x] Просмотр привязки `GET .../vulnerabilities/{vid}/jira`
- [ ] Двусторонняя синхронизация статусов (Jira → STORM)
- [ ] Webhooks из Jira
- [ ] Поддержка нескольких Jira-инстансов

## Эпик 12. Audit log

- [x] Запись действий в PostgreSQL (`audit_logs`) — единый источник правды
- [x] Эндпоинт `GET /api/v1/audit-logs` (admin) с фильтрами
- [x] Фильтры: `user_id`, `username`, `action`, `entity_type`, `entity_id`, `ip_address`, `query`, период
- [x] Скрытие шумных `LOGIN` от refresh
- [x] Запись действий agent-токенов от имени `created_by`
- [ ] Экспорт журнала в CSV/JSON
- [ ] Алерты на подозрительные паттерны

## Эпик 13. AI Agent API v2

- [x] `agent_api_tokens` — Bearer-токен с `name`, `scopes`, `token_hash`, `token_prefix`
- [x] `expires_at`, `revoked_at`, `last_used_at`
- [x] `agent_api_token_project_grants` — список разрешённых проектов
- [x] Флаг `all_projects` для глобального доступа
- [x] `GET/POST/DELETE /api/v1/agent-tokens` (admin), значение токена возвращается один раз
- [x] Scopes: `projects:read`, `assets:read`, `notes:read`, `notes:write`, `vulns:read`, `vulns:write`
- [x] `require_agent_scope` и `require_agent_project_access` зависимости
- [x] `GET /api/v2/projects` (projects:read)
- [x] `GET /api/v2/projects/{id}/hosts` (assets:read)
- [x] `GET/POST/PUT /api/v2/projects/{id}/notes` (notes:read/write)
- [x] `GET/POST/PUT /api/v2/projects/{id}/vulnerabilities` (vulns:read/write)
- [x] UI на `/ai-integration` для создания/отзыва токенов
- [ ] Rate-limiting per-token
- [ ] Удаление уязвимостей и операции с активами через v2

## Эпик 14. Real-time / WebSocket

- [x] `/ws/projects-index` — обновления списка проектов
- [x] `/ws/notifications` — персональные уведомления
- [x] `/ws/projects/{id}` — события проекта (с проверкой членства)
- [x] Авторизация WS по `access_token` cookie
- [x] Закрытие соединения 4401/4403 при ошибках авторизации
- [ ] Server-side rebroadcast событий с фильтрами по подсущностям
- [ ] WebSocket-канал для admin-mass-actions

## Эпик 15. Mail (RabbitMQ + SMTP)

- [x] `mail_jobs` — очередь писем (`pending` → `sent` / `failed`)
- [x] Публикация задания в RabbitMQ при сбросе пароля
- [x] SMTP-воркер `mail_worker` с retry и `last_error`
- [x] Поддержка Mailpit для локальной разработки
- [x] Шаблон `password_reset`
- [ ] Шаблон уведомления об упоминании
- [ ] Дайджест по проекту раз в день

## Эпик 16. Frontend (React + MUI)

- [x] Страницы: Login, ForceChangePassword, Profile, Projects, ProjectDetail, HostDetail, UsersAdmin, AuditLogs, AiAgentIntegration
- [x] Компоненты: ProjectTreeNav, ProjectNotesSection / TreePopover, ProjectHostsTreePopover, MarkdownEditor / Image / OutlinedReadonlyField, VulnerabilityStagesEditor
- [x] Темизация (PaletteMode dark/light)
- [x] Глобальные toast-уведомления (`useToastStore`)
- [x] Интеграция с WebSocket для уведомлений
- [x] Защищённые роуты (auth + role-based для admin-страниц)
- [x] Markdown rendering с безопасной трансформацией URL
- [x] Расчёт CVSS на клиенте (`cvss.ts`) для v3.1 и v4.0
- [ ] PWA / offline-режим
- [ ] i18n (en/ru)

## Эпик 17. Инфраструктура и DevOps

- [x] FastAPI + SQLAlchemy 2.x async + asyncpg
- [x] Alembic миграции (включая `mail_jobs`)
- [x] PostgreSQL — основное хранилище
- [x] MinIO — файлы и аватары
- [x] RabbitMQ — очередь писем
- [x] Docker / docker-compose для backend/frontend/инфры
- [x] Pytest-тесты сервисов и роутеров
- [ ] CI/CD пайплайн (GitHub Actions)
- [ ] Helm chart / Kubernetes-манифесты
- [ ] Метрики Prometheus + Grafana дашборды
