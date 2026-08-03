# Use Cases — STORM

Документ описывает ключевые сценарии использования системы. Все use cases опираются на
реализованный backend (`FastAPI` + `PostgreSQL` + `MinIO` + `RabbitMQ`)
и SPA-фронтенд на `React 18 + MUI`.

Роли:
- `admin` — полный доступ, управление пользователями/проектами/Jira/agent-токенами;
- `pentester` — работа внутри проектов, в которых он участник;
- `developer` — чтение/комментирование/смена статуса уязвимостей в своих проектах;
- `agent` — внешний AI-агент, обращающийся к `/api/v2` по Bearer-токену.

---

## UC-01. Аутентификация по логину и паролю

- **Участники:** любой пользователь.
- **Предусловия:** учётная запись существует, `is_active = true`.
- **Основной поток:**
  1. Пользователь открывает `/login` и вводит `username` + `password`.
  2. Frontend выполняет `POST /api/v1/auth/login` с CSRF-токеном из cookie.
  3. `AuthService.login` проверяет пароль (Argon2/bcrypt), пишет audit `LOGIN`.
  4. Backend выдаёт пару cookie: `access_token` (JWT, короткоживущий) и `refresh_token` (хэш сохранён в `refresh_tokens`).
  5. Возвращает `LoginResponse` с `id`, `username`, `role`.
- **Альтернативы:**
  - **Неверные креды** — 401, audit `LOGIN_FAILED`.
  - **`is_active = false`** — 403.
- **Постусловия:** активная сессия в браузере, открыт WebSocket-канал уведомлений.

## UC-02. — удалён

Механизм временного пароля (флаг `must_change_password` + экран принудительной
смены) убран из продукта. Номер не переиспользуется, чтобы ссылки на остальные
сценарии не разъехались.

## UC-03. Сброс пароля администратором с письмом по email

- **Участники:** `admin`, целевой пользователь.
- **Основной поток:**
  1. Админ на `/users` нажимает «Сбросить пароль» у пользователя.
  2. `PATCH /api/v1/users/{id}/password` генерирует временный пароль и отзывает активные refresh-токены.
  3. Создаётся `MailJob` (template `password_reset`), публикуется в RabbitMQ; SMTP-воркер отправляет письмо.
  4. Возвращается `PasswordResetOut` (`ok`, `email_sent_to`, опционально `mail_preview_url` для Mailpit).
- **Альтернативы:** при сбое RabbitMQ задача остаётся в `pending`, повторяется воркером.
- **Постусловия:** пользователь входит с временным паролем из письма и меняет его в профиле.

## UC-04. Создание проекта и иерархия папок

- **Участники:** `admin`.
- **Предусловия:** опционально создана нужная папка в дереве (`POST /api/v1/projects/folders`).
- **Основной поток:**
  1. Админ открывает «Проекты», создаёт папку или раскрывает существующую.
  2. Создаёт проект (`POST /api/v1/projects`) с полями `name`, `folder`, `description`, `start_date`, `end_date`, `status` (по умолчанию `active`).
  3. Опционально drag&drop переносит проекты/папки между уровнями (`PATCH .../folders/{id}/move`).
  4. Все клиенты получают broadcast по WebSocket-каналу `/ws/projects-index`.
- **Альтернативы:** дубль `(parent_id, name)` для папки → 409.
- **Постусловия:** проект виден только админам и добавленным членам.

## UC-05. Управление участниками проекта

- **Участники:** `admin`, члены проекта.
- **Основной поток:**
  1. Админ открывает карточку проекта → вкладка «Участники».
  2. `POST /api/v1/projects/{id}/members` с `user_id` добавляет участника (любая роль).
  3. `DELETE .../members/{user_id}` удаляет связь.
- **Постусловия:** middleware `require_project_access` начинает/прекращает пропускать пользователя в роуты проекта.

## UC-06. Создание хоста с несколькими IP, портами, сервисами и endpoints

- **Участники:** `pentester` (член проекта) или `admin`.
- **Предусловия:** проект существует.
- **Основной поток:**
  1. Открывается страница проекта, кнопка «Добавить хост».
  2. `POST /api/v1/projects/{id}/hosts` с массивом `ip_addresses` (одна запись с `is_primary=true`) и/или `hostname`.
  3. Для хоста добавляются порты (`POST .../ports`, ограничение 1..65535, уникальность `(host, port_number, protocol)`).
  4. К каждому порту цепляются сервисы (`name`, `version`, `banner`).
  5. На уровне хоста создаются HTTP endpoints (`method`, `path`, `query_params`, `request_headers`, `request_body`, `request_content_type`).
- **Альтернативы:**
  - **Импорт OpenAPI** (UC-13) для массового заведения endpoints.
  - **Парсинг raw HTTP запроса** в форме endpoint (фронтенд заполняет поля автоматически).
- **Постусловия:** хост виден на карте проекта, готов к привязке уязвимостей.

## UC-07. Заведение уязвимости и привязка к активам

- **Участники:** `pentester`.
- **Предусловия:** в проекте есть хосты/порты/сервисы/endpoints.
- **Основной поток:**
  1. На странице проекта или хоста кнопка «Создать уязвимость».
  2. Заполняются `title`, `severity`, описание, `steps_to_reproduce`, `impact`, `recommendations`, `cwe_id`, `workflow_steps` (массив этапов).
  3. Опционально выбирается версия CVSS (3.1 или 4.0); фронтенд по вектору вычисляет `cvss_score`.
  4. `POST /api/v1/projects/{id}/vulnerabilities` сохраняет запись (`status = open`).
  5. Привязываются активы — `POST .../vulnerabilities/{vid}/assets` с `asset_type` ∈ {host, port, service, endpoint} и `asset_id`.
- **Постусловия:** уязвимость попадает в списки проекта и привязанного хоста; broadcast по WS канала проекта.

## UC-08. Загрузка и скачивание файлов доказательной базы

- **Участники:** `pentester`, `admin`.
- **Основной поток:**
  1. В карточке уязвимости кнопка «Загрузить файл».
  2. `POST .../vulnerabilities/{vid}/files` (multipart). Backend проверяет mime по whitelist, размер ≤ 50 МБ.
  3. Файл сохраняется в MinIO; метаданные — в `files`.
  4. `GET /api/v1/files/{file_id}/download` отдаёт поток (inline для image/*, иначе attachment).
- **Альтернативы:** запрещённый mime → 415; превышение размера → 413.

## UC-09. Комментирование уязвимости с упоминаниями

- **Участники:** `pentester`, `admin`.
- **Основной поток:**
  1. На карточке уязвимости пишется комментарий с `@username`.
  2. `POST .../vulnerabilities/{vid}/comments` создаёт запись и парсит mentions.
  3. На каждого упомянутого создаётся `Notification` (type `mention`) и push в `/ws/notifications` соответствующего пользователя.
  4. Все клиенты проекта получают обновление списка комментариев через WS.
- **Постусловия:** счётчик непрочитанных у получателя растёт; в шапке появляется toast.

## UC-10. Работа с in-app уведомлениями

- **Участники:** все роли.
- **Основной поток:**
  1. SPA каждые 30 c вызывает `GET /api/v1/notifications/unread-count` и слушает WS.
  2. Клик по колокольчику → `GET /api/v1/notifications?is_read=false` → список.
  3. Клик по уведомлению → `PATCH /notifications/{id}/read` и навигация к контексту (project / host / vulnerability / comment).
  4. Кнопка «Прочитать все» → `PATCH /notifications/read-all`.

## UC-11. Заметки проекта (Confluence-like)

- **Участники:** все члены проекта.
- **Основной поток:**
  1. На странице проекта раздел «Заметки» отображает дерево из `GET /api/v1/projects/{id}/notes`.
  2. Создание страницы — `POST .../notes` с `parent_id` и markdown-контентом.
  3. Перетаскивание — `PATCH .../notes/{id}/move` (смена родителя), `PATCH .../notes/reorder` (порядок внутри уровня).
  4. К странице оставляются комментарии (`POST .../notes/{id}/comments`); реализованы edit/delete.
- **Альтернативы:** конфликт уникальности `(project_id, parent_id, title)` → 409.

## UC-12. Импорт PCF JSON-дампа в проект

- **Участники:** `pentester`, `admin`.
- **Основной поток:**
  1. На странице проекта «Импорт» загружается JSON-файл.
  2. `POST /api/v1/projects/{id}/import` парсит структуру (hosts/ports/services/endpoints/vulnerabilities/comments) и атомарно создаёт сущности.
  3. Возвращается `ImportResult` со счётчиками созданных объектов и предупреждениями.
- **Альтернативы:** битый JSON / схема — 422.

## UC-13. Импорт и экспорт OpenAPI для хоста

- **Участники:** `pentester`.
- **Основной поток:**
  1. На странице хоста «Импорт OpenAPI» загружается JSON или YAML.
  2. `POST .../hosts/{hid}/import-openapi` создаёт endpoints с заполненными `method`, `path`, `query_params`, `request_body`, `request_content_type`, `request_headers`.
  3. `GET .../hosts/{hid}/export-openapi` отдаёт сформированный OpenAPI 3.0 JSON (attachment).

## UC-14. Экспорт уязвимости в Jira

- **Участники:** `admin`, `pentester` (с членством и при настроенной интеграции).
- **Предусловия:** глобальный конфиг Jira создан (`PUT /api/v1/jira/config`); проект привязан (`PUT /api/v1/projects/{pid}/jira-link`).
- **Основной поток:**
  1. На карточке уязвимости кнопка «Экспортировать в Jira».
  2. `POST .../vulnerabilities/{vid}/jira/export` дешифрует API-токен Jira, создаёт issue (тип `default_issue_type`).
  3. Создаётся/обновляется `JiraIssueLink` с `jira_issue_key` и URL, `status = linked`.
- **Альтернативы:** ошибка Jira API — `status = error`, `last_error` в записи; UI показывает причину.
- **Постусловия:** в карточке отображается ссылка на Jira issue; повторный экспорт обновляет связь.

## UC-15. Генерация Word-отчётов «ПП» и «СЗИ»

- **Участники:** `pentester`, `admin`.
- **Основной поток:**
  1. На странице проекта меню «Отчёты» → «План пентеста» или «СЗИ».
  2. `POST /api/v1/projects/{id}/reports/pp` или `.../reports/szi`.
  3. `ReportService` подставляет данные проекта/уязвимостей в шаблоны `.docx`.
  4. Стрим возвращается с `Content-Disposition: attachment; filename*=UTF-8''<имя>.docx`.

## UC-16. Управление профилем пользователя

- **Участники:** любой авторизованный пользователь.
- **Основной поток:**
  1. Меню «Профиль» открывает `/profile`.
  2. `PATCH /api/v1/users/me` обновляет `full_name`, `email`, `tags`.
  3. `PATCH /api/v1/users/me/password` меняет пароль (требуется `current_password`).
  4. `POST /api/v1/users/me/avatar` загружает аватар (хранится в MinIO; URL версионируется по `avatar_uploaded_at`).
- **Альтернативы:** дубль email / username — 409.

## UC-17. Выпуск Bearer-токена для AI-агента

- **Участники:** `admin`.
- **Основной поток:**
  1. На `/ai-integration` кнопка «Создать токен».
  2. Указываются `name`, набор `scopes`, флаг `all_projects` или список `project_ids`, опциональный `expires_at`.
  3. `POST /api/v1/agent-tokens` возвращает значение `token` ровно один раз; в БД хранится только `token_hash` и `token_prefix`.
  4. Создаются записи `agent_api_token_project_grants` под выбранные проекты.
- **Альтернативы:** отзыв токена — `DELETE /api/v1/agent-tokens/{id}` ставит `revoked_at`.

## UC-18. Работа AI-агента через `/api/v2`

- **Участники:** внешний `agent`.
- **Предусловия:** валидный, не отозванный, не истёкший токен; нужный scope; разрешённый проект.
- **Основной поток:**
  1. Агент отправляет `Authorization: Bearer <token>` в `/api/v2/...`.
  2. `require_agent_scope` декодирует токен, проверяет scope; обновляет `last_used_at`.
  3. `require_agent_project_access` проверяет привязку проекта.
  4. Доступные операции:
     - `GET /api/v2/projects` (`projects:read`);
     - `GET /api/v2/projects/{id}/hosts` (`assets:read`);
     - `GET/POST/PUT /api/v2/projects/{id}/notes` (`notes:read`/`notes:write`);
     - `GET/POST/PUT /api/v2/projects/{id}/vulnerabilities` (`vulns:read`/`vulns:write`).
  5. Все мутации логируются в audit как действия `created_by` пользователя токена.
- **Альтернативы:** неверный/просроченный токен — 401; недостаточный scope — 403; недопустимый проект — 403.

## UC-19. Просмотр журнала действий администратором

- **Участники:** `admin`.
- **Основной поток:**
  1. На `/audit-logs` задаются фильтры: `username`, `action`, `entity_type`, `entity_id`, `ip_address`, `query`, период `created_from..created_to`.
  2. `GET /api/v1/audit-logs` читает журнал из PostgreSQL-таблицы `audit_logs` с outer join к `users` для имени пользователя.
  3. Список с пагинацией (по умолчанию 50/стр.) показывает кто/когда/что/откуда.
- **Постусловия:** возможен экспорт/копирование данных вручную.

## UC-20. Real-time обновления через WebSocket

- **Участники:** все авторизованные пользователи.
- **Основной поток:**
  1. SPA при загрузке открывает каналы:
     - `/ws/projects-index` — изменения в общем списке проектов;
     - `/ws/notifications` — персональные уведомления;
     - `/ws/projects/{id}` — события внутри открытого проекта (после проверки членства).
  2. На сообщение фронт обновляет соответствующий стейт без перезагрузки.
- **Альтернативы:** нет access cookie / отозван — close 4401; не член проекта — close 4403.
