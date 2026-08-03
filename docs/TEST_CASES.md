# Тест-кейсы STORM

> Pentest Collaboration Framework — система совместной работы над пентест-проектами.
> Документ описывает актуальное тестовое покрытие приложения и предложенные сценарии для расширения покрытия.

---

## 1. Введение

### 1.1 Цели документа
- Зафиксировать наблюдаемое тестовое покрытие проекта (что уже реализовано в `backend/tests/` и `frontend/src/**/*.test.tsx`).
- Предложить тест-кейсы (статус «Запланирован»), которые покрывают актуальную функциональность роутеров, но ещё не реализованы как автотесты.
- Дать QA-инженеру быструю карту: «функция → ID тест-кейса → существующий тест».

### 1.2 Стек тестов

| Слой | Инструменты | Запуск |
|---|---|---|
| Backend (юнит/сервисный) | `pytest`, `pytest-asyncio`, `unittest.mock.AsyncMock`, `MagicMock` | `cd backend && pytest` |
| Backend (схемы Pydantic) | `pytest`, `pydantic.ValidationError` | `pytest tests/test_schemas.py` |
| Backend (Word-отчёты) | `pytest`, `python-docx` (чтение результата) | `pytest tests/test_word_builder.py` |
| Frontend (компоненты/страницы) | `vitest`, `@testing-library/react`, `userEvent`, `vi.mock`, `vi.hoisted` | `cd frontend && npm run test` |
| Тестовая БД | In-memory SQLite (fallback) или PostgreSQL test DB; внешние зависимости (MinIO, SMTP, Jira) — мокаются через `monkeypatch` | — |

### 1.3 Стратегия
- Сервисный слой — основной объект юнит-тестирования (`AssetService`, `VulnerabilityService`, `ProjectService`, `ProjectNoteService`, `CommentService`, `ImportService`, `JiraIntegrationService`, `UserService`, `ReportService`).
- Pydantic-схемы покрываются граничными значениями (длина пароля, диапазоны портов, обязательность полей).
- Безопасность: cookie-флаги, CSRF Origin-валидация, проверка типов JWT, SSRF-защита Jira, ACL аватаров, шифрование api_token (Fernet).
- Интеграционных тестов через `httpx.AsyncClient` сейчас нет — соответствующие кейсы для роутеров и WebSocket помечены как «Запланирован».

### 1.4 Условные обозначения
- **ID** — уникальный идентификатор `TC-<MODULE>-<NNN>`.
- **Статус**:
  - **Реализован** — соответствующий тест найден в `backend/tests/` или `frontend/src/**/*.test.tsx`.
  - **Запланирован** — кейс описывает поведение, заявленное в роутерах/сервисах, но автотест отсутствует.
- В колонке «Шаги» приведён сжатый сценарий; для реализованных кейсов в скобках указан файл теста.

---

## 2. Тест-кейсы по модулям

### 2.1 Аутентификация (TC-AUTH-NNN)

Связано с: `app/security.py`, `app/routers/auth.py`, `app/dependencies.py`, `app/services.AuthService`.

| ID | Название | Предусловия | Шаги | Ожидаемый результат | Статус |
|---|---|---|---|---|---|
| TC-AUTH-001 | Round-trip access JWT | — | Создать access-token через `create_access_token(uuid)`, декодировать с `expected_type="access"` (`tests/test_security.py::test_access_token_roundtrip_tc_auth_001`) | `decode_token` возвращает исходный UUID | Реализован |
| TC-AUTH-002 | Round-trip refresh JWT | — | `create_refresh_token` → `decode_token(expected_type="refresh")` (`tests/test_security.py`) | Возвращается исходный UUID | Реализован |
| TC-AUTH-003 | Отказ декодирования при неверном типе токена | — | Передать refresh-token в `decode_token(expected_type="access")` | `UnauthorizedError("Некорректный тип токена")` | Реализован |
| TC-AUTH-004 | Хеш refresh-токена детерминирован | — | `hash_refresh_token` дважды для одной строки | Совпадающие SHA-256 длиной 64 | Реализован |
| TC-AUTH-005 | Cookie содержат security-флаги | — | `_set_auth_cookies(response, "a", "r")` (`tests/test_auth_cookies.py`) | `access_token` и `refresh_token` имеют `HttpOnly`, `SameSite=strict`, корректные `Path` (`/`, `/api/v1/auth/refresh`) | Реализован |
| TC-AUTH-006 | Logout очищает cookie с Max-Age=0 | — | `_clear_auth_cookies(response)` | Оба cookie получают `Max-Age=0` | Реализован |
| TC-AUTH-007 | CSRF: GET-запрос пропускается без Origin | — | `enforce_csrf(request_GET, origin=None)` (`tests/test_dependencies.py`) | Не выбрасывает исключения | Реализован |
| TC-AUTH-008 | CSRF: POST без Origin → 403 | — | `enforce_csrf(request_POST, origin=None)` | `ForbiddenError("Отсутствует заголовок Origin")` | Реализован |
| TC-AUTH-009 | CSRF: чужой Origin → 403 | — | `enforce_csrf(request_PATCH, origin="http://evil.local")` | `ForbiddenError("Недопустимый Origin")` | Реализован |
| TC-AUTH-010 | CSRF: разрешённый Origin принимается | — | `enforce_csrf(request_DELETE, origin="http://localhost:3000")` | Запрос проходит | Реализован |
| TC-AUTH-012 | Login: пустые credentials отклоняются | — | `LoginRequest(username="", password="")` (`tests/test_additional_validations.py`) | `pydantic.ValidationError` | Реализован |
| TC-AUTH-013 | Login: успешный логин выставляет cookie | Существует пользователь admin | POST `/api/v1/auth/login` с валидными credentials | 200; в `Set-Cookie` есть `access_token` (Path=/) и `refresh_token` (Path=/api/v1/auth/refresh); ответ не содержит token-полей | Запланирован |
| TC-AUTH-014 | Login: неверный пароль → 401 | Существует пользователь | POST `/api/v1/auth/login` с неверным паролем | 401 `UnauthorizedError` | Запланирован |
| TC-AUTH-015 | Login: неактивный пользователь → 401 | `is_active=False` | POST `/api/v1/auth/login` | 401, аудит `LOGIN_FAILED` | Запланирован |
| TC-AUTH-016 | Refresh: ротация — старый токен отзывается | Есть refresh cookie | POST `/api/v1/auth/refresh` | 200; новые `access_token`+`refresh_token`; `RefreshTokenRecord.revoked_at` старого выставлен | Запланирован |
| TC-AUTH-017 | Refresh: повторное использование отзывает все токены пользователя (reuse detection) | Refresh уже был обменен | POST `/api/v1/auth/refresh` со старым refresh-токеном | 401; все `RefreshTokenRecord` пользователя помечены revoked | Запланирован |
| TC-AUTH-018 | Logout: токены отзываются и cookie очищаются | Авторизован | POST `/api/v1/auth/logout` | 204; cookie с `Max-Age=0`; запись аудита `LOGOUT` | Запланирован |
| TC-AUTH-020 | Force-change-password: требует длину ≥ 8 | — | `ForceChangePasswordRequest(new_password="short")` | `pydantic.ValidationError` | Запланирован |
| TC-AUTH-021 | JWT: слишком короткий jwt_secret_key отклоняется в Settings | — | `Settings(jwt_secret_key="short-secret", ...)` (`tests/test_additional_validations.py`) | `pydantic.ValidationError` | Реализован |

### 2.2 Пользователи (TC-USER-NNN)

Связано с: `app/routers/users.py`, `app/services.UserService`.

| ID | Название | Предусловия | Шаги | Ожидаемый результат | Статус |
|---|---|---|---|---|---|
| TC-USER-001 | UserCreate отклоняет короткий пароль | — | `UserCreate(username, email, password="short")` (`tests/test_schemas.py`) | `pydantic.ValidationError` | Реализован |
| TC-USER-002 | UserCreate принимает роль admin | — | `UserCreate(..., role="admin")` (`tests/test_additional_validations.py`) | `payload.role.value == "admin"` | Реализован |
| TC-USER-003 | Admin не может менять email другого пользователя | Целевой user existing | `UserService.update_user(user_id, {"email": "new@..."}, actor_id=other)` (`tests/test_user_service_security.py`) | `ValidationError("не может менять email")` | Реализован |
| TC-USER-004 | Аватар: запрет просмотра чужого аватара пентестером | requester role=PENTESTER, target_id != requester.id | `UserService.ensure_can_view_avatar(requester, target_id)` | `ForbiddenError("чужого аватара")` | Реализован |
| TC-USER-005 | Создание admin / pentester через POST /users | Логин admin | POST `/api/v1/users` с разными ролями | 201, поля пользователя без `password_hash` | Запланирован |
| TC-USER-006 | Reset password (admin) генерирует временный пароль и письмо | Admin авторизован | PATCH `/api/v1/users/{user_id}/password` | 200, `ok=true`, `email_sent_to=<email>`, опционально `mail_preview_url`; активные refresh-токены отозваны | Запланирован |
| TC-USER-007 | Self-update profile (PATCH /users/me) меняет full_name/tags | Любой пользователь | PATCH `/api/v1/users/me` с `{full_name, tags}` | 200, обновлённый профиль | Запланирован |
| TC-USER-008 | Загрузка аватара POST /users/me/avatar | Авторизован | POST `/api/v1/users/me/avatar` с файлом изображения | 200, `avatar_url` обновлён | Запланирован |
| TC-USER-009 | Самоудаление запрещено (DELETE /users/{self_id}) | Admin | DELETE `/api/v1/users/{admin_id}` под admin | 400/403 | Запланирован |
| TC-USER-010 | Listing пользователей доступен только admin | Pentester | GET `/api/v1/users` без admin прав | 403 ForbiddenError | Запланирован |
| TC-USER-011 | Смена собственного пароля требует current_password | Любой пользователь | PATCH `/api/v1/users/me/password` с неверным текущим | 400/403 ValidationError | Запланирован |
| TC-USER-012 | Скачивание чужого аватара админом разрешено | Admin | GET `/api/v1/users/{other_id}/avatar` | 200, image content | Запланирован |

### 2.3 Проекты и папки (TC-PROJ-NNN)

Связано с: `app/routers/projects.py`, `app/services.ProjectService`.

| ID | Название | Предусловия | Шаги | Ожидаемый результат | Статус |
|---|---|---|---|---|---|
| TC-PROJ-001 | List projects: admin видит без фильтра по membership | Admin | `ProjectService.list_projects(admin, page=1, size=20, status="active")` (`tests/test_project_service.py`) | SQL содержит `projects.status`, не содержит `project_members` | Реализован |
| TC-PROJ-002 | List projects: pentester ограничен membership | Pentester | `list_projects(pentester, page=2, size=10)` | SQL содержит `JOIN project_members` и `project_members.user_id` | Реализован |
| TC-PROJ-003 | Delete project удаляет сущность и пишет аудит | — | `ProjectService.delete_project(project_id, actor_id, ip)` | `db.delete(project)`, `audit.log("DELETE", entity_type="project", ...)` | Реализован |
| TC-PROJ-004 | Update project: первый переход в non-active замораживает timeline | `status=ACTIVE`, `timeline_frozen_at=None` | Перевести в `HANDOVER_TO_DEVELOPMENT` | `timeline_frozen_at != None`, status обновился | Реализован |
| TC-PROJ-005 | Update project: повторный non-active не сбрасывает frozen | `status=HANDOVER_TO_DEVELOPMENT`, `timeline_frozen_at=ts` | Перевести в `VULNERABILITY_RECHECK` | `timeline_frozen_at` сохраняет прежнее значение | Реализован |
| TC-PROJ-006 | Update project: возврат в ACTIVE сбрасывает frozen | `status=VULNERABILITY_RECHECK`, frozen=ts | Перевести в `ACTIVE` | `timeline_frozen_at=None` | Реализован |
| TC-PROJ-007 | ProjectUpdate: неизвестный статус отклоняется | — | `ProjectUpdate(status="invalid_status")` (`tests/test_additional_validations.py`) | `pydantic.ValidationError` | Реализован |
| TC-PROJ-008 | ProjectUpdate: принимает все поддерживаемые статусы | — | Параметризованный тест по `ProjectStatus.{ACTIVE, HANDOVER_TO_DEVELOPMENT, VULNERABILITY_RECHECK, COMPLETED, ARCHIVED}` | Все валидируются | Реализован |
| TC-PROJ-009 | CRUD проекта через REST | Admin | POST/GET/PUT/DELETE `/api/v1/projects/{id}` | 201/200/200/204 | Запланирован |
| TC-PROJ-010 | Создание папки и вложенной папки | Admin | POST `/api/v1/projects/folders` с `parent_id` | 201, иерархия видна в `GET /folders` | Запланирован |
| TC-PROJ-011 | Move папки нельзя в её дочернюю | Папка A с подпапкой B | PATCH `/api/v1/projects/folders/{A}/move` с `parent_id=B` | `ValidationError` | Запланирован |
| TC-PROJ-012 | Members: добавление участника | Admin | POST `/api/v1/projects/{id}/members` `{user_id}` | 201, появляется в GET /members | Запланирован |
| TC-PROJ-013 | Members: pentester получает доступ к проекту | Pentester добавлен в members | GET `/api/v1/projects/{id}` под pentester | 200 | Запланирован |
| TC-PROJ-014 | Members: pentester без membership получает 403 | — | GET `/api/v1/projects/{id}` под чужим pentester | 403 | Запланирован |

### 2.4 Заметки проекта (TC-NOTE-NNN)

Связано с: `app/routers/project_notes.py`, `app/services.ProjectNoteService`.

| ID | Название | Предусловия | Шаги | Ожидаемый результат | Статус |
|---|---|---|---|---|---|
| TC-NOTE-001 | Move заметки в дочернюю → ValidationError | Существует note → child | `ProjectNoteService.move_note(project_id, note_id, child_id, actor)` (`tests/test_project_note_service.py`) | `ValidationError("дочернюю")` | Реализован |
| TC-NOTE-002 | Reorder требует полный набор siblings | 2 sibling под parent | `reorder_notes(parent_id, items=[только_один_sibling])` | `ValidationError("полный набор sibling")` | Реализован |
| TC-NOTE-003 | CRUD заметки в дереве | Member проекта | POST/GET/PUT/DELETE `/api/v1/projects/{id}/notes` | 201/200/200/204 | Запланирован |
| TC-NOTE-004 | Move в саму себя запрещён | Note существует | PATCH `/move` с `parent_id=note_id` | `ValidationError` | Запланирован |
| TC-NOTE-005 | Уникальность title среди siblings | Sibling с title="A" | POST с тем же title и тем же `parent_id` | `ValidationError` (unique constraint) | Запланирован |
| TC-NOTE-006 | Список комментариев к заметке (пагинация) | Note существует | GET `/api/v1/projects/{id}/notes/{note_id}/comments?page=1&size=50` | 200, `{items, total, page, size, pages}` | Запланирован |
| TC-NOTE-007 | Создание комментария к заметке участником | Member | POST `/api/v1/projects/{id}/notes/{note_id}/comments` | 201, объект ProjectNoteCommentOut | Запланирован |
| TC-NOTE-008 | Удаление чужого комментария к заметке запрещено даже admin | Comment чужого автора | DELETE comment под admin | `ForbiddenError("только свой комментарий")` (по аналогии с CommentService) | Запланирован |

### 2.5 Активы: хосты, порты, сервисы, endpoints (TC-ASSET-NNN)

Связано с: `app/routers/assets.py`, `app/services.AssetService`, `app/schemas.{HostCreate,PortCreate,EndpointCreate}`.

| ID | Название | Предусловия | Шаги | Ожидаемый результат | Статус |
|---|---|---|---|---|---|
| TC-ASSET-001 | Endpoint path с UUID нормализуется в `{UUID}` | — | `AssetService._normalize_endpoint_path(...)` (`tests/test_asset_service.py`) | `/api/v1/users/{UUID}/orders` | Реализован |
| TC-ASSET-002 | Парсинг raw HTTP request (UUID-нормализация) | — | `_apply_raw_request_payload({"request_raw": "GET /api/v1/users/<uuid>?page=1 ..."})` | `path="/api/v1/users/{UUID}"`, `query_params=[{name=page, value=1, ...}]` | Реализован |
| TC-ASSET-003 | Endpoint create: дубль по нормализованному UUID-пути не создаёт новый | Существует endpoint | `create_endpoint(...)` с тем же путём (raw uuid) | Возвращается existing endpoint, `db.add` не вызывается | Реализован |
| TC-ASSET-004 | apply_raw_request_payload: пустой `request_raw` отбрасывается | — | `_apply_raw_request_payload({"request_raw": None, ...})` | Без ключа `request_raw` | Реализован |
| TC-ASSET-005 | apply_raw_request_payload: парсинг POST с body и Content-Type | — | `_apply_raw_request_payload(POST .../api/v1/users?role=admin)` | `method=POST`, `path=/api/v1/users`, `request_content_type=application/json`, `request_body={"name":"alice"}`, `query_params=[{name=role, value=admin}]` | Реализован |
| TC-ASSET-006 | Несколько IP: дедупликация и пометка primary | Список с дублями | `_normalize_host_ip_entries("10.0.0.2", [{ip=10.0.0.1, primary=True}, {ip=10.0.0.2, primary=False}, {ip=10.0.0.1, primary=False}])` | Возвращается 2 entry; primary=True у `10.0.0.2` (значение из главного аргумента) | Реализован |
| TC-ASSET-007 | HostCreate требует ip_or_hostname | — | `HostCreate(notes="...")` (`tests/test_schemas.py`) | `pydantic.ValidationError` | Реализован |
| TC-ASSET-008 | HostCreate принимает только hostname | — | `HostCreate(hostname="target.example.com")` | OK, `ip_address=None` | Реализован |
| TC-ASSET-009 | PortCreate: граничные значения 1 и 65535 принимаются | — | Параметризованный тест (`tests/test_schemas.py`) | OK | Реализован |
| TC-ASSET-010 | PortCreate: 0 и 65536 отклоняются | — | Параметризованный тест | `pydantic.ValidationError` | Реализован |
| TC-ASSET-011 | EndpointCreate требует path | — | `EndpointCreate(method="GET")` | `pydantic.ValidationError` | Реализован |
| TC-ASSET-012 | Создание хоста с несколькими IP через REST | Member | POST `/api/v1/projects/{id}/hosts` `{ip_address, ip_addresses=[...]}` | 201, primary IP корректно выставлен | Запланирован |
| TC-ASSET-013 | Дубль порта (host, port_number, protocol) запрещён | Port уже существует | POST повторно с теми же данными | `ValidationError`/409 | Запланирован |
| TC-ASSET-014 | Создание сервиса под существующим портом | Port существует | POST `/api/v1/projects/{id}/hosts/{h}/ports/{p}/services` | 201 | Запланирован |
| TC-ASSET-015 | Удаление хоста каскадно удаляет порты/endpoints | Host со всеми связями | DELETE `/api/v1/projects/{id}/hosts/{h}` | 204; список ports пуст | Запланирован |
| TC-ASSET-016 | Sanitization headers: Authorization заменяется placeholder | Endpoint с raw request, содержащим `Authorization: Bearer xxx` | POST с `request_raw` | В сохранённом endpoint header Authorization имеет placeholder, шумные заголовки (Cookie, X-Forwarded-For) отброшены | Запланирован |

### 2.6 Уязвимости (TC-VULN-NNN)

Связано с: `app/routers/vulnerabilities.py`, `app/services.VulnerabilityService`, `app/schemas.{VulnerabilityCreate,VulnerabilityStatusPatch,VulnerabilityWorkflowStep}`.

| ID | Название | Предусловия | Шаги | Ожидаемый результат | Статус |
|---|---|---|---|---|---|
| TC-VULN-001 | normalize_workflow_steps отбрасывает пустые шаги | — | `_normalize_workflow_steps([{description="  "}, {description="...", image_file_ids=["f1"]}])` (`tests/test_vulnerability_workflow.py`) | Возвращается только второй шаг | Реализован |
| TC-VULN-002 | normalize_workflow_steps оставляет endpoint-only шаги | — | Шаг без description, но с `endpoint_request_raw` | Шаг сохранён с `description=None` | Реализован |
| TC-VULN-003 | workflow_steps_to_text рендерит нумерованные блоки | — | `_workflow_steps_to_text([2 шага])` | Строка с `1. Этап 1\n...` и счётчиком изображений | Реализован |
| TC-VULN-004 | CVSS 4.0 score с префиксом vector | — | `_calculate_cvss_score("4.0", "AV:N/AC:L/...")` | `normalized_vector` начинается с `CVSS:4.0/`, `score≈9.3` | Реализован |
| TC-VULN-005 | CVSS: enum CvssVersion.V40 принимается | — | `_calculate_cvss_score(CvssVersion.V40, "CVSS:4.0/...")` | `score≈9.3` | Реализован |
| TC-VULN-006 | CVSS: score без vector отклоняется | — | `_apply_calculated_cvss_fields({"cvss_score": 9.9, "cvss_vector": None, ...})` | `ValidationError("CVSS score рассчитывается автоматически")` | Реализован |
| TC-VULN-007 | CVSS: очистка vector обнуляет score и version | — | `_apply_calculated_cvss_fields({"cvss_vector": ""}, current_version="4.0", ...)` | `cvss_version=None`, `cvss_vector=None`, `cvss_score=None` | Реализован |
| TC-VULN-008 | Severity from CVSS score (диапазоны) | — | `_severity_from_cvss_score(9.3/7.2/5.5/1.8/0.0)` | CRITICAL/HIGH/MEDIUM/LOW/INFO | Реализован |
| TC-VULN-009 | hydrate_workflow_steps: legacy `steps_to_reproduce` → один шаг | `workflow_steps=None`, `steps_to_reproduce="..."` | `_hydrate_workflow_steps(vuln)` | `len(workflow_steps)==1` с описанием | Реализован |
| TC-VULN-010 | hydrate_workflow_steps не помечает SQLAlchemy-модель грязной | Vulnerability ORM | `_hydrate_workflow_steps(vuln)` | `sa_inspect(vuln).attrs.workflow_steps.history.has_changes() is False` | Реализован |
| TC-VULN-011 | list_for_host не использует DISTINCT по JSON-полям | Host существует | `VulnerabilityService.list_for_host(...)` | SQL count и items не содержит `DISTINCT` | Реализован |
| TC-VULN-012 | validate_workflow_step_images: чужие file_id отклоняются | Workflow step c file_id, не относящимся к vuln | `_validate_workflow_step_images(vuln_id, [step])` | `ValidationError("workflow_steps.image_file_ids")` | Реализован |
| TC-VULN-013 | VulnerabilityCreate: severity обязателен | — | `VulnerabilityCreate(title="No severity")` (`tests/test_additional_validations.py`) | `pydantic.ValidationError` | Реализован |
| TC-VULN-014 | VulnerabilityCreate: severity="extreme" отклоняется | — | `VulnerabilityCreate(severity="extreme")` | `pydantic.ValidationError` | Реализован |
| TC-VULN-015 | VulnerabilityCreate: cvss_score>10 отклоняется | — | `VulnerabilityCreate(cvss_score=10.1)` (`tests/test_schemas.py`) | `pydantic.ValidationError` | Реализован |
| TC-VULN-016 | VulnerabilityCreate: cvss_version="3.1" отклоняется (поддержка убрана) | — | `VulnerabilityCreate(cvss_version="3.1")` | `pydantic.ValidationError` | Реализован |
| TC-VULN-017 | VulnerabilityStatusPatch: status="closed" отклоняется (нет в enum) | — | `VulnerabilityStatusPatch(status="closed")` | `pydantic.ValidationError` | Реализован |
| TC-VULN-018 | VulnerabilityCreate принимает структурированные workflow_steps | host_id присутствует | `VulnerabilityCreate(host_id=..., workflow_steps=[VulnerabilityWorkflowStep(...)])` | `len(workflow_steps)==1` | Реализован |
| TC-VULN-019 | CRUD уязвимости через REST | Member, host существует | POST/GET/PUT/PATCH status/DELETE | Все успешные ответы | Запланирован |
| TC-VULN-020 | Привязка assets к уязвимости (POST/DELETE) | Vuln без assets | POST `/api/v1/projects/{id}/vulnerabilities/{vid}/assets` `{asset_type=host, asset_id}` | 201; повторный DELETE последнего host оставляет 204 (см. бизнес-правило) | Запланирован |
| TC-VULN-021 | Уязвимость без хоста запрещена | Создание | POST без `host_id` и без assets | `ValidationError` | Запланирован |
| TC-VULN-022 | Workflow step c image_file_id из чужой уязвимости отклоняется при PUT | Файл из другой vuln | PUT vulnerability с workflow_step image_file_ids=[чужой] | 400 ValidationError | Запланирован |

### 2.7 Файлы (TC-FILE-NNN)

Связано с: `app/routers/files.py`, `app/services.FileService`, константы `MAX_FILE_SIZE=50MB`, `ALLOWED_MIME_TYPES`.

| ID | Название | Предусловия | Шаги | Ожидаемый результат | Статус |
|---|---|---|---|---|---|
| TC-FILE-001 | Загрузка файла > 50 МБ отклоняется | Авторизован | POST `/api/v1/projects/{id}/vulnerabilities/{vid}/files` (51 МБ) | `ValidationError("Размер файла превышает 50 МБ")` | Запланирован |
| TC-FILE-002 | MIME вне whitelist отклоняется (через python-magic) | Файл с `.txt` но содержимое executable | POST upload | `ValidationError("Неподдерживаемый тип файла")` | Запланирован |
| TC-FILE-003 | Sanitization filename — path traversal убирается | Файл с именем `../../etc/passwd` | POST upload | `original_name` после `_sanitize_filename` без `../` и control chars | Запланирован |
| TC-FILE-004 | ACL download: чужому пентестеру 403 | Vuln в чужом проекте | GET `/api/v1/files/{file_id}/download` | `ForbiddenError("Нет доступа к файлу")` | Запланирован |
| TC-FILE-005 | Admin может скачать любой файл | Admin | GET `/api/v1/files/{file_id}/download` | 200, content | Запланирован |
| TC-FILE-006 | Inline disposition для image/* | Файл image/png | GET download | `Content-Disposition: inline; filename=...` | Запланирован |
| TC-FILE-007 | Удаление файла удаляет blob в MinIO | File загружен | DELETE `/api/v1/projects/{id}/vulnerabilities/{vid}/files/{file_id}` | 204; вызван `storage.delete(minio_key)` | Запланирован |

### 2.8 Комментарии и упоминания (TC-COMM-NNN)

Связано с: `app/services.CommentService`, `app/routers/comments.py`.

| ID | Название | Предусловия | Шаги | Ожидаемый результат | Статус |
|---|---|---|---|---|---|
| TC-COMM-001 | Admin не может редактировать чужой комментарий | Comment чужого автора | `CommentService.update(project_id, vuln_id, comment_id, content, admin)` (`tests/test_comment_service.py`) | `ForbiddenError("только свой комментарий")` | Реализован |
| TC-COMM-002 | Admin не может удалить чужой комментарий | Comment чужого автора | `CommentService.delete(...)` | `ForbiddenError("только свой комментарий")` | Реализован |
| TC-COMM-003 | @mentions при update создают только запись CommentMention, без Notification | Author редактирует, упоминая `@target` | `CommentService.update(..., "updated @target", actor)` | В `db.add` есть `CommentMention`, но нет `Notification`; `ws_manager.notify_user` не вызван; `ws_manager.broadcast` вызван 1 раз | Реализован |
| TC-COMM-004 | @mentions при create создают Notification | Comment создаётся с `@target` | POST `/api/v1/projects/{id}/vulnerabilities/{vid}/comments` `{content="@target test"}` | 201; в БД появляется `Notification`; `ws_manager.notify_user(target.id, ...)` вызван | Запланирован |
| TC-COMM-005 | Комментирование по чужой уязвимости — 403 | Pentester не member | POST comment | 403 | Запланирован |

### 2.9 Уведомления (TC-NOTIF-NNN)

Связано с: `app/routers/notifications.py`.

| ID | Название | Предусловия | Шаги | Ожидаемый результат | Статус |
|---|---|---|---|---|---|
| TC-NOTIF-001 | Список уведомлений с фильтром is_read | Есть прочитанные и непрочитанные | GET `/api/v1/notifications?is_read=false` | Только непрочитанные | Запланирован |
| TC-NOTIF-002 | Unread count | — | GET `/api/v1/notifications/unread-count` | `{count: N}` | Запланирован |
| TC-NOTIF-003 | Mark single as read | Есть unread | PATCH `/api/v1/notifications/{id}/read` | 200, `is_read=True` | Запланирован |
| TC-NOTIF-004 | Mark all as read | Есть несколько unread | PATCH `/api/v1/notifications/read-all` | 204; unread-count==0 | Запланирован |
| TC-NOTIF-005 | WS push при @mention | WS-подключение к проекту | Создать комментарий с `@target` | `target` получает WS-сообщение `{event:"notification", ...}` | Запланирован |

### 2.10 Импорт PCF/OpenAPI (TC-IMP-NNN)

Связано с: `app/services.ImportService`, `app/routers/import_.py`.

| ID | Название | Предусловия | Шаги | Ожидаемый результат | Статус |
|---|---|---|---|---|---|
| TC-IMP-001 | _find_matching_host: точный матч по ip+hostname | Host (10.0.0.5, api.local) | `ImportService._find_matching_host(project_id, host_data)` (`tests/test_import_service.py`) | Возвращается тот же host | Реализован |
| TC-IMP-002 | _merge_host_fields заполняет только недостающие поля | Host с пустыми ip/notes | `_merge_host_fields(host, host_data)` | ip_address и notes заполнены, hostname сохранён | Реализован |
| TC-IMP-003 | _merge_endpoint_fields заполняет недостающие данные | Endpoint без description | `_merge_endpoint_fields(...)` | description, query_params, body заполнены | Реализован |
| TC-IMP-004 | _load_json_or_yaml_document поддерживает YAML | YAML с openapi 3.0.0 | `_load_json_or_yaml_document(...)` | `parsed["openapi"]=="3.0.0"` | Реализован |
| TC-IMP-005 | _load_json_or_yaml_document поддерживает «relaxed» Swagger 2.0 | Текст без кавычек | `_load_json_or_yaml_document(...)` | `parsed["swagger"]=="2.0"`, basePath с ведущим слешем | Реализован |
| TC-IMP-006 | Validate OpenAPI: пустой payload отклоняется | — | `_validate_openapi_payload(b"")` | `ValidationError("пуст")` | Реализован |
| TC-IMP-007 | Validate OpenAPI: > 2 МБ отклоняется | — | `_validate_openapi_payload(b"a" * (2*1024*1024+1))` | `ValidationError("2 МБ")` | Реализован |
| TC-IMP-008 | Resolve openapi $ref (локальные ссылки) | Document с $ref в paths/components | `_resolve_openapi_ref(...)` | Распознаёт path item и operation | Реализован |
| TC-IMP-009 | import_openapi: дубликат endpoint пропускается с warning | Существует endpoint /users GET | `import_openapi(...)` | `endpoints_created=0`, `endpoints_skipped=1`, `result.errors` непуст, host description обновлён | Реализован |
| TC-IMP-010 | import_openapi принимает relaxed Swagger 2.0 | Swagger без кавычек | `import_openapi(...)` | `endpoints_created=1`, путь `/v1/users/{userId}` | Реализован |
| TC-IMP-011 | Swagger 2.0 body с $ref/definitions парсится | Pet schema | `_extract_openapi_request_details(...)` | `content_type=application/json`, body содержит `doggie` и `available` | Реализован |
| TC-IMP-012 | Swagger 2.0 form data → urlencoded body | parameters in formData | `_extract_openapi_request_details(...)` | `body=name=rex&status=available` | Реализован |
| TC-IMP-013 | Deprecated operations пропускаются | OpenAPI с `deprecated: true` | `import_openapi(...)` | `created=1`, в `errors` упоминание deprecated | Реализован |
| TC-IMP-014 | Export OpenAPI собирает документ из endpoints | Host с endpoint /pet/{petId} | `export_openapi(project_id, host_id)` | `openapi=3.0.0`, parameters содержат query+header, в т.ч. example | Реализован |
| TC-IMP-015 | Query params: enum/default подставляется как value | Param с `enum=[available,...]` | `_extract_openapi_query_params(...)` | `value="available"`, для `default=10` → `value="10"` | Реализован |
| TC-IMP-016 | PCF JSON: host без ip и hostname отклоняется | — | `PcfImportPayload.model_validate({"hosts":[{"status":"unknown"}]})` (`tests/test_schemas.py`) | `pydantic.ValidationError` | Реализован |
| TC-IMP-017 | PCF JSON: некорректный protocol порта отклоняется | — | Port с `protocol="icmp"` | `pydantic.ValidationError` | Реализован |
| TC-IMP-018 | PCF JSON: endpoint без path и без request_raw отклоняется | — | Endpoint с `method=GET` без path | `pydantic.ValidationError` | Реализован |

### 2.11 Отчёты Word (TC-REPORT-NNN)

Связано с: `app/services.ReportService`, `app/reports.{build_pp, build_szi}`, `app/routers/reports.py`.

| ID | Название | Предусловия | Шаги | Ожидаемый результат | Статус |
|---|---|---|---|---|---|
| TC-REPORT-001 | normalize_report_image_bytes ре-кодирует валидный PNG | Pillow PNG 8x8 | `ReportService._normalize_report_image_bytes(payload)` (`tests/test_report_service.py`) | Возвращён ненулевой буфер; через PIL читается с size=(8,8) | Реализован |
| TC-REPORT-002 | normalize_report_image_bytes пропускает невалидный buffer | b"not-an-image" | `_normalize_report_image_bytes(...)` | `None` | Реализован |
| TC-REPORT-003 | build_szi возвращает непустой DOCX | demo project, host, vuln HIGH+INFO | `build_szi(data, indexes, image_bytes_by_id={})` (`tests/test_word_builder.py`) | Контент начинается с `PK`, текст содержит имя проекта, заголовок vuln, hostname/IP | Реализован |
| TC-REPORT-004 | build_pp возвращает непустой DOCX | то же payload | `build_pp(...)` | то же | Реализован |
| TC-REPORT-005 | СЗИ разделяет «Уязвимости» и «Слабости» по severity | vuln HIGH + INFO | `build_szi` → `Document(...)`, парсинг Heading 2 | HIGH в секции «выявленным уязвимостям», INFO в секции «выявленным слабостям» | Реализован |
| TC-REPORT-006 | POST /reports/szi возвращает Word-стрим с корректным Content-Disposition | Member | POST `/api/v1/projects/{id}/reports/szi` | 200, `media_type=application/vnd.openxmlformats-officedocument.wordprocessingml.document`, `Content-Disposition` с ASCII filename и `filename*=UTF-8''<encoded>` | Запланирован |
| TC-REPORT-007 | POST /reports/pp аналогично | Member | POST `/reports/pp` | 200, корректный stream | Запланирован |
| TC-REPORT-008 | Reports без membership → 403 | Pentester не member | POST `/reports/szi` | 403 | Запланирован |

### 2.12 Jira Integration (TC-JIRA-NNN)

Связано с: `app/services.JiraIntegrationService`, `app/routers/jira.py`.

| ID | Название | Предусловия | Шаги | Ожидаемый результат | Статус |
|---|---|---|---|---|---|
| TC-JIRA-001 | api_token шифруется (Fernet) | — | `JiraIntegrationService._encrypt_secret("jira-secret")`, затем `_decrypt_secret(...)` (`tests/test_asset_service.py`) | encrypted != "jira-secret"; round-trip даёт исходное значение | Реализован |
| TC-JIRA-002 | SSRF: пустой base_url отклоняется | — | `_validate_external_url("")` | `ValidationError("не может быть пустым")` | Запланирован |
| TC-JIRA-003 | SSRF: схема не http/https отклоняется | — | `_validate_external_url("ftp://jira.local")` | `ValidationError("https:// или http://")` | Запланирован |
| TC-JIRA-004 | SSRF: http в production запрещён | `settings.debug=False` | `_validate_external_url("http://jira.example.com")` | `ValidationError("в production должен использовать https")` | Запланирован |
| TC-JIRA-005 | SSRF: localhost запрещён | — | `_validate_external_url("https://localhost/jira")` | `ValidationError("запрещённый хост")` | Запланирован |
| TC-JIRA-006 | SSRF: cloud metadata host запрещён | — | `_validate_external_url("https://metadata.google.internal/")` | `ValidationError("запрещённый хост")` | Запланирован |
| TC-JIRA-007 | SSRF: private/loopback/link-local/reserved/multicast IP запрещены | DNS резолв в `10.0.0.1` | `_validate_external_url("https://internal.invalid/")` (мокнуть `socket.getaddrinfo`) | `ValidationError("внутренний/приватный IP")` | Запланирован |
| TC-JIRA-008 | SSRF: некорректный host (gaierror) отклоняется | DNS error | `_validate_external_url("https://no-such-host.invalid")` | `ValidationError("Не удалось разрешить host Jira")` | Запланирован |
| TC-JIRA-009 | First config без api_token отклоняется | Нет JiraInstance | `upsert_config({base_url, name, email})` без `api_token` | `ValidationError("Для первой настройки Jira нужен api_token")` | Запланирован |
| TC-JIRA-010 | get_jira_config доступен только admin | Pentester | GET `/api/v1/jira/config` | 403 | Запланирован |
| TC-JIRA-011 | Export vulnerability to Jira | Member, link настроен | POST `/api/v1/projects/{id}/vulnerabilities/{vid}/jira/export` | 200, `JiraIssueLinkOut` с `issue_key` | Запланирован |
| TC-JIRA-012 | Project Jira link upsert (admin) | Admin | PUT `/api/v1/projects/{id}/jira-link` `{jira_project_key="ABC"}` | 200 | Запланирован |

### 2.13 Agent API v2 (TC-AGENT-NNN)

Связано с: `app/routers/v2_agent.py`, `app/routers/agent_tokens.py`, `app/services.AgentTokenService`, `app/dependencies.{require_agent_scope,require_agent_project_access}`.

| ID | Название | Предусловия | Шаги | Ожидаемый результат | Статус |
|---|---|---|---|---|---|
| TC-AGENT-001 | Создание agent token (admin only) | Admin | POST `/api/v1/agent-tokens` `{name, scopes, all_projects}` | 201, в ответе одноразовый `token` (raw) | Запланирован |
| TC-AGENT-002 | List agent tokens не возвращает raw token | Tokens существуют | GET `/api/v1/agent-tokens` | Поля без `token`/`token_hash` | Запланирован |
| TC-AGENT-003 | Revoke agent token | Token существует | DELETE `/api/v1/agent-tokens/{id}` | 204; `revoked_at` выставлен | Запланирован |
| TC-AGENT-004 | Bearer auth: отсутствие заголовка → 401 | — | GET `/api/v2/projects` без `Authorization` | 401 | Запланирован |
| TC-AGENT-005 | Bearer auth: revoked token → 401 | Token revoked | GET `/api/v2/projects` с этим токеном | 401 | Запланирован |
| TC-AGENT-006 | Scope check: scope `assets:read` нужен для GET hosts | Token со scope `projects:read` | GET `/api/v2/projects/{id}/hosts` | 403 | Запланирован |
| TC-AGENT-007 | Project grant: token с `all_projects=False` ограничен явным списком | Token grant на project A | GET `/api/v2/projects/{B}/hosts` | 403 | Запланирован |
| TC-AGENT-008 | Project grant: `all_projects=True` пропускает все | Token | GET `/api/v2/projects` | список всех проектов | Запланирован |
| TC-AGENT-009 | Создание заметки требует `notes:write` | Token со scope `notes:read` | POST `/api/v2/projects/{id}/notes` | 403 | Запланирован |
| TC-AGENT-010 | Создание уязвимости через v2 (`vulns:write`) | Token со scope | POST `/api/v2/projects/{id}/vulnerabilities` `{title, severity, host_id}` | 201, `VulnerabilityOut` | Запланирован |

### 2.14 Audit logs (TC-AUDIT-NNN)

Связано с: `app/services.AuditService`, `app/routers/audit_logs.py` (хранилище — PostgreSQL).

| ID | Название | Предусловия | Шаги | Ожидаемый результат | Статус |
|---|---|---|---|---|---|
| TC-AUDIT-001 | log() пишет AuditLog в БД | — | `AuditService.log("CREATE", user_id, entity_type=...)` | `db.add(AuditLog)` + `db.commit()` выполнены, запись доступна для чтения | Запланирован |
| TC-AUDIT-003 | GET /audit-logs только для admin | Pentester | GET `/api/v1/audit-logs` | 403 | Запланирован |
| TC-AUDIT-004 | Фильтрация audit logs по entity_type | Логи разных типов | GET `/audit-logs?entity_type=project` | Только records с `entity_type=project` | Запланирован |
| TC-AUDIT-005 | Поиск по `query` затрагивает username и details | Логи с разными username/details | GET `/audit-logs?query=foo` | Возвращены записи, где `foo` встречается в action / entity_type / ip / username / cast(details::text) | Запланирован |

### 2.15 Pagination (TC-PAG-NNN)

Связано с: `app/pagination.py`.

| ID | Название | Предусловия | Шаги | Ожидаемый результат | Статус |
|---|---|---|---|---|---|
| TC-PAG-001 | offset = (page-1)*size | — | `PageParams(page=2, size=20).offset` (`tests/test_pagination.py`) | `20` | Реализован |
| TC-PAG-002 | to_paginated_response для частичной последней страницы | items=5, total=25, size=20 | `to_paginated_response(...)` | `pages=2`, `page=2`, items сохранены | Реализован |
| TC-PAG-003 | Пустой набор → 1 page | items=[], total=0 | `to_paginated_response(...)` | `pages=1` | Реализован |
| TC-PAG-004 | Отрицательная page отклоняется | — | `PageParams(page=-1, size=20)` (`tests/test_additional_validations.py`) | `pydantic.ValidationError` | Реализован |
| TC-PAG-005 | size=0 отклоняется | — | `PageParams(page=1, size=0)` | `pydantic.ValidationError` | Реализован |
| TC-PAG-006 | size слишком большой (10000) отклоняется | — | `PageParams(page=1, size=10000)` | `pydantic.ValidationError` | Реализован |

### 2.16 WebSocket (TC-WS-NNN)

Связано с: `app/routers/websocket.py`, `ws_manager`.

| ID | Название | Предусловия | Шаги | Ожидаемый результат | Статус |
|---|---|---|---|---|---|
| TC-WS-001 | Подключение требует валидный access cookie | Гость | WS connect to `/ws/projects/{id}` без cookie | `close(1008)` | Запланирован |
| TC-WS-002 | Pentester без membership получает close 1008 | — | WS connect | close 1008 | Запланирован |
| TC-WS-003 | Broadcast при создании уязвимости | Member, активный WS | POST vulnerability | На WS приходит `{event:"created", entity:"vulnerability", ...}` | Запланирован |
| TC-WS-004 | Notify_user при @mention | 2 пользователя в проекте | Создать comment с `@user2` | user2 получает private WS-сообщение | Запланирован |

---

### 2.17 Frontend (TC-UI-NNN)

Связано с: `frontend/src/App.tsx`, `frontend/src/pages/{LoginPage, ForceChangePasswordPage}.tsx`, `frontend/src/components/ProjectTreeNav.tsx`, `frontend/src/markdownUrlTransform.ts`.

| ID | Название | Предусловия | Шаги | Ожидаемый результат | Статус |
|---|---|---|---|---|---|
| TC-UI-001 | App: показывает прогресс-бар, пока auth не инициализирован | `isInitialized=false` | `renderWithProviders(<App themeMode="dark"/>, "/login")` (`src/App.test.tsx`) | `screen.getByRole("progressbar")`; `initialize()` вызван | Реализован |
| TC-UI-002 | App: рендерит LoginPage для анонимного пользователя | `user=null` | renderWithProviders в `/login` | Видно «Login page» | Реализован |
| TC-UI-003 | App: не запрашивает unread notifications для анонимного | `user=null` | render | `unreadCount` не вызван | Реализован |
| TC-UI-005 | App: non-admin не видит admin-роут (/users) | role=pentester | render `/users` | Редирект на «Projects page» | Реализован |
| TC-UI-006 | LoginPage стартует с пустыми credentials | — | render LoginPage (`src/pages/LoginPage.test.tsx`) | username и password пустые | Реализован |
| TC-UI-007 | LoginPage: успешный логин ведёт на `/` | `signIn` resolves | заполнить, кликнуть «Войти» | `signIn("admin","admin")`, `navigate("/")` | Реализован |
| TC-UI-009 | LoginPage: при ошибке navigate не вызывается | `signIn` rejects | submit | `navigate` не вызван | Реализован |
| TC-UI-010 | ForceChangePasswordPage: кнопка disabled пока пароли не совпадают | — | type "Password123" + "Mismatch123" → match (`src/pages/ForceChangePasswordPage.test.tsx`) | enabled только при совпадении | Реализован |
| TC-UI-011 | ForceChangePasswordPage: submit вызывает API, setUser, navigate("/") replace | — | заполнить, click «Сохранить пароль» | `forceChangePassword("Password123")`, `setUser`, `navigate("/", {replace:true})` | Реализован |
| TC-UI-012 | ProjectTreeNav: клик «Порты (4)» внутри хоста переключает host+section | host-b с `portsCount=4` | click `Порты (4)` (`src/components/ProjectTreeNav.test.tsx`) | `onSelectHost("host-b")`, `onSelectSection("ports")`, `onOpenHost("host-b","ports")` | Реализован |
| TC-UI-013 | ProjectTreeNav: клик «Заметки» вне хоста меняет section | section="overview" | click «Заметки» | `onSelectSection("notes")` | Реализован |
| TC-UI-014 | markdownUrlTransform: разрешает data:image/png;base64,... | — | `markdownUrlTransform("data:image/png;base64,iVBOR...")` | возвращает исходный URL без изменения | Запланирован |
| TC-UI-015 | markdownUrlTransform: блокирует data:text/html,... | — | `markdownUrlTransform("data:text/html,<script>...")` | URL отбрасывается (defaultUrlTransform поведение) | Запланирован |
| TC-UI-016 | markdownUrlTransform: разрешает http/https | — | `markdownUrlTransform("https://example.com/img.png")` | URL возвращается | Запланирован |
| TC-UI-017 | App: WebSocket переподключение после разрыва | WS active | mock close → wait | повторный `new WebSocket(...)` | Запланирован |
| TC-UI-018 | Защищённые роуты: гость на `/projects` редиректится на `/login` | user=null | render `/projects` | redirect `/login` | Запланирован |
| TC-UI-019 | Профиль: смена email только сам себе | login pentester | open Profile, edit email | API call PATCH `/users/me` с email | Запланирован |
| TC-UI-020 | VulnerabilityStagesEditor: добавление шага и удаление превью этапа | open vulnerability edit | add step, attach image, remove image | image_file_ids уменьшается | Запланирован |
| TC-UI-021 | HostDetailPage: переключение между разделами host (ports/endpoints/vulns) | open host page | click таб | URL обновляется, данные загружаются | Запланирован |

---

## 3. Сводка покрытия

### 3.1 Реализованные тесты по файлам

| Файл | Тестов | Покрываемые ID |
|---|---|---|
| `backend/tests/test_security.py` | 4 | TC-AUTH-001..004 |
| `backend/tests/test_auth_cookies.py` | 2 | TC-AUTH-005, TC-AUTH-006 |
| `backend/tests/test_dependencies.py` | 5 | TC-AUTH-007..011 |
| `backend/tests/test_user_service_security.py` | 3 | TC-AUTH-019, TC-USER-003, TC-USER-004 |
| `backend/tests/test_project_service.py` | 5 | TC-PROJ-001..006 |
| `backend/tests/test_project_note_service.py` | 2 | TC-NOTE-001, TC-NOTE-002 |
| `backend/tests/test_asset_service.py` | 7 | TC-ASSET-001..006, TC-JIRA-001 |
| `backend/tests/test_vulnerability_workflow.py` | 12 | TC-VULN-001..012 |
| `backend/tests/test_comment_service.py` | 3 | TC-COMM-001..003 |
| `backend/tests/test_import_service.py` | 13 | TC-IMP-001..015 (часть) |
| `backend/tests/test_report_service.py` | 2 | TC-REPORT-001, TC-REPORT-002 |
| `backend/tests/test_word_builder.py` | 3 | TC-REPORT-003..005 (build_szi+build_pp параметризован, разделение severity) |
| `backend/tests/test_schemas.py` | 12 | TC-USER-001, TC-ASSET-007..011, TC-VULN-015..018, TC-IMP-016..018 |
| `backend/tests/test_additional_validations.py` | 8 | TC-AUTH-012, TC-AUTH-021, TC-USER-002, TC-VULN-013, TC-VULN-014, TC-PROJ-007, TC-PROJ-008, TC-PAG-004..006 |
| `backend/tests/test_pagination.py` | 3 | TC-PAG-001..003 |
| `frontend/src/App.test.tsx` | 5 | TC-UI-001..005 |
| `frontend/src/pages/LoginPage.test.tsx` | 4 | TC-UI-006..009 |
| `frontend/src/pages/ForceChangePasswordPage.test.tsx` | 2 | TC-UI-010, TC-UI-011 |
| `frontend/src/components/ProjectTreeNav.test.tsx` | 2 | TC-UI-012, TC-UI-013 |

### 3.2 Команды запуска

Backend:
```bash
cd backend
pytest                                # все тесты
pytest tests/test_vulnerability_workflow.py -v
pytest -k "tc_auth"                   # фильтр по подстроке в имени
```

Frontend:
```bash
cd frontend
npm run test                          # vitest run
npm run test -- --watch               # watch mode
npm run test -- src/App.test.tsx      # один файл
```

### 3.3 Известные пробелы (рекомендации)
- Нет интеграционных тестов через `httpx.AsyncClient` для роутеров — большинство кейсов «Запланирован» в этом документе адресует именно их.
- WebSocket-сценарии (TC-WS-NNN) не покрыты — стоит добавить fixture с `WebSocketTestSession`.
- File upload security (TC-FILE-NNN) полностью отсутствует в автотестах: критично, так как используются `python-magic`, sanitization filename и MinIO ACL.
- SSRF-защита Jira (`_validate_external_url`) покрыта только косвенно через шифрование секрета — рекомендуется параметризованный тест по серии URL (TC-JIRA-002..008).
- Frontend: компоненты редактирования (VulnerabilityStagesEditor, HostDetailPage) и страницы Projects/Profile/AuditLogs не покрыты — добавить компонентные сценарии рендера/взаимодействия.
- markdownUrlTransform: ключевая защита от XSS через `data:text/html` — нужно завести unit-тест в `frontend/src/markdownUrlTransform.test.ts`.

---

## 4. История изменений

| Дата | Изменение |
|---|---|
| 2026-05-13 | Полная переактуализация под текущий состав `backend/tests/` (добавлены модули assets/jira/word_builder/project_notes), reorganизация по новой иерархии `TC-<MODULE>-<NNN>`, добавлен раздел Agent API v2 и Pagination. |
