# ARCH_DIAGRAMS — Подробные диаграммы FROST

> Дополняет [ARCH.md](ARCH.md). Все диаграммы — Mermaid (рендерятся в GitHub / VSCode / Markdown-просмотрщиках с поддержкой Mermaid).
>
> Каждая секция отвечает за один аспект системы: один сценарий — одна диаграмма.

---

## 1. System Context (C4-L1)

Кто и как взаимодействует со FROST.

```mermaid
flowchart LR
    Pentester(["Пентестер<br/>(браузер)"])
    Developer(["Разработчик<br/>(браузер)"])
    Admin(["Администратор<br/>(браузер)"])
    AIAgent(["AI-агент<br/>(внешний процесс)"])

    subgraph FROST["FROST — Findings, Research, Offensive Security & Testing"]
        Frontend["Frontend<br/>React + Vite<br/>:3000"]
        Backend["Backend<br/>Go (cmd/api)<br/>:8000"]
        Worker["mail-worker /<br/>recon-worker<br/>(DB-поллеры)"]
    end

    SMTP[("Корпоративный SMTP<br/>Gmail / corporate")]

    Pentester -->|HTTPS<br/>cookie-auth| Frontend
    Developer -->|HTTPS<br/>cookie-auth| Frontend
    Admin -->|HTTPS<br/>cookie-auth| Frontend
    Frontend -->|REST + WebSocket| Backend
    AIAgent -->|HTTPS<br/>Bearer-token| Backend
    Backend -->|Publish job| Worker
    Worker -->|SMTP| SMTP
```

---

## 2. Container Diagram (C4-L2) — Docker Compose сервисы

Что развёрнуто в docker-compose и как сервисы общаются.

```mermaid
flowchart TB
    subgraph Browser["Браузер"]
        ClientApp["SPA<br/>(React 18, frost UI)"]
    end

    subgraph Compose["docker-compose"]
        direction TB

        subgraph App["Application tier"]
            Frontend["frontend<br/>Vite + nginx TLS<br/>:3000"]
            Backend["backend<br/>Go cmd/api<br/>:8000"]
            MailWorker["mail-worker /<br/>recon-worker<br/>(Go, DB-поллеры)"]
            ReportSidecar["report-sidecar<br/>(Python .docx)"]
        end

        subgraph Infra["Infrastructure tier"]
            Postgres[("db<br/>PostgreSQL 16<br/>:5433→5432")]
            MinIO[("minio<br/>S3-compatible<br/>:9000 + :9001")]
            Rabbit[("rabbitmq<br/>3-management<br/>:5672 + :15672")]
            Mailpit[("mailpit<br/>dev SMTP catcher<br/>:1025 + :8025")]
        end
    end

    ExternalSMTP[("Прод SMTP<br/>(Gmail / corporate)")]

    ClientApp -.->|HTTPS| Frontend
    Frontend -->|proxy /api| Backend
    Frontend -->|proxy /ws| Backend

    Backend -->|pgx/pgxpool| Postgres
    Backend -->|minio-go v7| MinIO
    Backend -.->|amqp091 (опц. fanout)| Rabbit
    Backend -->|HTTP (генерация .docx)| ReportSidecar

    MailWorker -->|poll mail_jobs / farm| Postgres
    MailWorker -->|SMTP/XOAUTH2<br/>dev| Mailpit
    MailWorker -.->|SMTP<br/>prod| ExternalSMTP
```

---

## 3. Backend — гексагональная архитектура

Запрос проходит путь chi-хендлер (адаптер) → use-case (контекст) → порт `Store` → repo (адаптер) → sqlc/pgx. DI — явная сборка в `cmd/api` (composition root), а не DI-контейнер.

```mermaid
flowchart TB
    HTTP["HTTP Request<br/>(/api/v1/...)"]

    subgraph Middleware["Middleware (adapters/http)"]
        CORS["CORS"]
        Auth["requireAuth / requireAdmin<br/>cookie → JWT → User"]
        CSRF["CSRF (Origin check)"]
        Access["requireProjectAccessFor(authz)"]
        AppErr["apperr → HTTP code<br/>{ detail }"]
    end

    subgraph Handlers["HTTP handlers (adapters/http/*_handlers.go)"]
        AuthH["auth"]
        UsersH["users"]
        ProjectsH["projects"]
        InvH["inventory"]
        VulnH["vulns"]
        NotifH["notifications"]
        ReconH["recon"]
        ReportsH["reports"]
        AgentH["agenttokens"]
        AuditH["audit"]
    end

    subgraph UseCases["Use-cases (internal/app/<context>)"]
        AuthUC["auth"]
        UserUC["users"]
        ProjUC["projects"]
        InvUC["inventory"]
        VulnUC["vulns"]
        NotifUC["notifications"]
        ReconUC["recon"]
        RepUC["reports"]
        AgentUC["agenttokens"]
        AuditUC["audit"]
    end

    subgraph Ports["Порты Store + репозитории (postgres/<ctx>repo)"]
        Repo["Store над sqlc + pgxpool<br/>(compound ops в tx)"]
        DB[("PostgreSQL 16")]
    end

    subgraph External["External adapters"]
        MinIOExt[("MinIO<br/>storage")]
        CVSSExt["cvss"]
        ReconExt["recon + netguard"]
        ReportExt["report-sidecar"]
    end

    HTTP --> Middleware --> Handlers
    Handlers --> UseCases
    UseCases --> Repo --> DB
    VulnUC --> CVSSExt
    VulnUC --> MinIOExt
    ReconUC --> ReconExt
    RepUC --> ReportExt
    UseCases -->|apperr| AppErr
    AppErr -->|JSON| HTTP
```

---

## 4. Аутентификация — login, refresh, logout

JWT в HttpOnly Secure cookies, CSRF через SameSite=Strict + проверку Origin. Refresh-токены с ротацией.

```mermaid
sequenceDiagram
    autonumber
    participant U as Пользователь
    participant FE as Frontend (axios)
    participant BE as Backend /auth
    participant DB as PostgreSQL

    Note over U,DB: ── LOGIN ──
    U->>FE: вводит username + password
    FE->>BE: POST /api/v1/auth/login
    BE->>DB: SELECT user, verify bcrypt
    DB-->>BE: User
    BE->>BE: create_access_token (JWT, 30m)
    BE->>BE: create_refresh_token (JWT, 30d)
    BE->>DB: INSERT refresh_tokens<br/>(SHA-256 hash)
    BE-->>FE: Set-Cookie: access_token, refresh_token<br/>200 LoginResponse
    BE->>DB: audit_logs INSERT (action="LOGIN")

    Note over U,DB: ── REFRESH (по таймауту access) ──
    FE->>BE: <запрос с истёкшим access>
    BE-->>FE: 401
    FE->>BE: POST /api/v1/auth/refresh (cookie refresh_token)
    BE->>DB: lookup refresh_token (sha256)
    DB-->>BE: row not revoked
    BE->>BE: новый access + новый refresh (rotation)
    BE->>DB: revoke старый refresh
    BE->>DB: INSERT новый refresh
    BE-->>FE: Set-Cookie новые токены
    FE->>BE: retry изначального запроса

    Note over U,DB: ── LOGOUT ──
    U->>FE: нажимает «Выйти»
    FE->>BE: POST /api/v1/auth/logout
    BE->>DB: UPDATE refresh_tokens<br/>SET revoked_at = now()<br/>WHERE user_id = ?
    BE-->>FE: 204 + Set-Cookie (очистка)
    BE->>DB: audit_logs INSERT (action="LOGOUT")
```

---

## 5. Управление сессией — refresh rotation детальнее

Защита от replay и кражи refresh-токена.

```mermaid
flowchart TB
    Start(["POST /auth/refresh"]) --> ReadCookie["read refresh_token cookie"]
    ReadCookie --> Hash["SHA-256(token) → hash"]
    Hash --> Lookup["SELECT FROM refresh_tokens<br/>WHERE token_hash = ?<br/>AND revoked_at IS NULL<br/>AND expires_at > now()"]
    Lookup -->|нет строки| Deny["401 UnauthorizedError"]
    Lookup -->|строка есть| Revoke["UPDATE revoked_at = now()<br/>(старый токен погашен)"]
    Revoke --> Issue["create_access_token + create_refresh_token<br/>(новая пара)"]
    Issue --> StoreNew["INSERT refresh_tokens<br/>(sha256, expires_at)"]
    StoreNew --> SetCookies["Set-Cookie:<br/>access_token (30m)<br/>refresh_token (30d)"]
    SetCookies --> Ok(["200 RefreshResponse"])
```

---

## 6. CSRF + Origin защита

`SameSite=Strict` блокирует cross-site cookies; дополнительно проверяем заголовок `Origin`.

```mermaid
flowchart LR
    Req["HTTP Request"] --> CookieFlag{"Cookie<br/>SameSite=Strict?"}
    CookieFlag -->|cross-site| BrowserStrip["Браузер не<br/>отправляет cookie"]
    BrowserStrip --> Anon["Request приходит<br/>как anonymous"]
    Anon --> Deny401["401"]

    CookieFlag -->|same-site| EnforceCSRF["CSRF middleware<br/>(adapters/http/csrf.go)"]
    EnforceCSRF --> Origin{"Origin / Referer<br/>в CSRF_ALLOWED_ORIGINS?"}
    Origin -->|нет| Deny403["403 Forbidden<br/>'CSRF Origin запрещён'"]
    Origin -->|да| Pass["далее в роут"]
```

---

## 7. Доступ к проекту — IDOR-проверки

`require_project_access` гарантирует, что pentester видит только свои проекты, admin — все.

```mermaid
flowchart TB
    Endpoint["роут с require_project_access<br/>(GET /projects/{id}/...)"]
    Endpoint --> User["get_current_user → User"]
    User --> Lookup["SELECT projects WHERE id = ?"]
    Lookup -->|нет проекта| NotFound["404 NotFoundError"]
    Lookup -->|проект найден| Role{"User.role?"}
    Role -->|admin| Allow["проект передаётся в роут"]
    Role -->|pentester| Member["SELECT project_members<br/>WHERE project_id=? AND user_id=?"]
    Member -->|строка есть| Allow
    Member -->|нет| Forbid["403 ForbiddenError"]
```

---

## 8. Жизненный цикл уязвимости

Статусы и workflow_steps (этапы воспроизведения).

```mermaid
stateDiagram-v2
    [*] --> open: создаётся pentester'ом

    open --> in_progress: developer берёт в работу
    in_progress --> fixed: developer закрыл,<br/>требует подтверждения
    fixed --> open: повторное обнаружение / recheck
    in_progress --> wont_fix: бизнес-решение
    open --> accepted_risk: явно принятый риск

    note right of open
        severity: critical/high/medium/low/info
        CVSS: v3.1 или v4.0 (auto score)
        workflow_steps: list[step]
          (раньше с title, сейчас без — учтено в goose-схеме)
    end note

    fixed --> [*]
    wont_fix --> [*]
    accepted_risk --> [*]
```

---

## 9. Загрузка evidence-файла в MinIO

Конвейер с валидацией и transaction outbox (метаданные в Postgres → объект в MinIO).

```mermaid
sequenceDiagram
    autonumber
    participant FE as Frontend
    participant R as POST /vulnerabilities/{id}/files
    participant FS as vulns use-case (upload)
    participant Mag as http.DetectContentType
    participant DB as PostgreSQL
    participant M as MinIO

    FE->>R: multipart/form-data (file)
    R->>FS: UploadFile(vuln_id, file, user)
    FS->>FS: read bytes (<=50 MiB)
    FS->>Mag: detect MIME (+WEBP ручной)
    Mag-->>FS: content_type
    FS->>FS: проверка whitelist<br/>(png, jpeg, pdf, txt, ...)
    alt MIME запрещён или size > 50MB
        FS-->>R: apperr (validation)
        R-->>FE: 422
    end
    FS->>FS: minio_key = f"{uuid}-{safe_name}"
    FS->>M: put_object(bucket, key, bytes)
    M-->>FS: ok
    FS->>DB: INSERT files (vuln_id, minio_key,<br/>content_type, size_bytes, uploaded_by)
    DB-->>FS: file row
    FS->>DB: audit_logs INSERT ("FILE_UPLOAD")
    FS-->>R: FileOut
    R-->>FE: 201 FileOut
```

---

## 10. Mail outbox + worker

Outbox-паттерн поверх durable-очереди в БД: роут вставляет `MailJob(status=pending)`, Go-воркер `cmd/mail-worker` поллит таблицу `mail_jobs` (≤5 с), забирает задачу, рендерит письмо и шлёт по SMTP. RabbitMQ не участвует в базовом пути (только опциональный fanout на несколько инстансов).

```mermaid
sequenceDiagram
    autonumber
    participant API as Backend (cmd/api)
    participant DB as PostgreSQL (mail_jobs)
    participant W as mail-worker (DB-поллер)
    participant SMTP as SMTP сервер<br/>(mailpit / Gmail / corporate)

    API->>DB: INSERT MailJob (status="pending")
    DB-->>API: job.id

    loop Poll loop (≤5s) + reclaim
        W->>DB: SELECT MailJob<br/>WHERE status="pending" OR<br/>(status="failed" AND attempts<MAX)
        DB-->>W: job
        W->>DB: UPDATE status="processing", attempts++
        W->>SMTP: send (STARTTLS / SSL / XOAUTH2)
        alt success
            SMTP-->>W: 250 OK
            W->>DB: UPDATE status="sent", sent_at=now()
        else error
            SMTP-->>W: 5xx / network
            alt attempts >= MAIL_MAX_ATTEMPTS
                W->>DB: UPDATE status="failed",<br/>last_error=...
            else
                W->>DB: UPDATE status="pending",<br/>last_error=... (retry)
            end
        end
    end
```

---

## 11. SSRF & DNS-rebind защита — внутренности

Исходящие HTTP-запросы делает только рекон-ферма. Предикат блок-листа
(`internal/adapters/recon/netguard`) — единый список внутренних адресов; кастомный
`DialContext` в recon-probe применяет его повторно прямо перед connect, закрывая окно
DNS-rebinding между резолвом и подключением. Редиректы отключены.

```mermaid
flowchart TB
    Client["http.Client{<br/>Transport с кастомным DialContext}"]
    Client --> Request["client.Do(req)"]
    Request --> TransportCheck["DialContext(host:port)"]
    TransportCheck --> Resolve["resolver.LookupIP(host)"]
    Resolve -->|ошибка| ConnectError["dial error"]
    Resolve --> ForEach["for ip in resolved:"]
    ForEach --> Disallowed{"netguard блокирует?<br/>(loopback / private /<br/>link_local / reserved /<br/>multicast / unspecified /<br/>169.254.169.254)"}
    Disallowed -->|да| ConnectError
    Disallowed -->|нет| Embedded{"встроенный в IPv6 IPv4<br/>(mapped / 6to4 / Teredo)<br/>тоже внутренний?"}
    Embedded -->|да| ConnectError
    Embedded -->|нет| ParentTransport["net.Dialer.DialContext<br/>(реальный socket connect)"]
```

---

## 12. WebSocket — каналы и события

Backend держит три типа каналов через WebSocket-хаб (`internal/adapters/ws`).

```mermaid
flowchart TB
    Browser1["Pentester @ ProjectDetailPage"]
    Browser2["Developer @ ProjectDetailPage"]
    Browser3["Pentester @ ProjectsPage"]
    Browser4["Pentester в notification toast"]

    subgraph WS["WebSocket-хаб (adapters/ws)"]
        ProjectsIdx["/ws/projects-index<br/>{ws_set}"]
        ProjectRoom["/ws/projects/{id}<br/>{project_id → ws_set}"]
        UserChan["/ws/notifications<br/>{user_id → ws_set}"]
    end

    subgraph Services["События use-cases"]
        CreateVuln["vulns.Create"]
        EditHost["inventory.UpdateHost"]
        AddComment["projects/comment Create<br/>(@mention)"]
        CreateProj["projects.Create"]
        AddNote["projects/note Create"]
    end

    Browser1 -->|connect| ProjectRoom
    Browser2 -->|connect| ProjectRoom
    Browser3 -->|connect| ProjectsIdx
    Browser4 -->|connect| UserChan

    CreateVuln -->|broadcast project_id| ProjectRoom
    EditHost -->|broadcast project_id| ProjectRoom
    AddComment -->|broadcast project_id| ProjectRoom
    AddComment -->|notify_user mentions| UserChan
    AddNote -->|broadcast project_id| ProjectRoom
    CreateProj -->|broadcast_projects_index| ProjectsIdx

    ProjectsIdx -->|"event":"created"<br/>"entity":"project"| Browser3
    ProjectRoom -->|"event":"created"<br/>"entity":"vulnerability"| Browser1
    ProjectRoom -->|"event":"updated"<br/>"entity":"host"| Browser2
    UserChan -->|"event":"notification"<br/>"entity":"notification"| Browser4
```

Подписка происходит вместе с handshake, аутентификация — `access_token` из cookie.

---

## 13. AI Agent API `/api/v2` — scoping и проверка доступа

Отдельный роутер (`apiv2`, strict JSON), смонтированный на `/api/v2`. Аутентификация — Bearer-токен, выпущенный администратором.

```mermaid
flowchart TB
    Request["HTTP /api/v2/...<br/>Authorization: Bearer pcf_v2_..."]
    Request --> Hash["hash_agent_token(raw)<br/>= SHA-256"]
    Hash --> Lookup["SELECT agent_api_tokens<br/>WHERE token_hash = ?<br/>AND revoked_at IS NULL<br/>AND (expires_at IS NULL OR expires_at > now())"]
    Lookup -->|нет строки| Deny["401"]
    Lookup -->|строка| ScopeCheck{"требуемый scope ∈ token.scopes?"}
    ScopeCheck -->|нет| Deny403["403"]
    ScopeCheck -->|да| ProjectCheck{"token.all_projects<br/>OR project_id ∈<br/>token's grants?"}
    ProjectCheck -->|нет| Deny403
    ProjectCheck -->|да| Service["вызов сервиса<br/>(от имени token.created_by)"]
    Service --> Audit["audit_logs INSERT<br/>user_id = token.created_by"]
    Service --> UpdateLastUsed["UPDATE last_used_at = now()"]
    Service --> Response["200 / 201"]
```

### Карта scopes → endpoints

```mermaid
flowchart LR
    subgraph Scopes
        SR["projects:read"]
        AR["assets:read"]
        NR["notes:read"]
        NW["notes:write"]
        VR["vulns:read"]
        VW["vulns:write"]
    end

    subgraph V2["/api/v2"]
        ListProjects["GET /projects"]
        ListHosts["GET /projects/{id}/hosts"]
        ListNotes["GET /projects/{id}/notes"]
        WriteNote["POST/PUT /projects/{id}/notes"]
        ListVulns["GET /projects/{id}/vulnerabilities"]
        WriteVuln["POST/PUT /projects/{id}/vulnerabilities"]
    end

    SR --> ListProjects
    AR --> ListHosts
    NR --> ListNotes
    NW --> WriteNote
    VR --> ListVulns
    VW --> WriteVuln
```

---

## 14. Audit log — запись и чтение

Единое хранилище — PostgreSQL. Запись синхронная с основной транзакцией, чтение через фильтры с full-text по action / entity_type / ip / username / cast(details::text).

```mermaid
flowchart TB
    subgraph Write
        ServiceOp["любая use-case операция<br/>(CRUD, LOGIN, FILE_UPLOAD, ...)"]
        ServiceOp --> Commit["commit основной транзакции"]
        Commit --> AuditLog["audit.Log(<br/>action, user_id, entity_type,<br/>entity_id, details, ip_address)"]
        AuditLog --> AuditAdd["INSERT audit_logs (sqlc)"]
        AuditAdd --> AuditCommit["commit"]
    end

    subgraph Read["GET /api/v1/audit-logs (admin)"]
        Query["параметры:<br/>user_id, username, action,<br/>entity_type, entity_id, ip_address,<br/>query, created_from, created_to,<br/>page, size"]
        Query --> Join["SELECT audit_logs LEFT JOIN users<br/>(username по user_id)"]
        Join --> Filters["WHERE conditions:<br/>• не показывать LOGIN with source=refresh<br/>• ILIKE для текстовых полей<br/>• datetime range для created_at"]
        Filters --> FullText{"query?"}
        FullText -->|есть| FTSearch["OR(<br/>action ILIKE,<br/>entity_type ILIKE,<br/>ip ILIKE,<br/>User.username ILIKE,<br/>cast(details::text) ILIKE)"]
        FullText -->|нет| Count
        FTSearch --> Count["COUNT(*) FROM stmt"]
        Count --> Page["ORDER BY created_at DESC<br/>OFFSET (page-1)*size<br/>LIMIT size"]
        Page --> Response["PaginatedResponse[AuditLogOut]"]
    end
```

---

## 15. Word-отчёты — конвейер генерации

ПП = все страницы landscape, СЗИ = portrait. Общая логика в `_build_common`. Сбор данных — Go (use-case `reports` + sqlc + MinIO), сборка самого `.docx` — временный Python-sidecar `report-sidecar`, которому Go передаёт данные по HTTP и отдаёт поток обратно клиенту.

```mermaid
flowchart TB
    Trigger["POST /projects/{id}/reports/{szi|pp}"]
    Trigger --> Service["reports use-case (kind)"]
    Service --> Collect["сбор данных (sqlc)<br/>(project, members, vulnerabilities,<br/>hosts, ports, assets, files)"]
    Collect --> Indexes["индексы<br/>(by_id, by_vuln_id, severity_stats, ...)"]
    Indexes --> Hydrate["hydrate workflow_steps<br/>(совместимость старых записей)"]
    Hydrate --> Images["выгрузка картинок<br/>(MinIO + EXIF normalize)"]
    Images --> ToThread["HTTP → report-sidecar<br/>(Python python-docx)"]

    subgraph Builder["report-sidecar: build_szi / build_pp → _build_common"]
        LoadTpl["load_template(kind)<br/>(.docx из templates/)"]
        Orient{"kind == pp?"}
        Orient -->|да| Landscape["_set_all_sections_landscape<br/>(swap width<->height, ORIENT=LANDSCAPE)"]
        Orient -->|нет| Skip
        Landscape --> Cover["_update_cover_page<br/>_update_cover_date"]
        Skip --> Cover
        Cover --> Intro["_update_project_intro<br/>_update_test_stand_paragraphs<br/>_update_footers_and_headers"]
        Intro --> Summary["_update_severity_summary_table<br/>(critical/high/medium/low/info counts)"]
        Summary --> Split["_split_vulnerabilities<br/>(weakness = severity==info)"]
        Split --> Sections["_build_section × 2<br/>(уязвимости + слабости)<br/>+ детальные карточки"]
        Sections --> Normalize["_force_h3_non_bold<br/>_normalize_heading_sizes<br/>_enable_auto_field_update<br/>_rebuild_toc"]
        Normalize --> Save["doc.save(buffer)"]
    end

    ToThread --> Builder
    Save --> Response["StreamingResponse<br/>(.docx, Content-Disposition)"]
```

---

## 16. Импорт OpenAPI/Swagger по endpoint'ам

Импорт спецификации в каталог endpoint'ов хоста.

```mermaid
sequenceDiagram
    autonumber
    participant FE as Frontend (HostDetailPage)
    participant R as POST /hosts/{id}/import-openapi
    participant IS as inventory use-case (import)
    participant DB as PostgreSQL

    FE->>R: { spec_text, format: "json"|"yaml" }
    R->>IS: ImportOpenAPIForHost(host_id, spec_text, format)
    IS->>IS: validate size <= 2 MiB
    IS->>IS: parse (YAML / JSON → OpenAPI)
    IS->>IS: проверить openapi >= 3.0
    IS->>IS: проверить paths count <= 2000
    loop по каждому path × method
        IS->>IS: build Endpoint<br/>(method, path,<br/>query_params, request_headers,<br/>request_body, content_type)
        IS->>DB: SELECT existing endpoint<br/>(host_id, method, path)
        alt существует
            IS->>DB: UPDATE поля (merge)
        else не существует
            IS->>DB: INSERT
        end
    end
    IS->>DB: commit
    IS-->>R: OpenApiImportResult{created, updated, skipped}
    R-->>FE: 200
```

---

## 17. PCF JSON импорт — атомарный

Полный rollback при любой ошибке. Идемпотентность по идентифицирующим полям.

```mermaid
flowchart TB
    Start["POST /projects/{id}/import"]
    Start --> Parse["PcfImportPayload validate"]
    Parse -->|invalid| Reject["422"]
    Parse --> Begin["BEGIN транзакция"]
    Begin --> Hosts["для каждого host:<br/>upsert by (hostname, primary IP)"]
    Hosts --> Ports["для каждого port:<br/>upsert by (host_id, port, protocol)"]
    Ports --> Services["для каждого service:<br/>upsert by (port_id, name)"]
    Services --> Endpoints["для каждого endpoint:<br/>upsert by (host_id, method, path)"]
    Endpoints --> Commit["COMMIT"]
    Commit --> Ok["ImportResult{counters}"]

    Hosts -.->|ошибка| Rollback
    Ports -.->|ошибка| Rollback
    Services -.->|ошибка| Rollback
    Endpoints -.->|ошибка| Rollback
    Rollback["ROLLBACK + 422"]
```

---

## 18. Frontend — высокоуровневая структура

```mermaid
flowchart TB
    subgraph Stores["zustand stores"]
        Auth["useAuthStore<br/>{user, login, logout}"]
        Toast["useToastStore<br/>{push, drop}"]
    end

    subgraph API["api.ts (axios singleton)"]
        Intercept["request: withCredentials=true<br/>response: on 401 → /auth/refresh → retry"]
        Funcs["функции: login, getProjects,<br/>createVulnerability, ..."]
    end

    subgraph Pages
        Login["LoginPage"]
        Projects["ProjectsPage"]
        ProjectDetail["ProjectDetailPage"]
        HostDetail["HostDetailPage"]
        Audit["AuditLogsPage"]
        Agent["AiAgentIntegrationPage"]
    end

    subgraph Comp["Components"]
        TreeNav["ProjectTreeNav<br/>(folders + dnd)"]
        Stages["VulnerabilityStagesEditor<br/>(workflow_steps)"]
        Notes["NotesTreeInline<br/>(Confluence-like)"]
        MD["MarkdownEditor<br/>(TipTap)"]
    end

    subgraph WS["WebSocket"]
        WSConn["createWebSocketConnection<br/>(автоматический reconnect)"]
    end

    Login -->|POST /auth/login| API
    Auth -.->|hydrate| Login
    Projects --> API
    Projects -.->|подписка| WSConn
    ProjectDetail --> TreeNav
    ProjectDetail --> Stages
    ProjectDetail --> Notes
    Notes --> MD
    ProjectDetail -.->|WS events| WSConn

    Intercept -->|state| Auth
    Pages -->|toast| Toast
```

---

## 19. ER-диаграмма (укорочённая)

Полное описание — в [DB_SCHEMA.md](DB_SCHEMA.md). Здесь укрупнённая карта связей.

```mermaid
erDiagram
    USERS ||--o{ REFRESH_TOKENS : has
    USERS ||--o{ PROJECT_MEMBERS : member_of
    USERS ||--o{ AGENT_API_TOKENS : creates
    USERS ||--o{ MAIL_JOBS : recipient_or_creator
    USERS ||--o{ AUDIT_LOGS : actor

    PROJECTS ||--o{ PROJECT_MEMBERS : has
    PROJECTS ||--o{ HOSTS : contains
    PROJECTS ||--o{ VULNERABILITIES : contains
    PROJECTS ||--o{ PROJECT_NOTES : contains
    PROJECT_FOLDERS ||--o{ PROJECTS : groups

    HOSTS ||--o{ HOST_IP_ADDRESSES : has
    HOSTS ||--o{ PORTS : has
    HOSTS ||--o{ ENDPOINTS : has
    PORTS ||--o{ SERVICES : has

    VULNERABILITIES ||--o{ VULNERABILITY_ASSETS : "linked to assets"
    VULNERABILITIES ||--o{ FILES : evidence
    VULNERABILITIES ||--o{ COMMENTS : has

    COMMENTS ||--o{ COMMENT_MENTIONS : mentions
    COMMENTS ||--o{ NOTIFICATIONS : triggers

    PROJECT_NOTES ||--o{ PROJECT_NOTE_COMMENTS : has

    AGENT_API_TOKENS ||--o{ AGENT_API_TOKEN_PROJECT_GRANTS : restricted_to
```
