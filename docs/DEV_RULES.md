# Правила разработки FROST
## Findings, Research, Offensive Security & Testing

> Этот документ обязателен к прочтению перед началом работы над проектом.  
> Соблюдение правил обязательно для всех участников команды разработки.
>
> Backend переписан на **Go 1.26** (гексагональная архитектура, `backend-go/`). Единственный
> оставшийся Python — временный sidecar генерации Word-отчётов `report-sidecar`.

---

# 1. Git и контроль версий

## 1.1 Ветки

Используется модель **Git Flow**:

```
main          ← только стабильные релизы (merge через PR, запрещён прямой push)
develop       ← основная ветка разработки
feature/*     ← новые функциональности
fix/*         ← исправление багов
refactor/*    ← рефакторинг без изменения функциональности
docs/*        ← только документация
```

**Именование веток:**
```
feature/vulnerability-import
feature/report-pp-landscape
fix/jwt-refresh-token-expiry
refactor/inventory-repo-cleanup
docs/api-endpoints-update
```

Правила:
- Ветка `main` защищена от прямых коммитов
- Каждая задача — отдельная ветка, создаётся от `develop`
- После мёрджа ветка удаляется

## 1.2 Коммиты

**Каждая завершённая фича/исправление = отдельный коммит с понятным описанием.**

Формат сообщения коммита:

```
<тип>(<область>): <краткое описание на русском>

[опциональное развёрнутое описание]

[опциональные ссылки: Closes #123]
```

**Типы коммитов:**

| Тип | Когда использовать |
|---|---|
| `feat` | Новая функциональность |
| `fix` | Исправление бага |
| `refactor` | Рефакторинг (поведение не изменилось) |
| `docs` | Только документация |
| `test` | Добавление/изменение тестов |
| `chore` | Настройка инфраструктуры, зависимости |
| `perf` | Улучшение производительности |
| `security` | Исправление уязвимости |

**Примеры:**

```
feat(vulns): добавить создание и редактирование уязвимости

Реализован полный CRUD для уязвимостей.
Добавлена валидация CVSS-вектора и полиморфная привязка к активам.
Аудит-лог записывается при каждой операции.

Closes #42
```

```
fix(auth): исправить ошибку валидации истёкшего refresh-токена
```

```
feat(recon): добавить DB-поллер рекон-джобов в cmd/recon-worker
```

**Запрещено:**
```
# Плохо — непонятно что сделано
git commit -m "fix"
git commit -m "wip"
git commit -m "changes"
git commit -m "update"
```

## 1.3 Pull Request

Каждое изменение в `develop` вносится через Pull Request:

- Название PR = краткое описание изменений на русском
- В описании PR обязательно указать: **что реализовано**, **как проверить**
- PR требует ревью хотя бы одного другого разработчика перед мёржем
- Нельзя мёрджить PR с незакрытыми замечаниями
- Нельзя мёрджить PR, если упали тесты (`go test ./... -race`, `vitest`)

---

# 2. Комментарии и документация к коду

## 2.1 Язык комментариев

**Все комментарии пишутся на русском языке.**  
Имена переменных, функций, типов — на английском (стандарт индустрии).

```go
// Хорошо
// Проверяем доступ пользователя к проекту перед возвратом данных
func (s *Service) GetProject(ctx context.Context, projectID int32, actor Actor) (Project, error) {
    ...
}

// Плохо
// Check user access to project before returning data
func (s *Service) GetProject(ctx context.Context, projectID int32, actor Actor) (Project, error) {
    ...
}
```

## 2.2 Документация к экспортируемым идентификаторам (doc-комментарии)

**Каждый экспортируемый тип, функция, метод use-case и репозитория обязан иметь
doc-комментарий** (аналог прежних docstring'ов). По конвенции Go комментарий начинается
с имени идентификатора.

Формат для Go:

```go
// CreateVulnerability создаёт новую уязвимость в проекте.
//
// Проверяет, что пользователь является участником проекта. После создания
// записывает событие в audit_log и создаёт строки notifications для участников
// (WebSocket-push отложен — см. TODO(phase2)).
//
// Возвращает apperr.Forbidden, если пользователь не участник проекта,
// и apperr.NotFound, если проект не существует.
func (s *Service) CreateVulnerability(
    ctx context.Context,
    projectID int32,
    in CreateVulnerabilityInput,
    actor Actor,
) (Vulnerability, error) {
    ...
}
```

Формат для TypeScript:

```typescript
/**
 * Загружает список уязвимостей проекта с пагинацией.
 *
 * @param projectId - ID проекта
 * @param params - Параметры фильтрации и пагинации
 * @returns Пагинированный список уязвимостей
 * @throws ApiError при ошибках сети или авторизации
 */
async function getVulnerabilities(
  projectId: number,
  params: VulnerabilityListParams,
): Promise<PaginatedResponse<Vulnerability>> {
  ...
}
```

## 2.3 Правила комментирования

**Комментируй «почему», а не «что»:**

```go
// Хорошо — объясняет причину решения
// MinIO не поддерживает транзакции, поэтому сначала удаляем из БД,
// а затем из хранилища. Если удаление из MinIO упадёт — строка уже удалена
// в рамках tx, поэтому делаем это после commit и логируем ошибку.
if err := r.deleteFileRow(ctx, fileID); err != nil { ... }
if err := s.storage.Delete(ctx, key); err != nil { ... }

// Плохо — просто пересказывает код
// Удаляем файл из репозитория
r.deleteFileRow(ctx, fileID)
// Удаляем файл из MinIO
s.storage.Delete(ctx, key)
```

**Не оставляй мёртвый код — удаляй его:**

```go
// Запрещено — закомментированный код без пояснений
// oldResult, _ := legacyService.Get(ctx, id)
result, err := newService.Get(ctx, id)
```

**TODO и FIXME должны содержать имя автора и описание:**

```go
// TODO(nikita): добавить кэширование результата после внедрения Redis
// FIXME(ivan): временное решение, до рефакторинга импорта (#87)
// TODO(phase2): push уведомления по WebSocket (строки notifications уже создаются)
```

---

# 3. Безопасность кода

## 3.1 Аутентификация и авторизация

- Каждый роут **явно** навешивает требуемую проверку через middleware (`requireAuth`,
  `requireAdmin`, `requireProjectAccessFor`) — не полагаться на «неявную» защиту
- Проверка прав выполняется **на уровне use-case**, а не только в HTTP-слое
- Никогда не возвращать `password_hash` в ответах API — использовать отдельные DTO ответа
- JWT-секрет и все секреты — только из переменных окружения (пакет `config`), никогда в коде

```go
// Хорошо — доступ проверяется явным middleware, хендлер делегирует use-case
r.With(requireProjectAccessFor(authz)).Get("/projects/{projectID}", h.getProject)

func (h *Handler) getProject(w http.ResponseWriter, r *http.Request) {
    project := projectFromContext(r.Context()) // уже проверен middleware
    writeJSON(w, http.StatusOK, toProjectDTO(project))
}

// Запрещено — доступ не проверяется, любой может получить любой проект
r.Get("/projects/{projectID}", func(w http.ResponseWriter, r *http.Request) {
    p, _ := repo.GetProject(r.Context(), pathInt32(r, "projectID"))
    writeJSON(w, http.StatusOK, p)
})
```

## 3.2 Валидация входных данных

- Входные DTO генерируются из OpenAPI-контракта (`oapi-codegen`); дополнительная
  доменная валидация — явными функциями в `internal/app/<ctx>` (например
  `internal/app/auth/validate.go`)
- Максимальные длины строк и диапазоны чисел проверять явно (регэкспы/границы),
  не полагаться только на типы
- Файлы — проверять MIME-тип **по содержимому** (`http.DetectContentType` + ручная
  проверка WEBP `RIFF....WEBP`), а не только по расширению

```go
var (
    usernameRe   = regexp.MustCompile(`^[A-Za-z0-9._-]{3,100}$`)
    errBadUser   = apperr.Validation("Некорректное имя пользователя")
    errBadPass   = apperr.Validation("Пароль должен быть от 8 до 128 символов")
)

// validateCredentials проверяет имя пользователя и длину пароля.
func validateCredentials(username, password string) error {
    if !usernameRe.MatchString(username) {
        return errBadUser
    }
    if n := len(password); n < 8 || n > 128 {
        return errBadPass
    }
    return nil
}
```

## 3.3 Работа с БД — защита от SQL-инъекций

- Использовать **только** sqlc-сгенерированные типизированные запросы поверх pgx
  (параметры всегда биндятся, не интерполируются)
- Никогда не собирать SQL-строку через `fmt.Sprintf`/конкатенацию с пользовательским вводом
- Динамические фильтры — через `sqlc.narg`/условия в самом `.sql`-запросе, а не строкой

```go
// Хорошо — типизированный запрос из db/queries/*.sql, параметр биндится
vulns, err := q.ListVulnerabilitiesByProject(ctx, projectID)

// Хорошо — динамический фильтр описан в .sql через sqlc.narg
logs, err := q.ListAuditLogs(ctx, sqlc.ListAuditLogsParams{
    EntityType: pgtype.Text{String: "project", Valid: true},
})

// ЗАПРЕЩЕНО — SQL-инъекция
sql := fmt.Sprintf("SELECT id FROM vulnerabilities WHERE project_id = %d", projectID)
rows, _ := pool.Query(ctx, sql)
```

## 3.4 Хранение секретов

- Секреты — только в `.env` файлах, добавленных в `.gitignore` (`.env`, `.env.prod`)
- В репозитории хранить только `.env.example` / `.env.prod.example` с пустыми значениями
- Никогда не логировать токены, пароли, ключи API
- Секреты интеграций хранятся Fernet-совместимо зашифрованными (ключ =
  urlsafe_b64(sha256(jwt_secret_key)))

```go
// ЗАПРЕЩЕНО
slog.Info("пользователь авторизован", "token", accessToken)

// Хорошо
slog.Info("пользователь успешно авторизован", "username", user.Username)
```

## 3.5 Защита от распространённых атак

| Угроза | Реализация защиты |
|---|---|
| SQL Injection | Только sqlc-типизированные/параметризованные запросы поверх pgx |
| XSS | Токены в `HttpOnly` cookie — JavaScript не имеет к ним доступа. Whitelist URL в Markdown-рендере (`http/https/mailto` + `data:image/...`) |
| CSRF | Cookie `SameSite=Strict` + проверка заголовка `Origin` на бэкенде (`enforceCSRF`) для мутирующих методов |
| Brute Force | (рекомендовано) rate limiting на nginx/reverse proxy перед `/auth/login` |
| Path Traversal | Никогда не использовать пользовательский ввод в путях файлов; ключ MinIO генерировать на сервере (`{uuid4}-{sanitized_name}`) |
| Mass Assignment | Отдельные DTO для Create/Update — никогда не писать произвольный map из запроса прямо в модель |
| IDOR | `requireProjectAccessFor` проверяет принадлежность ресурса проекту на каждый запрос (403, не 404) |
| Утечка токена | Токен никогда не попадает в тело ответа, URL, логи — только через `Set-Cookie` |
| SSRF (рекон-ферма) | `internal/adapters/recon/netguard`: блок-лист loopback/private/link-local/169.254.169.254 + повторная DNS-валидация перед запросом (DNS-rebind) + `follow_redirects=false` |

**Пример защиты от IDOR (запрос всегда скоупится проектом):**

```go
// GetVulnerability возвращает уязвимость только в рамках конкретного проекта,
// чтобы пользователь не мог получить данные чужого проекта, зная только ID.
func (r *Repo) GetVulnerability(ctx context.Context, projectID, vulnID int32) (Vulnerability, error) {
    row, err := r.q.GetVulnerabilityInProject(ctx, sqlc.GetVulnerabilityInProjectParams{
        ID:        vulnID,
        ProjectID: projectID, // ← обязательная проверка принадлежности
    })
    if errors.Is(err, pgx.ErrNoRows) {
        return Vulnerability{}, apperr.NotFound("Уязвимость не найдена")
    }
    return toVulnerability(row), err
}
```

---

# 4. Масштабируемость и архитектура

## 4.1 Не нарушать слои (гексагональная архитектура)

```
internal/adapters/http   → только HTTP: распарсить запрос, вызвать use-case, отдать ответ
internal/app/<ctx>       → только бизнес-логика (use-cases), зависит от портов
internal/domain/<ctx>    → сущности и порты (интерфейсы), без внешних зависимостей
internal/adapters/postgres/<ctx>repo → только работа с БД (реализация порта Store)
```

```go
// ЗАПРЕЩЕНО в HTTP-слое — бизнес-логика и прямой доступ к БД здесь не место
func (h *Handler) createVulnerability(w http.ResponseWriter, r *http.Request) {
    var dto apiv1.VulnerabilityCreate
    json.NewDecoder(r.Body).Decode(&dto)
    row, _ := h.pool.Exec(r.Context(), "INSERT INTO vulnerabilities ...")
    writeJSON(w, 201, row)
}

// Хорошо — хендлер делегирует use-case
func (h *Handler) createVulnerability(w http.ResponseWriter, r *http.Request) {
    var dto apiv1.VulnerabilityCreate
    if err := decodeJSON(r, &dto); err != nil { writeErr(w, err); return }
    v, err := h.vulns.CreateVulnerability(r.Context(), projectFromContext(r.Context()).ID, fromDTO(dto), actorFrom(r))
    if err != nil { writeErr(w, err); return }
    writeJSON(w, http.StatusCreated, toVulnerabilityDTO(v))
}
```

## 4.2 Не хардкодить константы

Все конфигурационные значения выносить в пакет `config` (чтение из env):

```go
// ЗАПРЕЩЕНО
const maxFileSize = 52428800 // не должно встречаться в коде
const jwtExpire = 30

// Хорошо — config/config.go, значения из env с дефолтами
type Config struct {
    MaxFileSizeBytes       int64         `env:"MAX_FILE_SIZE_BYTES" envDefault:"52428800"` // 50 МБ
    JWTAccessExpire        time.Duration `env:"JWT_ACCESS_EXPIRE" envDefault:"30m"`
    JWTRefreshExpire       time.Duration `env:"JWT_REFRESH_EXPIRE" envDefault:"720h"`
    AllowedMIMETypes       []string      // png/jpeg/gif/webp/plain/pdf/xml/json/zip
}
```

## 4.3 Не дублировать логику (DRY)

Общая логика — в middleware, хелперы или общие пакеты:

```go
// Проверка доступа к проекту — одно middleware, используется везде.
// Admin видит все проекты; pentester — только те, где он участник (иначе 403).
func requireProjectAccessFor(authz Authorizer) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            project, err := authz.ProjectForActor(r.Context(), pathInt32(r, "projectID"), actorFrom(r))
            if err != nil { writeErr(w, err); return }
            next.ServeHTTP(w, r.WithContext(withProject(r.Context(), project)))
        })
    }
}
```

## 4.4 Конкурентность и блокирующие операции

- Внешний I/O (БД, MinIO, сеть) всегда принимает `context.Context` — отмена и таймауты
  пробрасываются сквозь все слои
- Параллельный рекон — через `errgroup` + `golang.org/x/sync/semaphore` (ограничение
  параллелизма), а не неограниченные горутины
- CPU-тяжёлая генерация Word-отчётов вынесена во внешний процесс — Python-sidecar
  `report-sidecar` (Go-API обращается к нему по HTTP), event loop'а нет

```go
// Ограниченный параллелизм рекон-пробов
g, ctx := errgroup.WithContext(ctx)
sem := semaphore.NewWeighted(maxParallel)
for _, target := range targets {
    target := target
    if err := sem.Acquire(ctx, 1); err != nil { break }
    g.Go(func() error { defer sem.Release(1); return probe(ctx, target) })
}
err := g.Wait()
```

## 4.5 Единая обработка ошибок

Доменные ошибки — через пакет `internal/apperr`; HTTP-слой маппит их в статус-коды
централизованно, а не рассыпает `http.Error` по коду:

```go
// internal/apperr — доменные ошибки с «видом»
func NotFound(msg string) error   { return &Error{Kind: KindNotFound, Msg: msg} }
func Forbidden(msg string) error  { return &Error{Kind: KindForbidden, Msg: msg} }
func Conflict(msg string) error   { return &Error{Kind: KindConflict, Msg: msg} }
func Validation(msg string) error { return &Error{Kind: KindValidation, Msg: msg} }

// HTTP-слой — единый маппинг kind → статус + тело {"detail": "..."}
func writeErr(w http.ResponseWriter, err error) {
    var ae *apperr.Error
    status := http.StatusInternalServerError
    if errors.As(err, &ae) {
        status = ae.HTTPStatus() // 400/403/404/409/422
    }
    writeJSON(w, status, map[string]string{"detail": userMessage(err)})
}
```

---

# 5. Качество кода

## 5.1 Линтинг и форматирование

Инструменты запускаются автоматически (pre-commit hook или CI):

**Backend (Go):**

| Инструмент | Назначение |
|---|---|
| `gofmt` / `goimports` | Форматирование и порядок импортов |
| `go vet` | Статический анализ ошибок |
| `golangci-lint` | Металинтер (staticcheck, errcheck, ineffassign и др.) |

```bash
# Запустить перед коммитом (из backend-go/)
gofmt -l .
go vet ./...
golangci-lint run          # make lint
```

**Frontend (TypeScript):**

| Инструмент | Назначение |
|---|---|
| `eslint` | Линтер |
| `prettier` | Форматирование |
| `tsc` | Проверка типов |

```bash
npm run lint
npm run format
npm run type-check
```

**Код без ошибок линтера и типизации — обязательное условие для коммита.**

## 5.2 Типизация

- Go статически типизирован — не терять типы: избегать `interface{}`/`any`, кроме
  действительно динамических границ (JSON-поля, generic-хелперы) с комментарием-обоснованием
- DTO запросов/ответов — всегда сгенерированные из OpenAPI типы, не `map[string]any`
- В TypeScript: **запрещено `any`** без явного комментария-обоснования

```go
// Хорошо
func (r *Repo) GetByID(ctx context.Context, vulnID int32) (*Vulnerability, error) { ... }

// Плохо — теряется типобезопасность
func (r *Repo) GetByID(ctx context.Context, vulnID any) (any, error) { ... }
```

## 5.3 Тесты

- Каждая новая функциональность сопровождается тестами
- Юнит-тесты use-case'ов — табличные, с in-memory реализациями портов (Store/Tokens/Cipher/Storage)
- Тесты не должны ходить в реальный MinIO/SMTP — использовать stub-реализации портов
- DB-поведение (tx, SQL-фильтры, merge при импорте) покрывается env-gated e2e против
  одноразового `postgres:16-alpine`

```
backend-go/
├── internal/app/<ctx>/*_test.go           # табличные юнит-тесты use-case'ов (in-memory порты)
├── internal/adapters/security/*_test.go    # JWT/bcrypt/Fernet/TOTP round-trip
├── internal/adapters/cvss/*_test.go        # CVSS 4.0 против эталонных векторов
└── internal/adapters/http/*_e2e_test.go    # DB-backed e2e (по флагу FROST_TEST_DATABASE_URL)
```

---

# 6. Логирование

## 6.1 Что логировать

Структурное логирование через `log/slog`:

```go
import "log/slog"

// Логировать — запуск ключевых операций и их результат
slog.Info("создана уязвимость", "user", user.Username, "vuln_id", v.ID, "project_id", p.ID)
slog.Warn("неудачная попытка входа", "username", username)
slog.Error("ошибка удаления файла из MinIO", "err", err, "key", key)

// НЕ логировать секреты
slog.Debug("token", "value", accessToken) // ЗАПРЕЩЕНО
slog.Debug("password", "value", password) // ЗАПРЕЩЕНО
```

## 6.2 Уровни логирования

| Уровень | Когда |
|---|---|
| `Debug` | Детали для отладки (только в dev-окружении) |
| `Info` | Ключевые бизнес-события (вход, создание, изменение статуса) |
| `Warn` | Нестандартные ситуации, не являющиеся ошибкой |
| `Error` | Ошибки, требующие внимания (падение внешнего сервиса и т.д.) |

---

# 7. Работа с базой данных

## 7.1 Миграции

- Все изменения схемы БД — **только через goose-миграции** (`db/migrations/*.sql`)
- Миграции применяются автоматически на старте `cmd/api`
- Никогда не изменять БД вручную в prod
- Каждая миграция должна быть **обратимой**: секции `-- +goose Up` и `-- +goose Down`

```sql
-- db/migrations/00007_add_notifications.sql
-- Добавить таблицу notifications для in-app уведомлений

-- +goose Up
CREATE TABLE notifications ( ... );

-- +goose Down
DROP TABLE notifications;
```

После изменения схемы/запросов — перегенерировать типы: `make sqlc`.

## 7.2 N+1 запросы

- ORM и ленивой загрузки нет — связи выбираются явными запросами. Избегать N+1,
  формируя SQL с JOIN или батч-выборкой по списку id (`= ANY($1)`), а не запросом на
  каждой итерации
- При разработке проверять число запросов на горячих путях (список уязвимостей, экспорт отчёта)

```go
// Хорошо — связанные активы выбираются одним батч-запросом по списку vuln_id
assets, _ := q.ListAssetsForVulns(ctx, vulnIDs) // WHERE vulnerability_id = ANY($1)
byVuln := groupBy(assets, func(a Asset) int32 { return a.VulnerabilityID })

// Плохо — N+1: отдельный запрос за активами на каждую уязвимость
for _, v := range vulns {
    v.Assets, _ = q.ListAssetsForVuln(ctx, v.ID) // ← запрос на каждой итерации
}
```

## 7.3 Транзакции

Составные операции (запись сущности + аудит + уведомление) выполнять в одной транзакции
через хелпер репозитория:

```go
err := r.tx(ctx, func(q *sqlc.Queries) error {
    v, err := q.CreateVulnerability(ctx, params)
    if err != nil { return err }
    if err := q.InsertAuditLog(ctx, auditFor(v)); err != nil { return err }
    return q.InsertNotifications(ctx, notificationsFor(v))
})
```

---

# 8. Переменные окружения и конфигурация

- В репозитории хранить только `.env.example` / `.env.prod.example` с описанием всех
  переменных (без значений)
- `.env`, `.env.prod` — в `.gitignore`, никогда не коммитить
- Все секреты читаются пакетом `config` при старте — с валидацией
- При отсутствии обязательной переменной окружения приложение **не должно стартовать** (fail fast)

```go
// config/config.go — загрузка и валидация при старте
type Config struct {
    JWTSecretKey   string `env:"JWT_SECRET_KEY,required"` // мин. 32 символа — иначе fail
    DatabaseURL    string `env:"DATABASE_URL,required"`
    MinioAccessKey string `env:"MINIO_ACCESS_KEY,required"`
    Debug          bool   `env:"DEBUG" envDefault:"false"`
}

func Load() (Config, error) {
    var c Config
    if err := env.Parse(&c); err != nil { return c, err }
    if len(c.JWTSecretKey) < 32 {
        return c, errors.New("JWT_SECRET_KEY должен быть не короче 32 символов")
    }
    return c, nil
}
```

---

# 9. Кодовый ревью (Code Review)

Ревьюер проверяет:

- [ ] Нет хардкода секретов, URL, констант
- [ ] Все экспортируемые идентификаторы задокументированы doc-комментарием
- [ ] Комментарии на русском языке
- [ ] Покрытие тестами добавлено (юнит и/или e2e)
- [ ] Нет нарушений слоёв архитектуры (SQL в HTTP-слое, HTTP в репозитории)
- [ ] Нет N+1 запросов
- [ ] Входные данные валидируются
- [ ] Права доступа проверяются явно (middleware + use-case)
- [ ] Нет закомментированного кода без объяснения
- [ ] Миграция goose добавлена (если изменена схема), `make sqlc` выполнен
- [ ] `go vet` и `golangci-lint` проходят без ошибок

---

# 10. Запрещённые практики (Anti-patterns)

| Запрещено | Почему | Альтернатива |
|---|---|---|
| `SELECT *` в запросах | Нагрузка, утечка лишних полей | Явный список колонок в `db/queries/*.sql` |
| Бизнес-логика в HTTP-слое | Нарушение слоёв, несовместимость с тестами | Вынести в use-case `internal/app/<ctx>` |
| SQL через `fmt.Sprintf`/конкатенацию | SQL-инъекция | sqlc / параметризованные запросы |
| Секреты в коде | Утечка при компрометации репозитория | `.env` + пакет `config` |
| Проглоченная ошибка (`_ = err`, пустой `if err != nil {}`) | Скрывает сбои | Обработать, обернуть (`fmt.Errorf("...: %w", err)`) и пробросить |
| Мутация глобального состояния | Непредсказуемое поведение | Внедрение зависимостей через конструкторы в `cmd/api` |
| Горутина без ограничения/отмены | Утечки, перегрузка цели | `errgroup` + `semaphore`, проброс `context` |
| `panic` в обычном потоке запроса | Падение обработчика | Вернуть `error` (apperr) и смаппить в статус |
| Декодирование JSON напрямую в доменную модель | Нарушение слоёв, mass assignment | Декодировать в DTO, затем маппить |
| Хранение токена в `localStorage`/`sessionStorage` | XSS: JS имеет доступ к хранилищу | Только `HttpOnly` cookie, выставляемая сервером |
| Передача токена в URL (`?token=...`) | Токен попадает в логи и историю браузера | Cookie передаётся браузером автоматически |
| Ручная установка `Authorization: Bearer` для `/api/v1` | Нарушает cookie-архитектуру | `withCredentials: true` — браузер сам шлёт cookie |
| `any` в TypeScript без обоснования | Теряется типизация | Явный тип или `unknown` |
| Коммит в `main` напрямую | Нарушение Git Flow | Только через PR |

> `Authorization: Bearer` допустим и обязателен **только** для machine-API `/api/v2`
> (агентские токены) — это отдельный контур аутентификации.

---

# 11. Чеклист перед созданием PR

Прежде чем открыть Pull Request, убедись:

**Код:**
- [ ] Линтер не выдаёт ошибок (`go vet`, `golangci-lint` / `eslint`, `tsc`)
- [ ] Код отформатирован (`gofmt`/`goimports` / `prettier`)
- [ ] Все экспортируемые идентификаторы задокументированы
- [ ] Комментарии на русском языке

**Git:**
- [ ] Ветка создана от актуального `develop`
- [ ] Коммит содержит тип, область и описание на русском
- [ ] Нет лишних файлов (`.env`, `.env.prod`, бинарников сборки, `node_modules`)

**Функциональность:**
- [ ] Реализованное поведение соответствует требованиям в `TASK.md`
- [ ] Написаны тесты на новую логику (`go test ./... -race` зелёный)
- [ ] Если изменена схема БД — добавлена goose-миграция с `Up`/`Down` и выполнен `make sqlc`
- [ ] Если изменён API-контракт — обновлены `docs/openapi-v{1,2}.json` и выполнен `make oapi`
- [ ] Проверена авторизация: нельзя получить чужие данные

**Безопасность:**
- [ ] Нет хардкода секретов
- [ ] Входные данные валидируются через DTO/доменные валидаторы
- [ ] Нет SQL через строковое форматирование
