# Правила разработки STORM
## Pentest Collaboration Framework

> Этот документ обязателен к прочтению перед началом работы над проектом.  
> Соблюдение правил обязательно для всех участников команды разработки.

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
feature/report-pdf-generation
fix/jwt-refresh-token-expiry
refactor/host-repository-cleanup
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
feat(vulnerabilities): добавить создание и редактирование уязвимости

Реализован полный CRUD для уязвимостей.
Добавлена валидация CVSS-скора (0.0-10.0) и полиморфная привязка к активам.
Аудит-лог записывается при каждой операции.

Closes #42
```

```
fix(auth): исправить ошибку валидации истёкшего refresh-токена
```

```
feat(websocket): добавить рассылку событий при CRUD операциях над хостами
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
- Нельзя мёрджить PR, если упали тесты

---

# 2. Комментарии и документация к коду

## 2.1 Язык комментариев

**Все комментарии пишутся на русском языке.**  
Имена переменных, функций, классов — на английском (стандарт индустрии).

```python
# Хорошо
# Проверяем доступ пользователя к проекту перед возвратом данных
async def get_project(project_id: UUID, current_user: User) -> Project:
    ...

# Плохо
# Check user access to project before returning data
async def get_project(project_id: UUID, current_user: User) -> Project:
    ...
```

## 2.2 Документация к методам (Docstring)

**Каждый публичный метод сервиса и репозитория обязан иметь docstring.**

Формат для Python:

```python
async def create_vulnerability(
    self,
    project_id: UUID,
    data: VulnerabilityCreate,
    current_user: User,
) -> Vulnerability:
    """
    Создать новую уязвимость в проекте.

    Проверяет, что пользователь является участником проекта.
    После создания записывает событие в audit_log и рассылает
    WebSocket-уведомление всем участникам проекта.

    Args:
        project_id: UUID проекта, к которому привязывается уязвимость.
        data: Валидированные данные уязвимости (Pydantic-схема).
        current_user: Текущий авторизованный пользователь.

    Returns:
        Созданный объект Vulnerability с заполненными полями.

    Raises:
        ForbiddenError: Если пользователь не является участником проекта.
        NotFoundError: Если проект не существует.
    """
    ...
```

Формат для TypeScript:

```typescript
/**
 * Загружает список уязвимостей проекта с пагинацией.
 *
 * @param projectId - UUID проекта
 * @param params - Параметры фильтрации и пагинации
 * @returns Пагинированный список уязвимостей
 * @throws ApiError при ошибках сети или авторизации
 */
async function getVulnerabilities(
  projectId: string,
  params: VulnerabilityListParams,
): Promise<PaginatedResponse<Vulnerability>> {
  ...
}
```

## 2.3 Правила комментирования

**Комментируй «почему», а не «что»:**

```python
# Хорошо — объясняет причину решения
# MinIO не поддерживает транзакции, поэтому сначала удаляем из БД,
# а затем из хранилища. Если удаление из MinIO упадёт — вызываем rollback вручную.
await file_repo.delete(file_id)
await minio_client.delete(file.minio_key)

# Плохо — просто пересказывает код
# Удаляем файл из репозитория
await file_repo.delete(file_id)
# Удаляем файл из MinIO
await minio_client.delete(file.minio_key)
```

**Не оставляй мёртвый код — удаляй его:**

```python
# Запрещено — закомментированный код без пояснений
# old_result = await legacy_service.get(id)
result = await new_service.get(id)
```

**TODO и FIXME должны содержать имя автора и описание:**

```python
# TODO(nikita): добавить кэширование результата после внедрения Redis
# FIXME(ivan): временное решение, до рефакторинга импорта (#87)
```

---

# 3. Безопасность кода

## 3.1 Аутентификация и авторизация

- Каждый эндпоинт **явно** указывает требуемую роль через Dependency Injection — не полагаться на «неявную» защиту
- Проверка прав выполняется **на уровне сервиса**, а не только на уровне роутера
- Никогда не возвращать `password_hash` в ответах API — использовать схемы ответа без этого поля
- JWT-секрет и все секреты — только из переменных окружения, никогда в коде

```python
# Хорошо
@router.get("/projects/{project_id}")
async def get_project(
    project_id: UUID,
    project: Project = Depends(require_project_access),  # явная проверка доступа
):
    return project

# Запрещено — авторизация не указана явно
@router.get("/projects/{project_id}")
async def get_project(project_id: UUID):
    return await project_repo.get(project_id)  # любой может получить любой проект
```

## 3.2 Валидация входных данных

- **Всегда** валидировать входные данные через Pydantic-схемы на бэкенде
- Максимальные длины строк — указывать явно в схемах (`max_length`)
- Числовые диапазоны — ограничивать через `ge`, `le` в Pydantic
- Файлы — проверять MIME-тип по содержимому (`python-magic`), а не только по расширению

```python
class VulnerabilityCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    cvss_score: float | None = Field(None, ge=0.0, le=10.0)
    severity: Literal["critical", "high", "medium", "low", "info"]

    @validator("cvss_vector")
    def validate_cvss_vector(cls, v, values):
        # Проверяем соответствие вектора выбранной версии CVSS
        if v and values.get("cvss_version") == "3.1":
            if not v.startswith("CVSS:3.1/"):
                raise ValueError("Вектор должен начинаться с CVSS:3.1/")
        return v
```

## 3.3 Работа с БД — защита от SQL-инъекций

- Использовать **только параметризованные запросы** через SQLAlchemy ORM или `text()` с bind-параметрами
- Никогда не форматировать SQL-строку через f-string или `.format()`

```python
# Хорошо
result = await db.execute(
    select(Vulnerability).where(Vulnerability.project_id == project_id)
)

# Хорошо (raw SQL с параметрами)
result = await db.execute(
    text("SELECT * FROM vulnerabilities WHERE project_id = :pid"),
    {"pid": str(project_id)},
)

# ЗАПРЕЩЕНО — SQL-инъекция
query = f"SELECT * FROM vulnerabilities WHERE project_id = '{project_id}'"
result = await db.execute(text(query))
```

## 3.4 Хранение секретов

- Секреты — только в `.env` файлах, которые добавлены в `.gitignore`
- В репозитории хранить только `.env.example` с пустыми значениями
- Никогда не логировать токены, пароли, ключи API

```python
# ЗАПРЕЩЕНО
logger.info(f"Пользователь авторизован, токен: {access_token}")

# Хорошо
logger.info(f"Пользователь {user.username} успешно авторизован")
```

## 3.5 Защита от распространённых атак

| Угроза | Реализация защиты |
|---|---|
| SQL Injection | Только ORM / параметризованные запросы |
| XSS | Токены в `httpOnly` cookie — JavaScript не имеет к ним доступа. Sanitize HTML если используется markdown-рендер |
| CSRF | Cookie с атрибутом `SameSite=Strict` + проверка заголовка `Origin` на бэкенде для мутирующих запросов |
| Brute Force | Rate limiting на `/auth/login` (например, slowapi) |
| Path Traversal | Никогда не использовать пользовательский ввод в путях файлов; ключ MinIO генерировать на сервере |
| Mass Assignment | Использовать отдельные схемы для Create/Update — никогда не передавать dict из request напрямую в модель |
| IDOR | Проверять принадлежность ресурса к проекту, а не только существование по ID |
| Утечка токена | Токен никогда не попадает в тело ответа, URL, логи — только через `Set-Cookie` заголовок |

**Пример защиты от IDOR:**

```python
async def get_vulnerability(vuln_id: UUID, project_id: UUID, db) -> Vulnerability:
    """
    Получаем уязвимость только в рамках конкретного проекта,
    чтобы пользователь не мог получить данные чужого проекта,
    зная только ID уязвимости.
    """
    vuln = await db.execute(
        select(Vulnerability).where(
            Vulnerability.id == vuln_id,
            Vulnerability.project_id == project_id,  # ← обязательная проверка
        )
    )
    if not vuln:
        raise NotFoundError("Уязвимость не найдена")
    return vuln
```

---

# 4. Масштабируемость и архитектура

## 4.1 Не нарушать слои архитектуры

```
Router  → только HTTP: принять запрос, вернуть ответ
Service → только бизнес-логика
Repository → только работа с БД
```

```python
# ЗАПРЕЩЕНО в роутере — бизнес-логика не место здесь
@router.post("/vulnerabilities")
async def create_vulnerability(data: VulnerabilityCreate, db = Depends(get_db)):
    vuln = Vulnerability(**data.dict())
    db.add(vuln)
    await db.commit()
    return vuln

# Хорошо — роутер делегирует сервису
@router.post("/vulnerabilities", status_code=201)
async def create_vulnerability(
    data: VulnerabilityCreate,
    project: Project = Depends(require_project_access),
    service: VulnerabilityService = Depends(get_vulnerability_service),
    current_user: User = Depends(get_current_user),
):
    return await service.create_vulnerability(project.id, data, current_user)
```

## 4.2 Не хардкодить константы

Все конфигурационные значения выносить в `config.py` из переменных окружения:

```python
# ЗАПРЕЩЕНО
MAX_FILE_SIZE = 52428800  # встречаться в коде не должно
JWT_EXPIRE = 30

# Хорошо
# config.py
class Settings(BaseSettings):
    max_file_size_bytes: int = 52_428_800      # 50 МБ
    jwt_access_expire_minutes: int = 30
    jwt_refresh_expire_days: int = 30
    allowed_mime_types: list[str] = [
        "image/png", "image/jpeg", "image/gif", "image/webp",
        "text/plain", "application/pdf", "application/xml",
        "application/json", "application/zip",
    ]

settings = Settings()
```

## 4.3 Не дублировать логику (DRY)

Общая логика — в базовые классы, хелперы или декораторы:

```python
# Проверка доступа к проекту — одна функция, используется везде
async def require_project_access(
    project_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Project:
    """
    Dependency: проверяет доступ пользователя к проекту.
    Admin видит все проекты. Pentester — только назначенные.
    """
    ...
```

## 4.4 Асинхронность

- Весь I/O (БД, MinIO, сеть) — только `async/await`
- Не использовать синхронные блокирующие вызовы внутри async-функций
- Для CPU-heavy задач (генерация PDF) — использовать `asyncio.run_in_executor`

```python
# Генерация PDF — блокирующая операция, выносим в executor
async def generate_pdf(self, content: str) -> bytes:
    """Генерирует PDF в пуле потоков, не блокируя event loop."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, self._sync_generate_pdf, content)
```

## 4.5 Единая обработка ошибок

Централизованный обработчик исключений — не разбрасывать `raise HTTPException` по всему коду:

```python
# exceptions.py — кастомные исключения
class PCFError(Exception):
    """Базовое исключение приложения."""

class NotFoundError(PCFError):
    pass

class ForbiddenError(PCFError):
    pass

class ConflictError(PCFError):
    pass

# main.py — централизованный обработчик
@app.exception_handler(NotFoundError)
async def not_found_handler(request, exc):
    return JSONResponse(status_code=404, content={"detail": str(exc)})

@app.exception_handler(ForbiddenError)
async def forbidden_handler(request, exc):
    return JSONResponse(status_code=403, content={"detail": str(exc)})
```

---

# 5. Качество кода

## 5.1 Линтинг и форматирование

Инструменты запускаются автоматически (pre-commit hook или CI):

**Backend (Python):**

| Инструмент | Назначение |
|---|---|
| `ruff` | Линтер (заменяет flake8, isort, pyupgrade) |
| `black` | Форматирование кода |
| `mypy` | Статическая типизация |

```bash
# Запустить перед коммитом
ruff check .
black .
mypy app/
```

**Frontend (TypeScript):**

| Инструмент | Назначение |
|---|---|
| `eslint` | Линтер |
| `prettier` | Форматирование |
| `typescript` | Проверка типов |

```bash
npm run lint
npm run format
npm run type-check
```

**Код без ошибок линтера и типизации — обязательное условие для коммита.**

## 5.2 Типизация

- В Python: **обязательные аннотации типов** для всех аргументов и возвращаемых значений публичных методов
- В TypeScript: **запрещено использовать `any`** без явного комментария-обоснования
- Pydantic-схемы — для всех входящих и исходящих данных API (не `dict`)

```python
# Хорошо
async def get_by_id(self, vuln_id: UUID) -> Vulnerability | None:
    ...

# Плохо
async def get_by_id(self, vuln_id):
    ...
```

## 5.3 Тесты

- Каждая новая функциональность сопровождается тестами
- Минимальное покрытие сервисного слоя: **70%**
- Используй фикстуры для БД (тестовая БД, не production)
- Тесты не должны обращаться к реальному MinIO — использовать mock

```
tests/
├── unit/                # Тесты сервисов с замоканными репозиториями
│   ├── test_auth_service.py
│   ├── test_vulnerability_service.py
│   └── ...
├── integration/         # Тесты роутеров с тестовой БД
│   ├── test_auth_api.py
│   └── ...
└── conftest.py          # Фикстуры: тестовый клиент, тестовая БД, тестовые пользователи
```

---

# 6. Логирование

## 6.1 Что логировать

```python
import logging
logger = logging.getLogger(__name__)

# Логировать — запуск ключевых операций и их результат
logger.info("Пользователь %s создал уязвимость %s в проекте %s", user.username, vuln.id, project.id)
logger.warning("Неудачная попытка входа для пользователя: %s", username)
logger.error("Ошибка при удалении файла из MinIO: %s", exc, exc_info=True)

# НЕ логировать
logger.debug(f"token={access_token}")   # секреты
logger.debug(f"password={password}")    # секреты
```

## 6.2 Уровни логирования

| Уровень | Когда |
|---|---|
| `DEBUG` | Детали для отладки (только в dev-окружении) |
| `INFO` | Ключевые бизнес-события (вход, создание, изменение статуса) |
| `WARNING` | Нестандартные ситуации, не являющиеся ошибкой |
| `ERROR` | Ошибки, требующие внимания (падение внешнего сервиса и т.д.) |
| `CRITICAL` | Критические сбои системы |

---

# 7. Работа с базой данных

## 7.1 Миграции

- Все изменения схемы БД — **только через Alembic-миграции**
- Никогда не изменять БД вручную в prod
- Каждая миграция должна содержать описание: что изменено и зачем
- Миграции должны быть **обратимыми** (иметь `downgrade`)

```python
# migrations/versions/20240101_add_notifications_table.py
"""Добавить таблицу notifications для in-app уведомлений об @-упоминаниях

Revision ID: abc123
"""

def upgrade():
    op.create_table("notifications", ...)

def downgrade():
    op.drop_table("notifications")
```

## 7.2 N+1 запросы

- Использовать `joinedload` / `selectinload` для связанных объектов вместо lazy loading
- При разработке включать логирование SQL-запросов (`echo=True`) и проверять их количество

```python
# Хорошо — один запрос с JOIN
result = await db.execute(
    select(Vulnerability)
    .options(selectinload(Vulnerability.assets))
    .options(selectinload(Vulnerability.files))
    .where(Vulnerability.project_id == project_id)
)

# Плохо — N+1: для каждой уязвимости будет отдельный запрос за assets
vulns = await db.execute(select(Vulnerability).where(...))
for vuln in vulns:
    assets = vuln.assets  # <- вызывает запрос на каждой итерации
```

---

# 8. Переменные окружения и конфигурация

- В репозитории хранить только `.env.example` с описанием всех переменных (без значений)
- `.env` — в `.gitignore`, никогда не коммитить
- Все секреты читаются через `pydantic.BaseSettings` — с валидацией типов при старте
- При отсутствии обязательной переменной окружения приложение **не должно стартовать** (fail fast)

```python
class Settings(BaseSettings):
    jwt_secret_key: str                      # обязательная — упадёт если не задана
    database_url: str
    minio_access_key: str
    debug: bool = False

    class Config:
        env_file = ".env"

settings = Settings()  # при старте — валидация всех переменных
```

---

# 9. Кодовый ревью (Code Review)

Ревьюер проверяет:

- [ ] Нет хардкода секретов, URL, констант
- [ ] Все публичные методы задокументированы
- [ ] Комментарии на русском языке
- [ ] Покрытие тестами добавлено
- [ ] Нет нарушений слоёв архитектуры (SQL в роутере, HTTP в репозитории)
- [ ] Нет N+1 запросов
- [ ] Входные данные валидируются
- [ ] Права доступа проверяются явно
- [ ] Нет закомментированного кода без объяснения
- [ ] Миграция БД добавлена (если изменена схема)
- [ ] Линтер проходит без ошибок

---

# 10. Запрещённые практики (Anti-patterns)

| Запрещено | Почему | Альтернатива |
|---|---|---|
| `SELECT *` в запросах | Нагрузка, утечка лишних полей | Явно перечислять нужные колонки |
| Бизнес-логика в роутере | Нарушение слоёв, несовместимость с тестами | Вынести в Service |
| SQL через f-string | SQL-инъекция | ORM / параметризованные запросы |
| Секреты в коде | Утечка при компрометации репозитория | `.env` + `BaseSettings` |
| `except Exception: pass` | Скрывает ошибки | Логировать и пробрасывать далее |
| Мутация глобального состояния | Непредсказуемое поведение | Dependency Injection |
| `time.sleep()` в async-коде | Блокирует event loop | `asyncio.sleep()` |
| Прямое обращение к `request.json()` в сервисе | Нарушение слоёв | Передавать Pydantic-схему |
| Хранение токена в `localStorage` или `sessionStorage` | XSS-уязвимость: JS имеет доступ к хранилищу | Только `httpOnly` cookie, выставляемая сервером |
| Передача токена в URL (`?token=...`) | Токен попадает в логи сервера и историю браузера | Cookie передаётся автоматически браузером |
| Ручная установка `Authorization: Bearer` | Нарушает принятую архитектуру (cookie-based) | `withCredentials: true` — браузер сам отправляет cookie |
| `any` в TypeScript без обоснования | Теряется типизация | Явный тип или `unknown` |
| Коммит в `main` напрямую | Нарушение Git Flow | Только через PR |

---

# 11. Чеклист перед созданием PR

Прежде чем открыть Pull Request, убедись:

**Код:**
- [ ] Линтер не выдаёт ошибок (`ruff`, `mypy` / `eslint`, `tsc`)
- [ ] Код отформатирован (`black` / `prettier`)
- [ ] Все публичные методы задокументированы
- [ ] Комментарии на русском языке

**Git:**
- [ ] Ветка создана от актуального `develop`
- [ ] Коммит содержит тип, область и описание на русском
- [ ] Нет лишних файлов (`.env`, `__pycache__`, `node_modules`)

**Функциональность:**
- [ ] Реализованное поведение соответствует требованиям в `TASK.md`
- [ ] Написаны тесты на новую логику
- [ ] Если изменена схема БД — добавлена Alembic-миграция с `upgrade` и `downgrade`
- [ ] Проверена авторизация: нельзя получить чужие данные

**Безопасность:**
- [ ] Нет хардкода секретов
- [ ] Входные данные валидируются через схемы
- [ ] Нет SQL через строковое форматирование
