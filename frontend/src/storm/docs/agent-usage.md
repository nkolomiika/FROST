# Аутентификация и эндпоинты

Машинный доступ идёт в префикс `/api/v2`. Каждый запрос аутентифицируется agent-токеном, а доступ к конкретному эндпоинту проверяется по **scope** токена и его допуску к проекту.

## Аутентификация

Передавайте токен в заголовке `Authorization` по схеме Bearer:

```
Authorization: Bearer <ваш_токен>
```

Пользовательские cookie для v2 не нужны и не используются — токен самодостаточен. Если у токена нет нужного scope или он не допущен к проекту, эндпоинт вернёт ошибку доступа.

## Доступные эндпоинты

Каждый эндпоинт требует свой scope (в скобках):

**Проекты**
- `GET /api/v2/projects` — проекты, доступные токену: все или из списка допуска (`projects:read`).
- `GET /api/v2/projects/{id}` — один проект (`projects:read`).

**Хосты и активы** (только чтение)
- `GET /api/v2/projects/{id}/hosts` — список хостов проекта (`assets:read`).
- `GET /api/v2/projects/{id}/hosts/{host_id}` — хост с вложенными сущностями (`assets:read`).

**Уязвимости**
- `GET /api/v2/projects/{id}/hosts/{host_id}/vulnerabilities` — находки по хосту (`vulns:read`).
- `GET /api/v2/projects/{id}/hosts/{host_id}/vulnerabilities/{vuln_id}` — одна находка (`vulns:read`).
- `POST /api/v2/projects/{id}/vulnerabilities` — создать находку (`vulns:write`).
- `PUT /api/v2/projects/{id}/vulnerabilities/{vuln_id}` — обновить находку (`vulns:write`).

**Заметки**
- `GET /api/v2/projects/{id}/notes` — дерево заметок (`notes:read`).
- `GET /api/v2/projects/{id}/notes/{note_id}` — одна заметка (`notes:read`).
- `POST /api/v2/projects/{id}/notes` — создать заметку (`notes:write`).
- `PUT /api/v2/projects/{id}/notes/{note_id}` — обновить заметку (`notes:write`).

> Обратите внимание на асимметрию: **чтение** уязвимостей — в разрезе хоста, а **создание/обновление** — на уровне проекта. Удаления через Agent API нет; изменять активы тоже нельзя (нет `assets:write`).

Записи, сделанные токеном, приписываются пользователю, от имени которого выпущен токен.

## Примеры запросов

Получить список доступных проектов:

```
curl -s https://storm.example/api/v2/projects \
  -H "Authorization: Bearer $STORM_TOKEN"
```

Прочитать хосты проекта `42`:

```
curl -s https://storm.example/api/v2/projects/42/hosts \
  -H "Authorization: Bearer $STORM_TOKEN"
```

Создать находку в проекте `42` (поля находки — те же, что в интерфейсе: см. документ «Пользователь», глава «Уязвимости». Находка обязана быть привязана к хосту):

```
curl -s -X POST https://storm.example/api/v2/projects/42/vulnerabilities \
  -H "Authorization: Bearer $STORM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "title": "SQL injection in /api/login",
        "host_id": 100,
        "severity": "high",
        "status": "open"
      }'
```

> Замените `storm.example` на адрес вашего экземпляра Storm, а `$STORM_TOKEN` — на значение выпущенного токена. Значения `host_id` и id проекта берутся из ответов эндпоинтов чтения.

> Поле `severity` необязательно: если его не передать, критичность создаётся со значением `info` и уточняется позже CVSS-вектором.
