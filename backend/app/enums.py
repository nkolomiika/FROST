import enum


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    PENTESTER = "pentester"


class ProjectRole(str, enum.Enum):
    """Проектная роль пользователя — глобальная, задаётся в /members.

    Не путать с UserRole (аккаунтная роль admin/pentester). Лид остаётся обычным
    пользователем: роль лида лишь открывает дополнительные возможности в тех
    проектах, где он состоит участником (например, управление составом команды).
    """

    LEAD = "lead"
    PENTESTER = "pentester"


class ProjectStatus(str, enum.Enum):
    ACTIVE = "active"
    # Работы приостановлены: проект не активен, но и не завершён.
    FREEZE = "freeze"
    HANDOVER_TO_DEVELOPMENT = "handover_to_development"
    VULNERABILITY_RECHECK = "vulnerability_recheck"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class HostStatus(str, enum.Enum):
    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


class OsType(str, enum.Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    FREEBSD = "freebsd"
    ANDROID = "android"
    IOS = "ios"
    OTHER = "other"
    UNKNOWN = "unknown"


class Protocol(str, enum.Enum):
    TCP = "tcp"
    UDP = "udp"


class PortState(str, enum.Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class HttpMethod(str, enum.Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    # QUERY — метод из RFC-драфта httpbis (безопасный поиск с телом запроса).
    QUERY = "QUERY"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    # Значение по умолчанию для только что созданной находки, пока не проставлен
    # CVSS-вектор/уровень (отдельного «не определено» больше нет).
    INFO = "info"


class CvssVersion(str, enum.Enum):
    V31 = "3.1"
    V40 = "4.0"


class VulnerabilityStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    WONT_FIX = "wont_fix"
    ACCEPTED_RISK = "accepted_risk"


class AssetType(str, enum.Enum):
    HOST = "host"
    PORT = "port"
    SERVICE = "service"
    ENDPOINT = "endpoint"


class NotificationType(str, enum.Enum):
    """Поводы для in-app уведомления — других не создаём.

    Список намеренно узкий: уведомляем только о том, что касается пользователя
    лично, иначе лента превращается в шум (для «кто что сделал» есть активность
    проекта).
    """

    #: Пользователя упомянули через @username (в комментарии к находке или заметке).
    MENTION = "mention"
    #: Пользователя добавили в проект.
    PROJECT_MEMBER_ADDED = "project_member_added"
    #: Изменился статус находки, которую завёл пользователь.
    VULN_STATUS_CHANGED = "vuln_status_changed"
    #: Изменился статус проекта, в котором состоит пользователь.
    PROJECT_STATUS_CHANGED = "project_status_changed"


class ReconJobKind(str, enum.Enum):
    """Тип задачи рекон-фермы — определяет сервис-исполнитель и форму result."""

    HOSTS = "hosts"
    IPS = "ips"
    JS = "js"
    # Scanner-раздел: раскрытие поддоменов корня (crt.sh + subfinder).
    SUBS = "subs"
    # Scanner-раздел: скан произвольных открытых TCP-портов (nmap).
    PORTS = "ports"
    # Scanner-раздел: обратный резолв IP → PTR-имя → прогон имени фермой хостов.
    # Этот кросс-рекон убран из обычного «Add IPs» и делается только явным запуском.
    REVERSE = "reverse"


class ReconJobStatus(str, enum.Enum):
    """Жизненный цикл задачи фермы: pending → queued → running → done | failed.

    Хранится строкой (String-колонка host_farm_jobs.status, без DB-enum), поэтому
    из БД читается как обычный str; сравнения с членами работают за счёт (str, Enum).
    """

    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
