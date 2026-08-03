"""Встроенные regex-наборы для скана JS: секреты, пути, ссылки на .js.

Всё — чистые функции над строкой, без сети и БД: юнит-тестируемо и пригодно
для воркера. Заменяют внешние утилиты (gitleaks/SecretFinder — секреты,
LinkFinder — пути), которых в контейнере нет и которые тянуть ради одной фичи
не хочется. Наборы намеренно консервативны: лучше пропустить сомнительное, чем
завалить пентестера ложными срабатываниями.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

# --------------------------------------------------------------------- secrets

# kind -> (regex, severity). Паттерны с чётким префиксом (AKIA, AIza, ghp_) —
# high; контекстные (generic key=...) — medium.
_SECRET_SPECS: list[tuple[str, str, str]] = [
    ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b", "high"),
    ("google_api_key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "high"),
    ("github_pat", r"\bghp_[0-9A-Za-z]{36}\b", "high"),
    ("github_fine_grained_pat", r"\bgithub_pat_[0-9A-Za-z_]{22,}\b", "high"),
    ("slack_token", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", "high"),
    ("stripe_secret_key", r"\bsk_live_[0-9A-Za-z]{24,}\b", "high"),
    ("private_key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", "high"),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", "medium"),
    ("google_oauth_id", r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b", "medium"),
    ("firebase_url", r"\bhttps://[a-z0-9-]+\.firebaseio\.com\b", "low"),
    # Общий «ключ в коде»: имя-подсказка + строковый литерал ≥16 значимых символов.
    (
        "generic_api_key",
        r"""(?i)(?:api[_-]?key|apikey|secret|token|client[_-]?secret|passwd|password|access[_-]?key)"""
        r"""["'\s]*[:=]["'\s]*["']([0-9A-Za-z\-_]{16,})["']""",
        "medium",
    ),
]

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (kind, re.compile(pat), sev) for kind, pat, sev in _SECRET_SPECS
]


@dataclass
class Secret:
    kind: str
    match_preview: str
    snippet: str
    severity: str


def redact(value: str) -> str:
    """Скрывает середину секрета: первые/последние 4 символа, между ними звёзды.

    Полный секрет в БД не кладём — достаточно опознать находку и место.
    """
    value = value.strip()
    if len(value) <= 8:
        return value[0] + "***" if value else ""
    return f"{value[:4]}…{value[-4:]}"


def _snippet(text: str, start: int, end: int, width: int = 40) -> str:
    """Контекст вокруг совпадения, одной строкой, без переносов."""
    left = max(0, start - width)
    right = min(len(text), end + width)
    return re.sub(r"\s+", " ", text[left:right]).strip()


def find_secrets(text: str) -> list[Secret]:
    """Находит секреты. Дедуп по значению: тот же ключ не дублится, а специфичный
    паттерн (AKIA/AIza/…) выигрывает у общего generic_api_key — специфичные идут
    в наборе раньше, поэтому первое совпадение по значению и остаётся."""
    found: dict[str, Secret] = {}
    for kind, pattern, severity in _SECRET_PATTERNS:
        for m in pattern.finditer(text):
            # У generic-паттерна значение в группе 1, у остальных — всё совпадение.
            raw = m.group(1) if m.re.groups else m.group(0)
            preview = redact(raw)[:255]
            if preview in found:
                continue
            found[preview] = Secret(
                kind=kind,
                match_preview=preview,
                snippet=_snippet(text, m.start(), m.end())[:255],
                severity=severity,
            )
    return list(found.values())


# ----------------------------------------------------------------------- paths

# LinkFinder-style: пути/URL внутри кавычек в JS. Берём то, что похоже на роут.
_PATH_RE = re.compile(
    r"""["'`]
        (
            (?:https?:)?//[^"'`\s]{3,200}       # абсолютный URL
            |
            /[a-zA-Z0-9_./\-]{1,200}            # абсолютный путь /a/b
            |
            [a-zA-Z0-9_\-/]{1,100}/[a-zA-Z0-9_\-/]{1,100}  # относительный a/b
        )
        ["'`]""",
    re.VERBOSE,
)

# Расширения статики и мусорные фрагменты — отсекаем как неинтересные.
_PATH_NOISE_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".scss", ".less",
    ".woff", ".woff2", ".ttf", ".eot", ".ico", ".map", ".mp4", ".webp",
)
_PATH_DENY_SUBSTR = ("node_modules", "webpack://", "data:", "text/", "application/", "image/")


def _is_interesting_path(path: str) -> bool:
    low = path.lower()
    if any(low.endswith(ext) for ext in _PATH_NOISE_EXT):
        return False
    if any(s in low for s in _PATH_DENY_SUBSTR):
        return False
    # MIME-подобные "a/b" без реального смысла отсекаем: путь должен начинаться с /,
    # быть абсолютным URL или содержать хотя бы один осмысленный сегмент с буквами.
    if path.startswith("/") or path.startswith("http") or path.startswith("//"):
        return len(path) > 1
    return "/" in path and any(c.isalpha() for c in path)


def find_paths(text: str) -> list[str]:
    """Извлекает пути/URL из JS, отсекая статику и мусор. Порядок сохраняется."""
    seen: set[str] = set()
    out: list[str] = []
    for m in _PATH_RE.finditer(text):
        path = m.group(1).strip()
        if path in seen or not _is_interesting_path(path):
            continue
        seen.add(path)
        out.append(path)
    return out


# ------------------------------------------------------------------- js-in-html

_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*["']?([^"'>\s]+)""", re.IGNORECASE)
# .js-ссылки в любом атрибуте/строке (напр. динамически подгружаемые чанки).
_JS_REF_RE = re.compile(r"""["'(]([^"'()\s]+?\.js(?:\?[^"'()\s]*)?)["')]""", re.IGNORECASE)

# Шумные сторонние библиотеки — не качаем (аналитика, общие CDN-виджеты).
_JS_DENY_HOSTS = (
    "google-analytics.com", "googletagmanager.com", "gstatic.com",
    "facebook.net", "fbcdn.net", "doubleclick.net", "hotjar.com",
)


def extract_js_urls(html: str, base_url: str) -> list[str]:
    """Абсолютные URL .js-файлов из HTML: <script src> + .js-ссылки, дедуп.

    Относительные резолвятся через base_url. Отсекаются известные аналитические
    CDN. http(s)-only — прочие схемы (data:, blob:) не наши.
    """
    seen: set[str] = set()
    out: list[str] = []
    for pattern in (_SCRIPT_SRC_RE, _JS_REF_RE):
        for m in pattern.finditer(html):
            raw = m.group(1).strip()
            if not raw or raw.startswith(("data:", "blob:", "javascript:")):
                continue
            absolute = urljoin(base_url, raw)
            parsed = urlparse(absolute)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                continue
            if not parsed.path.lower().split("?")[0].endswith(".js"):
                continue
            if any(deny in parsed.netloc.lower() for deny in _JS_DENY_HOSTS):
                continue
            if absolute in seen:
                continue
            seen.add(absolute)
            out.append(absolute)
    return out
