"""Определение технологий и CDN веб-порта внешними утилитами.

Фаза пробива уже стучится в корень каждого веб-порта; у ответивших портов
дополнительно снимаем стек (сервер, CMS, фреймворки, CDN) и пишем его
Service-строками на порт. По стеку же выводим признак Cloudflare: у claude.com и
подобных за CF статический список CIDR даёт ложный минус, а инструмент видит
Cloudflare напрямую — поэтому CF = (адрес в диапазонах CF) ИЛИ (детект нашёл
Cloudflare).

Движок по умолчанию — httpx (ProjectDiscovery): быстрый batch-вызов, отдаёт tech
+ cdn_name. whatweb остаётся запасным движком (медленный, по одному URL). Оба
ходят по цели сами, в обход нашего SSRF-transport, поэтому запускаются только по
портам, уже ответившим на SSRF-защищённый пробив (значит цель прошла внешний-only
гейт).

Разбор вывода — чистые функции (покрыты тестами); запуск подменяется параметром
detector (сиид для тестов без бинарей).
"""

from __future__ import annotations

import asyncio
import json
import shutil
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from app.config import get_settings
from app.farm.core import ProbeResult
from app.farm.resolver import ResolvedHost, resolve_forward

settings = get_settings()

# Тип резолвера — сиид для тестов и точка ре-гейта перед выходом наружу.
Resolver = Callable[[list[str]], Awaitable[dict[str, ResolvedHost]]]

# Плагины whatweb, которые не являются технологиями (мета, сеть, заголовки).
_META_PLUGINS = frozenset(
    {
        "Country", "IP", "Title", "Cookies", "UncommonHeaders", "RedirectLocation",
        "Meta-Author", "Meta-Refresh-Redirect", "MetaGenerator", "Script", "HTML5",
        "Email", "Frame", "X-Frame-Options", "X-XSS-Protection", "HttpOnly",
        "Strict-Transport-Security", "Content-Security-Policy", "X-UA-Compatible",
        "Access-Control-Allow-Origin", "Allow", "Via-Proxy", "probably",
    }
)


@dataclass
class Tech:
    name: str
    version: str | None = None


def url_for(p: ProbeResult) -> str:
    host = f"[{p.hostname}]" if ":" in p.hostname else p.hostname
    return f"{p.scheme}://{host}:{p.port}/"


def _url_key(u: str) -> tuple[str, str, int]:
    """(scheme, host, port) с раскрытым дефолтным портом — для матчинга вывода
    инструмента (который нормализует URL) обратно на нашу цель."""
    s = urlsplit(u if "://" in u else f"//{u}")
    scheme = (s.scheme or "http").lower()
    host = (s.hostname or "").lower()
    try:
        port = s.port
    except ValueError:
        port = None
    port = port or (443 if scheme == "https" else 80)
    return scheme, host, port


def has_cloudflare(techs: list[Tech]) -> bool:
    """Есть ли среди технологий Cloudflare — для вывода CF-флага по детекту."""
    return any("cloudflare" in t.name.lower() for t in techs)


# --------------------------------------------------------------------- httpx


def _split_tech(raw: str) -> Tech:
    """'Nginx:1.25.3' → Tech(Nginx, 1.25.3); 'Cloudflare' / 'HTTP/3' → без версии."""
    s = raw.strip()
    if ":" in s:
        name, _, ver = s.rpartition(":")
        if name and ver and ver[0].isdigit():
            return Tech(name.strip()[:100], ver.strip()[:100])
    return Tech(s[:100], None)


def parse_httpx_jsonl(raw: str) -> dict[str, list[Tech]]:
    """httpx -json (JSONL) → {url: [Tech]}. Стек из tech + webserver + cdn_name.

    cdn_name/webserver добавляем как технологию, если их ещё нет: так Cloudflare
    попадёт в чипы (и во флаг CF) даже когда httpx не положил его в tech.
    """
    out: dict[str, list[Tech]] = {}
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict):
            continue
        url = entry.get("input") or entry.get("url")
        if not url:
            continue
        techs: dict[str, Tech] = {}
        for item in entry.get("tech") or []:
            t = _split_tech(str(item))
            techs.setdefault(t.name.lower(), t)
        for extra_key in ("webserver", "cdn_name"):
            val = entry.get(extra_key)
            if val and str(val).lower() not in techs:
                techs[str(val).lower()] = Tech(str(val).strip().capitalize()[:100], None)
        out[url] = list(techs.values())
    return out


async def _run_httpx(urls: list[str]) -> dict[str, list[Tech]]:
    timeout = settings.services_detect_timeout_seconds
    args = [
        settings.services_httpx_bin,
        "-json", "-silent", "-no-color",
        "-td", "-cdn",
        "-disable-update-check",
        "-timeout", str(int(timeout)),
        "-retries", "0",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(
            proc.communicate(input="\n".join(urls).encode("utf-8")),
            timeout=timeout + len(urls) * 2 + 15,
        )
    except (TimeoutError, OSError):
        return {}
    return parse_httpx_jsonl(out.decode("utf-8", "replace"))


# ------------------------------------------------------------------ whatweb


def parse_whatweb_json(raw: str) -> list[Tech]:
    """Стек из whatweb --log-json для одной цели (запасной движок)."""
    raw = (raw or "").strip()
    if not raw:
        return []
    entries: list[dict] = []
    try:
        data = json.loads(raw)
        entries = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        for line in raw.splitlines():
            line = line.strip().rstrip(",")
            if line and line not in ("[", "]"):
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    techs: dict[str, Tech] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for name, info in (entry.get("plugins") or {}).items():
            if name in _META_PLUGINS:
                continue
            version: str | None = None
            strings: list[str] = []
            if isinstance(info, dict):
                v = info.get("version")
                if isinstance(v, list) and v:
                    version = str(v[0])
                elif isinstance(v, str):
                    version = v
                s = info.get("string")
                strings = [str(x) for x in s] if isinstance(s, list) else ([str(s)] if s else [])
            label = name
            if name in ("HTTPServer", "PoweredBy", "X-Powered-By") and strings:
                label = strings[0].split("/")[0].strip() or name
            key = label.lower()
            if key not in techs or (version and not techs[key].version):
                techs[key] = Tech(label[:100], version or None)
    return list(techs.values())


async def _run_whatweb_one(url: str) -> list[Tech]:
    timeout = settings.services_detect_timeout_seconds
    cmd = [
        settings.services_whatweb_bin,
        "--quiet", "--no-errors", "--follow-redirect=never",
        "--open-timeout", str(int(timeout)), "--read-timeout", str(int(timeout)),
        "--log-json=-", url,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 5)
    except (TimeoutError, OSError):
        return []
    return parse_whatweb_json(out.decode("utf-8", "replace"))


async def _run_whatweb(urls: list[str]) -> dict[str, list[Tech]]:
    sem = asyncio.Semaphore(settings.services_max_concurrency)

    async def one(u: str) -> tuple[str, list[Tech]]:
        async with sem:
            return u, await _run_whatweb_one(u)

    return dict(await asyncio.gather(*(one(u) for u in urls)))


# ------------------------------------------------------------------ dispatch


def _pick_engine() -> Callable[[list[str]], Awaitable[dict[str, list[Tech]]]] | None:
    """Движок по настройке с фолбэком; None — ни один бинарь не установлен."""
    httpx_ok = shutil.which(settings.services_httpx_bin) is not None
    whatweb_ok = shutil.which(settings.services_whatweb_bin) is not None
    if settings.services_detect_engine == "whatweb" and whatweb_ok:
        return _run_whatweb
    if httpx_ok:
        return _run_httpx
    if whatweb_ok:
        return _run_whatweb
    return None


async def _regate_external(responding: list[ProbeResult], resolver: Resolver) -> list[ProbeResult]:
    """Свежий резолв ответивших хостов; оставляет только внешне-резолвящиеся."""
    hosts = list({p.hostname for p in responding})
    resolved = await resolver(hosts)
    external = {h for h, r in resolved.items() if r.ip is not None and not r.blocked}
    return [p for p in responding if p.hostname in external]


async def detect_services(
    probes: list[ProbeResult],
    *,
    detector: Callable[[list[str]], Awaitable[dict[str, list[Tech]]]] | None = None,
    resolver: Resolver | None = None,
) -> dict[tuple[str, int], list[Tech]]:
    """Технологии ответивших портов: {(hostname, port): [Tech]}.

    Пустой словарь = детект выключен либо инструмент не установлен: сервисы тогда
    не трогаем, порт остаётся «unknown». detector — сиид для тестов (urls → {url: [Tech]}).

    Ре-гейт: детект-бинарь (httpx-pd/whatweb) ходит на цель сам, в обход нашего
    SSRF-transport и резолвит имя независимо. Между пробивом и детектом DNS мог
    ребайндиться на внутренний адрес — поэтому свежим резолвом отсекаем хосты,
    теперь резолвящиеся во внутреннее/битое. Это сужает окно (нужно выиграть
    гонку дважды), но не закрывает TOCTOU полностью — бинарь резолвит ещё раз сам.
    resolver — сиид для тестов; в проде по умолчанию resolve_forward (внешний-only).
    """
    responding = [p for p in probes if p.responded]
    if not responding:
        return {}

    if detector is not None:
        run = detector
    else:
        if not settings.services_detect_enabled:
            return {}
        run = _pick_engine()
        if run is None:
            return {}
        # В проде (не тест) ре-гейтим, если ферма во внешнем-only режиме.
        if resolver is None and not settings.farm_allow_private_targets:
            resolver = resolve_forward

    if resolver is not None:
        responding = await _regate_external(responding, resolver)
        if not responding:
            return {}

    engine_out = await run([url_for(p) for p in responding])
    by_key = {_url_key(u): techs for u, techs in engine_out.items()}
    return {(p.hostname, p.port): by_key.get(_url_key(url_for(p)), []) for p in responding}
