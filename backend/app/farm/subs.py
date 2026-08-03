"""Scanner: раскрытие поддоменов корневого домена.

Источники объединяются и дедупятся:

  1. crt.sh — Certificate Transparency, HTTP JSON, ключ не нужен;
  2. subfinder (ProjectDiscovery) — если бинарь установлен, иначе тихо пропускаем.

Найденные (в scope корня) поддомены прогоняются фермой ХОСТОВ — резолв, пробив
веб-портов, детект сервисов, — поэтому scanner наполняет проект реальными
хостами, а не просто списком имён. Новыми считаются те, которых в проекте ещё
не было.

Фазы те же, что у остальных ферм, и то же правило: сеть — без БД. Разбор вывода
источников — чистые функции (покрыты тестами); сбор подменяется параметром
collector (сиид для тестов без сети/бинарей).
"""

from __future__ import annotations

import asyncio
import json
import shutil
from collections.abc import Awaitable, Callable

import httpx
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.enums import ReconJobKind, ReconJobStatus
from app.exceptions import NotFoundError, ValidationError
from app.farm.hosts import HostFarmService
from app.farm.resolver import is_ip_literal
from app.models import Host, HostFarmJob
from app.schemas import SubFarmResult
from app.services import AuditService
from app.ws_manager import ws_manager

settings = get_settings()

# collector: {root: (subdomains, sources_used, errors)} — сиид для тестов.
Collector = Callable[[list[str]], Awaitable[dict[str, tuple[set[str], list[str], list[str]]]]]


# ------------------------------------------------------------------ pure parse


def _normalize(name: str) -> str:
    """Имя хоста к каноничному виду: lower, без точки на конце и без '*.'-обёртки."""
    name = name.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    return name


def parse_roots(raw: str) -> list[str]:
    """Корневые домены из вставленного текста: дедуп, без IP и комментариев."""
    out: list[str] = []
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        for token in line.replace(",", " ").split():
            name = _normalize(token)
            if name and not is_ip_literal(name) and "." in name and name not in out:
                out.append(name)
    return out


def in_scope(name: str, root: str) -> bool:
    """name принадлежит поддереву root (сам root тоже в scope)."""
    return name == root or name.endswith("." + root)


def parse_crtsh(raw_json: str, root: str) -> set[str]:
    """Поддомены из JSON-ответа crt.sh (?output=json). Берём name_value каждого
    сертификата (может содержать несколько имён через \\n и wildcard '*.')."""
    try:
        data = json.loads(raw_json or "[]")
    except json.JSONDecodeError:
        return set()
    if not isinstance(data, list):
        return set()
    found: set[str] = set()
    for entry in data:
        if not isinstance(entry, dict):
            continue
        for field in ("name_value", "common_name"):
            value = entry.get(field)
            if not value:
                continue
            for piece in str(value).splitlines():
                name = _normalize(piece)
                if name and not is_ip_literal(name) and in_scope(name, root):
                    found.add(name)
    return found


def parse_subfinder(text: str, root: str) -> set[str]:
    """Поддомены из subfinder -silent (по имени на строку)."""
    found: set[str] = set()
    for line in (text or "").splitlines():
        name = _normalize(line)
        if name and not is_ip_literal(name) and in_scope(name, root):
            found.add(name)
    return found


# --------------------------------------------------------------- source runners


async def _fetch_crtsh(root: str) -> tuple[set[str], str | None]:
    """crt.sh по корню. Хост фиксированный (не пользовательский) — SSRF-transport
    не нужен; таймаут ограничивает зависание."""
    url = "https://crt.sh/"
    params = {"q": f"%.{root}", "output": "json"}
    timeout = httpx.Timeout(settings.subs_crtsh_timeout_seconds)
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(url, params=params)
        if resp.status_code != 200:
            return set(), f"crt.sh({root}): http_{resp.status_code}"
        return parse_crtsh(resp.text, root), None
    except Exception as exc:  # noqa: BLE001 — источник не обязателен, фиксируем в errors
        return set(), f"crt.sh({root}): {type(exc).__name__}"


async def _run_subfinder(root: str) -> tuple[set[str], str | None]:
    """subfinder -d root -silent. Нет бинаря — тихо пропускаем (None-ошибки нет)."""
    if not shutil.which(settings.subs_subfinder_bin):
        return set(), None
    args = [settings.subs_subfinder_bin, "-d", root, "-silent", "-no-color"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        out, _ = await asyncio.wait_for(
            proc.communicate(), timeout=settings.subs_subfinder_timeout_seconds
        )
    except (TimeoutError, OSError) as exc:
        return set(), f"subfinder({root}): {type(exc).__name__}"
    return parse_subfinder(out.decode("utf-8", "replace"), root), None


async def _default_collector(roots: list[str]) -> dict[str, tuple[set[str], list[str], list[str]]]:
    """Реальный сбор: crt.sh + subfinder по каждому корню, параллельно по корням."""
    async def one(root: str) -> tuple[str, tuple[set[str], list[str], list[str]]]:
        subs: set[str] = set()
        used: list[str] = []
        errors: list[str] = []
        if settings.subs_crtsh_enabled:
            crt, err = await _fetch_crtsh(root)
            if crt:
                used.append("crt.sh")
            subs |= crt
            if err:
                errors.append(err)
        if settings.subs_subfinder_enabled:
            sf, err = await _run_subfinder(root)
            if sf:
                used.append("subfinder")
            subs |= sf
            if err:
                errors.append(err)
        return root, (subs, used, errors)

    return dict(await asyncio.gather(*(one(r) for r in roots)))


# ----------------------------------------------------------------------- service


class SubdomainFarmService:
    """Раскрытие поддоменов проекта и прогон найденного фермой хостов."""

    kind = ReconJobKind.SUBS

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.audit = AuditService(db)

    async def _project_roots(self, project_id: int) -> list[str]:
        """Корни из доменных хостов проекта (origin=host, не IP-строки)."""
        rows = await self.db.scalars(
            select(Host.hostname).where(
                and_(Host.project_id == project_id, Host.origin == "host", Host.hostname.isnot(None))
            )
        )
        roots: list[str] = []
        for h in rows.all():
            name = _normalize(h or "")
            if name and not is_ip_literal(name) and "." in name and name not in roots:
                roots.append(name)
        return roots

    async def _project_hostnames(self, project_id: int) -> set[str]:
        rows = await self.db.scalars(
            select(Host.hostname).where(
                and_(Host.project_id == project_id, Host.hostname.isnot(None))
            )
        )
        return {_normalize(h) for h in rows.all() if h}

    async def _collect(
        self, roots: list[str], collector: Collector | None
    ) -> tuple[set[str], list[str], list[str]]:
        """Слить источники по всем корням: (поддомены, источники, ошибки)."""
        run = collector or _default_collector
        by_root = await run(roots)
        subs: set[str] = set()
        used: list[str] = []
        errors: list[str] = []
        for root_subs, root_used, root_errors in by_root.values():
            subs |= root_subs
            for u in root_used:
                if u not in used:
                    used.append(u)
            errors.extend(root_errors)
        return subs, used, errors

    async def probe_and_import(
        self,
        project_id: int,
        raw: str,
        actor_id: int,
        *,
        transport=None,
        detector=None,
        skip_targets: list[str] | None = None,
        collector: Collector | None = None,
    ) -> SubFarmResult:
        roots = parse_roots(raw) or await self._project_roots(project_id)
        result = SubFarmResult()
        if not roots:
            return result

        subs, sources_used, errors = await self._collect(roots, collector)
        # Кап найденного: младшие (короче/алфавит) остаются, чтобы прогон был предсказуем.
        capped = sorted(subs)[: settings.subs_max_results]
        existing = await self._project_hostnames(project_id)
        new = [s for s in capped if s not in existing]

        result.roots_scanned = len(roots)
        result.subdomains_found = len(capped)
        result.subdomains_new = len(new)
        result.sources_used = sources_used
        result.subdomains = capped
        result.errors = list(errors)

        # Прогон новых поддоменов фермой хостов: резолв + пробив + запись.
        if new:
            host_res = await HostFarmService(self.db).probe_and_import(
                project_id,
                "\n".join(new),
                actor_id,
                transport=transport,
                detector=detector,
                skip_targets=skip_targets,
            )
            result.hosts_created = host_res.hosts_created
            result.hosts_online = host_res.hosts_online
            result.hosts_offline = host_res.hosts_offline
            result.errors.extend(host_res.errors)

        await self.audit.log(
            "CREATE",
            user_id=actor_id,
            entity_type="sub_farm",
            entity_id=None,
            details={"project_id": str(project_id), **result.model_dump(exclude={"subdomains"})},
        )
        await ws_manager.broadcast(
            project_id,
            {"event": "imported", "entity": "host", "project_id": str(project_id), "data": {}},
        )
        return result

    async def create_job(self, project_id: int, raw: str, actor_id: int) -> HostFarmJob:
        roots = parse_roots(raw) or await self._project_roots(project_id)
        if not roots:
            raise ValidationError("Не удалось распознать ни одного корневого домена")
        # Снимок корней в raw: воркер живёт в другом процессе и получает только id.
        job = HostFarmJob(
            project_id=project_id,
            created_by=actor_id,
            kind=self.kind,
            status=ReconJobStatus.PENDING,
            targets_total=len(roots),
            raw="\n".join(roots),
        )
        self.db.add(job)
        await self.db.commit()
        await self.db.refresh(job)
        return job

    async def get_job(self, project_id: int, job_id: int) -> HostFarmJob:
        job = await self.db.scalar(
            select(HostFarmJob).where(
                and_(
                    HostFarmJob.id == job_id,
                    HostFarmJob.project_id == project_id,
                    HostFarmJob.kind == self.kind,
                )
            )
        )
        if not job:
            raise NotFoundError("Задача scanner не найдена")
        return job
