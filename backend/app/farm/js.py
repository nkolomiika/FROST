"""Ферма JS: идёт на домены проекта, находит .js, скачивает и грепает.

Те же четыре фазы, что и у остальных ферм, и то же правило: сеть — без БД,
БД трогает только persist, последовательно с коммитом на файл.

  1. domains   — какие домены сканировать (create_job снимает их в job.raw).
  2. discover  — GET корня домена → extract_js_urls (в памяти).
  3. download  — GET каждого .js через SSRF-transport, греп секретов и путей.
  4. persist   — апсерт JsFile по (project_id, url) под доменным хостом + JsSecret.

Скан «в памяти»: файл читается, грепается и выбрасывается — в БД только находки
и метаданные. Отдельного воркера/очереди не нужно: kind="js" едет по той же
recon-очереди, диспетч по kind в jobs.py.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import posixpath
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import unquote, urlparse

import httpx
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import get_settings
from app.enums import ReconJobKind, ReconJobStatus
from app.exceptions import NotFoundError, ValidationError
from app.farm import jsscan
from app.farm.core import build_transport
from app.farm.resolver import is_ip_literal, resolve_forward
from app.models import Host, HostFarmJob, JsFile, JsSecret
from app.schemas import JsFarmFileResult, JsFarmResult
from app.services import AuditService
from app.ws_manager import ws_manager

settings = get_settings()


@dataclass
class ScannedFile:
    url: str
    hostname: str
    status: str  # ok | failed | too_large
    error: str | None = None
    sha256: str | None = None
    size_bytes: int | None = None
    content_type: str | None = None
    secrets: list[jsscan.Secret] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)


class JsFarmService:
    """Скан JS-файлов доменов проекта на секреты и пути."""

    kind = ReconJobKind.JS

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.audit = AuditService(db)

    # -------------------------------------------------------------- domains

    async def _project_domains(self, project_id: int) -> list[str]:
        """Домены проекта: хосты с hostname и origin=host (не служебные IP-строки)."""
        rows = await self.db.scalars(
            select(Host.hostname).where(
                and_(Host.project_id == project_id, Host.origin == "host", Host.hostname.isnot(None))
            )
        )
        # Дедуп, IP-литералы отсекаем: ферма JS работает по доменам.
        seen: list[str] = []
        for h in rows.all():
            name = (h or "").strip().lower()
            if name and not is_ip_literal(name) and name not in seen:
                seen.append(name)
        return seen

    @staticmethod
    def _parse_raw(raw: str) -> list[str]:
        out: list[str] = []
        for line in (raw or "").splitlines():
            name = line.strip().lower()
            if name and name not in out:
                out.append(name)
        return out

    # ------------------------------------------------------ discover + scan

    async def _fetch(
        self, client: httpx.AsyncClient, url: str, *, max_bytes: int
    ) -> tuple[str | None, bytes | None, str | None, str | None]:
        """GET с капом размера. Возвращает (content_type, body, status, error).

        status: ok | too_large | failed. Тело читаем потоково и обрываем на лимите.
        """
        try:
            async with client.stream("GET", url) as resp:
                ctype = resp.headers.get("content-type")
                if resp.status_code >= 400:
                    # 404/500 отдают HTML-ошибку, а не JS — не грепаем как файл.
                    return ctype, None, "failed", f"http_{resp.status_code}"
                chunks: list[bytes] = []
                total = 0
                async for chunk in resp.aiter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        return ctype, None, "too_large", None
                    chunks.append(chunk)
                return ctype, b"".join(chunks), "ok", None
        except Exception as exc:  # noqa: BLE001 — любой сбой = файл не скачан
            return None, None, "failed", type(exc).__name__

    async def _discover_and_scan(
        self, domains: list[str], *, transport: httpx.AsyncBaseTransport | None = None
    ) -> tuple[list[ScannedFile], list[str]]:
        """Фазы 2–3 без БД: находит .js по доменам, качает и грепает."""
        errors: list[str] = []
        # SSRF-предфильтр: домены, резолвящиеся во внутренние/битые адреса, не трогаем.
        resolved = await resolve_forward(domains)

        limits = httpx.Limits(max_connections=settings.js_farm_max_concurrency)
        real_transport = build_transport(transport, limits)
        timeout = httpx.Timeout(settings.js_farm_download_timeout_seconds)
        sem = asyncio.Semaphore(settings.js_farm_max_concurrency)

        # follow_redirects=True: чанки часто отдаются 30x; SSRF-transport ре-гейтит
        # каждый хоп, поэтому редирект во внутреннюю сеть будет отклонён.
        async with httpx.AsyncClient(
            follow_redirects=True, max_redirects=3, timeout=timeout, transport=real_transport
        ) as client:

            async def discover(domain: str) -> tuple[str, list[str]]:
                r = resolved.get(domain)
                if r is None or r.ip is None or r.blocked:
                    if r is not None and r.error:
                        errors.append(r.error)
                    return domain, []
                # Корень домена: сначала https, потом http.
                for base in (f"https://{domain}/", f"http://{domain}/"):
                    async with sem:
                        ctype, body, status, _ = await self._fetch(
                            client, base, max_bytes=settings.js_farm_max_file_bytes
                        )
                    if status == "ok" and body is not None:
                        urls = jsscan.extract_js_urls(body.decode("utf-8", "replace"), base)
                        return domain, urls[: settings.js_farm_max_files_per_host]
                errors.append(f"{domain}: корень не отвечает")
                return domain, []

            discovered = await asyncio.gather(*(discover(d) for d in domains))

            # Кап на общее число файлов; помним, какому домену принадлежит URL.
            jobs: list[tuple[str, str]] = []
            for domain, urls in discovered:
                for url in urls:
                    if len(jobs) >= settings.js_farm_max_total_files:
                        break
                    jobs.append((domain, url))

            async def scan(domain: str, url: str) -> ScannedFile:
                async with sem:
                    ctype, body, status, error = await self._fetch(
                        client, url, max_bytes=settings.js_farm_max_file_bytes
                    )
                if status != "ok" or body is None:
                    return ScannedFile(url=url, hostname=domain, status=status, error=error, content_type=ctype)
                text = body.decode("utf-8", "replace")
                return ScannedFile(
                    url=url,
                    hostname=domain,
                    status="ok",
                    sha256=hashlib.sha256(body).hexdigest(),
                    size_bytes=len(body),
                    content_type=ctype,
                    secrets=jsscan.find_secrets(text),
                    endpoints=jsscan.find_paths(text),
                )

            scanned = await asyncio.gather(*(scan(d, u) for d, u in jobs)) if jobs else []
        return list(scanned), errors

    # --------------------------------------------------------------- persist

    async def _persist(
        self, project_id: int, files: list[ScannedFile], errors: list[str], actor_id: int
    ) -> JsFarmResult:
        result = JsFarmResult()
        result.errors = list(errors)
        # Домены → их Host (origin=host), чтобы привязать файлы.
        host_by_name: dict[str, Host] = {}
        rows = await self.db.scalars(
            select(Host).where(and_(Host.project_id == project_id, Host.origin == "host"))
        )
        for host in rows.all():
            if host.hostname:
                host_by_name.setdefault(host.hostname.lower(), host)

        domains = {f.hostname for f in files}
        result.domains_scanned = len(domains)
        result.files_found = len(files)

        for f in files:
            host = host_by_name.get(f.hostname)
            if host is None:
                result.errors.append(f"{f.hostname}: хост не найден")
                continue
            try:
                existing = await self.db.scalar(
                    select(JsFile)
                    .options(selectinload(JsFile.secrets))
                    .where(and_(JsFile.project_id == project_id, JsFile.url == f.url))
                )
                js = existing or JsFile(project_id=project_id, host_id=host.id, url=f.url)
                js.host_id = host.id
                js.status = f.status
                js.error = f.error
                js.sha256 = f.sha256
                js.size_bytes = f.size_bytes
                js.content_type = f.content_type
                js.endpoints = list(f.endpoints)
                js.endpoint_count = len(f.endpoints)
                js.secret_count = len(f.secrets)
                js.fetched_at = datetime.now(UTC)
                if existing is None:
                    self.db.add(js)
                    await self.db.flush()
                else:
                    # Пересканировали — старые секреты заменяем целиком.
                    for old in list(js.secrets):
                        await self.db.delete(old)
                    await self.db.flush()
                for s in f.secrets:
                    self.db.add(
                        JsSecret(
                            js_file_id=js.id,
                            kind=s.kind,
                            match_preview=s.match_preview,
                            snippet=s.snippet,
                            severity=s.severity,
                        )
                    )
                await self.db.commit()
            except Exception as exc:  # noqa: BLE001 — один файл не валит весь скан
                await self.db.rollback()
                result.errors.append(f"{f.url}: {type(exc).__name__}")
                continue

            if f.status == "ok":
                result.files_scanned += 1
            else:
                result.files_failed += 1
            result.secrets_found += len(f.secrets)
            result.endpoints_found += len(f.endpoints)
            result.files.append(
                JsFarmFileResult(
                    url=f.url,
                    hostname=f.hostname,
                    status=f.status,
                    secret_count=len(f.secrets),
                    endpoint_count=len(f.endpoints),
                )
            )

        await self.audit.log(
            "CREATE",
            user_id=actor_id,
            entity_type="js_farm",
            entity_id=None,
            details={"project_id": str(project_id), **result.model_dump(exclude={"files"})},
        )
        await ws_manager.broadcast(
            project_id,
            {"event": "imported", "entity": "js", "project_id": str(project_id), "data": {}},
        )
        return result

    # --------------------------------------------------------------- public

    async def probe_and_import(
        self, project_id: int, raw: str, actor_id: int, *, transport: httpx.AsyncBaseTransport | None = None
    ) -> JsFarmResult:
        domains = self._parse_raw(raw) or await self._project_domains(project_id)
        if not domains:
            return JsFarmResult()
        files, errors = await self._discover_and_scan(domains, transport=transport)
        return await self._persist(project_id, files, errors, actor_id)

    async def create_job(self, project_id: int, raw: str, actor_id: int) -> HostFarmJob:
        # Снимок доменов в raw: воркер живёт в другом процессе и получает только id.
        domains = self._parse_raw(raw) or await self._project_domains(project_id)
        if not domains:
            raise ValidationError("В проекте нет доменов для скана JS")
        job = HostFarmJob(
            project_id=project_id,
            created_by=actor_id,
            kind=self.kind,
            status=ReconJobStatus.PENDING,
            targets_total=len(domains),
            raw="\n".join(domains),
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
            raise NotFoundError("Задача фермы не найдена")
        return job

    # --------------------------------------------------------------- archive

    @staticmethod
    def _entry_name(url: str, used: set[str]) -> str:
        """Путь файла внутри архива: `<host>/<имя.js>`, коллизии разводятся суффиксом.

        Берём хост и последний сегмент пути из самого URL — Host-join не нужен, а
        группировка по домену совпадает с тем, как раздел JS показывает файлы.
        """
        parsed = urlparse(url)
        host = parsed.netloc or "unknown"
        base = posixpath.basename(unquote(parsed.path)) or "index.js"
        # Чистим имя от разделителей путей — иначе один файл «вылезет» из своей папки.
        base = base.replace("/", "_").replace("\\", "_") or "index.js"
        name = f"{host}/{base}"
        if name not in used:
            used.add(name)
            return name
        stem, dot, ext = base.rpartition(".")
        i = 2
        while True:
            variant = f"{host}/{(stem or base)}-{i}{dot}{ext}"
            if variant not in used:
                used.add(variant)
                return variant
            i += 1

    async def build_archive(
        self,
        project_id: int,
        host_id: int | None = None,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> tuple[str, bytes]:
        """Собирает zip из сохранённых URL JS-файлов, докачивая их по требованию.

        Файлы в БД не хранятся (скан в памяти), поэтому архив — это повторное
        скачивание известных URL через тот же SSRF-safe транспорт, что и скан.
        Контент может отличаться от момента скана (ключ мог быть ротирован).
        Скоуп: один хост (`host_id`) или все домены проекта.
        """
        conds = [JsFile.project_id == project_id]
        if host_id is not None:
            conds.append(JsFile.host_id == host_id)
        rows = (await self.db.scalars(select(JsFile).where(and_(*conds)).order_by(JsFile.url))).all()
        urls = [f.url for f in rows if f.url][: settings.js_farm_max_total_files]
        if not urls:
            raise NotFoundError("Нет JS-файлов для скачивания")

        # Имя архива — по хосту, если скоуп один хост, иначе по проекту.
        archive_host = urlparse(urls[0]).netloc if host_id is not None else None
        name = f"js-{archive_host}.zip" if archive_host else f"js-project-{project_id}.zip"

        limits = httpx.Limits(max_connections=settings.js_farm_max_concurrency)
        real_transport = build_transport(transport, limits)
        timeout = httpx.Timeout(settings.js_farm_download_timeout_seconds)
        sem = asyncio.Semaphore(settings.js_farm_max_concurrency)

        async with httpx.AsyncClient(
            follow_redirects=True, max_redirects=3, timeout=timeout, transport=real_transport
        ) as client:

            async def grab(url: str) -> tuple[str, bytes | None]:
                async with sem:
                    _ctype, body, status, _err = await self._fetch(
                        client, url, max_bytes=settings.js_farm_max_file_bytes
                    )
                return url, (body if status == "ok" else None)

            fetched = await asyncio.gather(*(grab(u) for u in urls))

        buf = io.BytesIO()
        used: set[str] = set()
        wrote = 0
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for url, body in fetched:
                if body is None:
                    continue
                zf.writestr(self._entry_name(url, used), body)
                wrote += 1
            if wrote == 0:
                # Ни один файл не докачался — кладём заметку, чтобы архив не был пустым/битым.
                zf.writestr("README.txt", "Ни один JS-файл не удалось скачать повторно.\n")
        return name, buf.getvalue()
