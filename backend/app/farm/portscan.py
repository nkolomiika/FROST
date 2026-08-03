"""Scanner: скан произвольных открытых TCP-портов через nmap.

В отличие от веб-пробива фермы хостов (который стучится в курируемый топ веб-портов),
здесь ищутся любые открытые TCP-порты — по ним потом можно догонять веб-пробив,
детект сервисов и nuclei.

SSRF: цель резолвится и гейтится ДО скана, а nmap получает уже проверенный
IP-литерал (не имя) — поэтому rebind-окна нет, nmap коннектится ровно туда, что
мы проверили. Приватные/внутренние адреса во внешнем-only режиме отсекаются.

Фазы те же: parse → resolve(gate) → scan(без БД) → persist(последовательно,
коммит на хост). Разбор XML nmap — чистая функция (покрыта тестами); запуск
подменяется параметром scanner (сиид для тестов без бинаря).
"""

from __future__ import annotations

import asyncio
import shutil
from collections.abc import Awaitable, Callable
from xml.etree import ElementTree  # nmap-вывод — доверенный (наш инструмент), не внешний XML

from sqlalchemy import and_, select

from app.config import get_settings
from app.enums import HostStatus, PortState, Protocol, ReconJobKind, ReconJobStatus
from app.exceptions import NotFoundError, ValidationError
from app.farm import core
from app.farm.core import ParsedTarget
from app.farm.hosts import HostFarmService
from app.farm.resolver import ResolvedHost
from app.models import Host, HostFarmJob, Port
from app.schemas import PortScanHostResult, PortScanResult
from app.ws_manager import ws_manager

settings = get_settings()

# scanner: {ip: [open_port, ...]} — сиид для тестов без бинаря.
Scanner = Callable[[list[str]], Awaitable[dict[str, list[int]]]]


# ------------------------------------------------------------------ pure parse


def parse_nmap_xml(xml: str) -> dict[str, list[int]]:
    """{ip: [открытый tcp-порт, ...]} из nmap -oX. Битый XML → пусто."""
    try:
        root = ElementTree.fromstring(xml or "")
    except ElementTree.ParseError:
        return {}
    out: dict[str, list[int]] = {}
    for host in root.iter("host"):
        ip: str | None = None
        for addr in host.iter("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr")
                break
        if not ip:
            continue
        ports: list[int] = []
        for port in host.iter("port"):
            if port.get("protocol") != "tcp":
                continue
            state = port.find("state")
            if state is not None and state.get("state") == "open":
                try:
                    ports.append(int(port.get("portid", "")))
                except ValueError:
                    continue
        if ports:
            out.setdefault(ip, []).extend(sorted(set(ports)))
    return out


# ----------------------------------------------------------------- nmap runner


async def _run_nmap(ips: list[str]) -> tuple[dict[str, list[int]], str | None]:
    """nmap по списку IP одной командой. Нет бинаря — тихо пусто (ошибки нет)."""
    if not ips or not shutil.which(settings.portscan_nmap_bin):
        return {}, None
    args = [settings.portscan_nmap_bin, "-Pn", "-n", "-T4", "--open", "-oX", "-"]
    if settings.portscan_top_ports > 0:
        args += ["--top-ports", str(settings.portscan_top_ports)]
    else:
        args += ["-p-"]
    args += ips
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=settings.portscan_timeout_seconds)
    except (TimeoutError, OSError) as exc:
        return {}, f"nmap: {type(exc).__name__}"
    return parse_nmap_xml(out.decode("utf-8", "replace")), None


# ----------------------------------------------------------------------- service


class PortScanFarmService(HostFarmService):
    """Скан открытых TCP-портов целей проекта. Наследует persist-хелперы фермы
    хостов (_find_or_create_host / _ensure_ips), но пишет порты своим upsert'ом,
    чтобы не затирать http_status, снятый веб-пробивом."""

    kind = ReconJobKind.PORTS

    async def _project_targets(self, project_id: int) -> list[str]:
        """Хосты проекта как цели скана: имя, либо IP у безымянных строк."""
        rows = await self.db.scalars(
            select(Host.hostname, Host.ip_address).where(Host.project_id == project_id)
        )
        out: list[str] = []
        for hostname, ip in rows.all():
            target = (hostname or ip or "").strip()
            if target and target not in out:
                out.append(target)
        return out

    async def _upsert_scan_port(self, host: Host, ip_row, port_number: int) -> bool:
        """Порт как OPEN, НЕ трогая http_status/сервисы (их снимает веб-пробив)."""
        existing = await self.db.scalar(
            select(Port).where(
                and_(
                    Port.ip_address_id == ip_row.id,
                    Port.port_number == port_number,
                    Port.protocol == Protocol.TCP,
                )
            )
        )
        if existing:
            existing.state = PortState.OPEN
            return False
        self.db.add(
            Port(
                host_id=host.id,
                ip_address_id=ip_row.id,
                port_number=port_number,
                protocol=Protocol.TCP,
                state=PortState.OPEN,
            )
        )
        await self.db.flush()
        return True

    async def _persist_scan(
        self,
        project_id: int,
        targets: dict[str, ParsedTarget],
        resolved: dict[str, ResolvedHost],
        scan: dict[str, list[int]],
        actor_id: int,
    ) -> PortScanResult:
        result = PortScanResult()
        for hostname, tgt in targets.items():
            r = resolved.get(hostname)
            if r is None or r.ip is None or r.blocked:
                continue  # не резолвится или внутренний — не сканировали
            open_ports = scan.get(r.ip, [])
            status = HostStatus.UP if open_ports else HostStatus.DOWN
            try:
                host, _created = await self._find_or_create_host(project_id, tgt, r, status)
                ip_row = await self._ensure_ips(host, r.ips or [r.ip])
                created = updated = 0
                if ip_row is not None:
                    for port_number in open_ports:
                        new_port = await self._upsert_scan_port(host, ip_row, port_number)
                        created += int(new_port)
                        updated += int(not new_port)
                await self.db.commit()
            except Exception as exc:  # noqa: BLE001 — один хост не валит весь скан
                await self.db.rollback()
                result.errors.append(f"{hostname}: {type(exc).__name__}")
                continue

            if open_ports:
                result.hosts_up += 1
            result.ports_found += len(open_ports)
            result.ports_created += created
            result.ports_updated += updated
            result.hosts.append(
                PortScanHostResult(
                    hostname=host.hostname, ip_address=host.ip_address, open_ports=open_ports
                )
            )

        await self.audit.log(
            "CREATE",
            user_id=actor_id,
            entity_type="port_scan",
            entity_id=None,
            details={"project_id": str(project_id), **result.model_dump(exclude={"hosts"})},
        )
        await ws_manager.broadcast(
            project_id,
            {"event": "imported", "entity": "host", "project_id": str(project_id), "data": {}},
        )
        return result

    async def probe_and_import(
        self,
        project_id: int,
        raw: str,
        actor_id: int,
        *,
        transport=None,  # noqa: ARG002 — единый интерфейс с прочими фермами
        detector=None,  # noqa: ARG002
        skip_targets: list[str] | None = None,
        scanner: Scanner | None = None,
    ) -> PortScanResult:
        targets, parse_errors = self.parse_targets(raw)
        if len(targets) > settings.portscan_max_targets:
            raise ValidationError(
                f"Слишком много целей: {len(targets)} (максимум {settings.portscan_max_targets})"
            )
        skip = set(skip_targets or [])
        targets = {k: t for k, t in targets.items() if k not in skip}

        resolved = await self._resolve_dns(list(targets.keys()))
        # Сканируем только внешне-резолвящиеся адреса (SSRF-гейт уже в resolve_forward).
        scan_ips = sorted({r.ip for r in resolved.values() if r.ip and not r.blocked})
        run = scanner or _run_nmap
        if scanner is not None:
            scan = await run(scan_ips)
            scan_error = None
        else:
            scan, scan_error = await run(scan_ips)

        result = await self._persist_scan(project_id, targets, resolved, scan, actor_id)
        result.targets_scanned = len(targets)
        result.targets_invalid = sum(1 for e in parse_errors if ": не распознан" in e)
        result.errors = parse_errors + [r.error for r in resolved.values() if r.error] + result.errors
        if scan_error:
            result.errors.append(scan_error)
        return result

    async def create_job(self, project_id: int, raw: str, actor_id: int) -> HostFarmJob:
        targets, _ = self.parse_targets(raw)
        target_keys = list(targets) if targets else await self._project_targets(project_id)
        if not target_keys:
            raise ValidationError("Не удалось распознать ни одной цели для скана портов")
        if len(target_keys) > settings.portscan_max_targets:
            raise ValidationError(
                f"Слишком много целей: {len(target_keys)} (максимум {settings.portscan_max_targets})"
            )
        job = HostFarmJob(
            project_id=project_id,
            created_by=actor_id,
            kind=self.kind,
            status=ReconJobStatus.PENDING,
            targets_total=len(target_keys),
            raw="\n".join(target_keys),
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
