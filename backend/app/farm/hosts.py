"""Ферма хостов: вставленный список имён → пробив портов → Host/Port.

Фаза 4 (запись) — единственная, которая трогает БД, и делает это строго
последовательным `for` с коммитом на каждый хост: async-сессию нельзя входить
конкурентно, а похостный коммит даёт фронту прогрессивную загрузку статусов.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import and_, delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.orm.attributes import set_committed_value

from app.cloudflare import is_cloudflare_ip
from app.config import get_settings
from app.enums import HostStatus, PortState, Protocol, ReconJobKind, ReconJobStatus
from app.exceptions import NotFoundError, ValidationError
from app.farm import core
from app.farm.core import ParsedTarget, ProbeCandidate, ProbeResult
from app.farm.fingerprint import Tech, detect_services, has_cloudflare
from app.farm.resolver import ResolvedHost, resolve_forward
from app.models import Host, HostFarmJob, HostIpAddress, Port, Service
from app.schemas import HostFarmHostResult, HostFarmPortResult, HostFarmResult
from app.services import AuditService
from app.ws_manager import ws_manager

settings = get_settings()

# Реэкспорт для обратной совместимости импортов вида `from app.farm import HTTPS_PORTS`.
HTTPS_PORTS = core.HTTPS_PORTS
TOP_WEB_PORTS = core.TOP_WEB_PORTS


class HostFarmService:
    """Парсинг + пробив + запись результатов пробива хостов проекта."""

    kind = ReconJobKind.HOSTS

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.audit = AuditService(db)

    # ------------------------------------------------------------------ parse
    # parse_targets остаётся точкой входа класса (зовётся как HostFarmService.parse_targets
    # из роутера/тестов и как self.parse_targets ниже); остальное берётся из farm.core.
    parse_targets = staticmethod(core.parse_targets)

    def _candidates_for(self, tgt: ParsedTarget) -> list[ProbeCandidate]:
        return core.candidates_for(tgt)

    # -------------------------------------------------------------- resolve

    async def _resolve_dns(self, hostnames: list[str]) -> dict[str, ResolvedHost]:
        return await resolve_forward(hostnames)

    # ---------------------------------------------------------------- probe

    async def _probe_all(
        self,
        targets: dict[str, ParsedTarget],
        resolved: dict[str, ResolvedHost],
        *,
        transport=None,
    ) -> list[ProbeResult]:
        candidates: list[ProbeCandidate] = []
        for host, tgt in targets.items():
            r = resolved.get(host)
            if r is None or r.ip is None or r.blocked:
                continue  # DNS-фейл или заблокирован → не пробиваем
            candidates.extend(self._candidates_for(tgt))
        return await core.probe_candidates(candidates, transport=transport)

    # -------------------------------------------------------------- persist

    async def _find_or_create_host(
        self, project_id: int, tgt: ParsedTarget, r: ResolvedHost | None, status: HostStatus
    ) -> tuple[Host, bool]:
        ip_value = r.ip if (r and r.ip) else None
        if tgt.is_ip:
            query = select(Host).options(selectinload(Host.ip_addresses)).where(
                and_(Host.project_id == project_id, Host.ip_address == tgt.hostname)
            )
        else:
            query = select(Host).options(selectinload(Host.ip_addresses)).where(
                and_(Host.project_id == project_id, Host.hostname == tgt.hostname)
            )
        existing = await self.db.scalar(query)
        if existing:
            existing.status = status
            return existing, False
        host = Host(
            project_id=project_id,
            hostname=None if tgt.is_ip else tgt.hostname,
            ip_address=ip_value,
            status=status,
            origin="host",
        )
        self.db.add(host)
        await self.db.flush()
        set_committed_value(host, "ip_addresses", [])  # тот же MissingGreenlet-guard, что в create_host
        return host, True

    async def _ensure_ips(
        self, host: Host, ips: list[str], cloudflare_hint: bool = False, cf_responded: bool = False
    ) -> HostIpAddress | None:
        """Заводит ВСЕ разрешённые адреса хоста; первый становится primary.

        За одним именем обычно стоит несколько A/AAAA-записей — раньше писался
        только первый, и остальные адреса терялись. Возвращает строку primary:
        на неё вешаются порты пробива (пробивали мы именно её).

        cloudflare_hint — на портах хоста увиден Cloudflare (по заголовкам пробива
        или детектом технологий). У claude.com и подобных статический список CIDR
        даёт ложный минус (BYOIP не в опубликованных диапазонах), поэтому
        CF = (адрес в диапазонах CF) ИЛИ (сигнал CF на пробиве). Хост за CF — значит
        и его адреса это CF-edge, помечаем все.

        cf_responded — на этом скане хост реально ответил, значит отсутствие CF-сигнала
        достоверно. Если False (хост не отозвался / детект не запускался), уже
        проставленный is_cloudflare НЕ понижаем: флейк движка не должен затирать факт.

        is_cloudflare — трёхзначный: True — виден CF; False — достоверно НЕ CF (хост
        ответил, сигнала CF нет); None — неизвестно (ещё пробивается / не ответил /
        детект не запускался). Пока хост «пробится», адреса ещё не заведены, а у нового
        адреса без сигнала CF = None (unknown), а не «нет CF».
        """
        primary_row: HostIpAddress | None = None
        for idx, ip in enumerate(ips):
            cf = is_cloudflare_ip(ip) or cloudflare_hint
            # cf_state: True/False/None по силе сигнала (см. docstring).
            cf_state = True if cf else (False if cf_responded else None)
            row = next((r for r in host.ip_addresses if r.ip_address == ip), None)
            if row is None:
                is_primary = idx == 0 and not any(a.is_primary for a in host.ip_addresses)
                row = HostIpAddress(
                    host_id=host.id,
                    ip_address=ip,
                    is_primary=is_primary,
                    is_cloudflare=cf_state,
                )
                self.db.add(row)
                await self.db.flush()
                set_committed_value(row, "ports", [])
                host.ip_addresses.append(row)
                if is_primary:
                    host.ip_address = ip
            elif cf:
                row.is_cloudflare = True
            elif cf_responded:
                # Достоверный отрицательный сигнал (хост ответил, CF нет) — снимаем флаг.
                row.is_cloudflare = False
            # else: сигнала нет — оставляем прежнее значение (не понижаем в unknown).
            if idx == 0:
                primary_row = row
        return primary_row

    async def _upsert_port(
        self,
        host: Host,
        ip_row: HostIpAddress,
        p: ProbeResult,
        state: PortState,
        techs: list[Tech] | None = None,
    ) -> bool:
        existing = await self.db.scalar(
            select(Port).where(
                and_(
                    Port.ip_address_id == ip_row.id,
                    Port.port_number == p.port,
                    Port.protocol == Protocol.TCP,
                )
            )
        )
        if existing:
            existing.state = state
            existing.http_status = p.http_status
            await self._replace_services(existing, techs)
            return False
        port = Port(
            host_id=host.id,
            ip_address_id=ip_row.id,
            port_number=p.port,
            protocol=Protocol.TCP,
            state=state,
            http_status=p.http_status,
        )
        self.db.add(port)
        await self.db.flush()
        await self._replace_services(port, techs)
        return True

    async def _replace_services(self, port: Port, techs: list[Tech] | None) -> None:
        """Заменяет технологии порта на свежедетектированные.

        techs=None — детект не запускался (whatweb выключен/недоступен): сервисы не
        трогаем. techs=[] — детект прошёл, но ничего не нашёл: чистим (порт станет
        «unknown»). Удаляем bulk-DELETE по port_id, не читая port.services —
        ленивая загрузка связи в async-сессии упала бы с MissingGreenlet.
        """
        if techs is None:
            return
        await self.db.execute(delete(Service).where(Service.port_id == port.id))
        for tech in techs:
            self.db.add(Service(port_id=port.id, name=tech.name[:100], version=tech.version, banner=None))
        await self.db.flush()

    async def _write_ports(
        self,
        host: Host,
        ip_row: HostIpAddress,
        probes: list[ProbeResult],
        techs_by_port: dict[tuple[str, int], list[Tech]],
    ) -> tuple[list[HostFarmPortResult], int, int]:
        """Пишет порты (общий код фермы хостов и IP): явные — всегда, выведенные —
        только ответившие. Возвращает (результаты для ответа, created, updated).

        techs=None у портов, для которых детект не запускался (не ответили / whatweb
        выключен), — в _replace_services их сервисы не трогаем.
        """
        results: list[HostFarmPortResult] = []
        created = updated = 0
        for p in probes:
            if not p.responded and p.inferred:
                continue
            port_state = PortState.OPEN if p.responded else PortState.FILTERED
            new_port = await self._upsert_port(
                host, ip_row, p, port_state, techs_by_port.get((p.hostname, p.port))
            )
            created += int(new_port)
            updated += int(not new_port)
            results.append(
                HostFarmPortResult(
                    port_number=p.port,
                    protocol="tcp",
                    scheme=p.scheme,
                    http_status=p.http_status,
                    state=port_state.value,
                    inferred=p.inferred,
                )
            )
        return results, created, updated

    async def _persist(
        self,
        project_id: int,
        targets: dict[str, ParsedTarget],
        resolved: dict[str, ResolvedHost],
        probes: list[ProbeResult],
        actor_id: int,
        techs_by_port: dict[tuple[str, int], list[Tech]] | None = None,
    ) -> HostFarmResult:
        result = HostFarmResult()
        techs_by_port = techs_by_port or {}
        probes_by_host: dict[str, list[ProbeResult]] = {}
        for p in probes:
            probes_by_host.setdefault(p.hostname, []).append(p)

        # Коммитим ПОХОСТНО: список хостов создаётся заранее (create_job) со статусом
        # unknown, а здесь у каждого статус/порты подтягиваются и сразу коммитятся —
        # так фронт (polling → reloadHosts) видит, как статусы «прогружаются».
        for hostname, tgt in targets.items():
            r = resolved.get(hostname)
            host_probes = probes_by_host.get(hostname, [])
            responded = any(p.responded for p in host_probes)
            if r is not None and r.blocked:
                status = HostStatus.UNKNOWN  # внутренний — не пробивали
            elif responded:
                status = HostStatus.UP
            else:
                status = HostStatus.DOWN

            try:
                host, created = await self._find_or_create_host(project_id, tgt, r, status)
                port_results: list[HostFarmPortResult] = []
                ports_created = ports_updated = 0
                if r is not None and r.ip is not None:
                    # CF на пробиве: заголовки ответа (server=cloudflare / cf-ray) ИЛИ
                    # детект технологий увидел Cloudflare — помечаем адреса CF даже
                    # когда статический CIDR-список промахнулся (BYOIP вроде claude.com).
                    cf_hint = any(p.cloudflare for p in host_probes) or has_cloudflare(
                        [t for hp in host_probes for t in techs_by_port.get((hp.hostname, hp.port), [])]
                    )
                    ip_row = await self._ensure_ips(
                        host, r.ips or [r.ip], cloudflare_hint=cf_hint, cf_responded=responded
                    )
                    if ip_row is not None and not r.blocked:
                        port_results, ports_created, ports_updated = await self._write_ports(
                            host, ip_row, host_probes, techs_by_port
                        )
                host_out = HostFarmHostResult(
                    hostname=host.hostname,
                    ip_address=host.ip_address,
                    status=status.value,
                    created=created,
                    ports=port_results,
                )
                await self.db.commit()
            except Exception as exc:  # noqa: BLE001 — один хост не валит весь импорт
                await self.db.rollback()
                result.errors.append(f"{hostname}: {type(exc).__name__}")
                continue

            result.hosts_created += int(created)
            result.hosts_updated += int(not created)
            if status is HostStatus.UP:
                result.hosts_online += 1
            elif status is HostStatus.DOWN:
                result.hosts_offline += 1
            result.ports_created += ports_created
            result.ports_updated += ports_updated
            result.hosts.append(host_out)

        await self.audit.log(
            "CREATE",
            user_id=actor_id,
            entity_type="host_farm",
            entity_id=None,
            details={"project_id": str(project_id), **result.model_dump(exclude={"hosts"})},
        )
        await ws_manager.broadcast(
            project_id,
            {"event": "imported", "entity": "host", "project_id": str(project_id), "data": {}},
        )
        return result

    # --------------------------------------------------------------- public

    async def probe_and_import(
        self,
        project_id: int,
        raw: str,
        actor_id: int,
        *,
        transport=None,
        detector=None,
        skip_targets: list[str] | None = None,
        resolve_ips: bool = True,
    ) -> HostFarmResult:
        targets, parse_errors = self.parse_targets(raw)
        if len(targets) > settings.farm_max_targets:
            raise ValidationError(f"Слишком много хостов: {len(targets)} (максимум {settings.farm_max_targets})")
        # Уже добавленные ранее цели (посчитаны в create_job до skeleton-заготовок)
        # не пробиваем заново — повторный импорт только сообщает, сколько пропущено.
        skip = set(skip_targets or [])
        skipped = [k for k in targets if k in skip]
        targets = {k: t for k, t in targets.items() if k not in skip}
        parse_errors.extend(core.trim_excess_ports(targets))

        resolved = await self._resolve_dns(list(targets.keys()))
        probes = await self._probe_all(targets, resolved, transport=transport)
        # Технологии ответивших портов (whatweb) — снимаем перед записью.
        techs_by_port = await detect_services(probes, detector=detector)
        result = await self._persist(project_id, targets, resolved, probes, actor_id, techs_by_port)

        result.targets_parsed = len(targets)
        result.targets_invalid = sum(1 for e in parse_errors if ": не распознан" in e)
        result.hosts_skipped = len(skipped)
        result.errors = parse_errors + [r.error for r in resolved.values() if r.error]

        # Цепочка (зеркало продвижения IP→хост): адреса, в которые разрезолвились
        # домены, отдельно пробиваем фермой IP. Запрос к голому IP идёт без
        # Host-заголовка и у vhost отвечает иначе, чем запрос к домену, поэтому
        # порты адреса нельзя переиспользовать из пробива домена — им нужен свой
        # замер. Ферма IP заводит их строкой origin='ip' (её и показывает IPs-view).
        # Только доменные цели: IP-литерал из списка хостов уже пробит как есть.
        # resolve_hosts=False обрывает рекурсию (иначе IP→имена→IP→…).
        if resolve_ips and settings.farm_host_resolve_ips_enabled:
            from app.farm.ips import IpFarmService  # локальный импорт: ips ↰ hosts

            ips = sorted(
                {
                    r.ip
                    for host, tgt in targets.items()
                    if not tgt.is_ip and (r := resolved.get(host)) is not None and r.ip and not r.blocked
                }
            )
            if ips:
                ip_res = await IpFarmService(self.db).probe_and_import(
                    project_id,
                    "\n".join(ips),
                    actor_id,
                    transport=transport,
                    detector=detector,
                    resolve_hosts=False,
                )
                result.ips_promoted = ip_res.ips_created + ip_res.ips_updated
                result.errors.extend(ip_res.errors)
        return result

    async def _existing_target_keys(self, project_id: int, targets: dict[str, ParsedTarget]) -> set[str]:
        """Ключи целей, уже присутствующих в проекте (те же предикаты, что у
        _find_or_create_host): домен — по hostname, IP-литерал — по ip_address.

        Единственное обращение к БД, и оно синхронное в запросе (create_job),
        поэтому конкурентного входа в сессию нет.
        """
        name_keys = [k for k, t in targets.items() if not t.is_ip]
        ip_keys = [k for k, t in targets.items() if t.is_ip]
        existing: set[str] = set()
        if name_keys:
            rows = await self.db.scalars(
                select(Host.hostname).where(
                    and_(Host.project_id == project_id, Host.hostname.in_(name_keys))
                )
            )
            existing.update(h for h in rows.all() if h)
        if ip_keys:
            rows = await self.db.scalars(
                select(Host.ip_address).where(
                    and_(Host.project_id == project_id, Host.ip_address.in_(ip_keys))
                )
            )
            existing.update(h for h in rows.all() if h)
        return existing

    async def _ensure_skeletons(
        self, project_id: int, targets: dict[str, ParsedTarget], existing: set[str]
    ) -> None:
        """Заводит хосты-заготовки (status unknown) сразу, чтобы список показался
        мгновенно; статус/порты подтянет фоновый пробив. Уже добавленные (existing)
        не трогаем — их и не пробиваем: повторный импорт их пропускает."""
        for hostname, tgt in targets.items():
            if hostname in existing:
                continue
            self.db.add(
                Host(
                    project_id=project_id,
                    hostname=None if tgt.is_ip else hostname,
                    ip_address=hostname if tgt.is_ip else None,
                    status=HostStatus.UNKNOWN,
                    origin="host",
                )
            )
        await self.db.commit()

    async def create_job(self, project_id: int, raw: str, actor_id: int) -> HostFarmJob:
        targets, _ = self.parse_targets(raw)
        if len(targets) > settings.farm_max_targets:
            raise ValidationError(f"Слишком много хостов: {len(targets)} (максимум {settings.farm_max_targets})")
        if not targets:
            raise ValidationError("Не удалось распознать ни одного хоста")
        # Существующие цели фиксируем ДО заготовок: иначе заготовка этой же задачи
        # выглядела бы как «уже добавленная». Воркер исключит их из пробива.
        existing = await self._existing_target_keys(project_id, targets)
        new_count = len(targets) - len(existing)
        # Заготовки создаём синхронно в запросе — фронт после ответа сразу видит хосты.
        await self._ensure_skeletons(project_id, targets, existing)
        job = HostFarmJob(
            project_id=project_id,
            created_by=actor_id,
            kind=self.kind,
            status=ReconJobStatus.PENDING,
            targets_total=new_count,
            raw=raw,
            skipped_targets=sorted(existing),
        )
        # Пробивать нечего (все цели уже добавлены) — закрываем задачу сразу и не
        # будим воркер: иначе фронт показал бы «Probing 0 hosts…» и зря поллил.
        if new_count == 0:
            job.status = ReconJobStatus.DONE
            job.result = HostFarmResult(hosts_skipped=len(existing)).model_dump()
            job.finished_at = datetime.now(UTC)
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
