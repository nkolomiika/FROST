"""Ферма IP: вставленный список адресов → обратный резолв → пробив портов.

Отличия от фермы хостов:

  * принимаются только IP-литералы (имя хоста — ошибка с подсказкой);
  * добавляется фаза обратного резолва: в какие имена резолвится адрес;
  * одна строка на адрес, сколько бы имён за ним ни стояло — имена лежат
    в JSON-колонке host_ip_addresses.hostnames.

Родительский Host всё равно нужен (Port → host_ip_addresses → hosts), но
помечается origin='ip' и не показывается в списке хостов: пользователь
добавлял адрес, а не хост, и безымянная строка в Hosts была бы мусором.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import and_, delete, select
from sqlalchemy.orm import selectinload
from sqlalchemy.orm.attributes import set_committed_value

from app.config import get_settings
from app.enums import HostStatus, ReconJobKind, ReconJobStatus
from app.exceptions import ValidationError
from app.farm import core
from app.farm.core import ParsedTarget, ProbeResult
from app.farm.fingerprint import Tech, detect_services, has_cloudflare
from app.farm.hosts import HostFarmService
from app.farm.resolver import ResolvedHost, ResolvedName, ReverseResult, reverse_resolve
from app.models import Host, HostFarmJob, HostIpAddress, ProjectHiddenIp
from app.schemas import HostFarmPortResult, IpFarmIpResult, IpFarmResult
from app.ws_manager import ws_manager

settings = get_settings()


class IpFarmService(HostFarmService):
    """Парсинг + обратный резолв + пробив + запись адресов проекта."""

    kind = ReconJobKind.IPS

    # ------------------------------------------------------------------ parse

    @staticmethod
    def parse_ip_targets(raw: str) -> tuple[dict[str, ParsedTarget], list[str]]:
        """Как parse_targets, но имена хостов отклоняются с подсказкой."""
        targets, errors = core.parse_targets(raw)
        ip_targets: dict[str, ParsedTarget] = {}
        for name, tgt in targets.items():
            if tgt.is_ip:
                ip_targets[name] = tgt
            else:
                errors.append(f"{name}: не IP-адрес — используйте импорт хостов")
        return ip_targets, errors

    # ---------------------------------------------------------------- resolve

    async def _existing_target_keys(self, project_id: int, targets: dict[str, ParsedTarget]) -> set[str]:
        """Адреса, уже заведённые строкой origin='ip' (те же предикаты, что у
        _find_or_attach_host). Доменные хосты, чей адрес совпал, не в счёт: ферма
        IP держит свои замеры на своих origin='ip' строках, повторным считается
        только уже импортированный тем же способом адрес."""
        ip_keys = list(targets.keys())
        if not ip_keys:
            return set()
        rows = await self.db.scalars(
            select(HostIpAddress.ip_address)
            .join(Host, Host.id == HostIpAddress.host_id)
            .where(
                and_(
                    Host.project_id == project_id,
                    Host.origin == "ip",
                    HostIpAddress.ip_address.in_(ip_keys),
                )
            )
        )
        return {ip for ip in rows.all() if ip}

    async def _load_project_hostnames(self, project_id: int) -> list[str]:
        """Имена хостов проекта — для перекрёстной сверки в обратном резолве.

        Единственное обращение к БД до фазы записи, и оно выполняется ДО любого
        gather: конкурентно входить в async-сессию нельзя.
        """
        rows = await self.db.scalars(
            select(Host.hostname).where(
                and_(Host.project_id == project_id, Host.hostname.isnot(None))
            )
        )
        return [h for h in rows.all() if h]

    # ---------------------------------------------------------------- persist

    async def _find_or_attach_host(
        self, project_id: int, ip: str, names: list[ResolvedName]
    ) -> tuple[Host, bool, bool]:
        """Куда положить адрес. Первое совпадение выигрывает:

        1. существующий origin='ip' хост с этим адресом → переиспользуем
           (идемпотентный повторный скан);
        2. иначе новый Host(origin='ip').

        Раньше адрес подшивался к ДОМЕННОМУ хосту (по существующему адресу, по
        legacy-зеркалу Host.ip_address, по подтверждённому PTR-имени). Но порты
        висят на общем HostIpAddress, а _upsert_port ключуется на ip_address_id,
        поэтому пробив по IP затирал порты, снятые пробивом по домену. Пользователь
        хочет, чтобы статус по домену и по IP определялся раздельно — поэтому ферма
        IP держит свои результаты на СВОИХ origin='ip' хостах и к доменным не
        подшивается. Имена в колонке Hostname всё равно показываются: они приходят
        из hostnames-JSON (reverse_resolve), а не из привязки портов, поэтому
        параметр names здесь больше не нужен для привязки.

        Возвращает (host, host_created, attached_to_existing).
        """
        existing = await self.db.scalar(
            select(Host)
            .options(selectinload(Host.ip_addresses))
            .join(HostIpAddress, HostIpAddress.host_id == Host.id)
            .where(
                and_(
                    Host.project_id == project_id,
                    Host.origin == "ip",
                    HostIpAddress.ip_address == ip,
                )
            )
            .order_by(Host.created_at)
        )
        if existing is not None:
            return existing, False, True

        host = Host(
            project_id=project_id,
            hostname=None,
            ip_address=ip,
            status=HostStatus.UNKNOWN,
            origin="ip",
        )
        self.db.add(host)
        await self.db.flush()
        set_committed_value(host, "ip_addresses", [])
        return host, True, False

    async def _persist_ips(
        self,
        project_id: int,
        targets: dict[str, ParsedTarget],
        resolved: dict[str, ResolvedHost],
        reverse: dict[str, ReverseResult],
        probes: list[ProbeResult],
        actor_id: int,
        techs_by_port: dict[tuple[str, int], list[Tech]] | None = None,
    ) -> IpFarmResult:
        result = IpFarmResult()
        techs_by_port = techs_by_port or {}
        probes_by_ip: dict[str, list[ProbeResult]] = {}
        for p in probes:
            probes_by_ip.setdefault(p.hostname, []).append(p)

        # Коммит на каждый адрес: фронт поллит задачу и перечитывает список,
        # поэтому строки появляются по мере пробива, а сбой одного адреса
        # не откатывает уже импортированные.
        for ip in targets:
            r = resolved.get(ip)
            rev = reverse.get(ip) or ReverseResult(ip=ip)
            ip_probes = probes_by_ip.get(ip, [])
            responded = any(p.responded for p in ip_probes)
            if r is not None and r.blocked:
                status = HostStatus.UNKNOWN  # внутренний — не пробивали
            elif responded:
                status = HostStatus.UP
            else:
                status = HostStatus.DOWN

            try:
                host, host_created, attached = await self._find_or_attach_host(project_id, ip, rev.names)
                # Статус трогаем только у собственных строк фермы IP: у настоящего
                # хоста он выведен из пробива его имени, и один из адресов,
                # ответивший или нет, не должен его переписывать.
                if host.origin == "ip":
                    host.status = status

                # CF на пробиве: заголовки ответа (server=cloudflare / cf-ray) ИЛИ
                # детект технологий. У голого IP без SNI Cloudflare обычно молчит —
                # тогда сигнала нет и _ensure_ips прежний флаг не понижает.
                cf_hint = any(p.cloudflare for p in ip_probes) or has_cloudflare(
                    [t for pp in ip_probes for t in techs_by_port.get((pp.hostname, pp.port), [])]
                )
                ip_existed = any(a.ip_address == ip for a in host.ip_addresses)
                # is_cloudflare проставляет _ensure_ips (со стики-логикой), отдельно не трогаем.
                ip_row = await self._ensure_ips(
                    host, [ip], cloudflare_hint=cf_hint, cf_responded=responded
                )
                if ip_row is None:
                    raise RuntimeError("не удалось завести адрес")
                # JSON-колонка не отслеживает мутацию на месте — присваиваем целиком.
                ip_row.hostnames = [n.as_dict() for n in rev.names]

                port_results: list[HostFarmPortResult] = []
                ports_created = ports_updated = 0
                if r is not None and not r.blocked:
                    port_results, ports_created, ports_updated = await self._write_ports(
                        host, ip_row, ip_probes, techs_by_port
                    )
                ip_out = IpFarmIpResult(
                    ip_address=ip,
                    host_id=host.id,
                    hostnames=[n.as_dict() for n in rev.names],
                    is_cloudflare=ip_row.is_cloudflare,
                    created=host_created,
                    attached_to_existing_host=attached,
                    ports=port_results,
                )
                await self.db.commit()
            except Exception as exc:  # noqa: BLE001 — один адрес не валит весь импорт
                await self.db.rollback()
                result.errors.append(f"{ip}: {type(exc).__name__}")
                continue

            result.ips_created += int(not ip_existed)
            result.ips_updated += int(ip_existed)
            if status is HostStatus.UP:
                result.ips_online += 1
            elif status is HostStatus.DOWN:
                result.ips_offline += 1
            result.hostnames_found += len(rev.names)
            result.ports_created += ports_created
            result.ports_updated += ports_updated
            result.ips.append(ip_out)

        await self.audit.log(
            "CREATE",
            user_id=actor_id,
            entity_type="ip_farm",
            entity_id=None,
            details={"project_id": str(project_id), **result.model_dump(exclude={"ips"})},
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
        resolve_hosts: bool = True,
    ) -> IpFarmResult:
        targets, parse_errors = self.parse_ip_targets(raw)
        if len(targets) > settings.farm_max_targets:
            raise ValidationError(f"Слишком много IP: {len(targets)} (максимум {settings.farm_max_targets})")
        # Уже добавленные адреса (посчитаны в create_job) не пробиваем заново.
        skip = set(skip_targets or [])
        skipped = [k for k in targets if k in skip]
        targets = {k: t for k, t in targets.items() if k not in skip}
        parse_errors.extend(core.trim_excess_ports(targets))

        project_hostnames = await self._load_project_hostnames(project_id)
        resolved = await self._resolve_dns(list(targets.keys()))
        reverse = await reverse_resolve(list(targets.keys()), project_hostnames)
        probes = await self._probe_all(targets, resolved, transport=transport)
        techs_by_port = await detect_services(probes, detector=detector)
        result = await self._persist_ips(project_id, targets, resolved, reverse, probes, actor_id, techs_by_port)

        result.targets_parsed = len(targets)
        result.targets_invalid = sum(1 for e in parse_errors if ": не распознан" in e or ": не IP-адрес" in e)
        result.ips_skipped = len(skipped)
        result.errors = parse_errors + [r.error for r in resolved.values() if r.error]

        # Цепочка: подтверждённые PTR-имена адресов прогоняем фермой ХОСТОВ — она
        # найдёт их веб-порты и сервисы (по имени, с Host-заголовком) и заведёт
        # полноценный Host(origin=host). Только confirmed: неподтверждённое PTR-имя
        # контролирует владелец адреса, заводить по нему хост нельзя. Свой origin=ip
        # хост (bare-IP замер) остаётся отдельно — статусы не смешиваются.
        # resolve_ips=False обрывает рекурсию (иначе имена→IP→имена→…), когда
        # ферма хостов сама была вызвана продвижением адресов домена.
        if resolve_hosts and settings.farm_ip_resolve_hosts_enabled:
            promoted = sorted(
                {n.hostname for rev in reverse.values() for n in rev.names if n.confirmed}
            )
            if promoted:
                host_res = await HostFarmService.probe_and_import(
                    self,
                    project_id,
                    "\n".join(promoted),
                    actor_id,
                    transport=transport,
                    detector=detector,
                    resolve_ips=False,
                )
                result.hosts_promoted = host_res.hosts_created + host_res.hosts_updated
                result.errors.extend(host_res.errors)
        return result

    async def create_job(self, project_id: int, raw: str, actor_id: int) -> HostFarmJob:
        targets, _ = self.parse_ip_targets(raw)
        if len(targets) > settings.farm_max_targets:
            raise ValidationError(f"Слишком много IP: {len(targets)} (максимум {settings.farm_max_targets})")
        if not targets:
            raise ValidationError("Не удалось распознать ни одного IP-адреса")
        # Явное «Add IPs» снимает адреса со скрытия: если пользователь раньше удалил
        # адрес из списка IP, повторное добавление возвращает его в список.
        await self.db.execute(
            delete(ProjectHiddenIp).where(
                and_(ProjectHiddenIp.project_id == project_id, ProjectHiddenIp.ip_address.in_(list(targets.keys())))
            )
        )
        # Уже добавленные адреса фиксируем синхронно — воркер исключит их из пробива.
        existing = await self._existing_target_keys(project_id, targets)
        new_count = len(targets) - len(existing)
        # Заготовок, в отличие от фермы хостов, не создаём: до обратного резолва
        # неизвестно, заводить ли новый Host или подшить адрес к существующему.
        # Строки всё равно появляются по ходу — _persist_ips коммитит поадресно.
        job = HostFarmJob(
            project_id=project_id,
            created_by=actor_id,
            kind=self.kind,
            status=ReconJobStatus.PENDING,
            targets_total=new_count,
            raw=raw,
            skipped_targets=sorted(existing),
        )
        # Пробивать нечего (все адреса уже добавлены) — закрываем задачу сразу и не
        # будим воркер: иначе фронт показал бы «Probing 0 IPs…» и зря поллил.
        if new_count == 0:
            job.status = ReconJobStatus.DONE
            job.result = IpFarmResult(ips_skipped=len(existing)).model_dump()
            job.finished_at = datetime.now(UTC)
        self.db.add(job)
        await self.db.commit()
        await self.db.refresh(job)
        return job
