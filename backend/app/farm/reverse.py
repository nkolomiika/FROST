"""Scanner: обратный резолв IP → PTR-имя → прогон именем фермой хостов.

Этот кросс-рекон раньше делался прямо в «Add IPs» (ферма IP с
resolve_hosts=True), но добавление одного адреса тянуло за собой его PTR-имя и
СОСЕДНИЕ адреса этого имени (8.8.8.8 → dns.google → ещё и 8.8.4.4). Поэтому он
вынесен сюда: обычное добавление заводит только сам адрес, а обратный резолв с
раскрытием хостов запускается явно как инструмент scanner.

Реализация делегирует ферме IP с resolve_hosts=True — там уже есть обратный
резолв, forward-confirm и продвижение подтверждённых PTR-имён в ферму хостов;
здесь только выбор целей (весь проект или вставленный список) и сводка.
"""

from __future__ import annotations

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.enums import ReconJobKind, ReconJobStatus
from app.exceptions import NotFoundError, ValidationError
from app.farm.ips import IpFarmService
from app.models import Host, HostFarmJob, HostIpAddress
from app.schemas import ReverseFarmResult
from app.services import AuditService
from app.ws_manager import ws_manager


class ReverseFarmService:
    """Обратный резолв адресов проекта и раскрытие хостов за ними."""

    kind = ReconJobKind.REVERSE

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.audit = AuditService(db)

    async def _project_ips(self, project_id: int) -> list[str]:
        """Адреса, добавленные как IP (origin='ip') — их и резолвим обратно.

        Единственное обращение к БД до делегирования; выполняется до gather внутри
        фермы IP, поэтому конкурентного входа в сессию нет.
        """
        rows = await self.db.scalars(
            select(HostIpAddress.ip_address)
            .join(Host, Host.id == HostIpAddress.host_id)
            .where(and_(Host.project_id == project_id, Host.origin == "ip"))
        )
        out: list[str] = []
        for ip in rows.all():
            if ip and ip not in out:
                out.append(ip)
        return out

    async def _targets(self, project_id: int, raw: str) -> list[str]:
        """Вставленные IP (только литералы) либо, если пусто, все IP проекта."""
        parsed, _ = IpFarmService.parse_ip_targets(raw)
        return list(parsed) if parsed else await self._project_ips(project_id)

    async def probe_and_import(
        self,
        project_id: int,
        raw: str,
        actor_id: int,
        *,
        transport=None,
        detector=None,
        skip_targets: list[str] | None = None,
    ) -> ReverseFarmResult:
        ips = await self._targets(project_id, raw)
        result = ReverseFarmResult()
        if not ips:
            return result

        # Ферма IP с resolve_hosts=True: обратный резолв + forward-confirm +
        # продвижение подтверждённых PTR-имён в ферму хостов.
        ip_res = await IpFarmService(self.db).probe_and_import(
            project_id,
            "\n".join(ips),
            actor_id,
            transport=transport,
            detector=detector,
            skip_targets=skip_targets,
            resolve_hosts=True,
        )
        result.ips_scanned = len(ips)
        result.hostnames_found = ip_res.hostnames_found
        result.hosts_discovered = ip_res.hosts_promoted
        result.errors = list(ip_res.errors)

        await self.audit.log(
            "CREATE",
            user_id=actor_id,
            entity_type="reverse_farm",
            entity_id=None,
            details={"project_id": str(project_id), **result.model_dump()},
        )
        await ws_manager.broadcast(
            project_id,
            {"event": "imported", "entity": "host", "project_id": str(project_id), "data": {}},
        )
        return result

    async def create_job(self, project_id: int, raw: str, actor_id: int) -> HostFarmJob:
        ips = await self._targets(project_id, raw)
        if not ips:
            raise ValidationError("В проекте нет IP-адресов для обратного резолва")
        # Снимок целей в raw: воркер живёт в другом процессе и получает только id.
        job = HostFarmJob(
            project_id=project_id,
            created_by=actor_id,
            kind=self.kind,
            status=ReconJobStatus.PENDING,
            targets_total=len(ips),
            raw="\n".join(ips),
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
