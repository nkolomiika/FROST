"""Постановка и прогон задач рекон-фермы.

Задача живёт в host_farm_jobs со своим kind (hosts|ips) и проходит цикл
pending → queued → running → done|failed. Ставит её роутер (status=pending),
дальше её забирает recon-worker: relay публикует pending-задачи в RabbitMQ,
consumer вызывает run_recon_job. Так тяжёлый сетевой рекон не живёт в процессе
API и переживает его перезапуск.

Флаг recon_worker_enabled=false возвращает старое поведение — прогон через
BackgroundTasks в том же процессе. Нужен для однопроцессной разработки и
тестов, где RabbitMQ нет.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from fastapi import BackgroundTasks
from sqlalchemy import select

from app.config import get_settings
from app.database import SessionLocal
from app.enums import ReconJobKind, ReconJobStatus
from app.farm.hosts import HostFarmService
from app.farm.ips import IpFarmService
from app.farm.js import JsFarmService
from app.farm.portscan import PortScanFarmService
from app.farm.reverse import ReverseFarmService
from app.farm.subs import SubdomainFarmService
from app.models import HostFarmJob

settings = get_settings()
logger = logging.getLogger(__name__)

_SERVICES = {
    ReconJobKind.HOSTS: HostFarmService,
    ReconJobKind.IPS: IpFarmService,
    ReconJobKind.JS: JsFarmService,
    ReconJobKind.SUBS: SubdomainFarmService,
    ReconJobKind.PORTS: PortScanFarmService,
    ReconJobKind.REVERSE: ReverseFarmService,
}

# Списки в result-блобе, которые обрезаем до recon_result_max_items (счётчики целы).
_RESULT_LIST_FIELDS = ("hosts", "ips", "files", "errors")


def _cap_result(payload: dict, limit: int) -> dict:
    """Обрезает детальные списки result до limit — размер блоба не зависит от
    числа целей. Счётчики (hosts_created, ports_created, …) — отдельные скаляры и
    не трогаются, поэтому итоги остаются точными."""
    for key in _RESULT_LIST_FIELDS:
        val = payload.get(key)
        if isinstance(val, list) and len(val) > limit:
            payload[key] = val[:limit]
    return payload


async def run_recon_job(job_id: int) -> None:
    """Прогон задачи по одному лишь id.

    Цели, тип и автор берутся из самой задачи: воркер живёт в другом процессе и
    получает из очереди только id. Сессия своя — сессия запроса к этому моменту
    уже закрыта.
    """
    async with SessionLocal() as db:
        job = await db.scalar(select(HostFarmJob).where(HostFarmJob.id == job_id))
        if job is None:
            logger.warning("Recon job %s not found", job_id)
            return
        if job.status in (ReconJobStatus.RUNNING, ReconJobStatus.DONE):
            return  # повторная доставка из очереди — не пробиваем дважды
        service_cls = _SERVICES.get(job.kind)
        if service_cls is None:
            job.status = ReconJobStatus.FAILED
            job.error = f"Неизвестный тип задачи фермы: {job.kind}"
            job.finished_at = datetime.now(UTC)
            await db.commit()
            return

        project_id, raw, actor_id, kind = job.project_id, job.raw or "", job.created_by, job.kind
        # Уже добавленные ранее цели (посчитаны в create_job) исключаются из пробива.
        # У фермы JS такого понятия нет — её probe_and_import не принимает skip_targets.
        skip_kwargs = {} if kind == ReconJobKind.JS else {"skip_targets": job.skipped_targets or []}
        # «Add IPs» заводит ТОЛЬКО сам адрес. Кросс-рекон (обратный резолв IP → его
        # PTR-имя → прогон имени фермой хостов) вынесен в scanner-инструмент Reverse
        # DNS и на обычном добавлении не запускается — иначе добавление 8.8.8.8
        # затягивало dns.google и его сосед-адрес 8.8.4.4.
        if kind == ReconJobKind.IPS:
            skip_kwargs["resolve_hosts"] = False
        job.status = ReconJobStatus.RUNNING
        job.attempts += 1
        await db.commit()

        try:
            result = await service_cls(db).probe_and_import(project_id, raw, actor_id, **skip_kwargs)
            job = await db.scalar(select(HostFarmJob).where(HostFarmJob.id == job_id))
            if job is not None:
                job.status = ReconJobStatus.DONE
                job.result = _cap_result(result.model_dump(), settings.recon_result_max_items)
                job.last_error = None
                job.error = None  # успешный ретрай стирает след прошлого провала
                job.finished_at = datetime.now(UTC)
                await db.commit()
        except Exception as exc:  # noqa: BLE001 — фиксируем провал в самой задаче
            await db.rollback()
            job = await db.scalar(select(HostFarmJob).where(HostFarmJob.id == job_id))
            if job is not None:
                job.status = ReconJobStatus.FAILED
                msg = str(exc)[:2000]
                # last_error — ошибка последней попытки (перетирается при ретрае);
                # error фиксируем только при ТЕРМИНАЛЬНОМ провале, когда попытки
                # исчерпаны и relay уже не вернёт задачу в очередь — это и есть то,
                # что UI показывает как окончательно «упавшую» задачу.
                job.last_error = msg
                if job.attempts >= settings.recon_max_attempts:
                    job.error = msg
                job.finished_at = datetime.now(UTC)
                await db.commit()
            logger.exception("Recon job %s (%s) failed", job_id, kind)


def enqueue_job(job: HostFarmJob, background_tasks: BackgroundTasks) -> None:
    """Отдаёт задачу исполнителю: очередь (recon-worker) либо BackgroundTasks.

    В режиме очереди делать ничего не нужно — задача уже лежит в БД со
    статусом pending, её подхватит relay воркера.
    """
    # Задача, закрытая ещё в create_job (пробивать нечего — все цели уже добавлены),
    # исполнителю не отдаётся: relay берёт только pending, а BackgroundTasks впустую
    # разбудил бы run_recon_job (тот всё равно вернётся на guard status==done).
    if job.status != ReconJobStatus.PENDING:
        return
    if settings.recon_worker_enabled:
        return
    background_tasks.add_task(run_recon_job, job.id)
