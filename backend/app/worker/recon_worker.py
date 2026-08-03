"""Воркер рекон-фермы: пробив хостов и IP отдельным процессом.

Устроен как mail_worker: relay опрашивает БД и публикует pending-задачи в
RabbitMQ, consumer забирает id и прогоняет задачу. Задачи обеих ферм (kind =
hosts | ips) идут через одну очередь — диспетч по kind внутри run_recon_job.

Зачем отдельный процесс: пробив сотен целей — это минуты сетевого ожидания.
В BackgroundTasks он занимал воркеры uvicorn и умирал вместе с перезапуском
API; здесь незавершённая задача останется pending и будет подхвачена снова.
"""

import asyncio
import logging
import socket
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import aio_pika
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import SessionLocal
from app.enums import ReconJobStatus
from app.farm import run_recon_job
from app.models import HostFarmJob

settings = get_settings()
logger = logging.getLogger(__name__)


async def reclaim_stale_jobs(
    db: AsyncSession,
    *,
    older_than_seconds: int,
    max_attempts: int,
    now: datetime | None = None,
) -> int:
    """Возвращает застрявшие в queued/running задачи в pending.

    Consumer стоит с requeue=False, а run_recon_job пропускает running/done —
    поэтому краш воркера между публикацией и записью статуса (queued) или посреди
    пробива (running) навсегда подвесил бы задачу: relay её не подхватит. Реклейм
    по updated_at (обновляется на смене статуса) переигрывает такие задачи, пока
    не исчерпаны попытки. Порог берётся с запасом больше времени пробива, чтобы не
    задеть живую задачу параллельного воркера.
    """
    cutoff = (now or datetime.now(UTC)) - timedelta(seconds=older_than_seconds)
    stale = list(
        (
            await db.scalars(
                select(HostFarmJob).where(
                    and_(
                        HostFarmJob.status.in_((ReconJobStatus.QUEUED, ReconJobStatus.RUNNING)),
                        HostFarmJob.updated_at < cutoff,
                        HostFarmJob.attempts < max_attempts,
                    )
                )
            )
        ).all()
    )
    for job in stale:
        logger.warning(
            "Reclaiming stale recon job %s (kind=%s, status=%s, attempts=%s)",
            job.id,
            job.kind,
            job.status,
            job.attempts,
        )
        job.status = ReconJobStatus.PENDING
    if stale:
        await db.commit()
    return len(stale)


async def wait_for_rabbitmq(host: str, port: int, retry_delay: float = 2.0) -> None:
    attempt = 0
    while True:
        try:
            reader, writer = await asyncio.open_connection(host, port)
        except OSError as exc:
            attempt += 1
            if attempt == 1:
                logger.info("Waiting for RabbitMQ (host=%s, port=%s): %s", host, port, exc)
            elif attempt % 10 == 0:
                logger.info("Still waiting for RabbitMQ (attempt=%s, host=%s)", attempt, host)
            await asyncio.sleep(retry_delay)
            continue

        writer.close()
        await writer.wait_closed()
        if attempt:
            logger.info("RabbitMQ is reachable after %s retry attempt(s)", attempt)
        return


async def relay_pending_jobs(channel: aio_pika.abc.AbstractChannel, queue_name: str) -> None:
    """Публикует задачи со статусом pending и помечает их queued.

    Задачи, упавшие с ошибкой, но не исчерпавшие попытки, тоже возвращаются в
    очередь — сетевой сбой не должен хоронить импорт целиком.
    """
    while True:
        async with SessionLocal() as db:
            # Реклейм застрявших задач перед выборкой pending — переигранные
            # (queued/running → pending) попадут в ту же выборку этого же тика.
            await reclaim_stale_jobs(
                db,
                older_than_seconds=settings.recon_stale_job_seconds,
                max_attempts=settings.recon_max_attempts,
            )
            jobs = list(
                (
                    await db.scalars(
                        select(HostFarmJob)
                        .where(
                            or_(
                                HostFarmJob.status == ReconJobStatus.PENDING,
                                and_(
                                    HostFarmJob.status == ReconJobStatus.FAILED,
                                    HostFarmJob.attempts < settings.recon_max_attempts,
                                ),
                            )
                        )
                        .order_by(HostFarmJob.created_at.asc())
                        .limit(50)
                    )
                ).all()
            )
            for job in jobs:
                await channel.default_exchange.publish(
                    aio_pika.Message(
                        body=str(job.id).encode("utf-8"),
                        content_type="text/plain",
                        delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
                    ),
                    routing_key=queue_name,
                )
                job.status = ReconJobStatus.QUEUED
                job.published_at = datetime.now(UTC)
                logger.info("Queued recon job %s (kind=%s, attempts=%s)", job.id, job.kind, job.attempts)
            if jobs:
                await db.commit()
        await asyncio.sleep(5)


async def consume_recon_jobs(queue: aio_pika.abc.AbstractQueue) -> None:
    async with queue.iterator() as iterator:
        async for message in iterator:
            async with message.process(requeue=False):
                await run_recon_job(int(message.body.decode("utf-8")))


async def main() -> None:
    if not settings.recon_worker_enabled:
        logger.warning("Recon worker is disabled (RECON_WORKER_ENABLED=false)")
        while True:
            await asyncio.sleep(60)

    parsed = urlsplit(settings.rabbitmq_url)
    rabbitmq_host = parsed.hostname or "rabbitmq"
    rabbitmq_port = parsed.port or 5672
    attempt = 0
    logger.info(
        "Recon worker starting (queue=%s, rabbitmq=%s:%s, max_attempts=%s)",
        settings.recon_queue_name,
        rabbitmq_host,
        rabbitmq_port,
        settings.recon_max_attempts,
    )
    while True:
        try:
            attempt += 1
            resolved = sorted(
                {
                    item[4][0]
                    for item in socket.getaddrinfo(rabbitmq_host, rabbitmq_port, type=socket.SOCK_STREAM)
                }
            )
            logger.info(
                "Connecting to RabbitMQ (attempt=%s, host=%s, port=%s, resolved=%s)",
                attempt,
                rabbitmq_host,
                rabbitmq_port,
                ",".join(resolved),
            )
            await wait_for_rabbitmq(rabbitmq_host, rabbitmq_port)
            connection = await aio_pika.connect_robust(settings.rabbitmq_url)
            async with connection:
                channel = await connection.channel()
                # Пробив — долгий, поэтому берём по одной задаче: иначе одна
                # инстанция заберёт всю пачку и остальные будут простаивать.
                await channel.set_qos(prefetch_count=1)
                queue = await channel.declare_queue(settings.recon_queue_name, durable=True)
                logger.info("Connected to RabbitMQ queue '%s'", queue.name)
                relay_task = asyncio.create_task(relay_pending_jobs(channel, queue.name))
                consumer_task = asyncio.create_task(consume_recon_jobs(queue))
                await asyncio.gather(relay_task, consumer_task)
        except Exception:  # noqa: BLE001 — переподключаемся, а не падаем
            logger.exception(
                "RabbitMQ connection failed (attempt=%s, host=%s, port=%s)",
                attempt,
                rabbitmq_host,
                rabbitmq_port,
            )
            await asyncio.sleep(5)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
