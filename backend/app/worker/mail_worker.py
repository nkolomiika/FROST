import asyncio
import logging
import socket
from datetime import UTC, datetime
from urllib.parse import urlsplit

import aio_pika
from sqlalchemy import and_, or_, select

from app.config import get_settings
from app.database import SessionLocal
from app.mail import send_plain_text_email
from app.models import MailJob

settings = get_settings()
logger = logging.getLogger(__name__)


async def wait_for_rabbitmq(host: str, port: int, retry_delay: float = 2.0) -> None:
    attempt = 0
    while True:
        try:
            reader, writer = await asyncio.open_connection(host, port)
        except OSError as exc:
            attempt += 1
            if attempt == 1:
                logger.info(
                    "Waiting for RabbitMQ to accept connections (host=%s, port=%s): %s",
                    host,
                    port,
                    exc,
                )
            elif attempt % 10 == 0:
                logger.info(
                    "Still waiting for RabbitMQ (attempt=%s, host=%s, port=%s)",
                    attempt,
                    host,
                    port,
                )
            await asyncio.sleep(retry_delay)
            continue

        writer.close()
        await writer.wait_closed()
        if attempt:
            logger.info(
                "RabbitMQ is reachable after %s retry attempt(s) (host=%s, port=%s)",
                attempt,
                host,
                port,
            )
        return


async def relay_pending_jobs(channel: aio_pika.abc.AbstractChannel, queue_name: str) -> None:
    while True:
        async with SessionLocal() as db:
            jobs = list(
                (
                    await db.scalars(
                        select(MailJob)
                        .where(
                            or_(
                                MailJob.status == "pending",
                                and_(MailJob.status == "failed", MailJob.attempts < settings.mail_max_attempts),
                            )
                        )
                        .order_by(MailJob.created_at.asc())
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
                job.status = "queued"
                job.published_at = datetime.now(UTC)
                job.last_error = None
                logger.info("Queued mail job %s (attempts=%s)", job.id, job.attempts)
            if jobs:
                await db.commit()
        await asyncio.sleep(5)


async def process_mail_job(job_id: int) -> None:
    async with SessionLocal() as db:
        job = await db.scalar(select(MailJob).where(MailJob.id == job_id))
        if not job or job.status == "sent":
            return
        job.status = "processing"
        job.attempts += 1
        await db.commit()
        try:
            html_body = job.payload.get("html")
            await send_plain_text_email(
                recipient_email=job.recipient_email,
                subject=job.subject,
                body=str(job.payload.get("body", "")),
                # Старые задания в очереди html не содержат — уйдут как обычный текст.
                html_body=str(html_body) if html_body else None,
            )
        except Exception as exc:
            job.last_error = str(exc)
            if job.attempts >= settings.mail_max_attempts:
                job.status = "failed"
            else:
                job.status = "pending"
            await db.commit()
            logger.exception("Mail job %s failed on attempt %s", job.id, job.attempts)
            return
        job.status = "sent"
        job.sent_at = datetime.now(UTC)
        job.last_error = None
        await db.commit()
        logger.info("Mail job %s sent to %s", job.id, job.recipient_email)


async def consume_mail_jobs(queue: aio_pika.abc.AbstractQueue) -> None:
    async with queue.iterator() as iterator:
        async for message in iterator:
            async with message.process(requeue=False):
                await process_mail_job(int(message.body.decode("utf-8")))


async def main() -> None:
    if not settings.mail_enabled:
        logger.warning("Mail worker is disabled (MAIL_ENABLED=false)")
        while True:
            await asyncio.sleep(60)
    parsed_rabbitmq_url = urlsplit(settings.rabbitmq_url)
    rabbitmq_host = parsed_rabbitmq_url.hostname or "rabbitmq"
    rabbitmq_port = parsed_rabbitmq_url.port or 5672
    attempt = 0
    logger.info(
        "Mail worker starting (queue=%s, rabbitmq=%s:%s, max_attempts=%s)",
        settings.mail_queue_name,
        rabbitmq_host,
        rabbitmq_port,
        settings.mail_max_attempts,
    )
    while True:
        try:
            attempt += 1
            resolved_addresses = sorted(
                {
                    item[4][0]
                    for item in socket.getaddrinfo(
                        rabbitmq_host,
                        rabbitmq_port,
                        type=socket.SOCK_STREAM,
                    )
                }
            )
            logger.info(
                "Connecting to RabbitMQ (attempt=%s, host=%s, port=%s, resolved=%s)",
                attempt,
                rabbitmq_host,
                rabbitmq_port,
                ",".join(resolved_addresses),
            )
            await wait_for_rabbitmq(rabbitmq_host, rabbitmq_port)
            connection = await aio_pika.connect_robust(settings.rabbitmq_url)
            async with connection:
                channel = await connection.channel()
                await channel.set_qos(prefetch_count=10)
                queue = await channel.declare_queue(settings.mail_queue_name, durable=True)
                logger.info("Connected to RabbitMQ queue '%s'", queue.name)
                relay_task = asyncio.create_task(relay_pending_jobs(channel, queue.name))
                consumer_task = asyncio.create_task(consume_mail_jobs(queue))
                await asyncio.gather(relay_task, consumer_task)
        except Exception as exc:
            logger.exception(
                "RabbitMQ connection failed (attempt=%s, host=%s, port=%s)",
                attempt,
                rabbitmq_host,
                rabbitmq_port,
            )
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
