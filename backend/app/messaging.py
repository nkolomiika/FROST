
import aio_pika
from aio_pika import DeliveryMode, Message

from app.config import get_settings

settings = get_settings()


async def publish_mail_job(job_id: int) -> None:
    if not settings.mail_enabled:
        return
    connection = await aio_pika.connect_robust(settings.rabbitmq_url)
    async with connection:
        channel = await connection.channel()
        queue = await channel.declare_queue(settings.mail_queue_name, durable=True)
        await channel.default_exchange.publish(
            Message(
                body=str(job_id).encode("utf-8"),
                content_type="text/plain",
                delivery_mode=DeliveryMode.PERSISTENT,
            ),
            routing_key=queue.name,
        )
