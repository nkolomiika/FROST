from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings

settings = get_settings()
engine = create_async_engine(settings.database_url, echo=settings.debug, future=True)
SessionLocal = async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    """Базовый класс SQLAlchemy-моделей."""


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """DI-фабрика для получения асинхронной сессии БД."""
    async with SessionLocal() as session:
        yield session
