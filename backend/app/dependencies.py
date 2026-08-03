from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import Cookie, Depends, Header, Request
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.enums import UserRole
from app.exceptions import ForbiddenError, UnauthorizedError
from app.models import AgentApiToken, AgentApiTokenProjectGrant, Project, ProjectMember, User
from app.security import decode_token, hash_agent_token

settings = get_settings()
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass(frozen=True)
class AgentTokenContext:
    token_id: int
    created_by: int
    name: str
    scopes: set[str]
    all_projects: bool
    project_ids: set[int]
    # Права создателя на момент запроса. Токен не может быть шире: даже с
    # all_projects=True не-админ достаёт только свои проекты (пересечение ниже).
    creator_is_admin: bool
    creator_project_ids: set[int]


def get_client_ip(request: Request) -> str | None:
    """Возвращает IP клиента из запроса."""
    if request.client:
        return request.client.host
    return None


async def enforce_csrf(request: Request, origin: str | None = Header(default=None, alias="Origin")) -> None:
    """Проверяет Origin для state-changing запросов."""
    if request.method.upper() not in MUTATING_METHODS:
        return
    if not origin:
        raise ForbiddenError("Отсутствует заголовок Origin")
    if origin not in settings.csrf_origins:
        raise ForbiddenError("Недопустимый Origin")


async def get_current_user(
    db: AsyncSession = Depends(get_db),
    access_token: str | None = Cookie(default=None),
) -> User:
    """Извлекает текущего пользователя из access cookie."""
    if not access_token:
        raise UnauthorizedError("Требуется авторизация")
    user_id = decode_token(access_token, expected_type="access")
    user = await db.scalar(select(User).where(User.id == user_id))
    if not user or not user.is_active or user.is_locked:
        raise UnauthorizedError("Пользователь не найден или деактивирован")
    return user


async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Проверяет, что текущий пользователь является администратором."""
    if current_user.role != UserRole.ADMIN:
        raise ForbiddenError("Недостаточно прав")
    return current_user


async def require_project_access(
    project_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Project:
    """Проверяет, что пользователь имеет доступ к проекту."""
    project = await db.scalar(select(Project).where(Project.id == project_id))
    if not project:
        raise ForbiddenError("Проект не найден или недоступен")
    if current_user.role == UserRole.ADMIN:
        return project
    membership = await db.scalar(
        select(ProjectMember).where(
            and_(
                ProjectMember.project_id == project_id,
                ProjectMember.user_id == current_user.id,
            )
        )
    )
    if not membership:
        raise ForbiddenError("Нет доступа к проекту")
    return project


def role_in(user: User, allowed: Iterable[UserRole]) -> bool:
    """Проверяет принадлежность роли пользователя допустимому набору."""
    return user.role in allowed


async def get_agent_token_context(
    authorization: str | None = Header(default=None, alias="Authorization"),
    db: AsyncSession = Depends(get_db),
) -> AgentTokenContext:
    """Проверяет Bearer-токен `/api/v2` и возвращает его scopes/project grants."""
    if not authorization or not authorization.startswith("Bearer "):
        raise UnauthorizedError("Требуется Bearer token")
    raw_token = authorization.removeprefix("Bearer ").strip()
    token = await db.scalar(select(AgentApiToken).where(AgentApiToken.token_hash == hash_agent_token(raw_token)))
    if not token or token.revoked_at is not None:
        raise UnauthorizedError("Agent API token недействителен")
    if token.expires_at and token.expires_at <= datetime.now(UTC):
        raise UnauthorizedError("Agent API token истёк")
    token_id = token.id
    created_by = token.created_by
    token_name = token.name
    scopes = set(token.scopes or [])
    all_projects = token.all_projects
    project_ids = set(
        (
            await db.scalars(
                select(AgentApiTokenProjectGrant.project_id).where(AgentApiTokenProjectGrant.token_id == token_id)
            )
        ).all()
    )
    token.last_used_at = datetime.now(UTC)
    await db.commit()
    # Права создателя на момент запроса — токен не может их превышать. Если
    # создатель потерял доступ к проекту, токен тоже его теряет.
    creator = await db.scalar(select(User).where(User.id == created_by))
    creator_is_admin = creator is not None and creator.role == UserRole.ADMIN
    creator_project_ids: set[int] = set()
    if creator is not None and not creator_is_admin:
        creator_project_ids = set(
            (
                await db.scalars(select(ProjectMember.project_id).where(ProjectMember.user_id == created_by))
            ).all()
        )
    return AgentTokenContext(
        token_id=token_id,
        created_by=created_by,
        name=token_name,
        scopes=scopes,
        all_projects=all_projects,
        project_ids=project_ids,
        creator_is_admin=creator_is_admin,
        creator_project_ids=creator_project_ids,
    )


def require_agent_scope(scope: str):
    async def dependency(context: AgentTokenContext = Depends(get_agent_token_context)) -> AgentTokenContext:
        if scope not in context.scopes:
            raise ForbiddenError(f"Недостаточно прав agent token: требуется {scope}")
        return context

    return dependency


async def require_agent_project_access(
    project_id: int,
    context: AgentTokenContext = Depends(get_agent_token_context),
    db: AsyncSession = Depends(get_db),
) -> Project:
    project = await db.scalar(select(Project).where(Project.id == project_id))
    if not project:
        raise ForbiddenError("Проект не найден или недоступен")
    # 1. Грант самого токена.
    if not context.all_projects and project_id not in context.project_ids:
        raise ForbiddenError("Agent token не имеет доступа к проекту")
    # 2. Не шире прав создателя: не-админ достаёт только свои проекты, даже
    #    если у токена стоит all_projects.
    if not context.creator_is_admin and project_id not in context.creator_project_ids:
        raise ForbiddenError("Agent token не имеет доступа к проекту")
    return project
