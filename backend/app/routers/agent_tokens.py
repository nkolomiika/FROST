
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import enforce_csrf, get_current_user
from app.models import User
from app.schemas import AgentTokenCreate, AgentTokenCreateResponse, AgentTokenOut
from app.services import AgentTokenService

router = APIRouter(prefix="/agent-tokens", tags=["agent-tokens"])


@router.get("", response_model=list[AgentTokenOut])
async def list_agent_tokens(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Возвращает agent API tokens текущего пользователя без секретных значений."""
    return await AgentTokenService(db).list_tokens(user.id)


@router.post("", response_model=AgentTokenCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_agent_token(
    payload: AgentTokenCreate,
    _: None = Depends(enforce_csrf),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Создаёт agent API token; значение token возвращается только один раз.

    Права токена не могут превышать права создателя: не-админ может выдать доступ
    только к проектам, где он участник (см. AgentTokenService.create_token и
    request-time проверку require_agent_project_access).
    """
    data, raw_token = await AgentTokenService(db).create_token(payload.model_dump(), user)
    return {**data, "token": raw_token}


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_agent_token(
    token_id: int,
    _: None = Depends(enforce_csrf),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Отзывает agent API token (свой — любой пользователь, чужой — только админ)."""
    await AgentTokenService(db).revoke_token(token_id, user)
