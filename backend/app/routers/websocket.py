
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt
from sqlalchemy import and_, select

from app.config import get_settings
from app.database import SessionLocal
from app.enums import UserRole
from app.models import ProjectMember, User
from app.ws_manager import ws_manager

router = APIRouter(tags=["websocket"])
settings = get_settings()


async def _authenticate_websocket_user(websocket: WebSocket) -> User | None:
    access_token = websocket.cookies.get("access_token")
    if not access_token:
        await websocket.close(code=4401)
        return None
    try:
        payload = jwt.decode(access_token, settings.jwt_secret_key, algorithms=["HS256"])
        if payload.get("type") != "access":
            await websocket.close(code=4401)
            return None
        user_id = payload.get("sub")
        if not user_id:
            await websocket.close(code=4401)
            return None
    except JWTError:
        await websocket.close(code=4401)
        return None

    async with SessionLocal() as db:
        user = await db.scalar(select(User).where(User.id == user_id))
        if not user or not user.is_active or user.is_locked:
            await websocket.close(code=4403)
            return None
    setattr(websocket.state, "user_id", user_id)
    return user


@router.websocket("/ws/projects-index")
async def projects_index_ws(websocket: WebSocket) -> None:
    """Общий WebSocket-канал списка проектов для real-time обновлений."""
    user = await _authenticate_websocket_user(websocket)
    if not user:
        return

    await ws_manager.connect_projects_index(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect_projects_index(websocket)


@router.websocket("/ws/notifications")
async def notifications_ws(websocket: WebSocket) -> None:
    """Персональный WebSocket-канал уведомлений текущего пользователя."""
    user = await _authenticate_websocket_user(websocket)
    if not user:
        return

    await ws_manager.connect_user(user.id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect_user(user.id, websocket)


@router.websocket("/ws/projects/{project_id}")
async def project_ws(websocket: WebSocket, project_id: int) -> None:
    """WebSocket-канал проекта с авторизацией по access cookie."""
    user = await _authenticate_websocket_user(websocket)
    if not user:
        return

    async with SessionLocal() as db:
        if user.role != UserRole.ADMIN:
            membership = await db.scalar(
                select(ProjectMember).where(and_(ProjectMember.project_id == project_id, ProjectMember.user_id == user.id))
            )
            if not membership:
                await websocket.close(code=4403)
                return

    await ws_manager.connect(project_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(project_id, websocket)
