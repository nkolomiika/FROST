from collections import defaultdict

from fastapi import WebSocket


class ConnectionManager:
    """Менеджер WebSocket-подключений по комнатам проекта."""

    def __init__(self) -> None:
        self.rooms: dict[int, set[WebSocket]] = defaultdict(set)
        self.projects_index_sockets: set[WebSocket] = set()
        self.user_sockets: dict[int, set[WebSocket]] = defaultdict(set)

    async def connect(self, project_id: int, websocket: WebSocket) -> None:
        """Принимает соединение и регистрирует его в комнате проекта."""
        await websocket.accept()
        self.rooms[project_id].add(websocket)

    def disconnect(self, project_id: int, websocket: WebSocket) -> None:
        """Удаляет соединение из комнаты проекта."""
        self.rooms[project_id].discard(websocket)
        if not self.rooms[project_id]:
            self.rooms.pop(project_id, None)

    async def connect_projects_index(self, websocket: WebSocket) -> None:
        """Подключает сокет к общему каналу списка проектов."""
        await websocket.accept()
        self.projects_index_sockets.add(websocket)

    def disconnect_projects_index(self, websocket: WebSocket) -> None:
        """Удаляет сокет из общего канала списка проектов."""
        self.projects_index_sockets.discard(websocket)

    async def connect_user(self, user_id: int, websocket: WebSocket) -> None:
        """Подключает сокет к персональному каналу уведомлений пользователя."""
        await websocket.accept()
        self.user_sockets[user_id].add(websocket)

    def disconnect_user(self, user_id: int, websocket: WebSocket) -> None:
        """Удаляет сокет из персонального канала пользователя."""
        self.user_sockets[user_id].discard(websocket)
        if not self.user_sockets[user_id]:
            self.user_sockets.pop(user_id, None)

    async def broadcast(self, project_id: int, payload: dict) -> None:
        """Рассылает событие всем активным подключениям комнаты."""
        stale: list[WebSocket] = []
        for ws in self.rooms.get(project_id, set()):
            try:
                await ws.send_json(payload)
            except Exception:
                stale.append(ws)

        for ws in stale:
            self.disconnect(project_id, ws)

    async def notify_user(self, user_id: int, payload: dict) -> None:
        """Рассылает персональное уведомление в персональный и проектные каналы пользователя."""
        stale_user_sockets: list[WebSocket] = []
        for ws in self.user_sockets.get(user_id, set()):
            try:
                await ws.send_json(payload)
            except Exception:
                stale_user_sockets.append(ws)
        for ws in stale_user_sockets:
            self.disconnect_user(user_id, ws)

        for room_id, sockets in list(self.rooms.items()):
            stale: list[WebSocket] = []
            for ws in sockets:
                if getattr(ws.state, "user_id", None) == user_id:
                    try:
                        await ws.send_json(payload)
                    except Exception:
                        stale.append(ws)
            for ws in stale:
                self.disconnect(room_id, ws)

    async def broadcast_projects_index(self, payload: dict) -> None:
        """Рассылает событие всем открытым страницам списка проектов."""
        stale: list[WebSocket] = []
        for ws in set(self.projects_index_sockets):
            try:
                await ws.send_json(payload)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self.disconnect_projects_index(ws)


ws_manager = ConnectionManager()
