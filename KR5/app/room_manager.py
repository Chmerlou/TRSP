from fastapi import WebSocket


class RoomManager:
    def __init__(self) -> None:
        self._rooms: dict[str, dict[str, WebSocket]] = {}

    async def connect(self, room_id: str, username: str, websocket: WebSocket) -> None:
        await websocket.accept()
        if room_id not in self._rooms:
            self._rooms[room_id] = {}
        self._rooms[room_id][username] = websocket
        await self.broadcast(
            room_id,
            {"type": "connected", "room_id": room_id, "username": username},
        )

    async def disconnect(
        self, room_id: str, username: str, websocket: WebSocket
    ) -> None:
        room = self._rooms.get(room_id)
        if room is None:
            return
        if room.get(username) is websocket:
            del room[username]
        if not room:
            del self._rooms[room_id]
        await self.broadcast(
            room_id,
            {"type": "disconnected", "room_id": room_id, "username": username},
        )

    async def broadcast(self, room_id: str, payload: dict) -> None:
        room = self._rooms.get(room_id, {})
        dead: list[str] = []
        for username, ws in room.items():
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(username)
        for username in dead:
            room.pop(username, None)

    def get_users(self, room_id: str) -> list[str]:
        room = self._rooms.get(room_id, {})
        return sorted(room.keys())

    def clear(self) -> None:
        self._rooms.clear()


room_manager = RoomManager()
