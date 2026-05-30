from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.room_manager import room_manager
from app.schemas import RoomUsersResponse

router = APIRouter(tags=["rooms"])

MAX_MESSAGE_LENGTH = 300


@router.websocket("/ws/rooms/{room_id}")
async def websocket_room(room_id: str, websocket: WebSocket, username: str = "") -> None:
    username = (username or "").strip()
    if not username:
        await websocket.close(code=1008)
        return

    await room_manager.connect(room_id, username, websocket)
    try:
        while True:
            data = await websocket.receive_json()
            if data.get("type") != "message":
                continue
            text = data.get("text", "")
            if len(text) > MAX_MESSAGE_LENGTH:
                await websocket.send_json(
                    {"type": "error", "detail": "Message is too long"}
                )
                continue
            await room_manager.broadcast(
                room_id,
                {
                    "type": "message",
                    "room_id": room_id,
                    "username": username,
                    "text": text,
                },
            )
    except WebSocketDisconnect:
        await room_manager.disconnect(room_id, username, websocket)


@router.get("/rooms/{room_id}/users", response_model=RoomUsersResponse)
def get_room_users(room_id: str) -> dict:
    return {"room_id": room_id, "users": room_manager.get_users(room_id)}
