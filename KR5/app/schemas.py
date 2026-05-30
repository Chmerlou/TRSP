from typing import Literal

from pydantic import BaseModel, Field

TaskStatus = Literal["todo", "in_progress", "done"]


class TaskCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=80)
    description: str | None = None
    status: TaskStatus = "todo"
    priority: int = Field(..., ge=1, le=5)


class TaskStatusUpdate(BaseModel):
    status: TaskStatus


class TaskResponse(BaseModel):
    id: int
    title: str
    description: str | None
    status: TaskStatus
    priority: int
    owner_id: int


class UserResponse(BaseModel):
    id: int
    role: str


class AdminStatsResponse(BaseModel):
    total_tasks: int
    by_status: dict[str, int]


class HealthResponse(BaseModel):
    status: str
    env: str


class RoomUsersResponse(BaseModel):
    room_id: str
    users: list[str]
