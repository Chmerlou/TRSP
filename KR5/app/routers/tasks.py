from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.dependencies import get_current_user, get_storage
from app.schemas import TaskCreate, TaskResponse, TaskStatus, TaskStatusUpdate
from app.storage import TaskStorage

router = APIRouter(prefix="/tasks", tags=["tasks"])


def _get_task_for_user(
    task_id: int, user_id: int, storage: TaskStorage
) -> dict[str, Any]:
    task = storage.get(task_id)
    if task is None or task["owner_id"] != user_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found",
        )
    return task


@router.post("", response_model=TaskResponse, status_code=status.HTTP_201_CREATED)
def create_task(
    payload: TaskCreate,
    current_user: Annotated[dict[str, Any], Depends(get_current_user)],
    storage: Annotated[TaskStorage, Depends(get_storage)],
) -> dict[str, Any]:
    return storage.create(
        {
            "title": payload.title,
            "description": payload.description,
            "status": payload.status,
            "priority": payload.priority,
            "owner_id": current_user["id"],
        }
    )


@router.get("", response_model=list[TaskResponse])
def list_tasks(
    current_user: Annotated[dict[str, Any], Depends(get_current_user)],
    storage: Annotated[TaskStorage, Depends(get_storage)],
    status: Annotated[TaskStatus | None, Query()] = None,
    min_priority: Annotated[int | None, Query(ge=1, le=5)] = None,
) -> list[dict[str, Any]]:
    return storage.list_for_owner(
        current_user["id"], status=status, min_priority=min_priority
    )


@router.get("/{task_id}", response_model=TaskResponse)
def get_task(
    task_id: int,
    current_user: Annotated[dict[str, Any], Depends(get_current_user)],
    storage: Annotated[TaskStorage, Depends(get_storage)],
) -> dict[str, Any]:
    return _get_task_for_user(task_id, current_user["id"], storage)


@router.patch("/{task_id}/status", response_model=TaskResponse)
def update_task_status(
    task_id: int,
    payload: TaskStatusUpdate,
    current_user: Annotated[dict[str, Any], Depends(get_current_user)],
    storage: Annotated[TaskStorage, Depends(get_storage)],
) -> dict[str, Any]:
    _get_task_for_user(task_id, current_user["id"], storage)
    updated = storage.update_status(task_id, payload.status)
    assert updated is not None
    return updated


@router.delete("/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_task(
    task_id: int,
    current_user: Annotated[dict[str, Any], Depends(get_current_user)],
    storage: Annotated[TaskStorage, Depends(get_storage)],
) -> None:
    _get_task_for_user(task_id, current_user["id"], storage)
    storage.delete(task_id)
