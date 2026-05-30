from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from app.dependencies import get_storage, require_admin
from app.schemas import AdminStatsResponse
from app.storage import TaskStorage

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/stats", response_model=AdminStatsResponse)
def get_stats(
    _: Annotated[dict, Depends(require_admin)],
    storage: Annotated[TaskStorage, Depends(get_storage)],
) -> dict:
    return storage.stats()


@router.delete("/tasks/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
def admin_delete_task(
    task_id: int,
    _: Annotated[dict, Depends(require_admin)],
    storage: Annotated[TaskStorage, Depends(get_storage)],
) -> None:
    if not storage.delete(task_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found",
        )
