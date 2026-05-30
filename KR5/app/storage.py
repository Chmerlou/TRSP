from typing import Any

from app.schemas import TaskStatus


class TaskStorage:
    def __init__(self) -> None:
        self._tasks: dict[int, dict[str, Any]] = {}
        self._next_id: int = 1

    def create(self, data: dict[str, Any]) -> dict[str, Any]:
        task_id = self._next_id
        self._next_id += 1
        task = {"id": task_id, **data}
        self._tasks[task_id] = task
        return task

    def get(self, task_id: int) -> dict[str, Any] | None:
        return self._tasks.get(task_id)

    def list_for_owner(
        self,
        owner_id: int,
        status: TaskStatus | None = None,
        min_priority: int | None = None,
    ) -> list[dict[str, Any]]:
        tasks = [t for t in self._tasks.values() if t["owner_id"] == owner_id]
        if status is not None:
            tasks = [t for t in tasks if t["status"] == status]
        if min_priority is not None:
            tasks = [t for t in tasks if t["priority"] >= min_priority]
        return tasks

    def update_status(self, task_id: int, status: TaskStatus) -> dict[str, Any] | None:
        task = self._tasks.get(task_id)
        if task is None:
            return None
        task["status"] = status
        return task

    def delete(self, task_id: int) -> bool:
        if task_id not in self._tasks:
            return False
        del self._tasks[task_id]
        return True

    def all_tasks(self) -> list[dict[str, Any]]:
        return list(self._tasks.values())

    def stats(self) -> dict[str, Any]:
        tasks = self.all_tasks()
        by_status = {"todo": 0, "in_progress": 0, "done": 0}
        for task in tasks:
            by_status[task["status"]] += 1
        return {"total_tasks": len(tasks), "by_status": by_status}

    def clear(self) -> None:
        self._tasks.clear()
        self._next_id = 1


storage = TaskStorage()
