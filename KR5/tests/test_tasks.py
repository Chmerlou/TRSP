def test_create_task_success(client):
    response = client.post(
        "/tasks",
        json={
            "title": "Подготовить тесты",
            "description": "Написать интеграционные тесты",
            "status": "todo",
            "priority": 4,
        },
        headers={"X-User-Id": "10"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["id"] == 1
    assert data["title"] == "Подготовить тесты"
    assert data["owner_id"] == 10
    assert data["status"] == "todo"
    assert data["priority"] == 4


def test_create_task_title_too_short_returns_422(client):
    response = client.post(
        "/tasks",
        json={"title": "ab", "priority": 1},
        headers={"X-User-Id": "10"},
    )
    assert response.status_code == 422


def test_missing_user_header_returns_401(client):
    response = client.post(
        "/tasks",
        json={"title": "Valid title", "priority": 1},
    )
    assert response.status_code == 401


def test_user_sees_only_own_tasks(client):
    client.post(
        "/tasks",
        json={"title": "Task user 10", "priority": 1},
        headers={"X-User-Id": "10"},
    )
    client.post(
        "/tasks",
        json={"title": "Task user 20", "priority": 2},
        headers={"X-User-Id": "20"},
    )

    response = client.get("/tasks", headers={"X-User-Id": "10"})
    assert response.status_code == 200
    tasks = response.json()
    assert len(tasks) == 1
    assert tasks[0]["owner_id"] == 10


def test_filter_tasks_by_status_and_min_priority(client):
    client.post(
        "/tasks",
        json={"title": "Todo low", "status": "todo", "priority": 1},
        headers={"X-User-Id": "10"},
    )
    client.post(
        "/tasks",
        json={"title": "Done high", "status": "done", "priority": 5},
        headers={"X-User-Id": "10"},
    )
    client.post(
        "/tasks",
        json={"title": "Todo high", "status": "todo", "priority": 4},
        headers={"X-User-Id": "10"},
    )

    response = client.get(
        "/tasks",
        params={"status": "todo", "min_priority": 3},
        headers={"X-User-Id": "10"},
    )
    assert response.status_code == 200
    tasks = response.json()
    assert len(tasks) == 1
    assert tasks[0]["title"] == "Todo high"


def test_update_task_status_success(client):
    create = client.post(
        "/tasks",
        json={"title": "Update me", "priority": 2},
        headers={"X-User-Id": "10"},
    )
    task_id = create.json()["id"]

    response = client.patch(
        f"/tasks/{task_id}/status",
        json={"status": "done"},
        headers={"X-User-Id": "10"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "done"


def test_foreign_or_missing_task_returns_404(client):
    client.post(
        "/tasks",
        json={"title": "Other user task", "priority": 1},
        headers={"X-User-Id": "20"},
    )

    response = client.get("/tasks/1", headers={"X-User-Id": "10"})
    assert response.status_code == 404

    response = client.get("/tasks/999", headers={"X-User-Id": "10"})
    assert response.status_code == 404


def test_delete_task_success(client):
    create = client.post(
        "/tasks",
        json={"title": "Delete me", "priority": 1},
        headers={"X-User-Id": "10"},
    )
    task_id = create.json()["id"]

    response = client.delete(f"/tasks/{task_id}", headers={"X-User-Id": "10"})
    assert response.status_code == 204

    response = client.get(f"/tasks/{task_id}", headers={"X-User-Id": "10"})
    assert response.status_code == 404
