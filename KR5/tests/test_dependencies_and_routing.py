def test_users_me_returns_current_user(client):
    response = client.get(
        "/users/me",
        headers={"X-User-Id": "10", "X-User-Role": "user"},
    )
    assert response.status_code == 200
    assert response.json() == {"id": 10, "role": "user"}


def test_users_me_without_header_returns_401(client):
    response = client.get("/users/me")
    assert response.status_code == 401


def test_regular_user_cannot_access_admin_stats(client):
    client.post(
        "/tasks",
        json={"title": "Some task", "priority": 1},
        headers={"X-User-Id": "10", "X-User-Role": "user"},
    )
    response = client.get(
        "/admin/stats",
        headers={"X-User-Id": "10", "X-User-Role": "user"},
    )
    assert response.status_code == 403


def test_admin_gets_stats_for_all_tasks(client):
    client.post(
        "/tasks",
        json={"title": "Task one", "status": "todo", "priority": 1},
        headers={"X-User-Id": "10"},
    )
    client.post(
        "/tasks",
        json={"title": "Task two", "status": "done", "priority": 2},
        headers={"X-User-Id": "20"},
    )
    client.post(
        "/tasks",
        json={"title": "Task three", "status": "in_progress", "priority": 3},
        headers={"X-User-Id": "10"},
    )

    response = client.get(
        "/admin/stats",
        headers={"X-User-Id": "1", "X-User-Role": "admin"},
    )
    assert response.status_code == 200
    assert response.json() == {
        "total_tasks": 3,
        "by_status": {"todo": 1, "in_progress": 1, "done": 1},
    }


def test_user_cannot_delete_foreign_task(client):
    create = client.post(
        "/tasks",
        json={"title": "Foreign task", "priority": 1},
        headers={"X-User-Id": "20"},
    )
    task_id = create.json()["id"]

    response = client.delete(f"/tasks/{task_id}", headers={"X-User-Id": "10"})
    assert response.status_code == 404


def test_admin_can_delete_foreign_task(client):
    create = client.post(
        "/tasks",
        json={"title": "Foreign task", "priority": 1},
        headers={"X-User-Id": "20"},
    )
    task_id = create.json()["id"]

    response = client.delete(
        f"/admin/tasks/{task_id}",
        headers={"X-User-Id": "1", "X-User-Role": "admin"},
    )
    assert response.status_code == 204

    response = client.get(f"/tasks/{task_id}", headers={"X-User-Id": "20"})
    assert response.status_code == 404


def test_openapi_tags_grouped(client):
    openapi = client.get("/openapi.json").json()
    paths = openapi["paths"]

    tasks_paths = [p for p in paths if p.startswith("/tasks")]
    users_paths = [p for p in paths if p.startswith("/users")]
    admin_paths = [p for p in paths if p.startswith("/admin")]

    for path in tasks_paths:
        for method in paths[path].values():
            assert "tasks" in method.get("tags", [])

    for path in users_paths:
        for method in paths[path].values():
            assert "users" in method.get("tags", [])

    for path in admin_paths:
        for method in paths[path].values():
            assert "admin" in method.get("tags", [])


def test_health_endpoint(client, monkeypatch):
    monkeypatch.setenv("APP_ENV", "docker")
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "env": "docker"}
