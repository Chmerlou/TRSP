import sys
from pathlib import Path

import pytest
from faker import Faker
from fastapi.testclient import TestClient

TASK11_DIR = Path(__file__).resolve().parent.parent
if str(TASK11_DIR) not in sys.path:
    sys.path.insert(0, str(TASK11_DIR))

from main import app, reset_storage

faker = Faker()


@pytest.fixture(autouse=True)
def clean_storage() -> None:
    reset_storage()
    yield
    reset_storage()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


class TestUsersSync:
    def test_create_user_returns_201(self, client: TestClient) -> None:
        username = faker.user_name()
        age = faker.random_int(min=18, max=80)
        response = client.post("/users", json={"username": username, "age": age})
        assert response.status_code == 201
        data = response.json()
        assert data["id"] == 1
        assert data["username"] == username
        assert data["age"] == age

    def test_get_existing_user_returns_200(self, client: TestClient) -> None:
        username = faker.user_name()
        age = faker.random_int(min=18, max=80)
        created = client.post("/users", json={"username": username, "age": age})
        user_id = created.json()["id"]

        response = client.get(f"/users/{user_id}")
        assert response.status_code == 200
        assert response.json() == {"id": user_id, "username": username, "age": age}

    def test_get_nonexistent_user_returns_404(self, client: TestClient) -> None:
        response = client.get("/users/9999")
        assert response.status_code == 404
        assert response.json()["detail"] == "User not found"

    def test_delete_existing_user_returns_204(self, client: TestClient) -> None:
        created = client.post(
            "/users",
            json={"username": faker.user_name(), "age": faker.random_int(min=18, max=80)},
        )
        user_id = created.json()["id"]

        response = client.delete(f"/users/{user_id}")
        assert response.status_code == 204
        assert client.get(f"/users/{user_id}").status_code == 404

    def test_delete_nonexistent_user_returns_404(self, client: TestClient) -> None:
        response = client.delete("/users/9999")
        assert response.status_code == 404
        assert response.json()["detail"] == "User not found"

    def test_boundary_age_values(self, client: TestClient) -> None:
        for age in (0, 1, 120):
            response = client.post(
                "/users",
                json={"username": faker.user_name(), "age": age},
            )
            assert response.status_code == 201
            assert response.json()["age"] == age
