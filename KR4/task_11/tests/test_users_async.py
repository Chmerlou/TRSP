import sys
from pathlib import Path

import httpx
import pytest
from faker import Faker
from httpx import ASGITransport, AsyncClient

TASK11_DIR = Path(__file__).resolve().parent.parent
if str(TASK11_DIR) not in sys.path:
    sys.path.insert(0, str(TASK11_DIR))

from main import app, reset_storage


@pytest.fixture
def faker_instance() -> Faker:
    return Faker()


@pytest.fixture(autouse=True)
def clean_storage() -> None:
    reset_storage()
    yield
    reset_storage()


@pytest.fixture
async def async_client() -> AsyncClient:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


class TestUsersAsync:
    async def test_create_user_returns_201(self, async_client: AsyncClient, faker_instance: Faker) -> None:
        username = faker_instance.user_name()
        age = faker_instance.random_int(min=18, max=80)
        response = await async_client.post("/users", json={"username": username, "age": age})

        assert response.status_code == 201
        data = response.json()
        assert set(data.keys()) == {"id", "username", "age"}
        assert data["username"] == username
        assert data["age"] == age
        assert isinstance(data["id"], int)

    async def test_get_existing_user_returns_200(self, async_client: AsyncClient, faker_instance: Faker) -> None:
        username = faker_instance.user_name()
        age = faker_instance.random_int(min=18, max=80)
        created = await async_client.post("/users", json={"username": username, "age": age})
        user_id = created.json()["id"]

        response = await async_client.get(f"/users/{user_id}")
        assert response.status_code == 200
        assert response.json() == {"id": user_id, "username": username, "age": age}

    async def test_get_nonexistent_user_returns_404(self, async_client: AsyncClient) -> None:
        response = await async_client.get("/users/9999")
        assert response.status_code == 404
        assert response.json()["detail"] == "User not found"

    async def test_delete_existing_user_returns_204(self, async_client: AsyncClient, faker_instance: Faker) -> None:
        created = await async_client.post(
            "/users",
            json={"username": faker_instance.user_name(), "age": faker_instance.random_int(min=18, max=80)},
        )
        user_id = created.json()["id"]

        response = await async_client.delete(f"/users/{user_id}")
        assert response.status_code == 204

        get_response = await async_client.get(f"/users/{user_id}")
        assert get_response.status_code == 404

    async def test_delete_same_user_twice_returns_404(self, async_client: AsyncClient, faker_instance: Faker) -> None:
        created = await async_client.post(
            "/users",
            json={"username": faker_instance.user_name(), "age": faker_instance.random_int(min=18, max=80)},
        )
        user_id = created.json()["id"]

        first_delete = await async_client.delete(f"/users/{user_id}")
        assert first_delete.status_code == 204

        second_delete = await async_client.delete(f"/users/{user_id}")
        assert second_delete.status_code == 404
        assert second_delete.json()["detail"] == "User not found"

    async def test_boundary_age_values(self, async_client: AsyncClient, faker_instance: Faker) -> None:
        for age in (0, 1, 120):
            response = await async_client.post(
                "/users",
                json={"username": faker_instance.user_name(), "age": age},
            )
            assert response.status_code == 201
            assert response.json()["age"] == age

    async def test_storage_isolated_between_tests(self, async_client: AsyncClient, faker_instance: Faker) -> None:
        await async_client.post(
            "/users",
            json={"username": faker_instance.user_name(), "age": 30},
        )
        response = await async_client.get("/users/1")
        assert response.status_code == 200
