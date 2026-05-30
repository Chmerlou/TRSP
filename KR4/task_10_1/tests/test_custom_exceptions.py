from fastapi.testclient import TestClient

from exceptions_app import app

client = TestClient(app)


class TestCustomExceptions:
    def test_validate_item_success(self) -> None:
        response = client.get("/items/2/validate")
        assert response.status_code == 200
        assert response.json()["message"] == "Item 2 is valid"

    def test_custom_exception_a(self) -> None:
        response = client.get("/items/0/validate")
        assert response.status_code == 400
        data = response.json()
        assert data["error_code"] == "CUSTOM_A"
        assert "below minimum" in data["message"]

    def test_get_item_success(self) -> None:
        response = client.get("/items/1")
        assert response.status_code == 200
        assert response.json() == {"id": 1, "name": "alpha"}

    def test_custom_exception_b(self) -> None:
        response = client.get("/items/999")
        assert response.status_code == 404
        data = response.json()
        assert data["error_code"] == "CUSTOM_B"
        assert "not found" in data["message"]
