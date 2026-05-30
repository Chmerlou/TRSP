from fastapi.testclient import TestClient

from validation_app import app

client = TestClient(app)


VALID_USER = {
    "username": "john_doe",
    "age": 25,
    "email": "john@example.com",
    "password": "secret123",
}


class TestUserValidation:
    def test_register_valid_user(self) -> None:
        response = client.post("/users/register", json=VALID_USER)
        assert response.status_code == 201
        assert "john_doe" in response.json()["message"]

    def test_register_with_default_phone(self) -> None:
        payload = {**VALID_USER, "username": "jane_doe", "email": "jane@example.com"}
        response = client.post("/users/register", json=payload)
        assert response.status_code == 201

    def test_invalid_age(self) -> None:
        payload = {**VALID_USER, "age": 17}
        response = client.post("/users/register", json=payload)
        assert response.status_code == 422
        data = response.json()
        assert data["error_code"] == "VALIDATION_ERROR"
        assert any(d["field"] == "age" for d in data["details"])

    def test_invalid_email(self) -> None:
        payload = {**VALID_USER, "email": "not-an-email"}
        response = client.post("/users/register", json=payload)
        assert response.status_code == 422
        data = response.json()
        assert data["error_code"] == "VALIDATION_ERROR"
        assert any(d["field"] == "email" for d in data["details"])

    def test_invalid_password_length(self) -> None:
        payload = {**VALID_USER, "password": "short"}
        response = client.post("/users/register", json=payload)
        assert response.status_code == 422
        data = response.json()
        assert data["error_code"] == "VALIDATION_ERROR"
        assert any(d["field"] == "password" for d in data["details"])

    def test_password_too_long(self) -> None:
        payload = {**VALID_USER, "password": "x" * 17}
        response = client.post("/users/register", json=payload)
        assert response.status_code == 422
        assert response.json()["error_code"] == "VALIDATION_ERROR"
