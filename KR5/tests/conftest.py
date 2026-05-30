import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.room_manager import room_manager
from app.storage import storage


@pytest.fixture
def client():
    storage.clear()
    room_manager.clear()
    with TestClient(app) as test_client:
        yield test_client
    storage.clear()
    room_manager.clear()
