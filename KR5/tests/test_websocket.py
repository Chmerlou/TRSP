def test_websocket_connect_with_valid_username(client):
    with client.websocket_connect("/ws/rooms/python?username=alice") as ws:
        event = ws.receive_json()
        assert event["type"] == "connected"
        assert event["username"] == "alice"
        assert event["room_id"] == "python"


def test_websocket_send_and_receive_message(client):
    with client.websocket_connect("/ws/rooms/python?username=alice") as ws:
        ws.receive_json()
        ws.send_json({"type": "message", "text": "Всем привет"})
        message = ws.receive_json()
        assert message == {
            "type": "message",
            "room_id": "python",
            "username": "alice",
            "text": "Всем привет",
        }


def test_two_clients_receive_same_message(client):
    with client.websocket_connect("/ws/rooms/python?username=alice") as ws1:
        ws1.receive_json()
        with client.websocket_connect("/ws/rooms/python?username=bob") as ws2:
            ws2.receive_json()
            ws1.receive_json()

            ws1.send_json({"type": "message", "text": "Общее сообщение"})

            msg_alice = ws1.receive_json()
            msg_bob = ws2.receive_json()

            expected = {
                "type": "message",
                "room_id": "python",
                "username": "alice",
                "text": "Общее сообщение",
            }
            assert msg_alice == expected
            assert msg_bob == expected


def test_different_rooms_do_not_receive_foreign_messages(client):
    with client.websocket_connect("/ws/rooms/python?username=alice") as ws_py:
        with client.websocket_connect("/ws/rooms/java?username=bob") as ws_java:
            ws_py.receive_json()
            ws_java.receive_json()

            ws_py.send_json({"type": "message", "text": "Только для python"})

            msg_python = ws_py.receive_json()
            assert msg_python["room_id"] == "python"

            ws_java.send_json({"type": "message", "text": "ping"})
            assert ws_java.receive_json()["room_id"] == "java"


def test_message_too_long_returns_error(client):
    with client.websocket_connect("/ws/rooms/python?username=alice") as ws:
        ws.receive_json()
        long_text = "x" * 301
        ws.send_json({"type": "message", "text": long_text})
        error = ws.receive_json()
        assert error == {"type": "error", "detail": "Message is too long"}


def test_user_removed_from_room_after_disconnect(client):
    with client.websocket_connect("/ws/rooms/python?username=alice"):
        pass

    response = client.get("/rooms/python/users")
    assert response.status_code == 200
    assert response.json() == {"room_id": "python", "users": []}
