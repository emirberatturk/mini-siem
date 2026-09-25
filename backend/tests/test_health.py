def test_health_returns_ok(client):
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["time"].endswith("+00:00")  # UTC olmalı
