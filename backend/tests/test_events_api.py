LOG = "\n".join(
    [
        '192.0.2.10 - - [23/Sep/2026:14:00:00 +0300] "GET /blog.html HTTP/1.1" 200 1 "-" "UA"',
        '192.0.2.10 - - [23/Sep/2026:14:05:00 +0300] "GET /yok_100%.html HTTP/1.1" 404 1 "-" "UA"',
        '203.0.113.5 - - [23/Sep/2026:14:10:00 +0300] "POST /app.php?type=login HTTP/1.1" '
        '401 1 "-" "UA"',
    ]
).encode()


def seed(client):
    client.post("/api/v1/ingest/upload", files={"file": ("a.log", LOG)})


def test_filters(client):
    seed(client)

    def total(**params):
        return client.get("/api/v1/events", params=params).json()["total"]

    assert total() == 3
    assert total(ip="192.0.2.10") == 2
    assert total(status=404) == 1
    assert total(status="4xx") == 2
    assert client.get("/api/v1/events", params={"status": "4x"}).status_code == 422
    assert total(event_type="authentication_failure") == 1
    assert total(since="2026-09-23T11:04:00Z") == 2  # 14:04 TR = 11:04 UTC
    assert total(since="2026-09-23T14:04:00+03:00") == 2  # aynı an, farklı yazım
    assert total(since="2026-09-23T11:04:00") == 2  # saat dilimi yok → UTC


def test_newest_first(client):
    seed(client)

    items = client.get("/api/v1/events").json()["items"]

    assert [i["source_ip"] for i in items] == ["203.0.113.5", "192.0.2.10", "192.0.2.10"]


def test_like_wildcards_are_literal(client):
    seed(client)

    # '%' joker olarak yorumlansaydı 3 olay dönerdi
    assert client.get("/api/v1/events", params={"path": "%"}).json()["total"] == 1
    assert client.get("/api/v1/events", params={"path": "_"}).json()["total"] == 1


def test_limit_is_capped(client):
    assert client.get("/api/v1/events", params={"limit": 100000}).status_code == 422


def test_batches_are_listed(client):
    seed(client)

    batches = client.get("/api/v1/ingest/batches").json()

    assert batches[0]["filename"] == "a.log"
    assert batches[0]["events_inserted"] == 3
