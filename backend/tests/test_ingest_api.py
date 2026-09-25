import gzip

from app.core.config import settings

LINE = b'192.0.2.10 - - [23/Sep/2026:14:00:00 +0300] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n'
LOGIN_FAIL = (
    b'203.0.113.5 - - [23/Sep/2026:14:00:01 +0300] "POST /app.php?type=login HTTP/1.1" '
    b'401 38 "-" "curl/8.0"\n'
)


def upload(client, name: str, content: bytes):
    return client.post("/api/v1/ingest/upload", files={"file": (name, content)})


def test_upload_plain_log(client):
    response = upload(client, "access.log", LINE + LOGIN_FAIL)

    assert response.status_code == 200
    body = response.json()
    assert body["lines_total"] == 2
    assert body["events_inserted"] == 2
    assert body["event_types"] == {"http_request": 1, "authentication_failure": 1}


def test_upload_cpanel_style_gz(client):
    response = upload(client, "ornek-klinik.com-Sep-2026.gz", gzip.compress(LINE * 2))

    assert response.status_code == 200
    assert response.json()["compressed"] is True
    assert response.json()["events_inserted"] == 2  # özdeş 2 satır = 2 olay


def test_reupload_creates_no_duplicates(client):
    upload(client, "a.log", LINE + LOGIN_FAIL)

    second = upload(client, "a-tekrar.log", LINE + LOGIN_FAIL).json()

    assert second["events_inserted"] == 0
    assert second["duplicates"] == 2
    assert client.get("/api/v1/events").json()["total"] == 2


def test_path_traversal_in_filename_is_stripped(client):
    response = upload(client, "../../etc/passwd", LINE)

    assert response.status_code == 200
    assert response.json()["filename"] == "passwd"


def test_too_large_upload_is_rejected(client, monkeypatch):
    monkeypatch.setattr(settings, "max_upload_bytes", 100)

    response = upload(client, "big.log", LINE * 10)

    assert response.status_code == 413


def test_binary_upload_is_rejected(client):
    response = upload(client, "resim.log", b"\x89PNG\r\n\x1a\n\x00\x00\x00")

    assert response.status_code == 415


def test_unsupported_format_is_rejected(client):
    response = upload(client, "notlar.txt", b"bu bir log degil\n")

    assert response.status_code == 422
