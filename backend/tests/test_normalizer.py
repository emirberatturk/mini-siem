import pytest

from app.ingestion.pipeline import process_lines
from app.normalization.schema import EventType


def line(method: str, target: str, status: int, referrer: str = "-") -> str:
    return (
        f'192.0.2.10 - - [23/Sep/2026:14:30:00 +0300] "{method} {target} HTTP/1.1" '
        f'{status} 100 "{referrer}" "Mozilla/5.0"'
    )


@pytest.mark.parametrize(
    ("method", "target", "status", "expected"),
    [
        ("POST", "/app.php?type=login", 200, EventType.AUTH_SUCCESS),
        ("POST", "/app.php?type=login", 401, EventType.AUTH_FAILURE),
        ("POST", "/app.php?type=login", 429, EventType.AUTH_LOCKOUT),
        ("GET", "/app.php?type=login", 200, EventType.HTTP_REQUEST),  # GET giriş denemesi değil
        ("GET", "/app.php?type=randevu_listesi", 200, EventType.ADMIN_ACCESS),
        ("GET", "/app.php?type=ayarlar", 401, EventType.ADMIN_ACCESS),
        ("GET", "/admin/", 200, EventType.ADMIN_ACCESS),
        ("GET", "/APP.PHP?type=users", 200, EventType.ADMIN_ACCESS),  # büyük harf hilesi
        ("GET", "/app.php?type=blog", 200, EventType.HTTP_REQUEST),
        ("GET", "/index.html", 200, EventType.HTTP_REQUEST),
    ],
)
def test_classification(method, target, status, expected):
    result = process_lines([line(method, target, status)])

    assert result.events[0].event_type == expected


def test_pii_never_reaches_normalized_event():
    raw = line(
        "GET",
        "/randevu.html?ad=Deneme+Hasta&tel=05550000000&email=deneme%40example.com",
        200,
        referrer="https://www.ornek-klinik.com/randevu.html?tel=05550000000",
    )

    result = process_lines([raw])
    stored = result.events[0].model_dump_json()

    for secret in ["Deneme", "05550000000", "example.com"]:
        assert secret not in stored
    assert result.redactions >= 4


def test_identical_lines_stay_separate_events_but_reupload_is_stable():
    raw = line("POST", "/app.php?type=login", 401)

    first = process_lines([raw, raw, "bozuk satır"])
    again = process_lines([raw, raw])

    keys = [e.event_key for e in first.events]
    assert len(set(keys)) == 2  # aynı saniyedeki 2 özdeş deneme = 2 olay
    assert keys == [e.event_key for e in again.events]  # tekrar yükleme aynı anahtarlar
    assert first.failed == 1
