from datetime import UTC, datetime, timedelta

import pytest

from app.alerts.workflow import AlertStatus, TransitionError, check_transition

T0 = datetime(2026, 9, 23, 11, 0, tzinfo=UTC)


def login_401(i: int) -> str:
    ts = (T0 + timedelta(seconds=10 * i)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'203.0.113.10 - - [{ts}] "POST /app.php?type=login HTTP/1.1" 401 38 "-" "curl/8.0"'


@pytest.fixture
def alert_id(client) -> int:
    log = "\n".join(login_401(i) for i in range(6)).encode()
    body = client.post("/api/v1/ingest/upload", files={"file": ("a.log", log)}).json()
    assert body["alerts_created"] == 1
    return client.get("/api/v1/alerts").json()["items"][0]["id"]


def patch(client, alert_id, status, note=""):
    return client.patch(f"/api/v1/alerts/{alert_id}", json={"status": status, "note": note})


def test_list_and_filter(client, alert_id):
    assert client.get("/api/v1/alerts", params={"severity": "medium"}).json()["total"] == 1
    assert client.get("/api/v1/alerts", params={"severity": "critical"}).json()["total"] == 0
    assert client.get("/api/v1/alerts", params={"status": ["new", "investigating"]}).json()[
        "total"
    ] == 1
    assert client.get("/api/v1/alerts", params={"ip": "203.0.113.10"}).json()["total"] == 1


def test_detail_contains_events_and_history(client, alert_id):
    detail = client.get(f"/api/v1/alerts/{alert_id}").json()

    assert len(detail["events"]) == 6
    assert detail["history"][0]["to_status"] == "new"
    assert detail["history"][0]["changed_by"] == "sistem"


def test_full_workflow_is_recorded(client, alert_id):
    assert patch(client, alert_id, "investigating").status_code == 200
    assert patch(client, alert_id, "confirmed", "Doktor girişi değil").status_code == 200
    detail = patch(client, alert_id, "resolved", "IP engellendi, şifre değiştirildi").json()

    assert detail["status"] == "resolved"
    assert [h["to_status"] for h in detail["history"]] == [
        "new", "investigating", "confirmed", "resolved"
    ]


def test_cannot_skip_investigation(client, alert_id):
    response = patch(client, alert_id, "resolved", "bakmadan kapatıyorum")

    assert response.status_code == 409


def test_false_positive_requires_note(client, alert_id):
    assert patch(client, alert_id, "false_positive").status_code == 409
    assert patch(client, alert_id, "false_positive", "   ").status_code == 409
    assert patch(client, alert_id, "false_positive", "Doktorun kendi denemeleri").status_code == 200


def test_unknown_status_and_alert(client, alert_id):
    assert patch(client, alert_id, "silindi").status_code == 422
    assert client.get("/api/v1/alerts/99999").status_code == 404


def test_rules_endpoint(client, alert_id):
    rules = {r["id"]: r for r in client.get("/api/v1/rules").json()}

    assert rules["AUTH-001"]["alert_count"] == 1
    assert rules["AUTH-001"]["open_alert_count"] == 1
    assert rules["RECON-001"]["mitre"] == ["T1595.003"]
    assert "enabled" not in rules["AUTH-001"]["config"]


def test_rerun_endpoint_is_idempotent(client, alert_id):
    assert client.post("/api/v1/detection/run").json() == {"created": 0, "updated": 0}


@pytest.mark.parametrize(
    ("current", "target", "note"),
    [
        ("resolved", AlertStatus.INVESTIGATING, ""),
        ("false_positive", AlertStatus.INVESTIGATING, ""),
    ],
)
def test_reopening_requires_note(current, target, note):
    with pytest.raises(TransitionError):
        check_transition(current, target, note)
    check_transition(current, target, "Aynı IP tekrar görüldü")
