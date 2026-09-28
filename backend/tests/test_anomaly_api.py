"""Anomali bilgisinin API'de görünmesi: olaylar, filtre, genel bakış, kural kartı."""

import pytest

from app.detection import anomaly
from tests.test_anomaly_integration import PROFILE

LOG = "\n".join([
    '203.0.113.10 - - [23/Sep/2026:14:00:00 +0300] "GET /urun.php?id=abc HTTP/1.1" 404 1 "-" "UA"',
    '192.0.2.10 - - [23/Sep/2026:14:05:00 +0300] "GET /urun.php?id=7 HTTP/1.1" 200 1 "-" "UA"',
]).encode()


@pytest.fixture
def with_profile(monkeypatch):
    monkeypatch.setattr(anomaly, "default_profile", lambda: PROFILE)


def seed(client):
    assert client.post("/api/v1/ingest/upload", files={"file": ("a.log", LOG)}).status_code == 200


def test_events_carry_anomalies_and_filter(client, with_profile):
    seed(client)

    items = client.get("/api/v1/events").json()["items"]
    assert sorted(e["anomalies"] for e in items) == [[], ["id:karakter"]]
    only = client.get("/api/v1/events", params={"anomaly": "any"}).json()["items"]
    assert [e["source_ip"] for e in only] == ["203.0.113.10"]
    assert client.get("/api/v1/events", params={"anomaly": "x"}).status_code == 422


def test_overview_lists_anomalies(client, with_profile):
    seed(client)

    [a] = client.get("/api/v1/stats/overview").json()["top_anomalies"]
    assert a == {"key": "id:karakter", "label": "id (beklenmeyen karakter)", "count": 1,
                 "blocked": 1}


def test_rule_card_shows_profile_summary(client, with_profile):
    rules = {r["id"]: r for r in client.get("/api/v1/rules").json()}

    assert rules["ANOM-001"]["anomaly_profile"] == {
        "paths": 2, "usable_paths": 2, "params": 3, "requests": 70}
    assert rules["ANOM-001"]["mitre"] == []
    assert rules["SIG-001"]["anomaly_profile"] is None


def test_rule_card_without_profile(client):
    rules = {r["id"]: r for r in client.get("/api/v1/rules").json()}
    assert rules["ANOM-001"]["anomaly_profile"] is None
