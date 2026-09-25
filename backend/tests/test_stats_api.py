from datetime import UTC, datetime, timedelta

from app.api.v1.stats import pick_bucket

T0 = datetime(2026, 9, 23, 11, 0, tzinfo=UTC)


def line(ip, method, target, status, at):
    ts = (T0 + at).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{ts}] "{method} {target} HTTP/1.1" {status} 10 "-" "UA"'


def test_empty_database(client):
    body = client.get("/api/v1/stats/overview").json()

    assert body["total_events"] == 0
    assert body["timeline"] == []
    assert body["open_alerts_by_severity"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}


def test_overview_numbers(client):
    lines = [line("203.0.113.10", "POST", "/app.php?type=login", 401, timedelta(seconds=10 * i))
             for i in range(6)]
    lines += [line("192.0.2.20", "GET", "/", 200, timedelta(minutes=30)),
              line("192.0.2.20", "GET", "/yok.html", 404, timedelta(minutes=59))]
    client.post("/api/v1/ingest/upload", files={"file": ("a.log", "\n".join(lines).encode())})

    body = client.get("/api/v1/stats/overview").json()

    assert body["total_events"] == 8
    assert body["total_alerts"] == 1
    assert body["open_alerts_by_severity"]["medium"] == 1
    assert body["top_ips"][0] == {"key": "203.0.113.10", "count": 6, "proxy": False}
    assert body["top_rules"] == [{"key": "AUTH-001", "count": 1, "proxy": False}]
    assert {c["key"]: c["count"] for c in body["status_classes"]} == {
        "2xx": 1, "4xx": 7
    }
    assert sum(b["events"] for b in body["timeline"]) == 8
    assert sum(b["auth_failures"] for b in body["timeline"]) == 6
    assert sum(b["alerts"] for b in body["timeline"]) == 1
    assert body["peak_events_per_minute"] == 6
    assert body["recent_alerts"][0]["rule_id"] == "AUTH-001"


def test_since_filter(client):
    lines = [line("192.0.2.20", "GET", "/", 200, timedelta(hours=h)) for h in range(5)]
    client.post("/api/v1/ingest/upload", files={"file": ("a.log", "\n".join(lines).encode())})

    body = client.get("/api/v1/stats/overview", params={"since": "2026-09-23T13:00:00Z"}).json()

    assert body["total_events"] == 3


def test_bucket_sizes():
    assert pick_bucket(timedelta(minutes=30)) == timedelta(minutes=1)
    assert pick_bucket(timedelta(hours=24)) == timedelta(minutes=30)
    assert pick_bucket(timedelta(days=4)) == timedelta(hours=3)
    assert pick_bucket(timedelta(days=365)) == timedelta(days=1)


def test_proxy_share_and_flag(client, tmp_path, monkeypatch):
    from app.core.config import settings

    cfg = tmp_path / "rules.yaml"
    cfg.write_text("proxy_ips:\n  - 192.0.2.254\n", encoding="utf-8")
    monkeypatch.setattr(settings, "rules_config", cfg)
    lines = [line("192.0.2.254", "GET", "/", 200, timedelta(seconds=i)) for i in range(3)]
    lines.append(line("198.51.100.7", "GET", "/", 200, timedelta(seconds=9)))
    client.post("/api/v1/ingest/upload", files={"file": ("a.log", "\n".join(lines).encode())})

    body = client.get("/api/v1/stats/overview").json()

    assert body["proxy_ips"] == ["192.0.2.254"]
    assert body["proxy_event_share"] == 75.0
    assert body["top_ips"][0] == {"key": "192.0.2.254", "count": 3, "proxy": True}
    assert body["top_ips"][1]["proxy"] is False


def test_false_positives_are_excluded_from_stats(client):
    lines = [line("203.0.113.10", "POST", "/app.php?type=login", 401, timedelta(seconds=10 * i))
             for i in range(6)]
    client.post("/api/v1/ingest/upload", files={"file": ("a.log", "\n".join(lines).encode())})
    alert_id = client.get("/api/v1/alerts").json()["items"][0]["id"]
    client.patch(f"/api/v1/alerts/{alert_id}",
                 json={"status": "false_positive", "note": "kendi testim"})

    body = client.get("/api/v1/stats/overview").json()

    assert body["total_alerts"] == 0
    assert body["false_positives"] == 1
    assert body["top_rules"] == []
    assert body["recent_alerts"] == []
    assert sum(b["alerts"] for b in body["timeline"]) == 0
