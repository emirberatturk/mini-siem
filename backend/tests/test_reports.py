"""Haftalık rapor: yerel gün sınırları, önceki hafta, alarm kararları, gezinme."""

from datetime import UTC, datetime, timedelta

from app.db.models import Alert, AlertHistory, Event, IngestBatch

URL = "/api/v1/reports/weekly"


def utc(day: int, hour: int, minute: int = 0, month: int = 9) -> datetime:
    return datetime(2026, month, day, hour, minute, tzinfo=UTC)


def add_events(db, rows):
    batch = IngestBatch(filename="access.log")
    db.add(batch)
    db.flush()
    for i, (ts, code, etype, sig, ip) in enumerate(rows):
        db.add(Event(batch_id=batch.id, timestamp=ts, source_ip=ip, http_method="GET",
                     url_path=f"/p{i}", status_code=code, event_category="web", event_type=etype,
                     event_outcome="success" if code < 400 else "failure", parser="t",
                     signatures=sig, event_key=f"k{i}"))
    db.commit()


def ev(ts, code=200, etype="http_request", sig="", ip="198.51.100.1"):
    return ts, code, etype, sig, ip


def add_alert(db, first_seen, status="new", severity="low", decided=None):
    a = Alert(rule_id="RECON-001", title="Tarama", severity=severity, status=status,
              source_ip="203.0.113.5", first_seen=first_seen, last_seen=first_seen, reason="r",
              evidence={}, recommended_steps=[], mitre=[])
    db.add(a)
    db.flush()
    db.add(AlertHistory(alert_id=a.id, from_status=None, to_status="new", changed_by="sistem"))
    if decided:
        db.add(AlertHistory(alert_id=a.id, from_status="new", to_status=status,
                            changed_by=decided[0], note=decided[1]))
    db.commit()
    return a


def test_default_week_ends_on_the_last_logged_day(client, db_session):
    add_events(db_session, [ev(utc(10, 12)), ev(utc(20, 12))])

    r = client.get(URL).json()

    assert (r["first_day"], r["last_day"]) == ("2026-09-14", "2026-09-20")
    assert [d["day"] for d in r["days"]][0] == "2026-09-14" and len(r["days"]) == 7


def test_days_follow_turkish_local_time(client, db_session):
    # 22 Eylül 21:30 UTC = 23 Eylül 00:30 Türkiye → 23'üne sayılır
    add_events(db_session, [ev(utc(22, 21, 30)), ev(utc(22, 20, 30))])

    r = client.get(URL, params={"end": "2026-09-23"}).json()

    by_day = {d["day"]: d["events"] for d in r["days"]}
    assert by_day["2026-09-23"] == 1 and by_day["2026-09-22"] == 1
    assert r["start"].startswith("2026-09-16T21:00")  # 17 Eylül 00:00 Türkiye


def test_totals_and_previous_week(client, db_session):
    add_events(db_session, [
        ev(utc(21, 10)), ev(utc(21, 11), 404, ip="203.0.113.9"),
        ev(utc(22, 10), 404, sig="path_traversal", ip="203.0.113.9"),
        ev(utc(22, 11), 200, sig="sqli"),  # şüpheli ve başarılı yanıt aldı
        ev(utc(23, 9), 200, "authentication_success"),
        ev(utc(23, 10), 401, "authentication_failure"),
        ev(utc(15, 10)),  # önceki hafta
        ev(utc(8, 10)),  # iki hafta önce: hiçbir toplamda sayılmaz
    ])

    r = client.get(URL, params={"end": "2026-09-23"}).json()

    t = r["totals"]
    assert (t["events"], t["client_errors"], t["suspicious"], t["suspicious_blocked"]) == (
        6, 3, 2, 1)
    assert (t["auth_ok"], t["auth_fail"], t["unique_ips"]) == (1, 1, 2)
    assert r["previous"]["events"] == 1
    assert r["top_sources"][0] == {"key": "203.0.113.9", "count": 2, "proxy": False}
    assert {s["key"] for s in r["top_signatures"]} == {"path_traversal", "sqli"}


def test_missing_days_are_flagged(client, db_session):
    add_events(db_session, [ev(utc(21, 10)), ev(utc(23, 10))])
    r = client.get(URL, params={"end": "2026-09-23"}).json()
    assert r["missing_days"] == ["2026-09-17", "2026-09-18", "2026-09-19", "2026-09-20",
                                 "2026-09-22"]


def test_alerts_with_analyst_decisions(client, db_session):
    add_events(db_session, [ev(utc(23, 10))])
    add_alert(db_session, utc(21, 10), "false_positive", decided=("berat", "kendi oturumum"))
    add_alert(db_session, utc(22, 10), "new", severity="high")
    add_alert(db_session, utc(1, 10), "investigating")  # başka hafta ama hâlâ açık

    r = client.get(URL, params={"end": "2026-09-23"}).json()

    assert [(a["severity"], a["status"]) for a in r["alerts"]] == [
        ("high", "new"), ("low", "false_positive")]  # önem sırası
    closed = r["alerts"][1]
    assert (closed["decided_by"], closed["decision_note"]) == ("berat", "kendi oturumum")
    assert r["alerts"][0]["decided_by"] is None  # "sistem" karar sayılmaz
    assert r["alerts_by_status"] == {"new": 1, "false_positive": 1}
    assert r["open_alerts_total"] == 2
    assert r["totals"]["alerts"] == 2


def test_navigation_links_only_where_data_exists(client, db_session):
    add_events(db_session, [ev(utc(10, 12)), ev(utc(20, 12)), ev(utc(28, 12))])

    middle = client.get(URL, params={"end": "2026-09-20"}).json()
    assert middle["prev_last_day"] == "2026-09-13" and middle["next_last_day"] == "2026-09-27"
    last = client.get(URL).json()
    assert last["next_last_day"] is None
    first = client.get(URL, params={"end": "2026-09-13"}).json()
    assert first["prev_last_day"] is None


def test_retention_info_is_included(client, db_session):
    add_events(db_session, [ev(utc(1, 12, month=8))])
    r = client.get(URL).json()
    assert r["retention_days"] == 90
    first = datetime.fromisoformat(r["oldest_event"])
    assert datetime.fromisoformat(r["next_purge_at"]) - first == timedelta(days=90)


def test_empty_database_gives_an_empty_week(client):
    r = client.get(URL).json()
    assert r["totals"]["events"] == 0 and len(r["missing_days"]) == 7
    assert r["prev_last_day"] is None and r["next_last_day"] is None


def test_analyst_can_read_the_report(analyst_client):
    assert analyst_client.get(URL).status_code == 200


def test_bad_date_is_rejected(client):
    assert client.get(URL, params={"end": "yarın"}).status_code == 422
