"""Tespit kuralı testleri: her kural için "yakalamalı" ve "yakalamamalı" senaryolar.

IP'ler RFC 5737 dokümantasyon bloklarından. Senaryolar yalnızca davranış içerir
(durum kodları, zamanlama, sıra).
"""

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.db.models import Alert
from app.db.repository import save_batch
from app.detection.engine import load_rules, run_detection, run_on_all
from app.ingestion.pipeline import process_lines

T0 = datetime(2026, 9, 23, 11, 0, tzinfo=UTC)
ATTACKER = "203.0.113.10"
DOCTOR = "198.51.100.200"


def req(ip, method, target, status, at: timedelta, ua="Mozilla/5.0") -> str:
    ts = (T0 + at).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{ts}] "{method} {target} HTTP/1.1" {status} 100 "-" "{ua}"'


def login(ip, status, at):
    return req(ip, "POST", "/app.php?type=login", status, at, ua="python-requests/2.32")


def ingest(db, lines):
    return save_batch(db, "test.log", len(lines), process_lines(lines))


def detect(db, lines):
    ingest(db, lines)
    run_on_all(db)
    return list(db.scalars(select(Alert).order_by(Alert.id)))


def by_rule(alerts, rule_id):
    return [a for a in alerts if a.rule_id == rule_id]


# ── AUTH-001 ────────────────────────────────────────────────────────────────
def test_failed_login_burst_medium(db_session):
    alerts = detect(db_session, [login(ATTACKER, 401, timedelta(seconds=20 * i))
                                 for i in range(6)])

    [a] = by_rule(alerts, "AUTH-001")
    assert a.severity == "medium"
    assert a.event_count == 6
    assert a.source_ip == ATTACKER
    assert a.mitre == ["T1110.001"]


def test_below_threshold_no_alert(db_session):
    alerts = detect(db_session, [login(ATTACKER, 401, timedelta(minutes=i)) for i in range(4)])

    assert by_rule(alerts, "AUTH-001") == []


def test_slow_failures_spread_over_hours_no_alert(db_session):
    # 6 deneme ama her biri 30 dk arayla: 10 dakikalık pencerede hiç eşik aşılmıyor
    alerts = detect(db_session, [login(ATTACKER, 401, timedelta(minutes=30 * i))
                                 for i in range(6)])

    assert by_rule(alerts, "AUTH-001") == []


def test_lockout_makes_it_high(db_session):
    lines = [login(ATTACKER, 401, timedelta(seconds=5 * i)) for i in range(5)]
    lines.append(login(ATTACKER, 429, timedelta(seconds=30)))

    [a] = by_rule(detect(db_session, lines), "AUTH-001")

    assert a.severity == "high"
    assert a.evidence["lockouts"] == 1


def test_identical_same_second_attempts_are_all_counted(db_session):
    # Aynı saniyede 6 özdeş satır: tekilleştirme saldırıyı küçültmemeli
    alerts = detect(db_session, [login(ATTACKER, 401, timedelta(0))] * 6)

    [a] = by_rule(alerts, "AUTH-001")
    assert a.event_count == 6


# ── CORR-001 ────────────────────────────────────────────────────────────────
def test_success_after_failures_is_critical_with_post_login_activity(db_session):
    lines = [login(ATTACKER, 401, timedelta(minutes=i)) for i in range(4)]
    lines.append(login(ATTACKER, 200, timedelta(minutes=5)))
    lines.append(req(ATTACKER, "GET", "/app.php?type=users", 200, timedelta(minutes=6)))
    lines.append(req(ATTACKER, "GET", "/app.php?type=randevu_listesi", 200, timedelta(minutes=7)))

    [a] = by_rule(detect(db_session, lines), "CORR-001")

    assert a.severity == "critical"
    assert a.event_count == 7
    assert [p["query"] for p in a.evidence["post_login"]] == ["type=users", "type=randevu_listesi"]
    assert a.mitre == ["T1078", "T1110"]


def test_legit_typo_then_success_is_not_an_attack(db_session):
    # Yazım hatası + başarılı giriş: brute-force değil. (Örnek profilde bilinen cihaz listesi
    # boş olduğu için AUTH-002 de yorum yapmaz.)
    ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")
    lines = [
        req(DOCTOR, "POST", "/app.php?type=login", 401, timedelta(0), ua=ua),
        req(DOCTOR, "POST", "/app.php?type=login", 200, timedelta(seconds=10), ua=ua),
        req(DOCTOR, "GET", "/app.php?type=randevu_listesi", 200, timedelta(seconds=15), ua=ua),
    ]

    assert detect(db_session, lines) == []


def test_failures_too_long_ago_do_not_correlate(db_session):
    lines = [login(ATTACKER, 401, timedelta(minutes=i)) for i in range(4)]
    lines.append(login(ATTACKER, 200, timedelta(hours=2)))

    assert by_rule(detect(db_session, lines), "CORR-001") == []


# ── ADMIN-001 ───────────────────────────────────────────────────────────────
def test_unauthorized_admin_api_probing(db_session):
    lines = [req(ATTACKER, "GET", f"/app.php?type={t}", 401, timedelta(seconds=10 * i))
             for i, t in enumerate(["users", "ayarlar", "randevu_listesi"])]

    [a] = by_rule(detect(db_session, lines), "ADMIN-001")

    assert a.severity == "medium"


# ── RECON-001 ───────────────────────────────────────────────────────────────
def test_many_distinct_404_paths_is_a_scan(db_session):
    lines = [req(ATTACKER, "GET", f"/eski-sayfa-{i}.html", 404, timedelta(seconds=5 * i))
             for i in range(25)]

    [a] = by_rule(detect(db_session, lines), "RECON-001")

    assert a.severity == "medium"
    assert a.evidence["unique_paths"] == 25
    assert a.mitre == ["T1595.003"]


def test_same_missing_file_repeated_is_low_without_mitre(db_session):
    # Ör. bozuk bir favicon bağlantısı: çok 404 ama tek yol → tarama değil
    lines = [req(ATTACKER, "GET", "/favicon.png", 404, timedelta(seconds=5 * i))
             for i in range(25)]

    [a] = by_rule(detect(db_session, lines), "RECON-001")

    assert a.severity == "low"
    assert a.mitre == []


# ── RATE-001 ────────────────────────────────────────────────────────────────
def test_high_request_rate(db_session):
    lines = [req(ATTACKER, "GET", "/", 200, timedelta(milliseconds=400 * i)) for i in range(130)]

    [a] = by_rule(detect(db_session, lines), "RATE-001")

    assert a.evidence["peak_per_window"] >= 120


def test_normal_visitor_triggers_nothing(db_session):
    lines = [req("192.0.2.20", "GET", p, 200, timedelta(seconds=15 * i))
             for i, p in enumerate(["/", "/tedaviler.html", "/blog.html", "/randevu.html"])]

    assert detect(db_session, lines) == []


# ── Motor: tekilleştirme ve yeniden çalıştırma ──────────────────────────────
def test_rerun_on_same_data_creates_nothing(db_session):
    detect(db_session, [login(ATTACKER, 401, timedelta(seconds=10 * i)) for i in range(6)])

    again = run_on_all(db_session)

    assert (again.created, again.updated) == (0, 0)


def test_continuing_attack_updates_existing_alert(db_session):
    detect(db_session, [login(ATTACKER, 401, timedelta(seconds=10 * i)) for i in range(6)])
    later = [login(ATTACKER, 401, timedelta(minutes=20, seconds=10 * i)) for i in range(6)]

    saved = ingest(db_session, later)
    times = [e.timestamp for e in saved.inserted]
    result = run_detection(db_session, min(times), max(times))

    [a] = by_rule(list(db_session.scalars(select(Alert))), "AUTH-001")
    assert (result.created, result.updated) == (0, 1)
    assert a.event_count == 12


def test_resolved_alert_is_not_recreated_on_rerun(db_session):
    [a] = detect(db_session, [login(ATTACKER, 401, timedelta(seconds=10 * i)) for i in range(6)])
    a.status = "resolved"
    db_session.commit()

    assert run_on_all(db_session).created == 0


def test_yaml_config_overrides_and_disables(tmp_path, db_session):
    cfg = tmp_path / "rules.yaml"
    cfg.write_text("AUTH-001:\n  threshold: 3\nRATE-001:\n  enabled: false\n", encoding="utf-8")
    ingest(db_session, [login(ATTACKER, 401, timedelta(seconds=10 * i)) for i in range(3)])

    rules = load_rules(cfg)
    result = run_detection(db_session, T0, T0 + timedelta(minutes=1), rules)

    assert result.created == 1
    assert not next(r for r in rules if r.id == "RATE-001").enabled


# ── Aracı sunucu (proxy) ────────────────────────────────────────────────────
PROXY = "192.0.2.254"


def proxy_rules():
    from app.detection.engine import RULE_CLASSES

    return [cls(None, frozenset({PROXY})) for cls in RULE_CLASSES]


def test_volume_rules_ignore_proxy_but_auth_rules_still_fire(db_session):
    lines = [req(PROXY, "GET", "/", 200, timedelta(milliseconds=300 * i)) for i in range(150)]
    lines += [req(PROXY, "GET", f"/yok-{i}.html", 404, timedelta(seconds=3 * i)) for i in range(25)]
    lines += [login(PROXY, 401, timedelta(seconds=5 * i)) for i in range(6)]
    ingest(db_session, lines)

    run_detection(db_session, T0, T0 + timedelta(minutes=5), proxy_rules())

    alerts = list(db_session.scalars(select(Alert)))
    assert {a.rule_id for a in alerts} == {"AUTH-001"}
    assert "aracı sunucu" in alerts[0].reason


def test_proxy_config_accepts_networks(tmp_path):
    cfg = tmp_path / "rules.yaml"
    cfg.write_text("proxy_ips:\n  - 10.0.0.0/8\n", encoding="utf-8")

    rule = load_rules(cfg)[0]

    assert rule.is_proxy("10.31.7.178")
    assert not rule.is_proxy("192.0.2.10")
    assert not rule.is_proxy("bozuk-ip")


# ── RECON-002: ısrarlı yoklama ──────────────────────────────────────────────
def test_low_and_slow_probe_over_days(db_session):
    # Günde 12 kez, 3 gün boyunca aynı var olmayan yol: kısa pencereli kurallar görmez
    lines = [req(ATTACKER, "GET", "/eski-kurulum.php", 404, timedelta(days=d, hours=2 * h))
             for d in range(3) for h in range(12)]

    alerts = detect(db_session, lines)

    assert by_rule(alerts, "RECON-001") == []
    [a] = by_rule(alerts, "RECON-002")
    assert a.event_count == 36
    assert a.evidence["days_active"] == 3


def test_occasional_404s_on_different_paths_are_not_persistent(db_session):
    lines = [req(ATTACKER, "GET", f"/sayfa-{i}.html", 404, timedelta(hours=i)) for i in range(20)]

    assert by_rule(detect(db_session, lines), "RECON-002") == []


# ── AUTH-002: tanınmayan cihaz ──────────────────────────────────────────────
WIN_CHROME = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")
DEVICES = {"known_devices": [
    {"name": "Windows bilgisayar (Chrome)", "match": ["Windows NT 10.0", "Chrome/"]},
    {"name": "iPhone", "match": ["iPhone"]},
]}


def device_rules():
    from app.detection.rules.auth import UnknownDeviceLogin

    return [UnknownDeviceLogin(DEVICES)]


def test_known_device_login_is_quiet_even_after_browser_update(db_session):
    newer = WIN_CHROME.replace("Chrome/153", "Chrome/160")
    ingest(db_session, [req(DOCTOR, "POST", "/app.php?type=login", 200, timedelta(0), ua=newer)])

    assert run_detection(db_session, T0, T0 + timedelta(minutes=1), device_rules()).created == 0


def test_unknown_device_login_is_high_with_post_login_activity(db_session):
    ingest(db_session, [
        req(ATTACKER, "POST", "/app.php?type=login", 200, timedelta(0), ua="curl/8.19.0"),
        req(ATTACKER, "GET", "/app.php?type=users", 200, timedelta(minutes=1), ua="curl/8.19.0"),
    ])

    run_detection(db_session, T0, T0 + timedelta(minutes=5), device_rules())

    [a] = list(db_session.scalars(select(Alert)))
    assert a.rule_id == "AUTH-002"
    assert a.severity == "high"
    assert a.evidence["user_agent"] == "curl/8.19.0"
    assert a.evidence["post_login"][0]["query"] == "type=users"


def test_no_known_devices_configured_means_no_opinion(db_session):
    from app.detection.rules.auth import UnknownDeviceLogin

    ingest(db_session, [login(ATTACKER, 200, timedelta(0))])

    rules = [UnknownDeviceLogin({"known_devices": []})]
    assert run_detection(db_session, T0, T0 + timedelta(minutes=1), rules).created == 0
