"""İmza (Sigma) tespiti testleri.

Mantık testleri zararsız işaretlerle (ör. "zzmarker") yazılmış küçük kurallar kullanır.
Gerçek SigmaHQ kuralları ise kendi dosyalarındaki ilk kalıpla sınanır: testlerde saldırı
metni uydurulmaz, kuralın kendisi kaynak alınır.
"""

import json
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

import pytest
import yaml
from sqlalchemy import create_engine, func, inspect, select, text

from app.core.config import settings
from app.db.models import Alert, Event
from app.db.repository import save_batch
from app.db.session import init_db
from app.detection import sigma
from app.detection.engine import load_rules, run_detection, run_on_all
from app.ingestion.pipeline import process_lines
from app.parsers import apache
from app.privacy.redactor import MASK

T0 = datetime(2026, 9, 23, 11, 0, tzinfo=UTC)
ATTACKER = "203.0.113.10"  # RFC 5737 dokümantasyon adresi
SQLI = settings.sigma_rules_dir / "web_sql_injection_in_access_logs.yml"
XSS = settings.sigma_rules_dir / "web_xss_in_access_logs.yml"


def req(ip, method, target, status, at: timedelta, ua="Mozilla/5.0") -> str:
    ts = (T0 + at).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{ts}] "{method} {target} HTTP/1.1" {status} 100 "-" "{ua}"'


def detect(db, lines, rules_path=None):
    """Satırları yükler, kuralları çalıştırır, SIG-001 alarmlarını döner."""
    save_batch(db, "test.log", len(lines), process_lines(lines))
    if rules_path is None:
        run_on_all(db)
    else:
        run_detection(db, T0 - timedelta(hours=1), T0 + timedelta(hours=1),
                      rules=load_rules(rules_path))
    return list(db.scalars(select(Alert).where(Alert.rule_id == "SIG-001")))


def view(target="/x", method="GET", status=200, ua="Mozilla/5.0"):
    line = req(ATTACKER, method, target, status, timedelta(0), ua=ua)
    return line, apache.parse_line(line)


def rule(detection: dict, category="webserver") -> sigma.SigmaRule:
    return sigma.parse_rule({"title": "Test", "level": "high", "tags": ["attack.t1190"],
                             "logsource": {"category": category}, "detection": detection},
                            "test")


def matches(r, target="/x", **kw) -> bool:
    return sigma.match(*view(target, **kw), rules=[r]) == ["test"]


# ── Sigma alt kümesi ────────────────────────────────────────────────────────
def test_keywords_search_whole_line_case_insensitive():
    r = rule({"keywords": ["ZZmarker"], "condition": "keywords"})

    assert matches(r, "/a?q=zzMARKER")
    assert matches(r, "/a", ua="tool-zzmarker")  # satırın herhangi bir yeri
    assert not matches(r, "/a?q=zz-marker")


def test_url_encoding_does_not_hide_the_pattern():
    r = rule({"keywords": ["zz'marker"], "condition": "keywords"})

    assert matches(r, "/a?q=zz%27marker")    # tek kodlama
    assert matches(r, "/a?q=zz%2527marker")  # çift kodlama


def test_field_contains_and_status_filter():
    r = rule({"selection": {"cs-method": "GET"},
              "keywords": ["zzmarker"],
              "filter_main_status": {"sc-status": 404},
              "condition": "selection and keywords and not 1 of filter_main_*"})

    assert matches(r, "/a?q=zzmarker", status=200)
    assert not matches(r, "/a?q=zzmarker", status=404)  # filtre
    assert not matches(r, "/a?q=zzmarker", method="POST")  # seçim


def test_all_of_or_and_parentheses():
    r = rule({"selection_a": {"cs-uri-query|contains": ["zza"]},
              "selection_b": {"cs-user-agent|startswith": "zzb"},
              "other": {"cs-uri-stem|endswith": ".zzc"},
              "condition": "all of selection_* or (other and not selection_a)"})

    assert matches(r, "/a?x=zza", ua="zzb-tool")
    assert not matches(r, "/a?x=zza")
    assert matches(r, "/file.zzc")
    assert not matches(r, "/file.zzc?x=zza")


@pytest.mark.parametrize(
    "detection",
    [
        {"sel": {"cs-host": "x"}, "condition": "sel"},                  # bilinmeyen alan
        {"sel": {"cs-uri-query|re": "x"}, "condition": "sel"},          # desteklenmeyen
        {"sel": {"cs-method": "GET"}, "condition": "sel and missing"},  # bilinmeyen isim
        {"sel": {"cs-method": "GET"}, "condition": "sel |"},            # ayrıştırılamaz
        {"sel": {"cs-method": "GET"}, "timeframe": "5m", "condition": "sel"},
    ],
)
def test_unsupported_rules_are_rejected_not_half_run(detection):
    with pytest.raises(sigma.SigmaError):
        rule(detection)


def test_only_webserver_rules():
    with pytest.raises(sigma.SigmaError):
        rule({"sel": {"cs-method": "GET"}, "condition": "sel"}, category="process_creation")


def test_loader_skips_bad_files(tmp_path, caplog):
    (tmp_path / "web_good.yml").write_text(yaml.safe_dump(
        {"title": "İyi", "logsource": {"category": "webserver"},
         "detection": {"k": ["zzmarker"], "condition": "k"}}), encoding="utf-8")
    (tmp_path / "web_bad.yml").write_text("detection: {condition: 1 of}", encoding="utf-8")

    assert [r.name for r in sigma.load_rules(tmp_path)] == ["good"]
    assert "web_bad.yml" in caplog.text


# ── Gerçek SigmaHQ kuralları (config/sigma) ─────────────────────────────────
VENDORED = sorted(settings.sigma_rules_dir.glob("*.yml"))


def first_pattern(path) -> str:
    """Kuralın kendi dosyasındaki ilk kalıp (anahtar kelime ya da |contains değeri)."""
    detection = yaml.safe_load(path.read_text(encoding="utf-8"))["detection"]
    for item in detection.values():
        if isinstance(item, list):
            return str(item[0])
        if isinstance(item, dict):
            for key, value in item.items():
                if key.endswith("|contains"):
                    return str(value[0] if isinstance(value, list) else value)
    raise AssertionError(f"kalıp bulunamadı: {path.name}")


def test_all_vendored_rules_load():
    assert len(VENDORED) == 10
    assert [r.name for r in sigma.load_rules(settings.sigma_rules_dir)] == [
        sigma.short_name(p) for p in VENDORED]


@pytest.mark.parametrize("path", VENDORED, ids=lambda p: p.stem)
def test_each_vendored_rule_fires_on_its_own_pattern(path):
    pattern = first_pattern(path)
    ua = "Mozilla/5.0 " + pattern.replace('"', '\\"')
    hits = sigma.match(*view(f"/x?q={quote(pattern, safe='')}", ua=ua))

    assert sigma.short_name(path) in hits


def test_ordinary_requests_match_nothing():
    for target in ["/", "/index.html", "/blog.html?sayfa=2", "/images/logo.png",
                   "/randevu.html?tarih=2026-09-24&saat=10:00"]:
        assert sigma.match(*view(target)) == [], target


def test_ssti_mitre_override():
    ssti = next(r for r in sigma.default_rules() if r.name == "ssti")
    assert ssti.mitre == ["T1190"]  # SigmaHQ'daki T1221 Office şablon enjeksiyonudur


# ── KVKK: imza maskelemeden önce kontrol edilir, ham metin saklanmaz ────────
def test_attack_in_masked_field_is_detected_but_not_stored():
    pattern = first_pattern(SQLI)
    line = req(ATTACKER, "GET", f"/iletisim.html?email={quote(pattern, safe='')}", 200,
               timedelta(0))

    [event] = process_lines([line]).events

    assert event.url_query == f"email={MASK}"  # KVKK maskesi aynen duruyor
    assert "sql_injection" in event.signatures.split(",")
    stored = json.dumps(event.model_dump(mode="json"), ensure_ascii=False).lower()
    assert pattern.lower() not in stored  # saldırı metni hiçbir alanda yok


# ── SIG-001 alarmı ──────────────────────────────────────────────────────────
def test_signature_alert_groups_attempts_by_ip(db_session):
    sqli, xss = (quote(first_pattern(p), safe="") for p in (SQLI, XSS))
    lines = [
        req(ATTACKER, "GET", f"/urun.php?id={sqli}", 200, timedelta(minutes=0)),
        req(ATTACKER, "GET", f"/ara.php?q={xss}", 403, timedelta(minutes=2)),
        req(ATTACKER, "GET", "/index.html", 200, timedelta(minutes=3)),  # masum
    ]

    [a] = detect(db_session, lines)

    assert a.event_count == 2
    assert a.severity == "high"
    assert {s["rule"] for s in a.evidence["signatures"]} == {"sql_injection", "xss"}
    assert a.evidence["success_responses"] == 1
    assert "1 tanesine başarılı" in a.reason
    assert a.mitre == ["T1189", "T1190"]


def test_alert_title_leads_with_the_signature_that_got_through(db_session):
    # Engellenen XSS denemesi daha çok ama alarmın sebebi 200 alan SQLi: başlık onunla başlamalı
    sqli, xss = (quote(first_pattern(p), safe="") for p in (SQLI, XSS))
    lines = [req(ATTACKER, "GET", f"/ara.php?q={xss}", 403, timedelta(minutes=i)) for i in range(3)]
    lines.append(req(ATTACKER, "GET", f"/urun.php?id={sqli}", 200, timedelta(minutes=4)))

    [a] = detect(db_session, lines)

    assert a.title == "Web saldırı imzası: SQL Injection Strings In URI (+1)"
    first, second = a.evidence["signatures"]
    assert (first["rule"], first["count"], first["success"]) == ("sql_injection", 1, 1)
    assert (second["rule"], second["count"], second["success"]) == ("xss", 3, 0)
    assert a.first_seen == T0


def test_blocked_attempts_are_recorded_but_do_not_alert(db_session):
    sqli = quote(first_pattern(SQLI), safe="")
    lines = [req(ATTACKER, "GET", f"/u.php?id={sqli}", status, timedelta(minutes=i))
             for i, status in enumerate([403, 500, 301])]  # 404'ü SQLi kuralı zaten dışlar

    assert detect(db_session, lines) == []  # hepsi engellendi → alarm yok
    stored = db_session.scalars(select(Event.signatures)).all()
    assert stored == ["sql_injection"] * 3  # ama olaylarda kayıtlı


def test_alert_on_all_alerts_even_when_blocked(db_session, tmp_path):
    cfg = tmp_path / "rules.yaml"
    cfg.write_text("SIG-001:\n  alert_on: all\n", encoding="utf-8")
    sqli = quote(first_pattern(SQLI), safe="")

    [a] = detect(db_session, [req(ATTACKER, "GET", f"/u.php?id={sqli}", 403, timedelta(0))],
                 rules_path=cfg)

    assert a.evidence["success_responses"] == 0
    assert "hiçbirine başarılı yanıt vermedi" in a.reason


def test_signature_rule_can_be_disabled(db_session, tmp_path):
    cfg = tmp_path / "rules.yaml"
    cfg.write_text("SIG-001:\n  enabled: false\n", encoding="utf-8")
    sqli = quote(first_pattern(SQLI), safe="")

    alerts = detect(db_session, [req(ATTACKER, "GET", f"/u.php?id={sqli}", 200, timedelta(0))],
                    rules_path=cfg)

    assert alerts == []
    assert db_session.scalar(select(func.count()).select_from(Alert)) == 0


# ── Veritabanı: eski veritabanına sütun eklenir, veri silinmez ──────────────
def test_existing_database_gets_signatures_column():
    engine = create_engine("sqlite://")
    init_db(engine)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE events DROP COLUMN signatures"))  # eski şema
    assert "signatures" not in {c["name"] for c in inspect(engine).get_columns("events")}

    init_db(engine)

    assert "signatures" in {c["name"] for c in inspect(engine).get_columns("events")}
