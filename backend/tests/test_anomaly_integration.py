"""Anomali tespitinin SIEM'e bağlanması: pipeline, ANOM-001 alarmı, eğitim ve yeniden tarama."""

import json
from datetime import timedelta
from urllib.parse import quote

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.db.models import Alert, Event
from app.db.repository import save_batch
from app.db.session import init_db
from app.detection import anomaly
from app.detection.engine import run_on_all
from app.ingestion.pipeline import process_lines
from app.privacy.redactor import MASK
from app.tools.rescan_signatures import rescan
from app.tools.train_profile import train_from_logs
from tests.test_sigma import ATTACKER, SQLI, first_pattern, req

VISITOR = "198.51.100.7"  # RFC 5737
PROFILE = anomaly.train(
    [("/urun.php", f"id={i}&adet={i % 5 + 1}") for i in range(1, 41)]
    + [("/iletisim.html", f"email=kisi{i}@example.com") for i in range(30)]
)


def lines_with(target, status=200, ip=ATTACKER, minute=0):
    return req(ip, "GET", target, status, timedelta(minutes=minute))


def ingest_and_detect(db, lines, profile=PROFILE):
    save_batch(db, "t.log", len(lines), process_lines(lines, profile))
    run_on_all(db)
    return list(db.scalars(select(Alert).where(Alert.rule_id == "ANOM-001")))


# ── pipeline ────────────────────────────────────────────────────────────────
def test_pipeline_marks_anomaly_without_storing_value():
    [e] = process_lines([lines_with("/urun.php?id=zq")], PROFILE).events  # 2 hane: yalnızca tür

    assert e.anomalies == "id:karakter"
    assert "zq" not in e.anomalies


def test_anomaly_found_even_in_masked_field_and_mask_kept():
    [e] = process_lines([lines_with("/iletisim.html?email=" + "x" * 200 + "%40a.com")],
                        PROFILE).events

    assert e.url_query == f"email={MASK}"  # KVKK maskesi aynen
    assert e.anomalies == "email:uzunluk"
    assert "xxxx" not in json.dumps(e.model_dump(mode="json"))


def test_no_profile_means_no_anomaly_check():
    [e] = process_lines([lines_with("/urun.php?id=zzqwerty")]).events  # testlerde profil yok
    assert e.anomalies == ""


# ── ANOM-001 ────────────────────────────────────────────────────────────────
def test_alert_only_when_server_accepted(db_session):
    lines = [lines_with("/urun.php?id=abc", 403, minute=0),
             lines_with("/urun.php?adet=" + "9" * 30, 200, minute=1)]

    [a] = ingest_and_detect(db_session, lines)

    assert a.title == "Anormal parametre değeri: adet (beklenenden uzun) (+1)"
    assert a.severity == "medium"
    assert a.mitre == []  # bilerek eşleme yok
    assert a.evidence["success_responses"] == 1
    first = a.evidence["anomalies"][0]
    assert (first["finding"], first["success"]) == ("adet:uzunluk", 1)


def test_all_rejected_means_no_alert_but_events_keep_findings(db_session):
    assert ingest_and_detect(db_session, [lines_with("/urun.php?id=abc", 404)]) == []
    assert db_session.scalars(select(Event.anomalies)).all() == ["id:karakter"]


def test_signature_matches_are_not_alerted_twice(db_session):
    attack = quote(first_pattern(SQLI), safe="")
    alerts = ingest_and_detect(db_session, [lines_with(f"/urun.php?id={attack}", 200)])

    assert alerts == []  # SIG-001 zaten alarm verdi; ANOM-001 tekrar etmez
    assert db_session.scalars(select(Alert.rule_id)).all() == ["SIG-001"]


# ── eğitim aracı ────────────────────────────────────────────────────────────
def test_training_skips_rejected_and_signature_requests(tmp_path):
    attack = quote(first_pattern(SQLI), safe="")
    log = tmp_path / "access_log"
    log.write_text("\n".join(
        [lines_with(f"/urun.php?id={i}", 200, VISITOR, i) for i in range(30)]
        + [lines_with("/urun.php?id=<<<", 404, minute=40)]          # reddedilmiş: öğrenilmez
        + [lines_with("/urun.php?id=%3E%3E", 301, minute=42)]       # yönlendirme: öğrenilmez
        + [lines_with(f"/urun.php?id={attack}", 200, minute=41)]    # imza: öğrenilmez
    ) + "\n", encoding="utf-8")

    profile, stats = train_from_logs([log])

    assert stats["öğrenilen"] == 30
    assert stats["başarısız/yönlendirme (2xx değil)"] == 2 and stats["imza eşleşen"] == 1
    assert set(profile.paths["/urun.php"]["id"].chars) == {"rakam"}  # saldırı öğrenilmedi
    assert profile.check("/urun.php", "id=<<<") == ["id:karakter"]


# ── yeniden tarama ──────────────────────────────────────────────────────────
def test_rescan_fills_anomalies_for_old_data(tmp_path):
    lines = [lines_with("/urun.php?id=7", 200, VISITOR), lines_with("/urun.php?id=abc", 200)]
    log = tmp_path / "access_log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    engine = create_engine(f"sqlite:///{tmp_path / 'siem.db'}")
    init_db(engine)
    with Session(engine) as db:  # anomali özelliğinden önce yüklenmiş gibi
        save_batch(db, "access_log", len(lines), process_lines(lines))

    assert rescan([log], dry_run=False, bind=engine, profile=PROFILE) == 1

    with Session(engine) as db:
        assert db.scalars(select(Event.anomalies).order_by(Event.id)).all() == ["", "id:karakter"]
        assert db.scalars(select(Alert.rule_id)).all() == ["ANOM-001"]
