"""Yeniden tarama aracı: eski veritabanında yalnızca imza sütununu doldurmalı,
başka hiçbir şeye (olaylar, alarmlar, notlar) dokunmamalı."""

from datetime import timedelta
from urllib.parse import quote

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.db.models import Alert, AlertHistory, Event
from app.db.repository import save_batch
from app.db.session import init_db
from app.ingestion.pipeline import process_lines
from app.tools.rescan_signatures import rescan
from tests.test_sigma import ATTACKER, SQLI, first_pattern, req

SNAPSHOT = (Event.id, Event.timestamp, Event.source_ip, Event.url_path, Event.url_query,
            Event.status_code, Event.user_agent, Event.event_type, Event.event_key)


def old_database(tmp_path):
    """İmza özelliğinden önce yüklenmiş veriyi taklit eder: signatures boş, notlu bir alarm var."""
    sqli = quote(first_pattern(SQLI), safe="")
    lines = [req(ATTACKER, "GET", f"/urun.php?id={sqli}", 200, timedelta(0)),
             req(ATTACKER, "GET", "/index.html", 200, timedelta(minutes=1))]
    log = tmp_path / "access_log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    engine = create_engine(f"sqlite:///{tmp_path / 'siem.db'}")
    init_db(engine)
    result = process_lines(lines)
    for e in result.events:
        e.signatures = ""  # eski sürüm imza bilmiyordu
    with Session(engine) as db:
        save_batch(db, "access_log", len(lines), result)
        db.add(Alert(rule_id="RECON-001", title="Eski alarm", severity="low", status="closed",
                     source_ip=ATTACKER, first_seen=result.events[0].timestamp,
                     last_seen=result.events[0].timestamp, reason="x", evidence={},
                     recommended_steps=[], mitre=[]))
        db.flush()
        db.add(AlertHistory(alert_id=1, from_status="new", to_status="closed",
                            changed_by="analist", note="Yanlış alarm: kendi testim"))
        db.commit()
    return engine, log


def snapshot(engine):
    with Session(engine) as db:
        return (db.execute(select(*SNAPSHOT).order_by(Event.id)).all(),
                db.execute(select(Alert.id, Alert.status, Alert.title)).all(),
                db.execute(select(AlertHistory.note)).all())


def test_dry_run_changes_nothing(tmp_path):
    engine, log = old_database(tmp_path)
    before = snapshot(engine)

    assert rescan([log], dry_run=True, bind=engine) == 1

    assert snapshot(engine) == before
    with Session(engine) as db:
        assert db.scalars(select(Event.signatures)).all() == ["", ""]


def test_rescan_fills_only_signatures_and_keeps_history(tmp_path):
    engine, log = old_database(tmp_path)
    events_before, alerts_before, notes_before = snapshot(engine)

    assert rescan([log], dry_run=False, bind=engine) == 1

    events_after, alerts_after, notes_after = snapshot(engine)
    assert events_after == events_before  # imza dışındaki tüm alanlar aynı
    assert alerts_after[:1] == alerts_before  # eski alarm aynen duruyor
    assert notes_after[:1] == notes_before  # analist notu kaybolmadı
    with Session(engine) as db:
        assert db.scalars(select(Event.signatures).order_by(Event.id)).all() == [
            "sql_injection", ""]
        [new] = db.scalars(select(Alert).where(Alert.rule_id == "SIG-001")).all()
        assert new.event_count == 1

    assert rescan([log], dry_run=False, bind=engine) == 0  # ikinci kez: değişiklik yok
