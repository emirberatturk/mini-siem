"""KVKK saklama süresi: eski olaylar silinir, kapatılmış alarmların IP'leri maskelenir."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.models import Alert, AlertEvent, AlertHistory, AuthEvent, Event, IngestBatch
from app.db.session import init_db, make_engine
from app.privacy.ipmask import mask_deep, mask_ip, mask_ips
from app.privacy.retention import apply_retention, retention_status
from app.tools import retention as tool

NOW = datetime(2026, 12, 1, 12, 0, tzinfo=UTC)
OLD = NOW - timedelta(days=100)
RECENT = NOW - timedelta(days=10)
OLD_IP = "203.0.113.77"
IPV6 = "2001:db8:3600::103"
DELETED_MARK = "/silinecek-iz-7f3a9c"
KEPT_MARK = "/kalacak-iz-51be02"


# ── IP maskeleme ────────────────────────────────────────────────────────────
@pytest.mark.parametrize("text, expected", [
    ("203.0.113.77 adresi", "203.x.x.x adresi"),
    (f"{IPV6} adresi", "2001:x:x::x adresi"),
    ("cümle sonu 198.51.100.7.", "cümle sonu 198.x.x.x."),
    ("adres: 198.51.100.7: tamam", "adres: 198.x.x.x: tamam"),
    ("(10.0.0.1)", "(10.x.x.x)"),
    ("ip=2001:db8::1&x", "ip=2001:x:x::x&x"),
    ("saat 13:32:45", "saat 13:32:45"),  # saat adres değildir
    ("tarih 2026-09-23", "tarih 2026-09-23"),
    ("cafe beef dead", "cafe beef dead"),
    ("v=1.2.3 ve 203.0.113.4.5", "v=1.2.3 ve 203.0.113.4.5"),  # 5 parça: adres değil
    (":: ve 0.0.0.0", ":: ve 0.0.0.0"),
    ("kaynak :203.0.113.5 idi", "kaynak :203.x.x.x idi"),  # baştaki iki nokta
    ("IP..198.51.100.7 gördüm", "IP..198.x.x.x gördüm"),
    ("ip2001:db8::1 bitişik", "ip2001:x:x::x bitişik"),
    ("::1 yerel", "0:x:x::x yerel"),
])
def test_mask_ips(text, expected):
    assert mask_ips(text) == expected
    assert mask_ips(expected) == expected  # tekrar maskelemek bozmaz


def test_mask_ip_and_deep():
    assert mask_ip(OLD_IP) == "203.x.x.x" and mask_ip("93.x.x.x") == "93.x.x.x"
    assert mask_ip("yerel-terminal") == "yerel-terminal"
    nested = {"ips": [OLD_IP, {"ip": IPV6}], "n": 5, OLD_IP: "anahtar değişmez"}
    assert mask_deep(nested) == {"ips": ["203.x.x.x", {"ip": "2001:x:x::x"}], "n": 5,
                                 OLD_IP: "anahtar değişmez"}


# ── saklama süresi ──────────────────────────────────────────────────────────
@pytest.fixture
def engine(tmp_path):
    e = make_engine(f"sqlite:///{tmp_path / 'siem.db'}")  # gerçek ayarlar: WAL + yabancı anahtar
    init_db(e)
    yield e
    e.dispose()


def _event(batch, ts, path, ip=OLD_IP, key=None):
    return Event(batch_id=batch.id, timestamp=ts, source_ip=ip, http_method="GET", url_path=path,
                 status_code=404, event_category="web", event_type="http_request",
                 event_outcome="failure", parser="apache_combined", event_key=key or path)


def _alert(status, last_seen, ip=OLD_IP):
    return Alert(rule_id="RECON-002", title=f"Tarama {ip}", severity="low", status=status,
                 source_ip=ip, first_seen=last_seen - timedelta(days=1), last_seen=last_seen,
                 event_count=2, reason=f"{ip} adresi yokladı ({IPV6} ile birlikte).",
                 evidence={"top_paths": [{"path": "/x", "count": 2}], "ips": [ip, IPV6]},
                 recommended_steps=[f"{ip} adresini engelle"], mitre=[])


@pytest.fixture
def data(engine):
    with Session(engine, expire_on_commit=False) as db:
        batch = IngestBatch(filename="access.log")
        db.add(batch)
        db.flush()
        old_ev = _event(batch, OLD, DELETED_MARK)
        edge_old = _event(batch, NOW - timedelta(days=91), "/91-gun", key="k91")
        edge_new = _event(batch, NOW - timedelta(days=89), "/89-gun", ip="198.51.100.8", key="k89")
        new_ev = _event(batch, RECENT, KEPT_MARK, ip="198.51.100.9")
        closed_old = _alert("resolved", OLD)
        open_old = _alert("investigating", OLD, ip="198.51.100.20")
        closed_new = _alert("false_positive", RECENT, ip="198.51.100.30")
        db.add_all([old_ev, edge_old, edge_new, new_ev, closed_old, open_old, closed_new])
        db.flush()
        db.add_all([AlertEvent(alert_id=closed_old.id, event_id=old_ev.id),
                    AlertEvent(alert_id=closed_new.id, event_id=new_ev.id),
                    AlertHistory(alert_id=closed_old.id, from_status="investigating",
                                 to_status="resolved", note=f"{OLD_IP} bot, etki yok",
                                 changed_by="berat"),
                    AuthEvent(at=OLD, username="berat", source_ip="127.0.0.1",
                              action="login_ok"),
                    AuthEvent(at=RECENT, username="berat", source_ip="127.0.0.1",
                              action="login_ok")])
        db.commit()
        return {"closed_old": closed_old.id, "open_old": open_old.id,
                "closed_new": closed_new.id}


def _count(engine, model, *where):
    with Session(engine) as db:
        return db.scalar(select(func.count()).select_from(model).where(*where))


def test_dry_run_counts_but_changes_nothing(engine, data):
    r = apply_retention(engine, 90, now=NOW, dry_run=True)

    assert (r.events_deleted, r.alerts_masked, r.open_alerts_kept, r.auth_events_deleted) == (
        2, 1, 1, 1)
    assert _count(engine, Event) == 4 and _count(engine, AuthEvent) == 2
    with Session(engine) as db:
        assert db.get(Alert, data["closed_old"]).source_ip == OLD_IP


def test_old_events_are_deleted_new_ones_kept(engine, data):
    r = apply_retention(engine, 90, now=NOW)

    assert r.events_deleted == 2
    with Session(engine) as db:
        paths = set(db.scalars(select(Event.url_path)))
        assert paths == {"/89-gun", KEPT_MARK}  # 91 gün silinir, 89 gün kalır
        links = db.execute(select(AlertEvent.alert_id)).scalars().all()
        assert links == [data["closed_new"]]  # silinen olayın alarm bağlantısı da gitti
        assert db.scalar(select(func.count()).select_from(IngestBatch)) == 1  # yükleme özeti


def test_closed_old_alert_is_kept_but_masked(engine, data):
    apply_retention(engine, 90, now=NOW)

    with Session(engine) as db:
        a = db.get(Alert, data["closed_old"])
        assert a.status == "resolved" and a.rule_id == "RECON-002"  # karar ve geçmiş kalır
        assert a.source_ip == "203.x.x.x" and a.title == "Tarama 203.x.x.x"
        assert a.reason == "203.x.x.x adresi yokladı (2001:x:x::x ile birlikte)."
        assert a.evidence["ips"] == ["203.x.x.x", "2001:x:x::x"]
        assert a.evidence["top_paths"] == [{"path": "/x", "count": 2}]
        assert a.recommended_steps == ["203.x.x.x adresini engelle"]
        note = db.scalar(select(AlertHistory.note).where(AlertHistory.alert_id == a.id))
        assert note == "203.x.x.x bot, etki yok"


def test_open_and_recent_alerts_are_untouched(engine, data):
    r = apply_retention(engine, 90, now=NOW)

    assert r.open_alerts_kept == 1
    with Session(engine) as db:
        assert db.get(Alert, data["open_old"]).source_ip == "198.51.100.20"  # inceleme sürüyor
        assert db.get(Alert, data["closed_new"]).source_ip == "198.51.100.30"  # süresi dolmadı


def test_own_login_records_follow_the_same_period(engine, data):
    apply_retention(engine, 90, now=NOW)
    with Session(engine) as db:
        assert list(db.scalars(select(AuthEvent.at))) == [RECENT]


def test_running_twice_changes_nothing_more(engine, data):
    apply_retention(engine, 90, now=NOW)
    with Session(engine) as db:
        before = db.get(Alert, data["closed_old"]).evidence

    r = apply_retention(engine, 90, now=NOW)

    assert (r.events_deleted, r.alerts_masked, r.auth_events_deleted) == (0, 0, 0)
    with Session(engine) as db:
        assert db.get(Alert, data["closed_old"]).evidence == before


def test_deleted_rows_do_not_survive_in_the_database_file(engine, data, tmp_path):
    # SQLite silinen satırı dosyada boş sayfa olarak bırakabilir; secure_delete ile ezilmeli
    apply_retention(engine, 90, now=NOW)
    engine.dispose()

    raw = b"".join(p.read_bytes() for p in tmp_path.glob("siem.db*"))
    assert KEPT_MARK.encode() in raw  # dosyayı doğru okuduğumuzun kanıtı
    assert DELETED_MARK.encode() not in raw
    assert OLD_IP.encode() not in raw  # maskelenen alarm + silinen olay: adres hiçbir yerde yok


def test_deleted_rows_are_gone_while_the_app_keeps_running(engine, data, tmp_path):
    # SIEM açıkken bağlantılar kapanmaz; silme, WAL dosyasından ana dosyaya hemen işlenmeli
    with engine.connect():  # açık kalan başka bir bağlantı (çalışan uygulama gibi)
        apply_retention(engine, 90, now=NOW)
        raw = b"".join(p.read_bytes() for p in tmp_path.glob("siem.db*"))
    assert KEPT_MARK.encode() in raw
    assert DELETED_MARK.encode() not in raw


def test_retention_status(engine, data):
    with Session(engine) as db:
        s = retention_status(db, 90)
    assert s.oldest_event == OLD and s.next_purge_at == OLD + timedelta(days=90)


def test_retention_period_has_a_floor():
    with pytest.raises(ValidationError):
        Settings(retention_days=3)


# ── terminal aracı ──────────────────────────────────────────────────────────
def test_tool_dry_run_reports_and_lists_backups(engine, data, tmp_path, monkeypatch, capsys):
    (tmp_path / "siem.db.yedek-2026-09-28").write_bytes(b"x")
    monkeypatch.setattr(tool, "engine", engine)
    monkeypatch.setattr(tool.settings, "database_url", f"sqlite:///{tmp_path / 'siem.db'}")

    tool.main(["--deneme", "--gun", "90"])

    out = capsys.readouterr().out
    assert "silinecek" in out and "siem.db.yedek-2026-09-28" in out
    assert _count(engine, Event) == 4  # deneme: hiçbir şey silinmedi


def test_tool_rejects_too_short_period(monkeypatch, engine):
    monkeypatch.setattr(tool, "engine", engine)
    with pytest.raises(SystemExit):
        tool.main(["--gun", "3"])
