"""Demo veri aracı: yalnızca sahte veri üretir; asıl veritabanına ve gerçek ayarlara dokunmaz."""

import ipaddress
import json

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from app.db.models import Alert, AlertHistory, Event, User
from app.tools import demo_veri

BELGE_AGLARI = [
    ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]


@pytest.fixture(scope="module")
def demo(tmp_path_factory):
    hedef = tmp_path_factory.mktemp("demo") / "demo.db"
    demo_veri.main([str(hedef), "--gun", "2", "--totp"])
    motor = create_engine(f"sqlite:///{hedef.as_posix()}")
    yield hedef, motor
    motor.dispose()


def test_only_documentation_ip_ranges(demo):
    _, motor = demo
    with Session(motor) as db:
        ipler = {ipaddress.ip_address(ip) for ip in db.scalars(select(Event.source_ip).distinct())}
    assert ipler and all(any(ip in ag for ag in BELGE_AGLARI) for ip in ipler)


def test_scenarios_raise_alerts_and_some_have_decisions(demo):
    _, motor = demo
    with Session(motor) as db:
        kurallar = set(db.scalars(select(Alert.rule_id)))
        durumlar = dict(db.execute(select(Alert.rule_id, Alert.status)).all())
        assert db.scalar(select(func.count()).select_from(Event)) > 1000
        notlar = db.scalars(
            select(AlertHistory.note).where(AlertHistory.changed_by == "analist")
        ).all()
    assert {"AUTH-001", "CORR-001", "RECON-001", "ADMIN-001", "SIG-001", "RATE-001"} <= kurallar
    assert durumlar["CORR-001"] == "new"  # incelenecek iş bilerek açık kalır
    assert durumlar["AUTH-001"] == "resolved" and any(notlar)


def test_users_and_credentials_file(demo):
    hedef, motor = demo
    bilgi = json.loads(hedef.with_name(hedef.name + ".giris.json").read_text(encoding="utf-8"))
    assert set(bilgi["kullanicilar"]) == {"demo", "analist"} and len(bilgi["totp"]) == 32
    with Session(motor) as db:
        roller = dict(db.execute(select(User.username, User.role)).all())
        assert set(db.scalars(select(User.totp_secret))) == {bilgi["totp"]}
    assert roller == {"demo": "admin", "analist": "analyst"}


def test_refuses_the_real_database_name(tmp_path):
    with pytest.raises(SystemExit):
        demo_veri.main([str(tmp_path / "siem.db")])


@pytest.mark.parametrize("ad", ["siem", "siem.db.yedek", "demo", "SIEM.db"])
def test_bad_names_never_touch_neighbouring_files(tmp_path, ad):
    # "data\\siem" gibi bir yazım hatası asıl veritabanını ya da yedekleri silmemeli
    komsular = ["siem.db", "siem.db-wal", "siem.db.yedek-2026-09-28", "demo.db.yedek"]
    for k in komsular:
        (tmp_path / k).write_bytes(b"gercek")
    with pytest.raises(SystemExit):
        demo_veri.main([str(tmp_path / ad)])
    assert all((tmp_path / k).read_bytes() == b"gercek" for k in komsular)


def test_overwrite_deletes_only_its_own_files(tmp_path):
    hedef = tmp_path / "demo.db"
    demo_veri.main([str(hedef), "--gun", "1"])
    (tmp_path / "demo.db.yedek").write_bytes(b"yedek")
    demo_veri.main([str(hedef), "--gun", "1", "--uzerine"])
    assert (tmp_path / "demo.db.yedek").read_bytes() == b"yedek"


def test_refuses_to_overwrite_without_flag(tmp_path):
    hedef = tmp_path / "demo.db"
    hedef.write_bytes(b"onemli")
    with pytest.raises(SystemExit):
        demo_veri.main([str(hedef)])
    assert hedef.read_bytes() == b"onemli"


def test_refuses_when_real_site_settings_are_on(tmp_path, monkeypatch):
    monkeypatch.setattr(demo_veri.settings, "use_local_config", True)
    with pytest.raises(SystemExit):
        demo_veri.olustur(tmp_path / "demo.db", gun=1)
