"""Veri saklama süresi (KVKK: kişisel veri, işleme amacının gerektirdiğinden uzun tutulmaz).

Süre, logdaki olayın zamanına göre sayılır (yükleme zamanına göre değil):
- Süresi dolan olaylar (log satırları) silinir.
- Alarmlar ve analist kararları kalır (geçmiş ve denetim izi kaybolmasın), ama içlerindeki IP
  adresleri maskelenir (93.x.x.x). Yalnızca KAPATILMIŞ alarmlar: incelemesi süren bir alarm
  bozulmaz; kapatıldıktan sonraki ilk çalıştırmada maskelenir.
- SIEM'in kendi giriş kayıtları (auth_events) da aynı sürede silinir.

SQLite silinen satırı hemen ezmez, dosyada boş sayfa olarak bırakır; bu yüzden silme
secure_delete açıkken yapılır (silinen içerik sıfırla ezilir) ve WAL dosyası boşaltılır.
Not: data/ klasöründeki elle alınmış yedek dosyalar bu kapsamın dışındadır.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.db.models import Alert, AlertEvent, AlertHistory, AuthEvent, Event
from app.privacy.ipmask import mask_deep, mask_ip, mask_ips

CLOSED = ("false_positive", "resolved")


@dataclass(frozen=True)
class RetentionResult:
    cutoff: datetime
    events_deleted: int
    alerts_masked: int
    open_alerts_kept: int  # süresi dolmuş ama hâlâ açık (incelenmesi bekleniyor)
    auth_events_deleted: int
    dry_run: bool


def _is_masked(ip: str) -> bool:
    return "x" in ip


def apply_retention(bind: Engine, days: int, *, now: datetime | None = None,
                    dry_run: bool = False) -> RetentionResult:
    cutoff = (now or datetime.now(UTC)) - timedelta(days=days)
    old_events = Event.timestamp < cutoff
    expired_alerts = [Alert.last_seen < cutoff, Alert.status.in_(CLOSED)]
    sqlite = bind.dialect.name == "sqlite"

    with Session(bind) as db:
        n_events = db.scalar(select(func.count()).select_from(Event).where(old_events)) or 0
        n_auth = db.scalar(select(func.count()).select_from(AuthEvent)
                           .where(AuthEvent.at < cutoff)) or 0
        to_mask = [a for a in db.scalars(select(Alert).where(*expired_alerts))
                   if not _is_masked(a.source_ip)]
        n_open = db.scalar(select(func.count()).select_from(Alert).where(
            Alert.last_seen < cutoff, Alert.status.not_in(CLOSED))) or 0
        result = RetentionResult(cutoff, n_events, len(to_mask), n_open, n_auth, dry_run)
        if dry_run or not (n_events or n_auth or to_mask):
            return result

        if sqlite:  # aynı bağlantıda: silinen içerik dosyada sıfırla ezilir
            db.connection().exec_driver_sql("PRAGMA secure_delete = ON")
        # Bağlantı tablosu açıkça temizlenir (SQLite'ta yabancı anahtar zinciri kapalı olabilir)
        db.execute(delete(AlertEvent).where(
            AlertEvent.event_id.in_(select(Event.id).where(old_events))))
        db.execute(delete(Event).where(old_events))
        db.execute(delete(AuthEvent).where(AuthEvent.at < cutoff))
        for alert in to_mask:
            alert.source_ip = mask_ip(alert.source_ip)
            alert.title = mask_ips(alert.title)
            alert.reason = mask_ips(alert.reason)
            alert.evidence = mask_deep(alert.evidence)
            alert.recommended_steps = mask_deep(alert.recommended_steps)
            for h in db.scalars(select(AlertHistory).where(AlertHistory.alert_id == alert.id)):
                h.note = mask_ips(h.note)  # analist notunda da adres geçebilir
        db.commit()
        if sqlite:
            db.connection().exec_driver_sql("PRAGMA secure_delete = OFF")
            db.connection().exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")
            db.commit()
    return result


@dataclass(frozen=True)
class RetentionStatus:
    days: int
    oldest_event: datetime | None
    next_purge_at: datetime | None  # en eski olayın silineceği an


def retention_status(db: Session, days: int) -> RetentionStatus:
    oldest = db.scalar(select(func.min(Event.timestamp)))
    return RetentionStatus(days, oldest, oldest + timedelta(days=days) if oldest else None)
