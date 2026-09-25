from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from app.db.session import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator):
    """Her zaman UTC yazar, UTC etiketiyle okur.

    SQLite saat dilimi saklamaz: etiketsiz dönen '11:30' tarayıcıda yerel saat sanılır ve
    tüm olaylar 3 saat kayar. Bu tip, SIEM'in tek zaman çizgisi kuralını veritabanında da korur.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("Saat dilimi olmayan zaman kaydedilemez")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value, dialect):
        return value.replace(tzinfo=UTC) if value is not None else None


class IngestBatch(Base):
    """Her yükleme bir kayıt: 'hangi olay hangi dosyadan geldi?' sorusunun cevabı."""

    __tablename__ = "ingest_batches"

    id: Mapped[int] = mapped_column(primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))
    received_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    lines_total: Mapped[int] = mapped_column(Integer, default=0)
    lines_failed: Mapped[int] = mapped_column(Integer, default=0)
    events_inserted: Mapped[int] = mapped_column(Integer, default=0)
    duplicates: Mapped[int] = mapped_column(Integer, default=0)
    redactions: Mapped[int] = mapped_column(Integer, default=0)


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)
    batch_id: Mapped[int] = mapped_column(ForeignKey("ingest_batches.id", ondelete="CASCADE"))
    ingested_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    source_ip: Mapped[str] = mapped_column(String(45))  # IPv6 en fazla 45 karakter
    http_method: Mapped[str | None] = mapped_column(String(16))
    url_path: Mapped[str] = mapped_column(Text)
    url_query: Mapped[str] = mapped_column(Text, default="")
    status_code: Mapped[int] = mapped_column(Integer, index=True)
    bytes_sent: Mapped[int] = mapped_column(Integer, default=0)
    referrer: Mapped[str] = mapped_column(Text, default="")
    user_agent: Mapped[str] = mapped_column(Text, default="")

    event_category: Mapped[str] = mapped_column(String(32))
    event_type: Mapped[str] = mapped_column(String(48))
    event_outcome: Mapped[str] = mapped_column(String(16))
    redactions: Mapped[int] = mapped_column(Integer, default=0)
    parser: Mapped[str] = mapped_column(String(32))
    # Eşleşen Sigma kurallarının kısa adları (virgülle); ham istek hiçbir yerde saklanmaz
    signatures: Mapped[str] = mapped_column(Text, default="", server_default="")
    # Tekrar yüklemede çift kaydı önler (bkz. normalizer.event_key)
    event_key: Mapped[str] = mapped_column(String(64), unique=True)

    __table_args__ = (
        # Tespit kuralları hep "bu IP, şu zaman aralığında" diye sorar
        Index("ix_events_ip_time", "source_ip", "timestamp"),
        Index("ix_events_type_time", "event_type", "timestamp"),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(24), default="new", index=True)
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    reason: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    recommended_steps: Mapped[list] = mapped_column(JSON, default=list)
    mitre: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)


class AlertEvent(Base):
    """Alert ↔ olay bağlantısı: 'bu alert'i hangi log satırları doğurdu?' sorusunun cevabı."""

    __tablename__ = "alert_events"

    alert_id: Mapped[int] = mapped_column(
        ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True
    )
    event_id: Mapped[int] = mapped_column(
        ForeignKey("events.id", ondelete="CASCADE"), primary_key=True, index=True
    )


class AlertHistory(Base):
    """Durum değişikliklerinin silinmeyen kaydı (audit trail): kim, ne zaman, neden."""

    __tablename__ = "alert_history"

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    from_status: Mapped[str | None] = mapped_column(String(24))
    to_status: Mapped[str] = mapped_column(String(24))
    note: Mapped[str] = mapped_column(Text, default="")
    changed_by: Mapped[str] = mapped_column(String(64), default="analist")
    changed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
