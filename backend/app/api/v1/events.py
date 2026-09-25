from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models import Event, IngestBatch
from app.db.session import get_session

router = APIRouter(tags=["events"])
STATUS_PATTERN = r"^[1-5](\d\d|xx)$"  # tam kod (404) veya sınıf (4xx)
SIGNATURE_PATTERN = r"^[a-z0-9_]{1,64}$"  # "any" ya da kural adı
DB = Annotated[Session, Depends(get_session)]


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    source_ip: str
    http_method: str | None
    url_path: str
    url_query: str
    status_code: int
    bytes_sent: int
    referrer: str
    user_agent: str
    event_category: str
    event_type: str
    event_outcome: str
    redactions: int
    signatures: list[str]  # eşleşen Sigma kurallarının kısa adları

    @field_validator("signatures", mode="before")
    @classmethod
    def split_signatures(cls, value: object) -> object:
        return [s for s in value.split(",") if s] if isinstance(value, str) else value


class EventPage(BaseModel):
    total: int
    items: list[EventOut]


class BatchOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    filename: str
    received_at: datetime
    lines_total: int
    lines_failed: int
    events_inserted: int
    duplicates: int
    redactions: int


def escape_like(value: str) -> str:
    """LIKE'ta % ve _ joker karakterdir; kullanıcı girdisinde düz karakter olarak ele alınmalı.

    (SQL injection değil — sorgu zaten parametreli — ama '%' araması her şeyi eşleştirir.)
    """
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@router.get("/events")
def list_events(
    db: DB,
    ip: str | None = None,
    event_type: str | None = None,
    status: Annotated[str | None, Query(pattern=STATUS_PATTERN, description="404 veya 4xx")] = None,
    path: Annotated[str | None, Query(max_length=200, description="içerir")] = None,
    signature: Annotated[str | None, Query(pattern=SIGNATURE_PATTERN,
                                           description="'any' veya kural adı")] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> EventPage:
    """Olay arama (threat hunting). Tüm filtreler parametreli sorguya dönüşür."""
    q = select(Event)
    if ip:
        q = q.where(Event.source_ip == ip.strip())
    if event_type:
        q = q.where(Event.event_type == event_type)
    if status:
        if status.endswith("xx"):  # yanıt sınıfı: 4xx → 400..499
            base = int(status[0]) * 100
            q = q.where(Event.status_code.between(base, base + 99))
        else:
            q = q.where(Event.status_code == int(status))
    if path:
        q = q.where(Event.url_path.like(f"%{escape_like(path)}%", escape="\\"))
    if signature == "any":
        q = q.where(Event.signatures != "")
    elif signature:  # virgüllü listede tam ad: ",sql_injection," (_ joker sayılmasın)
        q = q.where(("," + Event.signatures + ",")
                    .like(f"%,{escape_like(signature)},%", escape="\\"))
    if since:
        q = q.where(Event.timestamp >= as_utc(since))
    if until:
        q = q.where(Event.timestamp <= as_utc(until))

    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    newest_first = q.order_by(Event.timestamp.desc(), Event.id.desc())
    rows = db.scalars(newest_first.limit(limit).offset(offset))
    return EventPage(total=total, items=[EventOut.model_validate(r) for r in rows])


def as_utc(value: datetime) -> datetime:
    """Saat dilimi belirtilmemiş zamanlar UTC kabul edilir (SIEM'in ortak dili)."""
    return value if value.tzinfo else value.replace(tzinfo=UTC)


@router.get("/ingest/batches")
def list_batches(db: DB) -> list[BatchOut]:
    rows = db.scalars(select(IngestBatch).order_by(IngestBatch.id.desc()).limit(50))
    return [BatchOut.model_validate(r) for r in rows]
