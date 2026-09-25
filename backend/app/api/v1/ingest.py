from collections import Counter
from pathlib import PurePath
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.repository import save_batch
from app.db.session import get_session
from app.detection.engine import run_detection
from app.ingestion.pipeline import process_lines
from app.ingestion.reader import PayloadTooLarge, UnsupportedContent, read_log_lines
from app.normalization.schema import EventType, NormalizedEvent

router = APIRouter(prefix="/ingest", tags=["ingest"])

SUPPORTED_FORMATS = {"apache_combined"}


class IngestSummary(BaseModel):
    filename: str
    size_bytes: int
    compressed: bool
    lines_total: int
    lines_empty: int
    lines_truncated: int
    format_hint: str
    batch_id: int
    events_parsed: int
    events_inserted: int
    duplicates: int
    alerts_created: int
    alerts_updated: int
    lines_failed: int
    redactions: int
    event_types: dict[str, int]
    samples: list[NormalizedEvent]


def pick_samples(events: list[NormalizedEvent], n: int = 8) -> list[NormalizedEvent]:
    """Önce güvenlik açısından ilginç olayları (giriş, admin, maskelenmiş) göster."""
    interesting = [
        e for e in events if e.event_type != EventType.HTTP_REQUEST or e.redactions > 0
    ]
    rest = [e for e in events if e not in interesting[:n]]
    return (interesting[:n] + rest)[:n]


@router.post("/upload")
def upload_log(file: UploadFile, db: Annotated[Session, Depends(get_session)]
               ) -> IngestSummary:
    """Log dosyası (düz metin veya .gz) alır, ayrıştırır, maskeler, kaydeder ve özet döner."""
    # Sınırın 1 bayt fazlasını okuruz: okunan > sınır ise dosya büyüktür.
    # def (async değil): DB yazımı senkron; FastAPI bunu ayrı thread'de çalıştırır ve
    # büyük bir yükleme sürerken dashboard istekleri beklemez.
    data = file.file.read(settings.max_upload_bytes + 1)
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"Dosya {settings.max_upload_bytes // (1024 * 1024)} MB sınırını aşıyor",
        )

    try:
        read = read_log_lines(
            data,
            max_decompressed=settings.max_decompressed_bytes,
            max_line_length=settings.max_line_length,
        )
    except PayloadTooLarge as exc:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, str(exc)) from exc
    except UnsupportedContent as exc:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, str(exc)) from exc

    if read.format_hint not in SUPPORTED_FORMATS:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Desteklenmeyen log biçimi: {read.format_hint}. "
            "Şimdilik yalnızca Apache Combined (cPanel Raw Access Logs) destekleniyor.",
        )

    # İstemcinin gönderdiği ada güvenmeyiz: klasör kısmını at ("../../x" → "x"), kısalt.
    filename = PurePath(file.filename or "adsiz").name[:255]
    result = process_lines(read.lines)
    saved = save_batch(db, filename, len(read.lines), result)

    # Tespit sadece yeni olayların zaman aralığında çalışır (kurallar pencere kadar geriye bakar)
    detection = None
    if saved.inserted:
        times = [e.timestamp for e in saved.inserted]
        detection = run_detection(db, min(times), max(times))

    return IngestSummary(
        filename=filename,
        size_bytes=len(data),
        compressed=read.compressed,
        lines_total=len(read.lines),
        lines_empty=read.lines_empty,
        lines_truncated=read.lines_truncated,
        format_hint=read.format_hint,
        batch_id=saved.batch.id,
        events_parsed=len(result.events),
        events_inserted=saved.batch.events_inserted,
        duplicates=saved.batch.duplicates,
        alerts_created=detection.created if detection else 0,
        alerts_updated=detection.updated if detection else 0,
        lines_failed=result.failed,
        redactions=result.redactions,
        event_types=dict(Counter(e.event_type.value for e in result.events)),
        samples=pick_samples(result.events),
    )
