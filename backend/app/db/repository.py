from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import insert, select
from sqlalchemy.orm import Session

from app.db.models import Event, IngestBatch
from app.ingestion.pipeline import PipelineResult

_CHUNK = 500


@dataclass
class SaveResult:
    batch: IngestBatch
    inserted: list[Event]


def save_batch(session: Session, filename: str, lines_total: int, result: PipelineResult
               ) -> SaveResult:
    """Olayları kaydeder; daha önce yüklenmiş olanları (aynı event_key) atlar."""
    keys = [e.event_key for e in result.events]
    existing: set[str] = set()
    for i in range(0, len(keys), _CHUNK):
        existing.update(
            session.scalars(select(Event.event_key).where(Event.event_key.in_(keys[i:i + _CHUNK])))
        )

    batch = IngestBatch(
        filename=filename,
        lines_total=lines_total,
        lines_failed=result.failed,
        redactions=result.redactions,
    )
    session.add(batch)
    session.flush()  # batch.id oluşsun

    new_rows = [
        {**e.model_dump(mode="python"), "batch_id": batch.id}
        for e in result.events
        if e.event_key not in existing
    ]
    inserted: list[Event] = []
    if new_rows:
        inserted = list(session.scalars(insert(Event).returning(Event), new_rows))

    batch.events_inserted = len(new_rows)
    batch.duplicates = len(result.events) - len(new_rows)
    session.commit()
    return SaveResult(batch, inserted)
