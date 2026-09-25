from datetime import UTC, datetime

from fastapi import APIRouter

from app import __version__
from app.core.config import settings

router = APIRouter(tags=["system"])


@router.get("/health")
def health() -> dict:
    """SIEM ayakta mı? Dashboard üst bardaki 'Canlı' göstergesi bunu kullanır."""
    return {
        "status": "ok",
        "app": settings.app_name,
        "version": __version__,
        "time": datetime.now(UTC).isoformat(),  # SIEM içinde tüm zamanlar UTC
    }
