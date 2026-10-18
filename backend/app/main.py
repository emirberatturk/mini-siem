import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import __version__
from app.api.v1.router import api_router
from app.core.config import settings
from app.db.session import engine, init_db
from app.privacy.retention import apply_retention

log = logging.getLogger("uvicorn.error")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    # Saklama süresi her açılışta uygulanır (SIEM sürekli açık durmuyor; baslat.bat ile açılıyor)
    r = apply_retention(engine, settings.retention_days)
    log.info("Saklama süresi %d gün: %d olay silindi, %d alarmın IP'si maskelendi",
             settings.retention_days, r.events_deleted, r.alerts_masked)
    yield


def create_app() -> FastAPI:
    app = FastAPI(title=settings.app_name, version=__version__, lifespan=lifespan)
    # Tüm endpoint'ler /api/v1 altında: ileride API değişirse v2 eklenir, eski istemciler bozulmaz.
    app.include_router(api_router, prefix="/api/v1")
    return app


app = create_app()
