from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import __version__
from app.api.v1.router import api_router
from app.core.config import settings
from app.db.session import init_db


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


def create_app() -> FastAPI:
    app = FastAPI(title=settings.app_name, version=__version__, lifespan=lifespan)
    # Tüm endpoint'ler /api/v1 altında: ileride API değişirse v2 eklenir, eski istemciler bozulmaz.
    app.include_router(api_router, prefix="/api/v1")
    return app


app = create_app()
