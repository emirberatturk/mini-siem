from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings


class Base(DeclarativeBase):
    pass


def make_engine(url: str) -> Engine:
    if url.startswith("sqlite:///") and ":memory:" not in url:
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(url, connect_args={"check_same_thread": False})

    if engine.dialect.name == "sqlite":

        @event.listens_for(engine, "connect")
        def _pragmas(conn, _record):
            cur = conn.cursor()
            # WAL: yazma sırasında okumalar (dashboard) beklemez
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    return engine


engine = make_engine(settings.database_url)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def get_session() -> Iterator[Session]:
    """FastAPI bağımlılığı: her istek kendi oturumunu alır, sonunda kapatılır."""
    with SessionLocal() as session:
        yield session


def init_db(bind: Engine = engine) -> None:
    from app.db import models  # noqa: F401  (tabloların Base'e kaydolması için)

    Base.metadata.create_all(bind)
    _add_missing_columns(bind)


# Sonradan eklenen sütunlar. create_all var olan tabloya sütun eklemez; küçük bir projede
# Alembic yerine bu basit "ekle, yoksa" adımı yeterli (veri silinmez, yalnızca sütun eklenir).
_ADDED_COLUMNS = {("events", "signatures"): "TEXT NOT NULL DEFAULT ''"}


def _add_missing_columns(bind: Engine) -> None:
    insp = inspect(bind)
    with bind.begin() as conn:
        for (table, column), ddl in _ADDED_COLUMNS.items():
            if column not in {c["name"] for c in insp.get_columns(table)}:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
