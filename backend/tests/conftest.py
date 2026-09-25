"""Testler gerçek veritabanına (data/siem.db) asla dokunmaz: her test boş bir bellek-içi DB alır.

Siteye özel yerel ayarlar (config/*.local.yaml) da kapatılır: testler herkeste aynı örnek
profille çalışır. Bu satır, ayarları okuyan app modüllerinden ÖNCE çalışmalı.
"""

import os

os.environ["SIEM_USE_LOCAL_CONFIG"] = "false"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.db.session import get_session, init_db  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,  # tüm bağlantılar aynı bellek-içi DB'yi görsün
    )
    init_db(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as session:
        yield session
    engine.dispose()


@pytest.fixture
def client(db_session: Session):
    app.dependency_overrides[get_session] = lambda: db_session
    # lifespan'ı (gerçek DB'yi oluşturan init_db) çalıştırmamak için context manager kullanmıyoruz
    yield TestClient(app)
    app.dependency_overrides.clear()
