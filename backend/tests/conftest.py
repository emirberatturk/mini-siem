"""Testler gerçek veritabanına (data/siem.db) asla dokunmaz: her test boş bir bellek-içi DB alır.

Siteye özel yerel ayarlar (config/*.local.yaml) da kapatılır: testler herkeste aynı örnek
profille çalışır. Bu satır, ayarları okuyan app modüllerinden ÖNCE çalışmalı.
"""

import os
import secrets

os.environ["SIEM_USE_LOCAL_CONFIG"] = "false"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.api.v1.auth import CSRF_HEADER, CSRF_VALUE  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.db.models import User  # noqa: E402
from app.db.session import get_session, init_db  # noqa: E402
from app.main import app  # noqa: E402

# Her test çalıştırmasında rastgele: kodda sabit şifre bulunmaz
TEST_PASSWORD = secrets.token_urlsafe(18)
_TEST_HASH = hash_password(TEST_PASSWORD)  # scrypt yavaştır: bir kez hesapla


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


def make_user(db: Session, username: str, role: str) -> User:
    user = User(username=username, password_hash=_TEST_HASH, role=role)
    db.add(user)
    db.commit()
    return user


def _client(db_session: Session, username: str | None = None, role: str | None = None):
    app.dependency_overrides[get_session] = lambda: db_session
    # lifespan'ı (gerçek DB'yi oluşturan init_db) çalıştırmamak için context manager kullanmıyoruz;
    # arayüz gibi her istekte CSRF başlığını gönderir
    c = TestClient(app, headers={CSRF_HEADER: CSRF_VALUE})
    if username:
        make_user(db_session, username, role)
        r = c.post("/api/v1/auth/login", json={"username": username, "password": TEST_PASSWORD})
        assert r.status_code == 200, r.text
    return c


@pytest.fixture
def client(db_session: Session):
    """Giriş yapmış yönetici (API testlerinin varsayılanı)."""
    yield _client(db_session, "yonetici", "admin")
    app.dependency_overrides.clear()


@pytest.fixture
def analyst_client(db_session: Session):
    yield _client(db_session, "analist1", "analyst")
    app.dependency_overrides.clear()


@pytest.fixture
def anon_client(db_session: Session):
    """Giriş yapmamış (ama CSRF başlığını gönderen) istemci."""
    yield _client(db_session)
    app.dependency_overrides.clear()
