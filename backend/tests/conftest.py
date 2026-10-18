"""Testler gerçek veritabanına (data/siem.db) asla dokunmaz: her test boş bir bellek-içi DB alır.

Siteye özel yerel ayarlar (config/*.local.yaml) da kapatılır: testler herkeste aynı örnek
profille çalışır. Bu satır, ayarları okuyan app modüllerinden ÖNCE çalışmalı.
"""

import os
import secrets
import time

os.environ["SIEM_USE_LOCAL_CONFIG"] = "false"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, select  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.api.v1.auth import CSRF_HEADER, CSRF_VALUE  # noqa: E402
from app.core import mfa  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.db.models import User  # noqa: E402
from app.db.session import get_session, init_db  # noqa: E402
from app.main import app  # noqa: E402

# Her test çalıştırmasında rastgele: kodda sabit şifre bulunmaz
TEST_PASSWORD = secrets.token_urlsafe(18)
_TEST_HASH = hash_password(TEST_PASSWORD)  # scrypt yavaştır: bir kez hesapla
TEST_TOTP = mfa.new_secret()  # test kullanıcılarının "telefonundaki" anahtar


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


def make_user(db: Session, username: str, role: str, *, with_mfa: bool = True) -> User:
    """with_mfa=False: telefonunu henüz tanıtmamış (ilk girişte kurulum yapacak) hesap."""
    user = User(username=username, password_hash=_TEST_HASH, role=role,
                totp_secret=TEST_TOTP if with_mfa else None)
    db.add(user)
    db.commit()
    return user


def totp_code(db: Session, username: str) -> str:
    """Sunucunun kabul edeceği, henüz kullanılmamış bir kod. Aynı 30 saniyede ikinci giriş
    yapılırsa bir sonraki dilimin kodu (telefon saati hafif ileri gibi) kullanılır."""
    user = db.scalar(select(User).where(User.username == username))
    db.refresh(user)
    now = int(time.time() // mfa.STEP)
    last = user.totp_last_step
    return mfa.code_at(user.totp_secret, now if last is None or last < now else last + 1)


def full_login(c: TestClient, db: Session, username: str, password: str | None = None):
    """Şifre + telefon kodu: iki adımlı tam giriş. İkinci adımın yanıtını döndürür."""
    r = c.post("/api/v1/auth/login",
               json={"username": username, "password": password or TEST_PASSWORD})
    if r.status_code != 200:
        return r
    assert r.json() == {"stage": "mfa"}, r.text
    return c.post("/api/v1/auth/mfa/verify", json={"code": totp_code(db, username)})


def _client(db_session: Session, username: str | None = None, role: str | None = None):
    app.dependency_overrides[get_session] = lambda: db_session
    # lifespan'ı (gerçek DB'yi oluşturan init_db) çalıştırmamak için context manager kullanmıyoruz;
    # arayüz gibi her istekte CSRF başlığını gönderir
    c = TestClient(app, headers={CSRF_HEADER: CSRF_VALUE})
    if username:
        make_user(db_session, username, role)
        r = full_login(c, db_session, username)
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
