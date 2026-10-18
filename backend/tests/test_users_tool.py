"""Kullanıcı yönetimi aracı: ekleme, şifre politikası, şifre değişince oturumların kapanması."""

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from app.core import security
from app.db.models import AuthEvent, RecoveryCode, User, UserSession
from app.db.session import init_db
from app.tools import users

STRONG = "Guclu-Bir-Sifre-2026"


@pytest.fixture
def engine(tmp_path):
    e = create_engine(f"sqlite:///{tmp_path / 'u.db'}")
    init_db(e)
    return e


def test_add_user_stores_only_hash(engine):
    users.add_user(engine, "Emir", "yonetici", STRONG)

    with Session(engine) as db:
        u = db.scalar(select(User))
    assert (u.username, u.role) == ("emir", "admin")
    assert STRONG not in u.password_hash and security.verify_password(STRONG, u.password_hash)


@pytest.mark.parametrize(("name", "role", "password"), [
    ("ab", "analist", STRONG),                 # çok kısa ad
    ("emir berat", "analist", STRONG),         # boşluk
    ("emir", "patron", STRONG),                # bilinmeyen rol
])
def test_add_user_rejects_bad_input(engine, name, role, password):
    with pytest.raises(users.UserError):
        users.add_user(engine, name, role, password)


def test_weak_password_rejected(engine):
    with pytest.raises(security.WeakPassword):
        users.add_user(engine, "emir", "analist", "kisa")


def test_duplicate_user_rejected(engine):
    users.add_user(engine, "emir", "analist", STRONG)
    with pytest.raises(users.UserError):
        users.add_user(engine, "EMIR", "yonetici", STRONG)


def test_password_change_closes_open_sessions(engine):
    u = users.add_user(engine, "emir", "analist", STRONG)
    with Session(engine) as db:
        db.add(UserSession(token_hash="x" * 64, user_id=u.id,
                           expires_at=u.created_at.replace(year=2099)))
        db.commit()

    users.set_password(engine, "emir", "Yeni-Guclu-Sifre-2026")

    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(UserSession)) == 0
        new_hash = db.scalar(select(User)).password_hash
    assert security.verify_password("Yeni-Guclu-Sifre-2026", new_hash)


def test_unlock_records_event_and_list_hides_hashes(engine):
    users.add_user(engine, "emir", "yonetici", STRONG)
    users.unlock(engine, "emir")

    with Session(engine) as db:
        assert db.scalars(select(AuthEvent.action)).all() == ["unlock"]
    listed = users.list_users(engine)
    assert listed == [("emir", "admin", "—", False)]  # 2FA henüz kurulmadı
    assert "scrypt" not in repr(listed)


def test_remove_user(engine):
    users.add_user(engine, "emir", "analist", STRONG)
    users.remove_user(engine, "emir")
    assert users.list_users(engine) == []


def test_reset_mfa_clears_secret_codes_and_sessions(engine):
    u = users.add_user(engine, "emir", "yonetici", STRONG)
    with Session(engine) as db:
        user = db.get(User, u.id)
        user.totp_secret, user.totp_last_step = "A" * 32, 123
        db.add(RecoveryCode(user_id=u.id, code_hash="x" * 64))
        db.add(UserSession(token_hash="y" * 64, user_id=u.id,
                           expires_at=u.created_at.replace(year=2099)))
        db.commit()
    assert users.list_users(engine)[0][3] is True

    users.reset_mfa(engine, "emir")

    with Session(engine) as db:
        user = db.get(User, u.id)
        assert user.totp_secret is None and user.totp_last_step is None
        assert db.scalar(select(func.count()).select_from(RecoveryCode)) == 0
        assert db.scalar(select(func.count()).select_from(UserSession)) == 0
        assert db.scalars(select(AuthEvent.action)).all() == ["mfa_reset"]
    assert users.list_users(engine)[0][3] is False
