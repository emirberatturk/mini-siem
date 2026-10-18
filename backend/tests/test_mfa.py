"""İki adımlı doğrulama (TOTP + yedek kodlar) güvenlik testleri."""

import base64
import time
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, inspect, select, text, update

from app.api.v1.auth import COOKIE, PENDING_REQUIRED
from app.core import mfa
from app.core.config import settings
from app.db.models import AuthEvent, RecoveryCode, User, UserSession
from app.db.session import init_db
from tests.conftest import TEST_PASSWORD, TEST_TOTP, full_login, make_user, totp_code

VERIFY = "/api/v1/auth/mfa/verify"
SETUP = "/api/v1/auth/mfa/setup"
ENABLE = "/api/v1/auth/mfa/enable"


def password_step(c, username="emir"):
    return c.post("/api/v1/auth/login", json={"username": username, "password": TEST_PASSWORD})


def wrong_code(secret: str) -> str:
    """Şu an (±1 dilim) geçerli olmayan bir kod."""
    now = int(time.time() // mfa.STEP)
    valid = {mfa.code_at(secret, s) for s in range(now - 1, now + 2)}
    return next(c for c in (f"{i:06d}" for i in range(1000)) if c not in valid)


# ── TOTP hesabı: RFC 6238'in resmî test vektörleri (SHA-1, 6 hane) ──────────
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()  # RFC'deki örnek anahtar


@pytest.mark.parametrize("t, expected", [(59, "287082"), (1111111109, "081804"),
                                         (1111111111, "050471"), (1234567890, "005924"),
                                         (2000000000, "279037")])
def test_totp_matches_rfc6238_vectors(t, expected):
    assert mfa.code_at(RFC_SECRET, t // mfa.STEP) == expected


def test_match_step_accepts_one_step_of_clock_drift_only():
    now = 1_000_000_020.0
    step = int(now // mfa.STEP)
    code = lambda s: mfa.code_at(RFC_SECRET, s)  # noqa: E731
    assert mfa.match_step(RFC_SECRET, code(step), now, None) == step
    assert mfa.match_step(RFC_SECRET, code(step - 1), now, None) == step - 1
    assert mfa.match_step(RFC_SECRET, code(step + 1), now, None) == step + 1
    assert mfa.match_step(RFC_SECRET, code(step - 2), now, None) is None
    assert mfa.match_step(RFC_SECRET, code(step + 2), now, None) is None
    assert mfa.match_step(RFC_SECRET, " " + code(step)[:3] + " " + code(step)[3:], now,
                          None) == step  # "123 456" yazımı


def test_match_step_rejects_used_and_older_steps():
    now = 1_000_000_020.0
    step = int(now // mfa.STEP)
    assert mfa.match_step(RFC_SECRET, mfa.code_at(RFC_SECRET, step), now, step) is None
    assert mfa.match_step(RFC_SECRET, mfa.code_at(RFC_SECRET, step - 1), now, step - 1) is None
    assert mfa.match_step(RFC_SECRET, mfa.code_at(RFC_SECRET, step), now, step - 1) == step


@pytest.mark.parametrize("junk", ["", "12345", "1234567", "abcdef", "12345a"])
def test_match_step_rejects_malformed(junk):
    assert mfa.match_step(RFC_SECRET, junk, time.time(), None) is None


def test_secrets_and_recovery_codes_are_random_and_well_formed():
    assert len({mfa.new_secret() for _ in range(20)}) == 20
    codes = mfa.new_recovery_codes()
    assert len(codes) == mfa.RECOVERY_COUNT == len(set(codes))
    assert all(len(c) == 11 and c[5] == "-" for c in codes)
    assert mfa.recovery_digest(codes[0]) == mfa.recovery_digest(codes[0].upper().replace("-", " "))


# ── şifre tek başına yetmez ─────────────────────────────────────────────────
def test_password_alone_gives_no_access(anon_client, db_session):
    make_user(db_session, "emir", "admin")

    r = password_step(anon_client)

    assert r.status_code == 200 and r.json() == {"stage": "mfa"}
    assert f"max-age={settings.mfa_minutes * 60}" in r.headers["set-cookie"].lower()
    for path in ("/api/v1/alerts", "/api/v1/events", "/api/v1/auth/me"):
        assert anon_client.get(path).status_code == 401, path
    assert anon_client.post("/api/v1/detection/run").status_code == 401


def test_code_opens_a_new_session_and_kills_the_pending_one(anon_client, db_session):
    make_user(db_session, "emir", "admin")
    password_step(anon_client)
    pending_token = anon_client.cookies.get(COOKIE)

    r = anon_client.post(VERIFY, json={"code": totp_code(db_session, "emir")})

    assert r.status_code == 200 and r.json()["username"] == "emir"
    full_token = anon_client.cookies.get(COOKIE)
    assert full_token != pending_token  # oturum sabitlemeye karşı yeni belirteç
    assert anon_client.get("/api/v1/alerts").status_code == 200
    anon_client.cookies.set(COOKIE, pending_token, path="/api")
    assert anon_client.get("/api/v1/alerts").status_code == 401
    assert db_session.scalars(select(UserSession.stage)).all() == ["full"]


def test_wrong_code_is_rejected_and_recorded(anon_client, db_session):
    make_user(db_session, "emir", "admin")
    password_step(anon_client)

    r = anon_client.post(VERIFY, json={"code": wrong_code(TEST_TOTP)})

    assert r.status_code == 401
    assert anon_client.get("/api/v1/alerts").status_code == 401
    assert "mfa_fail" in db_session.scalars(select(AuthEvent.action)).all()


def test_same_code_cannot_be_used_twice(anon_client, db_session):
    make_user(db_session, "emir", "admin")
    password_step(anon_client)
    code = totp_code(db_session, "emir")
    assert anon_client.post(VERIFY, json={"code": code}).status_code == 200
    anon_client.post("/api/v1/auth/logout")

    password_step(anon_client)  # çalınan kodu hemen tekrar kullanmaya çalış
    assert anon_client.post(VERIFY, json={"code": code}).status_code == 401


def test_code_step_needs_the_password_step_first(anon_client, db_session):
    make_user(db_session, "emir", "admin")
    r = anon_client.post(VERIFY, json={"code": totp_code(db_session, "emir")})
    assert r.status_code == 401 and r.json()["detail"] == PENDING_REQUIRED


def test_full_session_cannot_be_used_as_pending(client, db_session):
    # tam oturum, ara oturumun yerine geçmez (kod adımını tekrar çalıştırıp yeni anahtar alamaz)
    assert client.post(VERIFY, json={"code": "000000"}).status_code == 401
    assert client.post(SETUP).status_code == 401


def test_pending_session_expires(anon_client, db_session):
    make_user(db_session, "emir", "admin")
    password_step(anon_client)
    db_session.execute(update(UserSession).values(
        expires_at=datetime.now(UTC) - timedelta(seconds=1)))
    db_session.commit()

    r = anon_client.post(VERIFY, json={"code": totp_code(db_session, "emir")})
    assert r.status_code == 401


# ── kilit: yanlış kod da sayılır, şifreyle yeniden girmek sayacı sıfırlamaz ──
def test_wrong_codes_lock_the_account_even_with_known_password(anon_client, db_session):
    make_user(db_session, "emir", "admin")
    for _ in range(settings.lockout_attempts):
        assert password_step(anon_client).status_code == 200  # saldırgan şifreyi biliyor
        assert anon_client.post(VERIFY, json={"code": wrong_code(TEST_TOTP)}).status_code == 401

    r = password_step(anon_client)
    assert r.status_code == 429
    assert "set-cookie" not in r.headers  # yeni (ara) oturum da açılmaz


def test_locked_account_rejects_even_the_correct_code(anon_client, db_session):
    make_user(db_session, "emir", "admin")
    password_step(anon_client)
    for _ in range(settings.lockout_attempts):
        anon_client.post(VERIFY, json={"code": wrong_code(TEST_TOTP)})

    r = anon_client.post(VERIFY, json={"code": totp_code(db_session, "emir")})

    assert r.status_code == 429
    assert anon_client.get("/api/v1/alerts").status_code == 401


# ── yedek kodlar ────────────────────────────────────────────────────────────
def _give_recovery_codes(db_session, user) -> list[str]:
    codes = mfa.new_recovery_codes()
    db_session.add_all(RecoveryCode(user_id=user.id, code_hash=mfa.recovery_digest(c))
                       for c in codes)
    db_session.commit()
    return codes


def test_recovery_code_works_exactly_once(anon_client, db_session):
    codes = _give_recovery_codes(db_session, make_user(db_session, "emir", "admin"))

    password_step(anon_client)
    assert anon_client.post(VERIFY, json={"code": codes[0].upper()}).status_code == 200
    anon_client.post("/api/v1/auth/logout")
    password_step(anon_client)
    assert anon_client.post(VERIFY, json={"code": codes[0]}).status_code == 401

    actions = db_session.scalars(select(AuthEvent.action)).all()
    assert "recovery_used" in actions


def test_other_users_recovery_code_is_useless(anon_client, db_session):
    make_user(db_session, "emir", "admin")
    other = _give_recovery_codes(db_session, make_user(db_session, "baska", "analyst"))
    password_step(anon_client)
    assert anon_client.post(VERIFY, json={"code": other[0]}).status_code == 401


# ── ilk kurulum (herkes için zorunlu) ───────────────────────────────────────
def _enroll(c, db_session, username="yeni"):
    assert password_step(c, username).json() == {"stage": "enroll"}
    body = c.post(SETUP).json()
    step = int(time.time() // mfa.STEP)
    return body, mfa.code_at(body["secret"], step)


@pytest.mark.parametrize("role", ["admin", "analyst"])
def test_new_account_must_set_up_2fa_before_any_access(anon_client, db_session, role):
    make_user(db_session, "yeni", role, with_mfa=False)
    assert password_step(anon_client, "yeni").json() == {"stage": "enroll"}
    assert anon_client.get("/api/v1/alerts").status_code == 401
    assert anon_client.post(VERIFY, json={"code": "123456"}).status_code == 401  # kurulum şart


def test_enrollment_flow(anon_client, db_session):
    make_user(db_session, "yeni", "analyst", with_mfa=False)

    body, code = _enroll(anon_client, db_session)
    assert body["qr"].startswith("data:image/svg+xml")
    assert anon_client.post(SETUP).json()["secret"] == body["secret"]  # yenilemede aynı anahtar
    assert anon_client.post(ENABLE, json={"code": wrong_code(body["secret"])}).status_code == 400

    r = anon_client.post(ENABLE, json={"code": code})

    assert r.status_code == 200
    out = r.json()
    assert out["me"]["username"] == "yeni" and len(out["recovery_codes"]) == 10
    assert anon_client.get("/api/v1/alerts").status_code == 200
    user = db_session.scalar(select(User).where(User.username == "yeni"))
    db_session.refresh(user)
    assert user.totp_secret == body["secret"]
    stored = db_session.scalars(select(RecoveryCode.code_hash)).all()
    assert len(stored) == 10 and not set(out["recovery_codes"]) & set(stored)  # yalnızca özet
    assert db_session.scalars(select(UserSession.pending_secret)).all() == [None]
    assert "mfa_enrolled" in db_session.scalars(select(AuthEvent.action)).all()


def test_concurrent_setup_requests_get_the_same_secret(anon_client, db_session, monkeypatch):
    # Sayfa kurulumu iki kez isterse (React geliştirme modu, çift tıklama) iki istek aynı anda
    # "anahtar yok" görür. Diğer istek bizden önce yazmış gibi yapıp ikisinin aynı anahtarı
    # döndürdüğünü kontrol et; yoksa ekrandaki QR ile veritabanındaki anahtar farklı olur.
    make_user(db_session, "yeni", "admin", with_mfa=False)
    password_step(anon_client, "yeni")
    winner = mfa.new_secret()
    real_new_secret = mfa.new_secret

    def other_request_commits_first():
        db_session.execute(update(UserSession).values(pending_secret=winner))
        return real_new_secret()

    monkeypatch.setattr(mfa, "new_secret", other_request_commits_first)

    assert anon_client.post(SETUP).json()["secret"] == winner
    assert db_session.scalars(select(UserSession.pending_secret)).all() == [winner]


def test_wrong_enrollment_codes_also_lock(anon_client, db_session):
    make_user(db_session, "yeni", "admin", with_mfa=False)
    body, code = _enroll(anon_client, db_session)
    for _ in range(settings.lockout_attempts):
        anon_client.post(ENABLE, json={"code": wrong_code(body["secret"])})

    assert anon_client.post(ENABLE, json={"code": code}).status_code == 429
    user = db_session.scalar(select(User))
    db_session.refresh(user)
    assert user.totp_secret is None


def test_existing_2fa_cannot_be_replaced_with_password_only(anon_client, db_session):
    make_user(db_session, "emir", "admin")
    password_step(anon_client)  # stage = mfa
    assert anon_client.post(SETUP).status_code == 401
    assert anon_client.post(ENABLE, json={"code": "123456"}).status_code == 401
    user = db_session.scalar(select(User))
    db_session.refresh(user)
    assert user.totp_secret == TEST_TOTP


def test_enrollment_code_is_single_use(anon_client, db_session):
    make_user(db_session, "yeni", "admin", with_mfa=False)
    _, code = _enroll(anon_client, db_session)
    anon_client.post(ENABLE, json={"code": code})
    anon_client.post("/api/v1/auth/logout")

    password_step(anon_client, "yeni")
    assert anon_client.post(VERIFY, json={"code": code}).status_code == 401


def test_enrollment_secret_dies_with_the_pending_session(anon_client, db_session):
    make_user(db_session, "yeni", "admin", with_mfa=False)
    first, _ = _enroll(anon_client, db_session)
    anon_client.post("/api/v1/auth/logout")

    second, _ = _enroll(anon_client, db_session)

    assert first["secret"] != second["secret"]


def test_old_sessions_of_accounts_without_2fa_are_rejected(anon_client, db_session):
    # bu özellikten ÖNCE açılmış tam oturum: artık geçmez, kullanıcı 2FA kurmak zorunda
    user = make_user(db_session, "eski", "admin", with_mfa=False)
    from app.core import security
    token = security.new_session_token()
    db_session.add(UserSession(token_hash=security.token_digest(token), user_id=user.id,
                               stage="full", expires_at=datetime.now(UTC) + timedelta(hours=1)))
    db_session.commit()
    anon_client.cookies.set(COOKIE, token, path="/api")

    assert anon_client.get("/api/v1/alerts").status_code == 401


def test_enrolling_does_not_revive_sessions_opened_without_2fa(anon_client, db_session):
    # 2FA kurulmadan önce (yalnızca şifreyle) açılmış oturum, kurulumdan SONRA da geçmemeli
    user = make_user(db_session, "yeni", "admin", with_mfa=False)
    from app.core import security
    old = security.new_session_token()
    db_session.add(UserSession(token_hash=security.token_digest(old), user_id=user.id,
                               stage="full", expires_at=datetime.now(UTC) + timedelta(hours=1)))
    db_session.commit()
    _, code = _enroll(anon_client, db_session)
    assert anon_client.post(ENABLE, json={"code": code}).status_code == 200

    anon_client.cookies.set(COOKIE, old, path="/api")
    assert anon_client.get("/api/v1/alerts").status_code == 401


def test_responses_never_leak_the_secret(client, db_session):
    assert TEST_TOTP not in client.get("/api/v1/auth/me").text
    c2 = full_login(client, db_session, "yonetici")
    assert TEST_TOTP not in c2.text


# ── eski veritabanı: sütunlar eklenir, mevcut kullanıcı silinmez ────────────
def test_existing_database_gets_2fa_columns():
    engine = create_engine("sqlite://")
    init_db(engine)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE users DROP COLUMN totp_secret"))
        conn.execute(text("ALTER TABLE users DROP COLUMN totp_last_step"))
        conn.execute(text("ALTER TABLE user_sessions DROP COLUMN stage"))
        conn.execute(text("ALTER TABLE user_sessions DROP COLUMN pending_secret"))
        conn.execute(text("INSERT INTO users (username, password_hash, role, created_at) "
                          "VALUES ('berat', 'h', 'admin', '2026-09-28 00:00:00')"))
        conn.execute(text("INSERT INTO user_sessions (token_hash, user_id, created_at, expires_at) "
                          "VALUES ('x', 1, '2026-09-28 00:00:00', '2099-01-01 00:00:00')"))

    init_db(engine)

    cols = {c["name"] for c in inspect(engine).get_columns("users")}
    assert {"totp_secret", "totp_last_step"} <= cols
    assert {"stage", "pending_secret"} <= {c["name"]
                                          for c in inspect(engine).get_columns("user_sessions")}
    with engine.connect() as conn:
        assert conn.execute(text("SELECT username, totp_secret FROM users")).all() == [
            ("berat", None)]
        # 2FA'dan önce açılmış oturumlar "tam" sayılmaz
        assert conn.execute(text("SELECT stage FROM user_sessions")).all() == [("legacy",)]
