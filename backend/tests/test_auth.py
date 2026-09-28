"""Giriş, oturum, yetki ve CSRF güvenlik testleri."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.routing import APIRoute
from sqlalchemy import select, update

from app.api.v1.auth import COOKIE, CSRF_HEADER, GENERIC_FAIL
from app.core import security
from app.core.config import settings
from app.db.models import Alert, AlertHistory, AuthEvent, UserSession
from app.main import app
from tests.conftest import TEST_PASSWORD, make_user

PUBLIC = {"/api/v1/health", "/api/v1/auth/login", "/api/v1/auth/logout", "/api/v1/auth/setup"}


def api_routes():
    for route in app.routes:
        if isinstance(route, APIRoute) and route.path.startswith("/api/v1"):
            for method in route.methods:
                yield method, route.path.replace("{alert_id}", "1")


def login(c, username, password=None):
    return c.post("/api/v1/auth/login",
                  json={"username": username, "password": password or TEST_PASSWORD})


# ── her uç korumalı mı? (yeni eklenen uç da otomatik kapsanır) ──────────────
def test_every_non_public_endpoint_requires_login(anon_client):
    checked = 0
    for method, path in api_routes():
        if path in PUBLIC:
            continue
        r = anon_client.request(method, path)
        assert r.status_code == 401, f"{method} {path} → {r.status_code}"
        checked += 1
    assert checked >= 8  # listenin boş kalmadığından emin ol


def test_setup_reports_when_no_users_exist(anon_client):
    assert anon_client.get("/api/v1/auth/setup").json() == {"has_users": False}


def test_public_endpoints_leak_nothing_sensitive(anon_client, db_session):
    make_user(db_session, "gizli.kullanici", "admin")
    assert anon_client.get("/api/v1/health").status_code == 200
    assert anon_client.get("/api/v1/auth/setup").json() == {"has_users": True}
    assert "gizli.kullanici" not in anon_client.get("/api/v1/auth/setup").text


# ── giriş ───────────────────────────────────────────────────────────────────
def test_login_sets_hardened_cookie_and_stores_only_hash(anon_client, db_session):
    make_user(db_session, "emir", "admin")

    r = login(anon_client, "emir")

    assert r.status_code == 200 and r.json()["role"] == "admin"
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/api" in cookie
    token = anon_client.cookies.get(COOKIE)
    stored = db_session.scalars(select(UserSession.token_hash)).all()
    assert stored == [security.token_digest(token)] and token not in stored


def test_wrong_password_and_unknown_user_look_identical(anon_client, db_session):
    make_user(db_session, "emir", "admin")

    wrong = login(anon_client, "emir", "yanlis-sifre-1234")
    unknown = login(anon_client, "olmayan", "yanlis-sifre-1234")

    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json() == {"detail": GENERIC_FAIL}
    assert COOKIE not in anon_client.cookies


def test_username_is_case_insensitive(anon_client, db_session):
    make_user(db_session, "emir", "analyst")
    assert login(anon_client, "  EMIR ").status_code == 200


# ── kilit (brute-force) ─────────────────────────────────────────────────────
def test_lockout_after_repeated_failures_even_with_correct_password(anon_client, db_session):
    make_user(db_session, "emir", "admin")
    for _ in range(settings.lockout_attempts):
        assert login(anon_client, "emir", "yanlis-sifre-1234").status_code == 401

    r = login(anon_client, "emir")  # doğru şifre bile kabul edilmez

    assert r.status_code == 429
    assert COOKIE not in anon_client.cookies


def test_unknown_usernames_lock_the_same_way(anon_client):
    for _ in range(settings.lockout_attempts):
        login(anon_client, "olmayan", "yanlis-sifre-1234")
    assert login(anon_client, "olmayan", "yanlis-sifre-1234").status_code == 429  # yoklanamaz


def test_success_resets_the_failure_count(anon_client, db_session):
    make_user(db_session, "emir", "admin")
    for _ in range(settings.lockout_attempts - 1):
        login(anon_client, "emir", "yanlis-sifre-1234")
    assert login(anon_client, "emir").status_code == 200
    for _ in range(settings.lockout_attempts - 1):
        login(anon_client, "emir", "yanlis-sifre-1234")
    assert login(anon_client, "emir").status_code == 200


def test_lock_expires_after_the_window(anon_client, db_session):
    make_user(db_session, "emir", "admin")
    for _ in range(settings.lockout_attempts):
        login(anon_client, "emir", "yanlis-sifre-1234")
    past = datetime.now(UTC) - timedelta(minutes=settings.lockout_minutes + 1)
    db_session.execute(update(AuthEvent).values(at=past))
    db_session.commit()

    assert login(anon_client, "emir").status_code == 200


def test_auth_events_are_recorded(anon_client, db_session):
    make_user(db_session, "emir", "admin")
    login(anon_client, "emir", "yanlis-sifre-1234")
    login(anon_client, "emir")
    anon_client.post("/api/v1/auth/logout")

    actions = db_session.scalars(select(AuthEvent.action).order_by(AuthEvent.id)).all()
    assert actions == ["login_fail", "login_ok", "logout"]


# ── oturum ──────────────────────────────────────────────────────────────────
def test_logout_invalidates_the_session(client):
    old = client.cookies.get(COOKIE)
    client.post("/api/v1/auth/logout")
    client.cookies.set(COOKIE, old, path="/api")  # çalınmış eski çerezle dönmeye çalış

    assert client.get("/api/v1/alerts").status_code == 401


def test_expired_session_is_rejected(client, db_session):
    db_session.execute(update(UserSession).values(
        expires_at=datetime.now(UTC) - timedelta(seconds=1)))
    db_session.commit()
    assert client.get("/api/v1/alerts").status_code == 401


@pytest.mark.parametrize("token", ["", "x", "a" * 43])
def test_forged_tokens_are_rejected(anon_client, token):
    anon_client.cookies.set(COOKIE, token, path="/api")
    assert anon_client.get("/api/v1/alerts").status_code == 401


def test_me_returns_identity_without_secrets(client):
    body = client.get("/api/v1/auth/me").json()
    assert body == {"username": "yonetici", "role": "admin", "role_label": "Yönetici"}


# ── CSRF ────────────────────────────────────────────────────────────────────
def test_state_changing_requests_need_csrf_header(client):
    del client.headers[CSRF_HEADER]
    assert client.post("/api/v1/detection/run").status_code == 403
    assert client.patch("/api/v1/alerts/1", json={"status": "investigating"}).status_code == 403
    assert client.get("/api/v1/alerts").status_code == 200  # okuma serbest


def test_login_also_needs_csrf_header(anon_client, db_session):
    make_user(db_session, "emir", "admin")
    del anon_client.headers[CSRF_HEADER]
    assert login(anon_client, "emir").status_code == 403


# ── roller ──────────────────────────────────────────────────────────────────
def test_analyst_cannot_do_admin_actions(analyst_client):
    assert analyst_client.post("/api/v1/detection/run").status_code == 403
    r = analyst_client.post("/api/v1/ingest/upload", files={"file": ("a.log", b"x")})
    assert r.status_code == 403


def test_analyst_can_review_and_close_alerts_under_own_name(analyst_client, db_session):
    now = datetime.now(UTC)
    db_session.add(Alert(rule_id="AUTH-001", title="t", severity="low", status="new",
                         source_ip="203.0.113.10", first_seen=now, last_seen=now, reason="r",
                         evidence={}, recommended_steps=[], mitre=[]))
    db_session.commit()

    assert analyst_client.get("/api/v1/alerts").status_code == 200
    r = analyst_client.patch("/api/v1/alerts/1", json={"status": "investigating", "note": "bak"})

    assert r.status_code == 200
    assert db_session.scalars(select(AlertHistory.changed_by)).all() == ["analist1"]


def test_admin_can_do_admin_actions(client):
    assert client.post("/api/v1/detection/run").status_code == 200


# ── şifre saklama ───────────────────────────────────────────────────────────
def test_password_hashing():
    h1, h2 = security.hash_password("Guclu-Sifre-2026"), security.hash_password("Guclu-Sifre-2026")
    assert h1 != h2  # her seferinde farklı tuz
    assert h1.startswith("scrypt$") and "Guclu" not in h1
    assert security.verify_password("Guclu-Sifre-2026", h1)
    assert not security.verify_password("guclu-sifre-2026", h1)
    assert not security.verify_password("x", "bozuk$kayit")


@pytest.mark.parametrize("password", ["kisa-1", "emir-uzun-sifre-99", "aaaaaaaaaaaaaaaa"])
def test_password_policy_rejects_weak(password):
    with pytest.raises(security.WeakPassword):
        security.check_policy(password, "emir")
