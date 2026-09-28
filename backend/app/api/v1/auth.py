"""Giriş, çıkış ve yetki kontrolü.

Oturum, HttpOnly + SameSite=Strict bir çerezde taşınır:
- HttpOnly: JavaScript çerezi okuyamaz (arayüzde bir XSS olsa bile oturum çalınamaz).
- SameSite=Strict: başka bir site, kullanıcının tarayıcısı üzerinden istek atamaz (CSRF).
Buna ek olarak durum değiştiren her istek özel bir başlık (X-Requested-With) taşımak zorundadır;
basit HTML formları bu başlığı ekleyemez (derinlemesine savunma).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core import security
from app.core.config import settings
from app.db.models import AuthEvent, User, UserSession
from app.db.session import get_session

router = APIRouter(tags=["auth"])
DB = Annotated[Session, Depends(get_session)]

COOKIE = "siem_session"
CSRF_HEADER = "X-Requested-With"
CSRF_VALUE = "mini-siem"
ROLES = {"admin": "Yönetici", "analyst": "Analist"}
GENERIC_FAIL = "Kullanıcı adı veya şifre hatalı."


def utcnow() -> datetime:
    return datetime.now(UTC)


# ── her istekte ─────────────────────────────────────────────────────────────
def csrf_guard(request: Request) -> None:
    """Durum değiştiren isteklerde özel başlık zorunlu (GET/HEAD/OPTIONS hariç)."""
    if request.method not in ("GET", "HEAD", "OPTIONS") and \
            request.headers.get(CSRF_HEADER) != CSRF_VALUE:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "İstek reddedildi (CSRF koruması).")


def current_user(request: Request, db: DB) -> User:
    token = request.cookies.get(COOKIE)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Giriş gerekli.")
    row = db.execute(
        select(UserSession, User).join(User, User.id == UserSession.user_id)
        .where(UserSession.token_hash == security.token_digest(token))
    ).first()
    if row is None or row[0].expires_at <= utcnow():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Oturum geçersiz veya süresi doldu.")
    return row[1]


CurrentUser = Annotated[User, Depends(current_user)]


def require_admin(user: CurrentUser) -> User:
    if user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Bu işlem yalnızca yöneticiye açık.")
    return user


# ── giriş / çıkış ───────────────────────────────────────────────────────────
class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class Me(BaseModel):
    username: str
    role: str
    role_label: str


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def _is_locked(db: Session, username: str, now: datetime) -> bool:
    """Son kilit penceresinde, son başarılı girişten sonra yeterince hata varsa kilitli.
    Var olmayan kullanıcı adları da aynı şekilde sayılır (kullanıcı adı yoklanamaz)."""
    since = now - timedelta(minutes=settings.lockout_minutes)
    last_ok = db.scalar(select(func.max(AuthEvent.at)).where(
        AuthEvent.username == username, AuthEvent.action.in_(("login_ok", "unlock"))))
    floor = max(since, last_ok) if last_ok else since
    fails = db.scalar(select(func.count()).select_from(AuthEvent).where(
        AuthEvent.username == username, AuthEvent.action == "login_fail", AuthEvent.at > floor))
    return (fails or 0) >= settings.lockout_attempts


@router.post("/auth/login")
def login(creds: Credentials, request: Request, response: Response, db: DB) -> Me:
    now = utcnow()
    username = creds.username.strip().lower()
    ip = _client_ip(request)
    if _is_locked(db, username, now):
        security.burn_time(creds.password)
        db.add(AuthEvent(username=username, source_ip=ip, action="login_locked"))
        db.commit()
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            f"Çok fazla hatalı deneme. {settings.lockout_minutes} dakika sonra "
                            "tekrar deneyin.")

    user = db.scalar(select(User).where(User.username == username))
    ok = security.verify_password(creds.password, user.password_hash) if user else \
        security.burn_time(creds.password) or False
    if not ok:
        db.add(AuthEvent(username=username, source_ip=ip, action="login_fail"))
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, GENERIC_FAIL)

    token = security.new_session_token()
    db.add(UserSession(token_hash=security.token_digest(token), user_id=user.id,
                       expires_at=now + timedelta(hours=settings.session_hours)))
    db.execute(delete(UserSession).where(UserSession.expires_at <= now))  # eski oturumları temizle
    user.last_login_at = now
    db.add(AuthEvent(username=username, source_ip=ip, action="login_ok"))
    db.commit()
    response.set_cookie(COOKIE, token, max_age=settings.session_hours * 3600, httponly=True,
                        samesite="strict", secure=settings.cookie_secure, path="/api")
    return Me(username=user.username, role=user.role, role_label=ROLES[user.role])


@router.post("/auth/logout")
def logout(request: Request, response: Response, db: DB) -> dict:
    token = request.cookies.get(COOKIE)
    if token:
        s = db.scalar(select(UserSession)
                      .where(UserSession.token_hash == security.token_digest(token)))
        if s:
            user = db.get(User, s.user_id)
            db.delete(s)
            db.add(AuthEvent(username=user.username if user else "?",
                             source_ip=_client_ip(request), action="logout"))
            db.commit()
    response.delete_cookie(COOKIE, path="/api", samesite="strict", httponly=True,
                           secure=settings.cookie_secure)
    return {"ok": True}


@router.get("/auth/me")
def me(user: CurrentUser) -> Me:
    return Me(username=user.username, role=user.role, role_label=ROLES[user.role])


@router.get("/auth/setup")
def setup_status(db: DB) -> dict:
    """Hiç kullanıcı yoksa arayüz ilk kurulum talimatını gösterir (kullanıcı adı sızdırmaz)."""
    return {"has_users": bool(db.scalar(select(func.count()).select_from(User)))}
