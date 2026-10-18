"""Giriş, çıkış ve yetki kontrolü.

Oturum, HttpOnly + SameSite=Strict bir çerezde taşınır:
- HttpOnly: JavaScript çerezi okuyamaz (arayüzde bir XSS olsa bile oturum çalınamaz).
- SameSite=Strict: başka bir site, kullanıcının tarayıcısı üzerinden istek atamaz (CSRF).
Buna ek olarak durum değiştiren her istek özel bir başlık (X-Requested-With) taşımak zorundadır;
basit HTML formları bu başlığı ekleyemez (derinlemesine savunma).

Giriş iki adımlıdır ve herkes için zorunludur (bkz. core/mfa.py):
1. Kullanıcı adı + şifre doğruysa kısa ömürlü bir "ara oturum" açılır (stage = mfa / enroll).
   Bu oturumla hiçbir veri okunamaz; yalnızca kod uçları kullanılabilir.
2. Telefon kodu (ya da yedek kod) doğruysa ara oturum silinir ve YENİ bir belirteçle tam oturum
   açılır. Telefonu henüz tanıtılmamış hesap önce kurulumu tamamlar.
Yanlış kodlar yanlış şifrelerle aynı kilit sayacına işlenir; şifreyi bilen biri tekrar tekrar
giriş yaparak sayacı sıfırlayamaz (sayaç yalnızca iki adım da başarılı olunca sıfırlanır).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from app.core import mfa, security
from app.core.config import settings
from app.db.models import AuthEvent, RecoveryCode, User, UserSession
from app.db.session import get_session

router = APIRouter(tags=["auth"])
DB = Annotated[Session, Depends(get_session)]

COOKIE = "siem_session"
CSRF_HEADER = "X-Requested-With"
CSRF_VALUE = "mini-siem"
ROLES = {"admin": "Yönetici", "analyst": "Analist"}
GENERIC_FAIL = "Kullanıcı adı veya şifre hatalı."
CODE_FAIL = "Kod hatalı ya da süresi geçmiş."
PENDING_REQUIRED = "Önce kullanıcı adı ve şifreyle giriş yapın."


def utcnow() -> datetime:
    return datetime.now(UTC)


# ── her istekte ─────────────────────────────────────────────────────────────
def csrf_guard(request: Request) -> None:
    """Durum değiştiren isteklerde özel başlık zorunlu (GET/HEAD/OPTIONS hariç)."""
    if request.method not in ("GET", "HEAD", "OPTIONS") and \
            request.headers.get(CSRF_HEADER) != CSRF_VALUE:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "İstek reddedildi (CSRF koruması).")


def _session(request: Request, db: Session) -> tuple[UserSession, User] | None:
    token = request.cookies.get(COOKIE)
    if not token:
        return None
    row = db.execute(
        select(UserSession, User).join(User, User.id == UserSession.user_id)
        .where(UserSession.token_hash == security.token_digest(token))
    ).first()
    if row is None or row[0].expires_at <= utcnow():
        return None
    return row[0], row[1]


def current_user(request: Request, db: DB) -> User:
    found = _session(request, db)
    if found is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Oturum geçersiz veya süresi doldu.")
    sess, user = found
    # Ara oturum veri göremez; iki adımlı doğrulaması kurulmamış hesabın eski oturumları da
    # (bu özellikten önce açılmış olanlar) geçersizdir
    if sess.stage != "full" or user.totp_secret is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "İki adımlı doğrulama gerekli.")
    return user


CurrentUser = Annotated[User, Depends(current_user)]


def require_admin(user: CurrentUser) -> User:
    if user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Bu işlem yalnızca yöneticiye açık.")
    return user


# ── giriş / çıkış ───────────────────────────────────────────────────────────
class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class CodeIn(BaseModel):
    code: str = Field(min_length=1, max_length=32)


class Me(BaseModel):
    username: str
    role: str
    role_label: str


class LoginStep(BaseModel):
    stage: Literal["mfa", "enroll"]  # telefon kodu mu isteniyor, yoksa ilk kurulum mu


class Enrollment(BaseModel):
    secret: str  # QR okutulamazsa elle girilecek anahtar
    qr: str  # data:image/svg+xml;… (yalnızca <img> ile gösterilir)


class Enabled(BaseModel):
    me: Me
    recovery_codes: list[str]  # yalnızca bu yanıtta gösterilir; sunucuda özetleri kalır


def _me(user: User) -> Me:
    return Me(username=user.username, role=user.role, role_label=ROLES[user.role])


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
        AuthEvent.username == username, AuthEvent.action.in_(("login_fail", "mfa_fail")),
        AuthEvent.at > floor))
    return (fails or 0) >= settings.lockout_attempts


def _reject_if_locked(db: Session, username: str, ip: str, now: datetime) -> None:
    if _is_locked(db, username, now):
        db.add(AuthEvent(username=username, source_ip=ip, action="login_locked"))
        db.commit()
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            f"Çok fazla hatalı deneme. {settings.lockout_minutes} dakika sonra "
                            "tekrar deneyin.")


def _open_session(db: Session, response: Response, user: User, stage: str,
                  lifetime: timedelta, now: datetime) -> UserSession:
    token = security.new_session_token()
    sess = UserSession(token_hash=security.token_digest(token), user_id=user.id, stage=stage,
                       expires_at=now + lifetime)
    db.add(sess)
    db.execute(delete(UserSession).where(UserSession.expires_at <= now))  # eski oturumları temizle
    response.set_cookie(COOKIE, token, max_age=int(lifetime.total_seconds()), httponly=True,
                        samesite="strict", secure=settings.cookie_secure, path="/api")
    return sess


def _pending(request: Request, db: Session, stage: str) -> tuple[UserSession, User]:
    found = _session(request, db)
    if found is None or found[0].stage != stage:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, PENDING_REQUIRED)
    return found


# Bağımlılık olarak: istek gövdesi okunmadan önce ara oturum kontrol edilir (girişsiz istek 401)
def pending_mfa(request: Request, db: DB) -> tuple[UserSession, User]:
    return _pending(request, db, "mfa")


def pending_enroll(request: Request, db: DB) -> tuple[UserSession, User]:
    return _pending(request, db, "enroll")


MfaPending = Annotated[tuple[UserSession, User], Depends(pending_mfa)]
EnrollPending = Annotated[tuple[UserSession, User], Depends(pending_enroll)]


def _finish_login(db: Session, request: Request, response: Response, pending: UserSession,
                  user: User, now: datetime) -> Me:
    """Ara oturumu siler, yeni belirteçle tam oturum açar (oturum sabitleme saldırısına karşı:
    şifre adımındaki belirteç hiçbir zaman tam yetki kazanmaz)."""
    db.delete(pending)
    _open_session(db, response, user, "full", timedelta(hours=settings.session_hours), now)
    user.last_login_at = now
    db.add(AuthEvent(username=user.username, source_ip=_client_ip(request), action="login_ok"))
    db.commit()
    return _me(user)


@router.post("/auth/login")
def login(creds: Credentials, request: Request, response: Response, db: DB) -> LoginStep:
    now = utcnow()
    username = creds.username.strip().lower()
    ip = _client_ip(request)
    if _is_locked(db, username, now):
        security.burn_time(creds.password)
        _reject_if_locked(db, username, ip, now)

    user = db.scalar(select(User).where(User.username == username))
    ok = security.verify_password(creds.password, user.password_hash) if user else \
        security.burn_time(creds.password) or False
    if not ok:
        db.add(AuthEvent(username=username, source_ip=ip, action="login_fail"))
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, GENERIC_FAIL)

    stage = "mfa" if user.totp_secret else "enroll"
    _open_session(db, response, user, stage, timedelta(minutes=settings.mfa_minutes), now)
    # "password_ok" kilit sayacını SIFIRLAMAZ (yalnızca iki adım da geçilince login_ok sıfırlar)
    db.add(AuthEvent(username=username, source_ip=ip, action="password_ok"))
    db.commit()
    return LoginStep(stage=stage)


@router.post("/auth/mfa/verify")
def verify_mfa(pending: MfaPending, body: CodeIn, request: Request, response: Response,
               db: DB) -> Me:
    """Telefon uygulamasındaki 6 haneli kod ya da tek kullanımlık yedek kod."""
    sess, user = pending
    now = utcnow()
    ip = _client_ip(request)
    _reject_if_locked(db, user.username, ip, now)

    step = mfa.match_step(user.totp_secret, body.code, now.timestamp(), user.totp_last_step)
    if step is not None:
        user.totp_last_step = step
    else:
        spare = db.scalar(select(RecoveryCode).where(
            RecoveryCode.user_id == user.id, RecoveryCode.used_at.is_(None),
            RecoveryCode.code_hash == mfa.recovery_digest(body.code)))
        if spare is None:
            db.add(AuthEvent(username=user.username, source_ip=ip, action="mfa_fail"))
            db.commit()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, CODE_FAIL)
        spare.used_at = now
        db.add(AuthEvent(username=user.username, source_ip=ip, action="recovery_used"))
    return _finish_login(db, request, response, sess, user, now)


@router.post("/auth/mfa/setup")
def setup_mfa(pending: EnrollPending, db: DB) -> Enrollment:
    """İlk kurulum: yeni anahtar üretir (ara oturuma bağlı; oturum düşerse anahtar da gider)."""
    sess, user = pending
    if user.totp_secret is not None:  # kurulu anahtar yalnızca şifreyle değiştirilemez
        raise HTTPException(status.HTTP_409_CONFLICT, "İki adımlı doğrulama zaten kurulu.")
    if sess.pending_secret is None:
        # Aynı anda iki istek gelirse (sayfa iki kez yüklenirse) ikisi de AYNI anahtarı almalı:
        # yalnızca hâlâ boşsa yaz, sonra veritabanındaki (kazanan) değeri oku
        db.execute(update(UserSession)
                   .where(UserSession.id == sess.id, UserSession.pending_secret.is_(None))
                   .values(pending_secret=mfa.new_secret()))
        db.commit()
        db.refresh(sess)
    uri = mfa.provisioning_uri(sess.pending_secret, user.username)
    return Enrollment(secret=sess.pending_secret, qr=mfa.qr_data_uri(uri))


@router.post("/auth/mfa/enable")
def enable_mfa(pending: EnrollPending, body: CodeIn, request: Request, response: Response,
               db: DB) -> Enabled:
    """Telefonun anahtarı doğru okuduğunu bir kodla kanıtlar; yedek kodlar bir kez gösterilir."""
    sess, user = pending
    if user.totp_secret is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "İki adımlı doğrulama zaten kurulu.")
    if sess.pending_secret is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Önce kurulumu başlatın.")
    now = utcnow()
    ip = _client_ip(request)
    _reject_if_locked(db, user.username, ip, now)

    step = mfa.match_step(sess.pending_secret, body.code, now.timestamp(), None)
    if step is None:
        db.add(AuthEvent(username=user.username, source_ip=ip, action="mfa_fail"))
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{CODE_FAIL} Telefonun saati doğru mu?")
    user.totp_secret, user.totp_last_step = sess.pending_secret, step
    # 2FA'dan geçmeden (yalnızca şifreyle) açılmış diğer oturumlar kurulumla geçerli hale gelmesin
    db.execute(delete(UserSession).where(UserSession.user_id == user.id,
                                         UserSession.id != sess.id))
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    codes = mfa.new_recovery_codes()
    db.add_all(RecoveryCode(user_id=user.id, code_hash=mfa.recovery_digest(c)) for c in codes)
    db.add(AuthEvent(username=user.username, source_ip=ip, action="mfa_enrolled"))
    return Enabled(me=_finish_login(db, request, response, sess, user, now),
                   recovery_codes=codes)


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
    return _me(user)


@router.get("/auth/setup")
def setup_status(db: DB) -> dict:
    """Hiç kullanıcı yoksa arayüz ilk kurulum talimatını gösterir (kullanıcı adı sızdırmaz)."""
    return {"has_users": bool(db.scalar(select(func.count()).select_from(User)))}
