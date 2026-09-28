"""SIEM kullanıcı yönetimi (terminalden).

Varsayılan kullanıcı/şifre YOKTUR ("admin/admin" gibi hazır hesaplar en yaygın açıklardandır);
ilk hesap bu araçla oluşturulur. Şifreler ekrana yazılmadan sorulur (getpass).

Kullanım (backend klasöründe):
    .venv\\Scripts\\python.exe -m app.tools.users ekle emir --rol yonetici
    .venv\\Scripts\\python.exe -m app.tools.users listele
    .venv\\Scripts\\python.exe -m app.tools.users sifre emir
    .venv\\Scripts\\python.exe -m app.tools.users kilit-ac emir
    .venv\\Scripts\\python.exe -m app.tools.users sil emir
"""

from __future__ import annotations

import argparse
import getpass
import re
import sys

from sqlalchemy import delete, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.core import security
from app.db.models import AuthEvent, User, UserSession
from app.db.session import engine, init_db

ROLE_ALIASES = {"yonetici": "admin", "yönetici": "admin", "admin": "admin",
                "analist": "analyst", "analyst": "analyst"}
USERNAME = re.compile(r"^[a-z0-9._-]{3,32}$")


class UserError(ValueError):
    pass


def normalize_username(name: str) -> str:
    name = name.strip().lower()
    if not USERNAME.fullmatch(name):
        raise UserError("Kullanıcı adı 3-32 karakter olmalı: küçük harf, rakam, . _ -")
    return name


def add_user(bind: Engine, username: str, role: str, password: str) -> User:
    username = normalize_username(username)
    if role not in ROLE_ALIASES:
        raise UserError("Rol 'yonetici' ya da 'analist' olmalı.")
    security.check_policy(password, username)
    with Session(bind, expire_on_commit=False) as db:
        if db.scalar(select(User).where(User.username == username)):
            raise UserError(f"'{username}' zaten var.")
        user = User(username=username, password_hash=security.hash_password(password),
                    role=ROLE_ALIASES[role])
        db.add(user)
        db.commit()
        return user


def set_password(bind: Engine, username: str, password: str) -> None:
    """Şifreyi değiştirir ve kullanıcının tüm açık oturumlarını kapatır."""
    username = normalize_username(username)
    security.check_policy(password, username)
    with Session(bind) as db:
        user = _get(db, username)
        user.password_hash = security.hash_password(password)
        db.execute(delete(UserSession).where(UserSession.user_id == user.id))
        db.commit()


def unlock(bind: Engine, username: str) -> None:
    """Kilidi açar: sayım bu andan itibaren yeniden başlar (geçmiş kayıtlar silinmez)."""
    username = normalize_username(username)
    with Session(bind) as db:
        db.add(AuthEvent(username=username, source_ip="yerel-terminal", action="unlock"))
        db.commit()


def remove_user(bind: Engine, username: str) -> None:
    with Session(bind) as db:
        db.delete(_get(db, normalize_username(username)))  # oturumları da silinir (CASCADE)
        db.commit()


def list_users(bind: Engine) -> list[tuple[str, str, str]]:
    with Session(bind) as db:
        return [(u.username, u.role, u.last_login_at.isoformat() if u.last_login_at else "—")
                for u in db.scalars(select(User).order_by(User.username))]


def _get(db: Session, username: str) -> User:
    user = db.scalar(select(User).where(User.username == username))
    if user is None:
        raise UserError(f"'{username}' bulunamadı.")
    return user


def _ask_password() -> str:
    first = getpass.getpass("Yeni şifre (en az 12 karakter, ekranda görünmez): ")
    if getpass.getpass("Tekrar: ") != first:
        raise UserError("Şifreler aynı değil.")
    return first


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="SIEM kullanıcı yönetimi")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("ekle")
    p.add_argument("ad")
    p.add_argument("--rol", required=True, choices=["yonetici", "analist"])
    sub.add_parser("listele")
    for cmd in ("sifre", "kilit-ac", "sil"):
        sub.add_parser(cmd).add_argument("ad")
    args = parser.parse_args(argv)

    init_db(engine)
    try:
        if args.cmd == "ekle":
            user = add_user(engine, args.ad, args.rol, _ask_password())
            print(f"✅ '{user.username}' eklendi ({args.rol}).")
        elif args.cmd == "listele":
            for name, role, last in list_users(engine):
                print(f"{name:20} {role:8} son giriş: {last}")
        elif args.cmd == "sifre":
            set_password(engine, args.ad, _ask_password())
            print("✅ Şifre değişti; açık oturumlar kapatıldı.")
        elif args.cmd == "kilit-ac":
            unlock(engine, args.ad)
            print("✅ Kilit açıldı.")
        elif args.cmd == "sil":
            remove_user(engine, args.ad)
            print("✅ Silindi.")
    except (UserError, security.WeakPassword) as exc:
        sys.exit(f"❌ {exc}")


if __name__ == "__main__":
    main()
