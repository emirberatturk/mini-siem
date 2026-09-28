"""Şifre saklama ve oturum belirteçleri.

- Şifreler scrypt ile (rastgele tuzla) saklanır: veritabanı sızsa bile şifreler kolayca
  kırılamaz. scrypt bellek-yoğundur; ekran kartıyla toplu deneme yapmayı pahalı kılar.
- Karşılaştırma sabit zamanlıdır (hmac.compare_digest): yanıt süresinden bilgi sızmaz.
- Oturum belirteci rastgeledir; veritabanında yalnızca SHA-256 özeti tutulur, böylece
  veritabanı sızsa bile açık oturumlar ele geçirilemez.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

# scrypt parametreleri: ~16 MB bellek (128 * r * n), tek çekirdek. OWASP önerisiyle uyumlu.
_N, _R, _P, _DKLEN = 2**14, 8, 1, 32
MIN_PASSWORD_LENGTH = 12


class WeakPassword(ValueError):
    """Şifre politikaya uymuyor."""


def check_policy(password: str, username: str = "") -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPassword(f"Şifre en az {MIN_PASSWORD_LENGTH} karakter olmalı.")
    if username and username.lower() in password.lower():
        raise WeakPassword("Şifre kullanıcı adını içermemeli.")
    if len(set(password)) < 5:
        raise WeakPassword("Şifre çok tekdüze (en az 5 farklı karakter).")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P, dklen=_DKLEN)
    return f"scrypt${_N}${_R}${_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, digest = stored.split("$")
        if algo != "scrypt":
            return False
        expected = base64.b64decode(digest)
        actual = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(salt),
                                n=int(n), r=int(r), p=int(p), dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


# Var olmayan kullanıcı için de aynı işi yap: yanıt süresi "kullanıcı var mı?" sızdırmasın
_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def burn_time(password: str) -> None:
    verify_password(password, _DUMMY_HASH)


def new_session_token() -> str:
    return secrets.token_urlsafe(32)  # 256 bit


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
