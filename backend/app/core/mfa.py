"""İki adımlı doğrulama: zamana dayalı tek kullanımlık kod (TOTP, RFC 6238) ve yedek kodlar.

Google Authenticator, Microsoft Authenticator gibi uygulamalar aynı standardı kullanır: sunucu
ve telefon ortak bir gizli anahtarı bilir, ikisi de o anki 30 saniyelik dilim için aynı 6 haneli
kodu hesaplar. Kod ağ üzerinden gönderilmez; telefon internete bağlı olmasa da çalışır.

- Aynı kod iki kez kabul edilmez (son kullanılan dilim saklanır): ekran görüntüsü ya da
  omuz üstünden görülen bir kod, sahibi kullandıktan sonra işe yaramaz.
- Yedek kodlar telefon kaybolursa içindir; her biri tek kullanımlıktır ve şifreler gibi
  yalnızca özetleri saklanır.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import string
import struct
from urllib.parse import quote, urlencode

STEP = 30  # saniye
DIGITS = 6
DRIFT = 1  # telefon saati bir dilim (±30 sn) kaymış olabilir
ISSUER = "Mini-SIEM"
RECOVERY_COUNT = 10
# Karışabilecek karakterler (0/o, 1/l/i) yok: kâğıda yazılıp geri okunacak
_RECOVERY_ALPHABET = "".join(c for c in string.ascii_lowercase + string.digits if c not in "01ilo")


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")  # 160 bit (RFC 4226)


def code_at(secret: str, step: int) -> str:
    digest = hmac.new(base64.b32decode(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def match_step(secret: str, code: str, now: float, last_step: int | None) -> int | None:
    """Kod geçerliyse ait olduğu dilimi döndürür. Daha önce kullanılan (ya da daha eski)
    dilimler kabul edilmez."""
    code = "".join(code.split())
    if len(code) != DIGITS or not code.isdigit():
        return None
    current = int(now // STEP)
    for step in range(current - DRIFT, current + DRIFT + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(code_at(secret, step), code):
            return step
    return None


def provisioning_uri(secret: str, username: str) -> str:
    """Telefon uygulamasının QR koddan okuduğu adres."""
    label = quote(f"{ISSUER}:{username}")
    query = urlencode({"secret": secret, "issuer": ISSUER, "digits": DIGITS, "period": STEP})
    return f"otpauth://totp/{label}?{query}"


def qr_data_uri(uri: str) -> str:
    """QR kodu SVG resim olarak (data: adresi). Arayüz bunu <img> ile gösterir; HTML olarak
    sayfaya eklenmediği için içinde betik çalışamaz."""
    import segno

    return segno.make(uri, error="m").svg_data_uri(scale=5, border=2)


def new_recovery_codes() -> list[str]:
    codes = []
    for _ in range(RECOVERY_COUNT):
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10))  # ~49 bit
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def recovery_digest(code: str) -> str:
    """Yedek kodun özeti. Kodlar rastgele ve uzun olduğundan (şifrelerin aksine) tahmin
    edilemez; bu yüzden yavaş scrypt yerine SHA-256 yeterli."""
    normalized = "".join(code.split()).replace("-", "").lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
