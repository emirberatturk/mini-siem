"""KVKK: kişisel veriyi veritabanına ulaşmadan önce maskeler.

Üç katman:
  1. Kişisel veri formu olan sayfalarda TÜM parametre değerleri maskelenir (izin listesi değil,
     "varsayılan olarak gizle" yaklaşımı).
  2. Adı hassas olan parametreler (tel, email, sifre...) her sayfada maskelenir.
  3. Diğer değerler e-posta / telefon / TC Kimlik No kalıplarına karşı taranır.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote_plus, urlsplit

from app.core import site_profile

MASK = "***"

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}")
# TR cep telefonu: 05xx xxx xx xx, +90 5xx..., 5xxxxxxxxx (boşluk/tire serbest)
_PHONE = re.compile(r"(?<!\d)(?:\+?90[\s-]?|0)?5\d{2}[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}(?!\d)")
_TCKN = re.compile(r"(?<!\d)[1-9]\d{10}(?!\d)")

# Asla maskelenmeyen parametreler: olay sınıflandırması için gerekli ve kişisel veri değil
_ALWAYS_KEEP = frozenset({"type"})


@dataclass
class Redacted:
    value: str
    count: int = 0


def is_valid_tckn(digits: str) -> bool:
    """TC Kimlik No kontrol hanesi algoritması.

    Her 11 haneli sayıyı maskelersek sipariş no, zaman damgası gibi zararsız değerleri de
    maskeleriz. Kontrol hanesi doğrulaması yanlış pozitifleri ~%99 azaltır.
    """
    if len(digits) != 11 or not digits.isdigit() or digits[0] == "0":
        return False
    d = [int(c) for c in digits]
    d10 = ((d[0] + d[2] + d[4] + d[6] + d[8]) * 7 - (d[1] + d[3] + d[5] + d[7])) % 10
    d11 = sum(d[:10]) % 10
    return d[9] == d10 and d[10] == d11


def redact_text(text: str) -> Redacted:
    """Serbest metindeki e-posta, telefon ve geçerli TC Kimlik No'ları maskeler."""
    count = 0

    def sub(pattern: re.Pattern[str], s: str, check=None) -> str:
        nonlocal count

        def repl(m: re.Match[str]) -> str:
            nonlocal count
            if check and not check(m.group()):
                return m.group()
            count += 1
            return MASK

        return pattern.sub(repl, s)

    out = sub(_EMAIL, text)
    out = sub(_TCKN, out, is_valid_tckn)  # telefondan önce: 11 hane telefona da benzeyebilir
    out = sub(_PHONE, out)
    return Redacted(out, count)


def _is_pii_endpoint(path: str, params: list[tuple[str, str]]) -> bool:
    if path.lower() in site_profile.PII_PAGES:
        return True
    types = {v for k, v in params if k == "type"}
    return path.lower() == site_profile.LOGIN_PATH and bool(types & site_profile.PII_API_TYPES)


def redact_query(path: str, query: str) -> Redacted:
    """Query string'i maskelenmiş haliyle yeniden kurar: 'ad=***&type=blog'."""
    if not query:
        return Redacted("")

    params = parse_qsl(query, keep_blank_values=True)
    if not params:  # 'k=v' biçiminde olmayan query (ör. '?abc'): metin olarak tara
        return redact_text(unquote_plus(query))

    mask_all = _is_pii_endpoint(path, params)
    parts: list[str] = []
    count = 0
    for key, value in params:
        k = key.lower()
        if k in _ALWAYS_KEEP:
            parts.append(f"{key}={value}")
        elif value and (mask_all or k in site_profile.SENSITIVE_PARAMS):
            parts.append(f"{key}={MASK}")
            count += 1
        else:
            r = redact_text(value)
            parts.append(f"{key}={r.value}")
            count += r.count
    return Redacted("&".join(parts), count)


def redact_referrer(referrer: str) -> Redacted:
    """Referrer'dan query'yi tamamen atar: önceki sayfanın form verisi burada sızabilir."""
    if not referrer or referrer == "-":
        return Redacted("")
    parts = urlsplit(referrer)
    if not parts.query:
        return redact_text(referrer)
    base = f"{parts.scheme}://{parts.netloc}{parts.path}" if parts.netloc else parts.path
    r = redact_text(base)
    return Redacted(r.value, r.count + 1)
