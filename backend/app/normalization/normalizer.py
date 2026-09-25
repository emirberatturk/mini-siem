from __future__ import annotations

import hashlib
from urllib.parse import parse_qsl

from app.core import site_profile
from app.normalization.schema import EventCategory, EventOutcome, EventType, NormalizedEvent
from app.parsers.apache import ParsedRequest
from app.privacy.redactor import redact_query, redact_referrer, redact_text


def api_type(req: ParsedRequest) -> str | None:
    if req.path.lower() != site_profile.LOGIN_PATH:
        return None
    for key, value in parse_qsl(req.query, keep_blank_values=True):
        if key == "type":
            return value
    return None


def classify(req: ParsedRequest) -> tuple[EventCategory, EventType, EventOutcome]:
    """İsteğe güvenlik açısından anlam kazandırır: '401' değil, 'başarısız giriş'."""
    outcome = EventOutcome.SUCCESS if req.status_code < 400 else EventOutcome.FAILURE
    kind = api_type(req)

    if kind == site_profile.LOGIN_TYPE and req.method == "POST":
        if req.status_code == 200:
            return EventCategory.AUTHENTICATION, EventType.AUTH_SUCCESS, EventOutcome.SUCCESS
        if req.status_code == 429:
            return EventCategory.AUTHENTICATION, EventType.AUTH_LOCKOUT, EventOutcome.FAILURE
        if req.status_code in (400, 401, 403):
            return EventCategory.AUTHENTICATION, EventType.AUTH_FAILURE, EventOutcome.FAILURE
        return EventCategory.AUTHENTICATION, EventType.AUTH_FAILURE, EventOutcome.UNKNOWN

    if kind in site_profile.ADMIN_API_TYPES or req.path.lower() in site_profile.ADMIN_PAGES:
        return EventCategory.WEB, EventType.ADMIN_ACCESS, outcome

    return EventCategory.WEB, EventType.HTTP_REQUEST, outcome


def event_key(raw_line: str, occurrence: int) -> str:
    """Satır + dosyadaki kaçıncı tekrarı olduğu.

    Sadece satırın hash'i yetmez: brute-force aracı aynı saniyede aynı isteği 5 kez atarsa
    log'da 5 özdeş satır oluşur. Hash'le tekilleştirsek saldırı 1 olaya iner. Tekrar sırasını
    eklersek 5 olay korunur, ama aynı dosyanın ikinci kez yüklenmesi yine çift kayıt üretmez.
    """
    data = f"{raw_line}\x00{occurrence}".encode("utf-8", errors="replace")
    return hashlib.sha256(data).hexdigest()


def normalize(raw_line: str, req: ParsedRequest, parser: str, occurrence: int = 0,
              signatures: list[str] | None = None) -> NormalizedEvent:
    category, event_type, outcome = classify(req)
    query = redact_query(req.path, req.query)
    path = redact_text(req.path)
    referrer = redact_referrer(req.referrer)
    ua = redact_text(req.user_agent)

    return NormalizedEvent(
        timestamp=req.timestamp,
        source_ip=req.source_ip,
        http_method=req.method,
        url_path=path.value,
        url_query=query.value,
        status_code=req.status_code,
        bytes_sent=req.bytes_sent,
        referrer=referrer.value,
        user_agent=ua.value,
        event_category=category,
        event_type=event_type,
        event_outcome=outcome,
        redactions=query.count + path.count + referrer.count + ua.count,
        event_key=event_key(raw_line, occurrence),
        parser=parser,
        signatures=",".join(signatures or []),
    )
