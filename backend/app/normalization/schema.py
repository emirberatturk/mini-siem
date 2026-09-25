"""Ortak olay şeması. Alan adları Elastic Common Schema'dan (ECS) esinlenmiştir.

Hangi kaynaktan gelirse gelsin (Apache, ileride syslog, uygulama logu) her olay bu şekle
dönüştürülür. Tespit kuralları sadece bu şemayı bilir; log biçimlerini bilmek zorunda kalmaz.
"""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel


class EventCategory(StrEnum):
    WEB = "web"
    AUTHENTICATION = "authentication"


class EventType(StrEnum):
    HTTP_REQUEST = "http_request"
    AUTH_SUCCESS = "authentication_success"
    AUTH_FAILURE = "authentication_failure"
    AUTH_LOCKOUT = "authentication_lockout"
    ADMIN_ACCESS = "admin_access"


class EventOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class NormalizedEvent(BaseModel):
    timestamp: datetime  # UTC
    source_ip: str
    http_method: str | None
    url_path: str
    url_query: str  # maskelenmiş
    status_code: int
    bytes_sent: int
    referrer: str  # query'si atılmış
    user_agent: str
    event_category: EventCategory
    event_type: EventType
    event_outcome: EventOutcome
    redactions: int  # bu olayda kaç değer maskelendi
    event_key: str  # tekrar yüklemede çift kaydı önler (bkz. normalizer.event_key)
    parser: str
    # Eşleşen imza (Sigma) kurallarının kısa adları, virgülle. Ham istek maskelemeden önce
    # bellekte kontrol edilir; buraya yalnızca kural adı yazılır (bkz. detection/sigma.py).
    signatures: str = ""
