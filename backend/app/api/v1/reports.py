"""Haftalık özet rapor: 7 günün olayları, alarmları ve analist kararları, önceki haftayla birlikte.

Hafta, logdaki olay zamanına göre ve yerel günlerle (Türkiye) hesaplanır. Varsayılan hafta, son
yüklenen logun son günüyle biter: loglar elle ve gecikmeli yüklendiği için "bugünden geriye 7 gün"
çoğu zaman boş çıkardı.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, date, datetime, time, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.v1.stats import Count, SignatureCount, finding_counts
from app.core.config import settings
from app.db.models import Alert, AlertHistory, Event
from app.db.session import get_session
from app.detection import sigma
from app.detection.base import ProxyMatcher
from app.detection.engine import OPEN_STATUSES, load_config, proxy_ips
from app.detection.rules.parameter import describe
from app.privacy.retention import retention_status

router = APIRouter(tags=["reports"])
DB = Annotated[Session, Depends(get_session)]

AUTH_OK = "authentication_success"
AUTH_FAIL = ("authentication_failure", "authentication_lockout")
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class DayStat(BaseModel):
    day: date
    events: int
    suspicious: int  # imza ya da anomali bulunan istek
    auth_failures: int
    alerts: int


class Totals(BaseModel):
    events: int
    unique_ips: int
    client_errors: int  # 4xx
    suspicious: int
    suspicious_blocked: int  # şüpheli olup sunucunun başarılı yanıt VERMEDİĞİ
    auth_ok: int
    auth_fail: int
    alerts: int  # yanlış alarmlar dahil


class WeeklyAlert(BaseModel):
    id: int
    rule_id: str
    title: str
    severity: str
    status: str
    source_ip: str
    first_seen: datetime
    decided_by: str | None
    decision_note: str | None


class WeeklyReport(BaseModel):
    start: datetime
    end: datetime  # hariç
    first_day: date
    last_day: date
    prev_last_day: date | None  # önceki haftada veri varsa
    next_last_day: date | None
    days: list[DayStat]
    missing_days: list[date]  # hiç olay yok: log yüklenmemiş olabilir
    totals: Totals
    previous: Totals
    alerts: list[WeeklyAlert]
    alerts_by_status: dict[str, int]
    open_alerts_total: int  # haftadan bağımsız: hâlâ bekleyen iş
    top_signatures: list[SignatureCount]
    top_anomalies: list[SignatureCount]
    top_sources: list[Count]  # en çok hata/şüpheli istek üreten adresler
    retention_days: int
    oldest_event: datetime | None
    next_purge_at: datetime | None


def local_tz() -> timezone:
    return timezone(timedelta(hours=settings.local_utc_offset_hours))


def _totals(db: Session, start: datetime, end: datetime) -> Totals:
    rng = [Event.timestamp >= start, Event.timestamp < end]
    suspicious = or_(Event.signatures != "", Event.anomalies != "")
    ok_code = Event.status_code.between(200, 299)

    def count(*where) -> int:
        return db.scalar(select(func.count()).select_from(Event).where(*rng, *where)) or 0

    return Totals(
        events=count(),
        unique_ips=db.scalar(select(func.count(func.distinct(Event.source_ip))).where(*rng)) or 0,
        client_errors=count(Event.status_code.between(400, 499)),
        suspicious=count(suspicious),
        suspicious_blocked=count(suspicious, ~ok_code),
        auth_ok=count(Event.event_type == AUTH_OK),
        auth_fail=count(Event.event_type.in_(AUTH_FAIL)),
        alerts=db.scalar(select(func.count()).select_from(Alert).where(
            Alert.first_seen >= start, Alert.first_seen < end)) or 0,
    )


def _decision(db: Session, alert_id: int) -> AlertHistory | None:
    return db.scalar(select(AlertHistory).where(
        AlertHistory.alert_id == alert_id, AlertHistory.changed_by != "sistem")
        .order_by(AlertHistory.id.desc()).limit(1))


@router.get("/reports/weekly")
def weekly(db: DB, end: date | None = None) -> WeeklyReport:
    """end: haftanın son günü (yerel, dahil). Verilmezse son olayın günü."""
    tz = local_tz()
    lo, hi = db.execute(select(func.min(Event.timestamp), func.max(Event.timestamp))).one()
    last_day = end or (hi.astimezone(tz).date() if hi else datetime.now(tz).date())
    first_day = last_day - timedelta(days=6)
    start = datetime.combine(first_day, time(0), tz)
    stop = datetime.combine(last_day + timedelta(days=1), time(0), tz)
    rng = [Event.timestamp >= start, Event.timestamp < stop]

    per_day = {first_day + timedelta(days=i): [0, 0, 0, 0] for i in range(7)}
    for ts, etype, sig, anom in db.execute(
            select(Event.timestamp, Event.event_type, Event.signatures, Event.anomalies)
            .where(*rng)):
        d = per_day[ts.astimezone(tz).date()]
        d[0] += 1
        d[1] += bool(sig or anom)
        d[2] += etype in AUTH_FAIL
    alerts = sorted(
        db.scalars(select(Alert).where(Alert.first_seen >= start, Alert.first_seen < stop)),
        key=lambda a: (SEVERITY_ORDER.get(a.severity, 9), a.first_seen))
    for a in alerts:
        per_day[a.first_seen.astimezone(tz).date()][3] += 1

    weekly_alerts = []
    for a in alerts:
        h = _decision(db, a.id)
        weekly_alerts.append(WeeklyAlert(
            id=a.id, rule_id=a.rule_id, title=a.title, severity=a.severity, status=a.status,
            source_ip=a.source_ip, first_seen=a.first_seen,
            decided_by=h.changed_by if h else None, decision_note=h.note if h else None))

    is_proxy = ProxyMatcher(proxy_ips(load_config()))
    noisy = or_(Event.signatures != "", Event.anomalies != "",
                Event.status_code.between(400, 499))
    sources = db.execute(
        select(Event.source_ip, func.count()).where(*rng, noisy)
        .group_by(Event.source_ip).order_by(func.count().desc()).limit(5)).all()
    sig_rules = sigma.rule_by_name()
    status = retention_status(db, settings.retention_days)

    return WeeklyReport(
        start=start.astimezone(UTC), end=stop.astimezone(UTC), first_day=first_day,
        last_day=last_day,
        prev_last_day=last_day - timedelta(days=7) if lo and lo < start else None,
        next_last_day=last_day + timedelta(days=7) if hi and hi >= stop else None,
        days=[DayStat(day=d, events=v[0], suspicious=v[1], auth_failures=v[2], alerts=v[3])
              for d, v in per_day.items()],
        missing_days=[d for d, v in per_day.items() if v[0] == 0],
        totals=_totals(db, start, stop),
        previous=_totals(db, start - timedelta(days=7), start),
        alerts=weekly_alerts,
        alerts_by_status=dict(Counter(a.status for a in alerts)),
        open_alerts_total=db.scalar(select(func.count()).select_from(Alert)
                                    .where(Alert.status.in_(OPEN_STATUSES))) or 0,
        top_signatures=finding_counts(
            db, Event.signatures, rng, lambda n: sig_rules[n].title if n in sig_rules else n),
        top_anomalies=finding_counts(db, Event.anomalies, rng, describe),
        top_sources=[Count(key=ip, count=n, proxy=is_proxy(ip)) for ip, n in sources],
        retention_days=status.days,
        oldest_event=status.oldest_event,
        next_purge_at=status.next_purge_at,
    )
