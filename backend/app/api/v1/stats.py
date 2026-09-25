"""Dashboard istatistikleri.

Zaman aralığı verilmezse verideki ilk ve son olay arasındaki dönem kullanılır: yüklenen loglar
geçmişe ait olabilir (ör. dün indirilen cPanel logu), 'son 24 saat' boş görünürdü.
"""

from collections import Counter
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.v1.alerts import AlertOut
from app.api.v1.events import as_utc
from app.db.models import Alert, Event
from app.db.session import get_session
from app.detection.base import ProxyMatcher
from app.detection.engine import OPEN_STATUSES, load_config, proxy_ips

router = APIRouter(tags=["stats"])
DB = Annotated[Session, Depends(get_session)]

# Okunaklı dilimler: aralığa göre en uygun olanı seçilir (~24-60 çubuk)
_BUCKETS = [timedelta(minutes=m) for m in (1, 5, 15, 30, 60, 180, 360, 720, 1440)]


class Count(BaseModel):
    key: str
    count: int
    proxy: bool = False  # IP listelerinde: bu adres bir kişi değil, aracı sunucu


class TimelineBucket(BaseModel):
    start: datetime
    events: int
    auth_failures: int
    alerts: int


class Overview(BaseModel):
    range_start: datetime | None
    range_end: datetime | None
    bucket_minutes: int
    total_events: int
    total_alerts: int  # yanlış alarmlar hariç
    false_positives: int
    proxy_ips: list[str]
    proxy_event_share: float  # olayların yüzde kaçı aracı sunucudan geldi (0-100)
    open_alerts_by_severity: dict[str, int]
    events_per_minute: float
    peak_events_per_minute: int
    top_ips: list[Count]
    top_rules: list[Count]
    status_classes: list[Count]
    event_types: list[Count]
    timeline: list[TimelineBucket]
    recent_alerts: list[AlertOut]


def pick_bucket(span: timedelta) -> timedelta:
    for b in _BUCKETS:
        if span / b <= 60:
            return b
    return _BUCKETS[-1]


def floor_to(ts: datetime, bucket: timedelta, origin: datetime) -> datetime:
    return origin + ((ts - origin) // bucket) * bucket


@router.get("/stats/overview")
def overview(db: DB, since: datetime | None = None, until: datetime | None = None) -> Overview:
    lo, hi = db.execute(select(func.min(Event.timestamp), func.max(Event.timestamp))).one()
    start = as_utc(since) if since else lo
    end = as_utc(until) if until else hi

    in_range = [Event.timestamp >= start, Event.timestamp <= end] if start else []
    alert_range = [Alert.last_seen >= start, Alert.first_seen <= end] if start else []
    # Yanlış alarm olarak kapatılanlar istatistikleri çarpıtmasın (ayrıca sayılır)
    real_alerts = [*alert_range, Alert.status != "false_positive"]

    total_events = db.scalar(select(func.count()).select_from(Event).where(*in_range)) or 0
    total_alerts = db.scalar(select(func.count()).select_from(Alert).where(*real_alerts)) or 0
    is_fp = Alert.status == "false_positive"
    false_positives = db.scalar(
        select(func.count()).select_from(Alert).where(*alert_range, is_fp)
    ) or 0

    open_sev = dict(db.execute(
        select(Alert.severity, func.count())
        .where(Alert.status.in_(OPEN_STATUSES), *alert_range)
        .group_by(Alert.severity)
    ).all())

    # Aracı sunucu payı: IP bazlı tespitlerin ne kadar güvenilir olduğunu gösterir
    proxies = proxy_ips(load_config())
    is_proxy = ProxyMatcher(proxies)
    ip_counts = db.execute(
        select(Event.source_ip, func.count().label("n")).where(*in_range)
        .group_by(Event.source_ip).order_by(func.count().desc())
    ).all()
    top_ips = ip_counts[:8]
    via_proxy = sum(n for ip, n in ip_counts if is_proxy(ip))
    top_rules = db.execute(
        select(Alert.rule_id, func.count().label("n")).where(*real_alerts)
        .group_by(Alert.rule_id).order_by(func.count().desc())
    ).all()
    statuses = db.execute(
        select(Event.status_code, func.count()).where(*in_range).group_by(Event.status_code)
    ).all()
    classes: Counter[str] = Counter()
    for code, n in statuses:
        classes[f"{code // 100}xx"] += n
    types = db.execute(
        select(Event.event_type, func.count()).where(*in_range)
        .group_by(Event.event_type).order_by(func.count().desc())
    ).all()

    # Zaman çizelgesi: sadece zaman damgası sütunu okunur (hafif). Çok büyük veride SQL'de
    # gruplamak gerekir; SQLite ve PostgreSQL'in tarih fonksiyonları farklı olduğu için
    # taşınabilirlik adına şimdilik Python'da yapıyoruz.
    timeline: list[TimelineBucket] = []
    bucket = timedelta(minutes=60)
    epm = 0.0
    peak = 0
    if start and end and total_events:
        span = max(end - start, timedelta(minutes=1))
        bucket = pick_bucket(span)
        origin = floor_to(start, timedelta(days=1), datetime(2000, 1, 1, tzinfo=start.tzinfo))
        first = floor_to(start, bucket, origin)
        n_buckets = int((end - first) // bucket) + 1
        ev = [0] * n_buckets
        fails = [0] * n_buckets
        al = [0] * n_buckets
        per_minute: Counter[datetime] = Counter()
        for ts, etype in db.execute(select(Event.timestamp, Event.event_type).where(*in_range)):
            i = int((ts - first) // bucket)
            ev[i] += 1
            if etype in ("authentication_failure", "authentication_lockout"):
                fails[i] += 1
            per_minute[ts.replace(second=0, microsecond=0)] += 1
        for (ts,) in db.execute(select(Alert.first_seen).where(*real_alerts)):
            i = int((max(ts, first) - first) // bucket)
            if 0 <= i < n_buckets:
                al[i] += 1
        timeline = [
            TimelineBucket(start=first + i * bucket, events=ev[i], auth_failures=fails[i],
                           alerts=al[i])
            for i in range(n_buckets)
        ]
        epm = round(total_events / (span.total_seconds() / 60), 2)
        peak = max(per_minute.values(), default=0)

    recent = db.scalars(
        select(Alert).where(*real_alerts).order_by(Alert.last_seen.desc(), Alert.id.desc())
        .limit(8)
    )
    return Overview(
        range_start=start,
        range_end=end,
        bucket_minutes=int(bucket.total_seconds() // 60),
        total_events=total_events,
        total_alerts=total_alerts,
        false_positives=false_positives,
        proxy_ips=sorted(proxies),
        proxy_event_share=round(100 * via_proxy / total_events, 1) if total_events else 0.0,
        open_alerts_by_severity={s: open_sev.get(s, 0) for s in ("critical", "high", "medium",
                                                                   "low")},
        events_per_minute=epm,
        peak_events_per_minute=peak,
        top_ips=[Count(key=ip, count=n, proxy=is_proxy(ip))
                 for ip, n in top_ips],
        top_rules=[Count(key=r, count=n) for r, n in top_rules],
        status_classes=[Count(key=k, count=v) for k, v in sorted(classes.items())],
        event_types=[Count(key=t, count=n) for t, n in types],
        timeline=timeline,
        recent_alerts=[AlertOut.model_validate(a) for a in recent],
    )
