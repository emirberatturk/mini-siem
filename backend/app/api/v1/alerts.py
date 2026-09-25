from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.alerts.workflow import AlertStatus, TransitionError, check_transition
from app.api.v1.events import EventOut, as_utc
from app.db.models import Alert, AlertEvent, AlertHistory, Event
from app.db.session import get_session
from app.detection import sigma
from app.detection.engine import OPEN_STATUSES, load_rules, run_on_all

router = APIRouter(tags=["alerts"])
DB = Annotated[Session, Depends(get_session)]


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: str
    title: str
    severity: str
    status: str
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    reason: str
    evidence: dict
    recommended_steps: list[str]
    mitre: list[str]
    created_at: datetime
    updated_at: datetime


class HistoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    from_status: str | None
    to_status: str
    note: str
    changed_by: str
    changed_at: datetime


class AlertDetail(AlertOut):
    history: list[HistoryOut]
    events: list[EventOut]


class AlertPage(BaseModel):
    total: int
    items: list[AlertOut]


class StatusChange(BaseModel):
    status: AlertStatus
    note: str = Field(default="", max_length=2000)


class SignatureRuleOut(BaseModel):
    name: str
    title: str
    level: str
    mitre: list[str]
    author: str


class RuleOut(BaseModel):
    id: str
    title: str
    description: str
    enabled: bool
    config: dict
    mitre: list[str]
    alert_count: int
    open_alert_count: int
    skips_proxies: bool  # hacim tabanlı: aracı sunucu IP'lerinde çalışmaz
    known_devices: list[str] = []  # AUTH-002: tanınan cihaz adları
    alert_on: str | None = None  # SIG-001: "success" (yalnızca 2xx) veya "all"
    signature_rules: list[SignatureRuleOut] = []  # SIG-001: yüklü Sigma kuralları


@router.get("/alerts")
def list_alerts(
    db: DB,
    severity: Annotated[list[str] | None, Query()] = None,
    status_: Annotated[list[str] | None, Query(alias="status")] = None,
    rule_id: str | None = None,
    ip: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AlertPage:
    q = select(Alert)
    if severity:
        q = q.where(Alert.severity.in_(severity))
    if status_:
        q = q.where(Alert.status.in_(status_))
    if rule_id:
        q = q.where(Alert.rule_id == rule_id)
    if ip:
        q = q.where(Alert.source_ip == ip.strip())
    if since:
        q = q.where(Alert.last_seen >= as_utc(since))
    if until:
        q = q.where(Alert.first_seen <= as_utc(until))

    total = db.scalar(select(func.count()).select_from(q.subquery())) or 0
    newest_first = q.order_by(Alert.last_seen.desc(), Alert.id.desc())
    rows = db.scalars(newest_first.limit(limit).offset(offset))
    return AlertPage(total=total, items=[AlertOut.model_validate(r) for r in rows])


def _get(db: Session, alert_id: int) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert bulunamadı")
    return alert


def _detail(db: Session, alert: Alert) -> AlertDetail:
    history = db.scalars(
        select(AlertHistory).where(AlertHistory.alert_id == alert.id).order_by(AlertHistory.id)
    )
    events = db.scalars(
        select(Event)
        .join(AlertEvent, AlertEvent.event_id == Event.id)
        .where(AlertEvent.alert_id == alert.id)
        .order_by(Event.timestamp, Event.id)
        .limit(200)
    )
    return AlertDetail(
        **AlertOut.model_validate(alert).model_dump(),
        history=[HistoryOut.model_validate(h) for h in history],
        events=[EventOut.model_validate(e) for e in events],
    )


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: int, db: DB) -> AlertDetail:
    return _detail(db, _get(db, alert_id))


@router.patch("/alerts/{alert_id}")
def change_status(alert_id: int, change: StatusChange, db: DB) -> AlertDetail:
    alert = _get(db, alert_id)
    try:
        check_transition(alert.status, change.status, change.note)
    except TransitionError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    db.add(AlertHistory(alert_id=alert.id, from_status=alert.status, to_status=change.status,
                        note=change.note.strip()))
    alert.status = change.status
    db.commit()
    return _detail(db, alert)


@router.get("/rules")
def list_rules(db: DB) -> list[RuleOut]:
    counts = dict(db.execute(select(Alert.rule_id, func.count()).group_by(Alert.rule_id)).all())
    open_counts = dict(db.execute(
        select(Alert.rule_id, func.count())
        .where(Alert.status.in_(OPEN_STATUSES))
        .group_by(Alert.rule_id)
    ).all())
    return [
        RuleOut(
            id=r.id, title=r.title, description=r.description, enabled=r.enabled,
            config={k: v for k, v in r.config.items() if isinstance(v, int | float)
                    and not isinstance(v, bool)},
            mitre=sorted(r.mitre),
            alert_count=counts.get(r.id, 0), open_alert_count=open_counts.get(r.id, 0),
            skips_proxies=r.volume_based,
            known_devices=[d.get("name", "?") for d in r.config.get("known_devices", [])],
            alert_on=r.config.get("alert_on"),
            signature_rules=[
                SignatureRuleOut(name=s.name, title=s.title, level=s.level, mitre=s.mitre,
                                 author=s.author)
                for s in sigma.default_rules()
            ] if r.id == "SIG-001" else [],
        )
        for r in load_rules()
    ]


@router.post("/detection/run")
def rerun_detection(db: DB) -> dict:
    """Tüm olaylar üzerinde kuralları yeniden çalıştırır (ör. rules.yaml değiştikten sonra)."""
    result = run_on_all(db)
    return {"created": result.created, "updated": result.updated}
