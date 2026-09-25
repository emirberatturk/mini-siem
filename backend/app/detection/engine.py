"""Tespit motoru: kuralları çalıştırır, adayları alert'e dönüştürür, tekilleştirir."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import yaml
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Alert, AlertEvent, AlertHistory, Event
from app.detection.base import SEVERITIES, AlertCandidate, Rule
from app.detection.rules.auth import (
    AdminProbe,
    AuthFailureBurst,
    LoginAfterFailures,
    UnknownDeviceLogin,
)
from app.detection.rules.traffic import Excessive404, HighRequestRate, PersistentProbe

RULE_CLASSES: list[type[Rule]] = [
    AuthFailureBurst,
    LoginAfterFailures,
    UnknownDeviceLogin,
    AdminProbe,
    Excessive404,
    PersistentProbe,
    HighRequestRate,
]

OPEN_STATUSES = ("new", "investigating", "confirmed")
# Aynı IP+kural için son aktiviteden bu kadar sonra gelen olay YENİ bir saldırı sayılır
MERGE_GAP = timedelta(hours=1)
_CHUNK = 500


def _read_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    # safe_load: yaml.load() dosyadaki etiketlerle Python nesnesi (ve kod) çalıştırabilir
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def load_config(path: Path | None = None) -> dict:
    """rules.yaml + varsa rules.local.yaml (siteye özel, git'e girmeyen ayarlar).

    Yerel dosya üstüne yazar: kural başına alanlar birleşir, diğer anahtarlar değiştirilir.
    """
    path = path or settings.rules_config
    config = _read_yaml(path)
    local = path.with_name(f"{path.stem}.local{path.suffix}")
    if settings.use_local_config:
        for key, value in _read_yaml(local).items():
            if isinstance(value, dict) and isinstance(config.get(key), dict):
                config[key] = {**config[key], **value}
            else:
                config[key] = value
    return config


def proxy_ips(config: dict) -> frozenset[str]:
    return frozenset(str(p) for p in config.get("proxy_ips") or [])


def load_rules(path: Path | None = None) -> list[Rule]:
    config = load_config(path)
    proxies = proxy_ips(config)
    return [cls(config.get(cls.id), proxies) for cls in RULE_CLASSES]


@dataclass
class DetectionResult:
    created: int = 0
    updated: int = 0


def _linked_event_ids(db: Session, rule_id: str, event_ids: list[int]) -> set[int]:
    linked: set[int] = set()
    for i in range(0, len(event_ids), _CHUNK):
        linked.update(db.scalars(
            select(AlertEvent.event_id)
            .join(Alert, Alert.id == AlertEvent.alert_id)
            .where(Alert.rule_id == rule_id, AlertEvent.event_id.in_(event_ids[i:i + _CHUNK]))
        ))
    return linked


def _worse(a: str, b: str) -> str:
    return max(a, b, key=SEVERITIES.index)


def upsert_alert(db: Session, cand: AlertCandidate) -> str | None:
    """'created' / 'updated' / None (bu olaylar bu kural için zaten bir alert'e bağlı)."""
    linked = _linked_event_ids(db, cand.rule_id, cand.event_ids)
    new_ids = [i for i in dict.fromkeys(cand.event_ids) if i not in linked]
    if not new_ids:
        return None  # aynı veri tekrar tarandı: kapatılmış alert'ler de yeniden açılmaz

    alert = db.scalar(
        select(Alert)
        .where(Alert.rule_id == cand.rule_id, Alert.source_ip == cand.source_ip,
               Alert.status.in_(OPEN_STATUSES))
        .order_by(Alert.last_seen.desc())
    )
    if alert is None or cand.first_seen - alert.last_seen > MERGE_GAP:
        alert = Alert(
            rule_id=cand.rule_id, title=cand.title, severity=cand.severity, status="new",
            source_ip=cand.source_ip, first_seen=cand.first_seen, last_seen=cand.last_seen,
            reason=cand.reason, evidence=cand.evidence,
            recommended_steps=cand.recommended_steps, mitre=sorted(set(cand.mitre)),
        )
        db.add(alert)
        db.flush()
        db.add(AlertHistory(alert_id=alert.id, from_status=None, to_status="new",
                            changed_by="sistem", note=f"{cand.rule_id} kuralı tarafından"))
        outcome = "created"
    else:
        # Tekilleştirme: aynı saldırının devamı → mevcut alert büyür, yeni alert açılmaz
        if SEVERITIES.index(cand.severity) > SEVERITIES.index(alert.severity):
            alert.title = cand.title
        alert.severity = _worse(alert.severity, cand.severity)
        alert.first_seen = min(alert.first_seen, cand.first_seen)
        alert.last_seen = max(alert.last_seen, cand.last_seen)
        alert.reason, alert.evidence = cand.reason, cand.evidence
        alert.mitre = sorted(set(alert.mitre) | set(cand.mitre))
        outcome = "updated"

    db.add_all(AlertEvent(alert_id=alert.id, event_id=i) for i in new_ids)
    db.flush()
    alert.event_count = db.scalar(
        select(func.count()).select_from(AlertEvent).where(AlertEvent.alert_id == alert.id)
    ) or 0
    return outcome


def run_detection(db: Session, start: datetime, end: datetime,
                  rules: list[Rule] | None = None) -> DetectionResult:
    result = DetectionResult()
    for rule in rules if rules is not None else load_rules():
        if not rule.enabled:
            continue
        for cand in rule.evaluate(db, start, end):
            outcome = upsert_alert(db, cand)
            if outcome == "created":
                result.created += 1
            elif outcome == "updated":
                result.updated += 1
    db.commit()
    return result


def run_on_all(db: Session) -> DetectionResult:
    lo, hi = db.execute(select(func.min(Event.timestamp), func.max(Event.timestamp))).one()
    if lo is None:
        return DetectionResult()
    return run_detection(db, lo, hi)
