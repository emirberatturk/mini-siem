"""Tespit kuralı arayüzü ve ortak yardımcılar.

Her kural aynı sözleşmeye uyar: bir zaman aralığı alır, AlertCandidate listesi döner.
Yeni kural eklemek = rules/ altına bir sınıf + registry'ye bir satır + testleri.
"""

from __future__ import annotations

import ipaddress
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import ClassVar

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Event

SEVERITIES = ("low", "medium", "high", "critical")


@dataclass
class AlertCandidate:
    rule_id: str
    title: str
    severity: str
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    event_ids: list[int]
    reason: str
    evidence: dict
    recommended_steps: list[str]
    mitre: list[str] = field(default_factory=list)


class ProxyMatcher:
    """Bir IP'nin yapılandırılmış aracı sunuculardan (tek IP veya ağ) biri olup olmadığı."""

    def __init__(self, proxies: frozenset[str] = frozenset()):
        self.networks = [ipaddress.ip_network(p, strict=False) for p in proxies]

    def __call__(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.networks)


class Rule(ABC):
    id: ClassVar[str]
    title: ClassVar[str]
    description: ClassVar[str]
    mitre: ClassVar[list[str]] = []
    recommended_steps: ClassVar[list[str]] = []
    defaults: ClassVar[dict] = {}
    # Hacim tabanlı kurallar (istek/404 sayar) aracı sunucu IP'lerinde anlamsızdır: o adres
    # bir kişi değil, binlerce ziyaretçinin ortak çıkış noktasıdır.
    volume_based: ClassVar[bool] = False

    def __init__(self, config: dict | None = None, proxies: frozenset[str] = frozenset()):
        self.config = {**self.defaults, **(config or {})}
        self.is_proxy = ProxyMatcher(proxies)

    def skip_ip(self, ip: str) -> bool:
        return self.volume_based and self.is_proxy(ip)

    def proxy_note(self, ip: str) -> str:
        return (" Not: kaynak adres bir aracı sunucu; gerçek istemci loglarda görünmüyor, "
                "aynı adresin arkasında farklı kişiler olabilir.") if self.is_proxy(ip) else ""

    @property
    def enabled(self) -> bool:
        return bool(self.config.get("enabled", True))

    @property
    def lookback(self) -> timedelta:
        """Aralığın başından ne kadar geriye bakılmalı (pencere taşmasın diye)."""
        return timedelta(minutes=self.config.get("window_minutes", 0))

    @abstractmethod
    def evaluate(self, db: Session, start: datetime, end: datetime) -> list[AlertCandidate]: ...


def fetch_events(db: Session, start: datetime, end: datetime, *conditions) -> list[Event]:
    q = (
        select(Event)
        .where(Event.timestamp >= start, Event.timestamp <= end, *conditions)
        .order_by(Event.source_ip, Event.timestamp, Event.id)
    )
    return list(db.scalars(q))


def group_by_ip(events: list[Event]) -> dict[str, list[Event]]:
    groups: dict[str, list[Event]] = {}
    for e in events:
        groups.setdefault(e.source_ip, []).append(e)
    return groups


def max_in_window(events: list[Event], window: timedelta) -> int:
    """Zamana göre sıralı olaylarda, herhangi bir 'window' süresine düşen en fazla olay sayısı."""
    best = left = 0
    for right, ev in enumerate(events):
        while ev.timestamp - events[left].timestamp > window:
            left += 1
        best = max(best, right - left + 1)
    return best


def bursts(events: list[Event], window: timedelta, threshold: int) -> list[list[Event]]:
    """Olayları 'window'dan uzun sessizliklerle ayrılmış kümelere böler;
    içinde eşiği aşan pencere olan kümeleri döner. (Bir saldırı = bir küme = bir alert.)"""
    clusters: list[list[Event]] = []
    current: list[Event] = []
    for ev in events:
        if current and ev.timestamp - current[-1].timestamp > window:
            clusters.append(current)
            current = []
        current.append(ev)
    if current:
        clusters.append(current)
    return [c for c in clusters if max_in_window(c, window) >= threshold]


def summarize(events: list[Event], max_items: int = 10) -> dict:
    """Alert kanıtı: analistin ilk bakışta görmesi gerekenler (veriler zaten maskeli)."""
    paths = Counter(e.url_path for e in events)
    return {
        "top_paths": [{"path": p, "count": c} for p, c in paths.most_common(max_items)],
        "unique_paths": len(paths),
        "status_codes": dict(Counter(str(e.status_code) for e in events).most_common()),
        "user_agents": [ua for ua, _ in Counter(e.user_agent for e in events).most_common(3)],
        "methods": dict(Counter(e.http_method or "?" for e in events)),
    }
