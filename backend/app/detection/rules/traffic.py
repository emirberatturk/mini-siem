from __future__ import annotations

import math
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.db.models import Event
from app.detection.base import (
    AlertCandidate,
    Rule,
    bursts,
    fetch_events,
    group_by_ip,
    max_in_window,
    summarize,
)


class Excessive404(Rule):
    id = "RECON-001"
    title = "Aşırı 404 yanıtı"
    description = "Aynı IP'den kısa sürede çok sayıda 'bulunamadı' yanıtı."
    mitre = ["T1595.003"]  # Active Scanning: Wordlist Scanning (yalnızca tarama tespitinde)
    volume_based = True
    defaults = {"window_minutes": 5, "threshold": 20, "scan_unique_paths": 15}
    recommended_steps = [
        "Kanıttaki yollara bak: var olmayan yönetim panelleri, yedek/yapılandırma dosyaları "
        "aranıyorsa bu otomatik bir taramadır.",
        "Aynı IP'nin 200 aldığı istekler var mı? Tarama bir şey bulmuş olabilir (Olay Arama'da "
        "IP'ye göre filtrele).",
        "User-agent bir arama motoru botu gibi görünse bile doğrulanmadan güvenilmemeli: "
        "UA başlığı istemci tarafından serbestçe yazılır.",
        "Tek başına düşük risklidir; başka alert'lerle aynı IP'de birleşiyorsa önceliği artır.",
    ]

    def evaluate(self, db: Session, start: datetime, end: datetime) -> list[AlertCandidate]:
        window = timedelta(minutes=self.config["window_minutes"])
        events = fetch_events(db, start - window, end, Event.status_code == 404)
        out = []
        for ip, evs in group_by_ip(events).items():
            if self.skip_ip(ip):
                continue
            for cluster in bursts(evs, window, self.config["threshold"]):
                ev = summarize(cluster)
                scan = ev["unique_paths"] >= self.config["scan_unique_paths"]
                out.append(AlertCandidate(
                    rule_id=self.id,
                    title="Olası dizin/dosya taraması" if scan else self.title,
                    severity="medium" if scan else "low",
                    source_ip=ip,
                    first_seen=cluster[0].timestamp,
                    last_seen=cluster[-1].timestamp,
                    event_ids=[e.id for e in cluster],
                    reason=(
                        f"{ip} adresi {len(cluster)} istekte 404 aldı; "
                        f"{ev['unique_paths']} farklı yol denendi."
                        + (" Çok sayıda farklı yol, bir kelime listesiyle tarama yapıldığına "
                           "işaret eder." if scan else "")
                    ),
                    evidence=ev,
                    recommended_steps=self.recommended_steps,
                    # Sadece gerçekten "çok farklı yol" varsa Wordlist Scanning deriz
                    mitre=self.mitre if scan else [],
                ))
        return out


class HighRequestRate(Rule):
    id = "RATE-001"
    title = "Anormal istek hızı"
    description = "Tek bir IP'den dakikada eşiği aşan sayıda istek."
    volume_based = True
    defaults = {"window_minutes": 1, "threshold": 120}
    recommended_steps = [
        "IP'nin hangi yollara istek attığına bak: tek sayfaya mı (flood), çok sayfaya mı "
        "(crawler/scraper)?",
        "Aynı dönemde sitede yavaşlama ya da 5xx hatası artışı var mı?",
        "Meşru bir arama motoru botu olabilir; UA'ya değil, IP'nin sahibine (reverse DNS) bak.",
    ]

    def evaluate(self, db: Session, start: datetime, end: datetime) -> list[AlertCandidate]:
        window = timedelta(minutes=self.config["window_minutes"])
        events = fetch_events(db, start - window, end)
        out = []
        for ip, evs in group_by_ip(events).items():
            if self.skip_ip(ip):
                continue
            for cluster in bursts(evs, window, self.config["threshold"]):
                peak = max_in_window(cluster, window)
                out.append(AlertCandidate(
                    rule_id=self.id,
                    title=self.title,
                    severity="low",
                    source_ip=ip,
                    first_seen=cluster[0].timestamp,
                    last_seen=cluster[-1].timestamp,
                    event_ids=[e.id for e in cluster],
                    reason=(f"{ip} adresinden {self.config['window_minutes']} dakikada en fazla "
                            f"{peak} istek geldi (eşik {self.config['threshold']})."),
                    evidence={"peak_per_window": peak, "total": len(cluster), **summarize(cluster)},
                    recommended_steps=self.recommended_steps,
                    mitre=self.mitre,
                ))
        return out


class PersistentProbe(Rule):
    """'Low and slow': eşiklerin altında kalmak için yavaş ama günlerce süren tekrar.

    Kısa pencereli kurallar (RECON-001: 5 dk'da 20) bunu görmez; burada aynı IP'nin aynı
    var olmayan yolu uzun bir pencerede kaç kez istediğine bakılır.
    """

    id = "RECON-002"
    title = "Israrlı yoklama (düşük ve yavaş)"
    description = "Aynı IP'nin var olmayan aynı yolu uzun süre boyunca tekrar tekrar istemesi."
    volume_based = True
    defaults = {"window_minutes": 1440, "threshold": 10}
    recommended_steps = [
        "İstenen yola bak: sitede gerçekten olmayan bir yazılımı (ör. başka bir CMS'in kurulum "
        "sayfasını) arıyorsa bu otomatik bir bottur ve hedefli değildir.",
        "Aynı IP'nin 200 aldığı istek var mı? Yoksa şu an bir risk oluşturmuyor.",
        "Uzun süredir devam ediyorsa IP'yi (veya sabit user-agent'ı) hosting/WAF tarafında "
        "engellemek log gürültüsünü azaltır.",
    ]

    def evaluate(self, db: Session, start: datetime, end: datetime) -> list[AlertCandidate]:
        window = timedelta(minutes=self.config["window_minutes"])
        events = fetch_events(db, start - window, end, Event.status_code == 404)
        out = []
        for ip, evs in group_by_ip(events).items():
            if self.skip_ip(ip):
                continue
            by_path: dict[str, list[Event]] = {}
            for e in evs:
                by_path.setdefault(e.url_path, []).append(e)
            for path, path_events in by_path.items():
                for cluster in bursts(path_events, window, self.config["threshold"]):
                    # Takvim günü saymak saat dilimine bağlıdır (UTC'de 4, TR'de 3 gün olabilir);
                    # ilk ve son görülme arasındaki süre tutarlı bir ölçü.
                    span = cluster[-1].timestamp - cluster[0].timestamp
                    days = max(1, math.ceil(span / timedelta(days=1)))
                    out.append(AlertCandidate(
                        rule_id=self.id,
                        title=self.title,
                        severity="low",
                        source_ip=ip,
                        first_seen=cluster[0].timestamp,
                        last_seen=cluster[-1].timestamp,
                        event_ids=[e.id for e in cluster],
                        reason=(f"{ip} adresi var olmayan {path} yolunu {days} gün boyunca "
                                f"{len(cluster)} kez istedi (günde ortalama "
                                f"{len(cluster) / days:.0f})."),
                        evidence={"path": path, "days_active": days, "total": len(cluster),
                                  **summarize(cluster)},
                        recommended_steps=self.recommended_steps,
                        mitre=self.mitre,
                    ))
        return out
