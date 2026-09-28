from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.db.models import Event
from app.detection.base import AlertCandidate, Rule, bursts, fetch_events, group_by_ip, summarize

KIND_LABEL = {"uzunluk": "beklenenden uzun", "karakter": "beklenmeyen karakter",
              "parametre": "bilinmeyen parametre"}


def describe(finding: str) -> str:
    name, _, kind = finding.rpartition(":")
    return f"{name} ({KIND_LABEL.get(kind, kind)})"


class ParameterAnomaly(Rule):
    """İmzalar bilinen kalıpları arar; bu kural öğrenilmiş "normal"den sapan parametre
    değerlerini işaretler (parametre kurcalama). İmzanın zaten yakaladığı istekler burada
    tekrar alarm üretmez."""

    id = "ANOM-001"
    title = "Anormal parametre değeri"
    description = ("Bir sayfanın parametresine, o parametre için öğrenilmiş normalden sapan bir "
                   "değer gönderildi (çok uzun ya da beklenmeyen karakterli).")
    # MITRE eşlemesi yok: "değer normalden sapıyor" tek başına belirli bir teknik değildir
    mitre: list[str] = []
    defaults = {"window_minutes": 60, "alert_on": "success"}
    recommended_steps = [
        "Kanıttaki parametre ve sapma türüne bak: hangi sayfaya, nasıl bir değer gitmiş?",
        "Olay aramasında bu isteği bul: maskelenmemiş kısımlarda saldırı izi var mı?",
        "Sunucu 2xx döndüyse sayfanın bu değeri nasıl işlediğini (doğrulama var mı?) incele; "
        "yanıt boyutunu aynı sayfanın normal yanıtlarıyla karşılaştır.",
        "Normal ama nadir bir değerse (uzun bir isim gibi) gerekçesiyle yanlış alarm kapat; "
        "sık oluyorsa anomali profilini yeniden eğit.",
    ]

    def evaluate(self, db: Session, start: datetime, end: datetime) -> list[AlertCandidate]:
        window = timedelta(minutes=self.config["window_minutes"])
        events = fetch_events(db, start - window, end, Event.anomalies != "",
                              Event.signatures == "")
        out = []
        for ip, evs in group_by_ip(events).items():
            for cluster in bursts(evs, window, 1):
                ok = sum(200 <= e.status_code < 300 for e in cluster)
                if ok == 0 and self.config["alert_on"] != "all":
                    continue  # hepsi reddedilmiş: olaylarda görünür, alarm üretmez
                counts: Counter[str] = Counter()
                successes: Counter[str] = Counter()
                for e in cluster:
                    for f in filter(None, e.anomalies.split(",")):
                        counts[f] += 1
                        successes[f] += 200 <= e.status_code < 300
                findings = sorted(counts, key=lambda f: (-successes[f], -counts[f]))
                reason = (
                    f"{ip} adresinden {len(cluster)} istekte parametre değerleri öğrenilmiş "
                    f"normalden saptı: {', '.join(describe(f) for f in findings)}. "
                    + (f"Sunucu bunların {ok} tanesine başarılı (2xx) yanıt verdi; incelenmeli."
                       if ok else "Sunucu hiçbirine başarılı yanıt vermedi.")
                    + self.proxy_note(ip)
                )
                out.append(AlertCandidate(
                    rule_id=self.id,
                    title=f"{self.title}: {describe(findings[0])}"
                          + (f" (+{len(findings) - 1})" if len(findings) > 1 else ""),
                    severity="medium" if ok else "low",
                    source_ip=ip,
                    first_seen=cluster[0].timestamp,
                    last_seen=cluster[-1].timestamp,
                    event_ids=[e.id for e in cluster],
                    reason=reason,
                    evidence={
                        "anomalies": [{"finding": f, "title": describe(f), "count": counts[f],
                                       "success": successes[f]} for f in findings],
                        "success_responses": ok,
                        **summarize(cluster),
                    },
                    recommended_steps=self.recommended_steps,
                    mitre=[],
                ))
        return out
