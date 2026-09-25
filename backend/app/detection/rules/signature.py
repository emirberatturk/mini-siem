from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.db.models import Event
from app.detection import sigma
from app.detection.base import (
    SEVERITIES,
    AlertCandidate,
    Rule,
    bursts,
    fetch_events,
    group_by_ip,
    summarize,
)


class WebAttackSignature(Rule):
    """Davranış kuralları "ne kadar/ne sıklıkla" sorar; bu kural isteğin İÇERİĞİNE bakar.
    Tek bir istekle yapılan saldırı (ör. SQL injection) hiçbir eşiği aşmadan geçebilir."""

    id = "SIG-001"
    title = "Web saldırı imzası"
    description = ("İstek, SigmaHQ topluluk kurallarındaki bilinen bir saldırı kalıbıyla "
                   "eşleşti (SQL injection, XSS, dizin gezinme…).")
    mitre = ["T1190"]  # kuralların çoğunun ortak tekniği; her alert kendi eşlemesini taşır
    # alert_on: "success" → yalnızca sunucu 2xx yanıt verdiyse (saldırı başarılı olmuş olabilir)
    # alarm üretilir; engellenen (3xx/4xx/5xx) denemeler olaylarda imza olarak görünür ama
    # alarm gürültüsü yaratmaz. "all" → her eşleşme alarm olur.
    defaults = {"window_minutes": 60, "alert_on": "success"}
    recommended_steps = [
        "Kanıttaki imza adlarına ve istenen yollara bak: hangi saldırı türü denenmiş?",
        "Yanıt kodlarına bak: 2xx dönen istek varsa saldırı başarılı olmuş olabilir; ilgili "
        "sayfanın kodunu ve sunucu hata loglarını incele.",
        "Hepsi 403/404 ise büyük olasılıkla otomatik bir tarayıcıdır; aynı IP'nin tarama "
        "(RECON) alarmları var mı?",
        "Aynı kalıp birden çok IP'den geliyorsa hosting/WAF tarafında engelleme düşün.",
        "Masum bir istekse (ör. arama kutusuna yazılmış metin) gerekçesiyle yanlış alarm kapat.",
    ]

    def evaluate(self, db: Session, start: datetime, end: datetime) -> list[AlertCandidate]:
        window = timedelta(minutes=self.config["window_minutes"])
        events = fetch_events(db, start - window, end, Event.signatures != "")
        known = sigma.rule_by_name()
        out = []
        for ip, evs in group_by_ip(events).items():
            for cluster in bursts(evs, window, 1):
                counts: Counter[str] = Counter()
                successes: Counter[str] = Counter()  # imza başına 2xx yanıt
                for e in cluster:
                    for n in filter(None, e.signatures.split(",")):
                        counts[n] += 1
                        successes[n] += 200 <= e.status_code < 300
                ok = sum(200 <= e.status_code < 300 for e in cluster)
                if ok == 0 and self.config["alert_on"] != "all":
                    continue  # hepsi engellenmiş: kayıtta kalır, alarm üretmez
                # Alarmın sebebi olan (başarılı yanıt alan) imza başlıkta önce gelsin
                names = sorted(counts, key=lambda n: (-successes[n], -counts[n]))
                matched = [known.get(n) for n in names]
                titles = [r.title if r else n for r, n in zip(matched, names, strict=True)]
                severity = max((r.level if r else "medium" for r in matched),
                               key=SEVERITIES.index)
                reason = (
                    f"{ip} adresinden {len(cluster)} istek bilinen saldırı kalıplarıyla "
                    f"eşleşti: {', '.join(titles)}. "
                    + (f"Sunucu bunların {ok} tanesine başarılı (2xx) yanıt verdi; incelenmeli."
                       if ok else "Sunucu hiçbirine başarılı yanıt vermedi.")
                    + self.proxy_note(ip)
                )
                out.append(AlertCandidate(
                    rule_id=self.id,
                    title=f"{self.title}: {titles[0]}"
                          + (f" (+{len(titles) - 1})" if len(titles) > 1 else ""),
                    severity=severity,
                    source_ip=ip,
                    first_seen=cluster[0].timestamp,
                    last_seen=cluster[-1].timestamp,
                    event_ids=[e.id for e in cluster],
                    reason=reason,
                    evidence={
                        "signatures": [
                            {"rule": n, "title": t, "count": counts[n], "success": successes[n],
                             "level": r.level if r else "medium"}
                            for n, t, r in zip(names, titles, matched, strict=True)
                        ],
                        "success_responses": ok,
                        **summarize(cluster),
                    },
                    recommended_steps=self.recommended_steps,
                    mitre=sorted({m for r in matched if r for m in r.mitre}) or self.mitre,
                ))
        return out
