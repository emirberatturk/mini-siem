from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.db.models import Event
from app.detection.base import AlertCandidate, Rule, bursts, fetch_events, group_by_ip, summarize
from app.normalization.schema import EventType

FAILURE_TYPES = (EventType.AUTH_FAILURE.value, EventType.AUTH_LOCKOUT.value)


class AuthFailureBurst(Rule):
    id = "AUTH-001"
    title = "Başarısız giriş patlaması"
    description = "Aynı IP'den kısa sürede çok sayıda başarısız admin girişi."
    mitre = ["T1110.001"]  # Brute Force: Password Guessing
    defaults = {"window_minutes": 10, "threshold": 5, "high_threshold": 20}
    recommended_steps = [
        "IP'nin aynı dönemde başarılı bir girişi var mı kontrol et (CORR-001 alert'i?).",
        "Denemelerin tek hesaba mı, birden çok hesaba mı yapıldığını site loglarından doğrula.",
        "User-agent otomatik bir araç mı (curl, python-requests vb.)?",
        "Devam ediyorsa IP'yi hosting panelinden (Plesk) geçici olarak engellemeyi değerlendir.",
        "Admin şifrelerinin güçlü olduğundan ve iki faktörlü doğrulama seçeneğinden emin ol.",
    ]

    def evaluate(self, db: Session, start: datetime, end: datetime) -> list[AlertCandidate]:
        window = timedelta(minutes=self.config["window_minutes"])
        events = fetch_events(db, start - window, end, Event.event_type.in_(FAILURE_TYPES))
        out = []
        for ip, evs in group_by_ip(events).items():
            for cluster in bursts(evs, window, self.config["threshold"]):
                lockouts = sum(e.event_type == EventType.AUTH_LOCKOUT for e in cluster)
                failures = len(cluster) - lockouts
                high = len(cluster) >= self.config["high_threshold"] or lockouts > 0
                reason = (
                    f"{ip} adresinden {failures} başarısız giriş denemesi"
                    + (f" ve {lockouts} hesap kilidi yanıtı (429)" if lockouts else "")
                    + f"; en yoğun {self.config['window_minutes']} dakikada eşik "
                    f"({self.config['threshold']}) aşıldı." + self.proxy_note(ip)
                )
                out.append(AlertCandidate(
                    rule_id=self.id,
                    title="Olası brute-force saldırısı" if high else self.title,
                    severity="high" if high else "medium",
                    source_ip=ip,
                    first_seen=cluster[0].timestamp,
                    last_seen=cluster[-1].timestamp,
                    event_ids=[e.id for e in cluster],
                    reason=reason,
                    evidence={"failed_logins": failures, "lockouts": lockouts,
                              **summarize(cluster)},
                    recommended_steps=self.recommended_steps,
                    mitre=self.mitre,
                ))
        return out


class LoginAfterFailures(Rule):
    """Korelasyon: tek başına 'başarısız giriş' gürültüdür, 'başarılı giriş' normaldir.
    İkisi aynı IP'de art arda gelirse saldırının BAŞARILI olmuş olabileceğini gösterir."""

    id = "CORR-001"
    title = "Başarısız denemelerden sonra başarılı giriş"
    description = "Birden çok başarısız denemenin ardından aynı IP'den başarılı admin girişi."
    mitre = ["T1110", "T1078"]  # Brute Force → Valid Accounts
    defaults = {"lookback_minutes": 30, "min_failures": 3, "followup_minutes": 15}
    recommended_steps = [
        "ÖNCELİKLİ: Bu girişi hesap sahibi mi yaptı? Doktor/personelle hemen teyit et.",
        "Teyit edilemezse ilgili admin şifresini değiştir ve tüm oturumları sonlandır.",
        "Girişten sonraki admin erişimlerini incele (kanıttaki 'post_login' listesi): "
        "randevu/kullanıcı verisi görüntülendi mi?",
        "IP'yi engelle; aynı dönemde başka IP'lerden de benzer deneme var mı bak.",
        "Kişisel veri erişimi doğrulanırsa KVKK ihlal bildirimi sürecini değerlendir (72 saat).",
    ]

    @property
    def lookback(self) -> timedelta:
        return timedelta(minutes=self.config["lookback_minutes"])

    def evaluate(self, db: Session, start: datetime, end: datetime) -> list[AlertCandidate]:
        lookback = self.lookback
        follow = timedelta(minutes=self.config["followup_minutes"])
        successes = fetch_events(db, start, end,
                                 Event.event_type == EventType.AUTH_SUCCESS.value)
        out = []
        for ok in successes:
            failures = fetch_events(
                db, ok.timestamp - lookback, ok.timestamp,
                Event.source_ip == ok.source_ip, Event.event_type.in_(FAILURE_TYPES),
            )
            if len(failures) < self.config["min_failures"]:
                continue
            post = fetch_events(
                db, ok.timestamp, ok.timestamp + follow,
                Event.source_ip == ok.source_ip,
                Event.event_type == EventType.ADMIN_ACCESS.value,
            )
            minutes = (ok.timestamp - failures[0].timestamp).total_seconds() / 60
            out.append(AlertCandidate(
                rule_id=self.id,
                title=self.title,
                severity="critical",
                source_ip=ok.source_ip,
                first_seen=failures[0].timestamp,
                last_seen=post[-1].timestamp if post else ok.timestamp,
                event_ids=[e.id for e in failures] + [ok.id] + [e.id for e in post],
                reason=(
                    f"{ok.source_ip} adresi {minutes:.0f} dakika içinde {len(failures)} başarısız "
                    f"denemeden sonra başarılı giriş yaptı"
                    + (f" ve ardından {len(post)} admin isteği gönderdi." if post else ".")
                    + self.proxy_note(ok.source_ip)
                ),
                evidence={
                    "failed_before": len(failures),
                    "success_at": ok.timestamp.isoformat(),
                    "post_login": [
                        {"path": e.url_path, "query": e.url_query, "status": e.status_code}
                        for e in post[:20]
                    ],
                    "user_agents": sorted({e.user_agent for e in failures + [ok]})[:3],
                },
                recommended_steps=self.recommended_steps,
                mitre=self.mitre,
            ))
        return out


class AdminProbe(Rule):
    id = "ADMIN-001"
    title = "Yetkisiz admin erişim denemeleri"
    description = "Oturum olmadan admin API'lerine/sayfalarına tekrarlanan reddedilen istekler."
    defaults = {"window_minutes": 10, "threshold": 3}
    recommended_steps = [
        "Reddedilen isteklerin hangi admin API türlerine yapıldığına bak (kanıttaki yollar).",
        "Aynı IP'nin başarılı bir girişi var mı? Yoksa bu bir keşif/yoklama davranışıdır.",
        "Meşru bir kullanıcının oturumu süresi dolmuş olabilir: az sayıda ve tarayıcı UA'sı "
        "ise yanlış alarm olarak işaretlemeyi değerlendir.",
    ]

    def evaluate(self, db: Session, start: datetime, end: datetime) -> list[AlertCandidate]:
        window = timedelta(minutes=self.config["window_minutes"])
        events = fetch_events(
            db, start - window, end,
            Event.event_type == EventType.ADMIN_ACCESS.value,
            Event.status_code.in_((401, 403)),
        )
        out = []
        for ip, evs in group_by_ip(events).items():
            for cluster in bursts(evs, window, self.config["threshold"]):
                out.append(AlertCandidate(
                    rule_id=self.id,
                    title=self.title,
                    severity="medium",
                    source_ip=ip,
                    first_seen=cluster[0].timestamp,
                    last_seen=cluster[-1].timestamp,
                    event_ids=[e.id for e in cluster],
                    reason=(f"{ip} adresinin admin kaynaklarına yaptığı {len(cluster)} istek "
                            "yetkisiz olduğu için reddedildi (401/403)." + self.proxy_note(ip)),
                    evidence=summarize(cluster),
                    recommended_steps=self.recommended_steps,
                    mitre=self.mitre,
                ))
        return out


class UnknownDeviceLogin(Rule):
    """Başarılı admin girişi, bilinen cihazlardan biri değilse.

    Aracı sunucu yüzünden IP işe yaramadığında elde kalan sinyal cihaz/tarayıcı bilgisidir.
    User-agent taklit edilebilir; bu kural her saldırganı yakalamaz ama farklı bir
    bilgisayardan veya otomatik bir araçla yapılan girişleri yakalar.
    """

    id = "AUTH-002"
    title = "Tanınmayan cihazdan admin girişi"
    description = "Bilinen cihaz listesinde olmayan bir tarayıcı/cihazdan başarılı admin girişi."
    mitre = ["T1078"]  # Valid Accounts: geçerli kimlik bilgisiyle yapılmış giriş
    defaults = {"followup_minutes": 15, "known_devices": []}
    recommended_steps = [
        "ÖNCELİKLİ: Bu girişi sen mi yaptın? Yeni telefon/bilgisayar, farklı tarayıcı veya "
        "bir test aracı (curl vb.) olabilir.",
        "Sen değilsen: admin şifresini hemen değiştir ve açık oturumları sonlandır.",
        "Kanıttaki 'post_login' listesine bak: girişten sonra hangi admin verileri istendi?",
        "Yeni cihaz senin ise config/rules.yaml → AUTH-002 → known_devices listesine ekle.",
    ]

    def matches(self, ua: str) -> str | None:
        """Eşleşen bilinen cihazın adı; cihazın tüm ifadeleri UA'da geçmeli (sürüm yok)."""
        low = ua.casefold()
        for device in self.config["known_devices"]:
            if all(part.casefold() in low for part in device.get("match", [])):
                return device.get("name", "?")
        return None

    def evaluate(self, db: Session, start: datetime, end: datetime) -> list[AlertCandidate]:
        if not self.config["known_devices"]:
            return []  # "normal" tanımlanmadan "anormal" söylenemez
        follow = timedelta(minutes=self.config["followup_minutes"])
        out = []
        for ok in fetch_events(db, start, end, Event.event_type == EventType.AUTH_SUCCESS.value):
            if self.matches(ok.user_agent):
                continue
            post = fetch_events(
                db, ok.timestamp, ok.timestamp + follow,
                Event.source_ip == ok.source_ip,
                Event.event_type == EventType.ADMIN_ACCESS.value,
            )
            out.append(AlertCandidate(
                rule_id=self.id,
                title=self.title,
                severity="high",
                source_ip=ok.source_ip,
                first_seen=ok.timestamp,
                last_seen=post[-1].timestamp if post else ok.timestamp,
                event_ids=[ok.id] + [e.id for e in post],
                reason=(f"Admin paneline bilinen cihazların hiçbirine uymayan bir tarayıcıdan "
                        f"başarılı giriş yapıldı: \"{ok.user_agent[:120]}\"."
                        + self.proxy_note(ok.source_ip)),
                evidence={
                    "user_agent": ok.user_agent,
                    "known_devices": [d.get("name", "?") for d in self.config["known_devices"]],
                    "post_login": [
                        {"path": e.url_path, "query": e.url_query, "status": e.status_code}
                        for e in post[:20]
                    ],
                },
                recommended_steps=self.recommended_steps,
                mitre=self.mitre,
            ))
        return out
