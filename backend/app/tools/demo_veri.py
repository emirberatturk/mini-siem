"""SIEM'i gerçek log OLMADAN denemek için sahte demo veritabanı (tanıtım görselleri de bundan).

Hiçbir gerçek log, IP ya da site bilgisi kullanılmaz:
- IP'ler RFC 5737 belge aralıklarındandır (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24):
  internette kimseye atanmaz.
- Site profili repodaki ÖRNEK profildir: yerel (gerçek) ayarlar bu araçta kapatılır ve
  bu denetlenir.

Üç haftalık normal trafik + gerçek veride görülen saldırı türleri (tarama, brute-force,
başarısız denemelerden sonra başarılı giriş, yetkisiz admin isteği, SQL injection, dizin gezinme,
"low and slow" bot, hızlı tarayıcı), "demo" (yönetici) ve "analist" kullanıcıları, bazı
alarmlarda analist kararları.

Kullanım (backend klasöründe):
    .venv\\Scripts\\python.exe -m app.tools.demo_veri data\\demo.db
    $env:SIEM_DATABASE_URL = "sqlite:///data/demo.db"; $env:SIEM_USE_LOCAL_CONFIG = "false"
    .venv\\Scripts\\python.exe -m uvicorn app.main:app --port 8001
Şifreler `<veritabani>.giris.json` dosyasına yazılır. Kullanıcılar ilk girişte telefonlarını
tanıtır (iki adımlı doğrulama); otomasyon için `--totp` sabit bir anahtar kurar ve dosyaya yazar.
"""

from __future__ import annotations

import os

# Uygulama modüllerinden ÖNCE: site profili içe aktarılırken okunur (gerçek profil karışmasın)
os.environ["SIEM_USE_LOCAL_CONFIG"] = "false"

import argparse  # noqa: E402
import json  # noqa: E402
import random  # noqa: E402
import secrets  # noqa: E402
from datetime import UTC, datetime, timedelta  # noqa: E402
from pathlib import Path  # noqa: E402

from sqlalchemy import select  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.core import mfa  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.db.models import Alert, AlertHistory, User  # noqa: E402
from app.db.repository import save_batch  # noqa: E402
from app.db.session import init_db, make_engine  # noqa: E402
from app.detection.engine import run_detection  # noqa: E402
from app.ingestion.pipeline import process_lines  # noqa: E402
from app.tools import users  # noqa: E402

BASLANGIC = datetime(2026, 9, 21)
TZ = "+0300"
TARAYICILAR = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/141.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 15; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/141.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/18.6 Safari/605.1.15",
]
SAYFALAR = [
    "/",
    "/hizmetler.html",
    "/hakkimizda.html",
    "/iletisim.html",
    "/randevu.html",
    "/blog.html",
]
DOSYALAR = ["/style.css", "/script.js", "/images/klinik.webp", "/images/ekip.webp", "/favicon.ico"]
TARAMA_YOLLARI = [
    "/admin.php",
    "/phpmyadmin/",
    "/.git/HEAD",
    "/server-status",
    "/config.php",
    "/backup.tar.gz",
    "/wp-config.php.bak",
    "/.DS_Store",
    "/actuator/health",
    "/cgi-bin/test.cgi",
    "/console/",
    "/.svn/entries",
    "/install.php",
    "/xmlrpc.php",
    "/vendor/phpunit/",
    "/storage/logs/laravel.log",
    "/.htaccess",
    "/test.php",
    "/info.php",
    "/old/",
    "/uploads/",
    "/api/v1/users",
    "/swagger.json",
    "/graphql",
    "/debug/",
    "/.idea/",
    "/composer.json",
    "/package.json",
    "/docker-compose.yml",
    "/.travis.yml",
    "/web.config",
    "/sitemap.old.xml",
    "/temp/",
    "/admin/config.php",
    "/login.php",
    "/shell.php",
    "/cmd.php",
    "/upload.php",
    "/db/",
    "/sql/",
    "/dump.sql",
    "/site.zip",
    "/.npmrc",
    "/id_rsa",
    "/.bash_history",
]
KARARLAR = {  # kural → (son durum, analist notu); CORR-001 ve SQLi imzası bilerek açık kalır
    "RECON-002": (
        "resolved",
        "Aynı bot haftalardır /wp-admin/install.php arıyor; site WordPress değil, hepsi 404. "
        "Etki yok.",
    ),
    "RECON-001": (
        "resolved",
        "Nmap ile otomatik tarama; yolların hepsi 404. Gizli dosya yok, etki yok.",
    ),
    "AUTH-001": (
        "resolved",
        "Brute-force; hesap kilidi devreye girdi, başarılı giriş yok. IP engellendi.",
    ),
    "ADMIN-001": (
        "false_positive",
        "Yöneticinin oturumu süresi dolmuş sekmesi; tekrar giriş yapınca düzeldi.",
    ),
    "RATE-001": (
        "false_positive",
        "Arama motoru benzeri tarayıcı; yalnızca herkese açık sayfalar.",
    ),
}


def log_satirlari(gun: int = 24, tohum: int = 2026) -> list[str]:
    """Apache Combined biçiminde sahte trafik (zamana göre sıralı)."""
    rnd = random.Random(tohum)  # noqa: S311  (sahte trafik; tekrarlanabilir olsun diye sabit tohum)
    satirlar: list[str] = []

    def log(ts, ip, yontem, yol, kod, boyut, ua, ref="-"):
        satirlar.append(
            f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S")} {TZ}] "{yontem} {yol} HTTP/1.1" '
            f'{kod} {boyut} "{ref}" "{ua}"'
        )

    for g in range(gun):
        gun_basi = BASLANGIC + timedelta(days=g)
        for _ in range(rnd.randint(55, 95) + (25 if gun_basi.weekday() < 5 else 0)):  # ziyaretçiler
            ip, ua = f"198.51.100.{rnd.randint(2, 240)}", rnd.choice(TARAYICILAR)
            t = gun_basi + timedelta(
                hours=rnd.choice(range(8, 23)),
                minutes=rnd.randint(0, 59),
                seconds=rnd.randint(0, 59),
            )
            for sayfa in rnd.sample(SAYFALAR, rnd.randint(1, 4)):
                log(t, ip, "GET", sayfa, 200, rnd.randint(18_000, 36_000), ua)
                for dosya in rnd.sample(DOSYALAR, 3):
                    log(
                        t + timedelta(seconds=1),
                        ip,
                        "GET",
                        dosya,
                        200,
                        rnd.randint(2_000, 90_000),
                        ua,
                        sayfa,
                    )
                log(
                    t + timedelta(seconds=1),
                    ip,
                    "GET",
                    "/app.php?type=yorumlar",
                    200,
                    8_900,
                    ua,
                    sayfa,
                )
                t += timedelta(seconds=rnd.randint(20, 140))
            if rnd.random() < 0.08:  # randevu formu: kişisel veri alanları kayıtta maskelenir
                log(
                    t,
                    ip,
                    "GET",
                    "/app.php?type=randevu_olustur&ad=Ayse&tel=05551234567",
                    200,
                    400,
                    ua,
                )
            if rnd.random() < 0.05:
                log(t, ip, "GET", "/eski-sayfa.html", 404, 820, ua)
        if gun_basi.weekday() < 6:  # site yöneticisi her gün panele bakar
            t, yonetici = gun_basi + timedelta(hours=9, minutes=rnd.randint(0, 40)), "192.0.2.10"
            log(t, yonetici, "GET", "/admin/giris.html", 200, 3_100, TARAYICILAR[0])
            log(
                t + timedelta(seconds=20),
                yonetici,
                "POST",
                "/app.php?type=login",
                200,
                450,
                TARAYICILAR[0],
            )
            for api in ("randevu_listesi", "users", "randevu_listesi"):
                t += timedelta(minutes=rnd.randint(1, 9))
                log(
                    t,
                    yonetici,
                    "GET",
                    f"/app.php?type={api}",
                    200,
                    2_400,
                    TARAYICILAR[0],
                    "/admin/",
                )
        for _ in range(rnd.randint(25, 60)):  # arka plan: gizli dosya arayan botlar (engelli)
            yol = rnd.choice(
                [
                    "/.env",
                    "/.env.backup",
                    "/api/.env",
                    "/.git/config",
                    "/backup.zip",
                    "/db.sql",
                    "/.aws/credentials",
                    "/wp-login.php",
                ]
            )
            log(
                gun_basi + timedelta(minutes=rnd.randint(0, 1439)),
                f"203.0.113.{rnd.randint(130, 250)}",
                "GET",
                yol,
                403 if ".env" in yol or ".git" in yol else 404,
                820,
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
            )
        for _ in range(rnd.randint(11, 14)):  # "low and slow": aynı yol, her gün (RECON-002)
            log(
                gun_basi + timedelta(minutes=rnd.randint(0, 1439)),
                "192.0.2.44",
                "GET",
                "/wp-admin/install.php",
                404,
                820,
                "http://ornek-klinik.example/wp-admin/install.php?step=1",
            )

    def an(ay, gun_, saat, dk=0):
        return datetime(2026, ay, gun_, saat, dk)

    for i, yol in enumerate(TARAMA_YOLLARI):  # tarama: 2 dakikada 45 yol, Nmap imzası
        log(
            an(10, 7, 3, 12) + timedelta(seconds=i * 2.5),
            "203.0.113.9",
            "GET",
            yol,
            404,
            820,
            "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
        )
    for i in range(22):  # brute-force, sonra hesap kilidi
        log(
            an(10, 9, 2, 14) + timedelta(seconds=i * 15),
            "203.0.113.50",
            "POST",
            "/app.php?type=login",
            401,
            380,
            "python-requests/2.32.3",
        )
    for i in range(6):
        log(
            an(10, 9, 2, 20) + timedelta(seconds=i * 20),
            "203.0.113.50",
            "POST",
            "/app.php?type=login",
            429,
            300,
            "python-requests/2.32.3",
        )
    t = an(10, 11, 23, 41)  # korelasyon: yanlış şifrelerden sonra başarılı giriş ve admin erişimi
    for i in range(4):
        log(
            t + timedelta(seconds=i * 30),
            "203.0.113.77",
            "POST",
            "/app.php?type=login",
            401,
            380,
            TARAYICILAR[0],
        )
    log(
        t + timedelta(minutes=3),
        "203.0.113.77",
        "POST",
        "/app.php?type=login",
        200,
        450,
        TARAYICILAR[0],
    )
    log(
        t + timedelta(minutes=4),
        "203.0.113.77",
        "GET",
        "/app.php?type=users",
        200,
        2_400,
        TARAYICILAR[0],
    )
    log(
        t + timedelta(minutes=5),
        "203.0.113.77",
        "GET",
        "/app.php?type=disa_aktar",
        200,
        51_000,
        TARAYICILAR[0],
    )
    for i in range(5):  # yetkisiz admin API
        log(
            an(10, 4, 15, 30) + timedelta(seconds=i * 40),
            "203.0.113.120",
            "GET",
            "/app.php?type=users",
            401,
            380,
            TARAYICILAR[1],
        )
    for i, q in enumerate(
        [
            "id=1%27%3D%271",
            "id=1+UNION+select+@@version",
            "q=concat_ws(0x3a,user())",
            "id=1=select%20password%20from%20users",
        ]
    ):  # SQL injection: biri sayfayı döndürdü
        log(
            an(10, 2, 13, 5) + timedelta(seconds=i * 7),
            "203.0.113.33",
            "GET",
            f"/app.php?type=yorumlar&{q}",
            200 if i == 3 else 403,
            8_900 if i == 3 else 300,
            TARAYICILAR[3],
        )
    log(
        an(10, 13, 10, 2),
        "203.0.113.61",
        "GET",
        "/?file=../../../../etc/passwd",
        200,
        35_153,
        TARAYICILAR[2],
    )
    for i in range(160):  # hızlı tarayıcı
        log(
            an(9, 29, 4) + timedelta(seconds=i * 0.35),
            "198.51.100.250",
            "GET",
            rnd.choice(SAYFALAR),
            200,
            21_000,
            "Mozilla/5.0 (compatible; OrnekCrawler/1.0)",
        )
    return sorted(
        satirlar,
        key=lambda s: datetime.strptime(s.split("[", 1)[1].split(" ", 1)[0], "%d/%b/%Y:%H:%M:%S"),
    )


def olustur(hedef: Path, gun: int = 24, totp: bool = False) -> dict:
    """Demo veritabanını kurar; giriş bilgilerini döndürür."""
    if settings.use_local_config:
        raise SystemExit(
            "Yerel (gerçek) site ayarları açık: demo verisine karışabilir. Durduruldu."
        )
    motor = make_engine(f"sqlite:///{hedef.as_posix()}")
    init_db(motor)
    satirlar = log_satirlari(gun)
    with Session(motor) as db:
        sonuc = process_lines(satirlar)
        kayit = save_batch(db, "access_log_demo.log", len(satirlar), sonuc)
        zamanlar = [e.timestamp for e in kayit.inserted]
        tespit = run_detection(db, min(zamanlar), max(zamanlar))
    bilgi: dict = {"olay": len(kayit.inserted), "alarm": tespit.created, "kullanicilar": {}}
    for ad, rol in (("demo", "yonetici"), ("analist", "analist")):
        sifre = "Tanitim-" + secrets.token_urlsafe(14)
        users.add_user(motor, ad, rol, sifre)
        bilgi["kullanicilar"][ad] = sifre
    with Session(motor) as db:
        # Otomasyon (ekran görüntüsü betikleri) için sabit anahtar; elle denemede ilk girişte QR
        if totp:
            bilgi["totp"] = mfa.new_secret()
            for u in db.scalars(select(User)):
                u.totp_secret = bilgi["totp"]
        for a in db.scalars(select(Alert).order_by(Alert.id)):
            if a.rule_id == "SIG-001" and a.source_ip == "203.0.113.61":
                durum, not_ = (
                    "false_positive",
                    "Dönen sayfa 35.153 bayt: anasayfanın aynısı. Dosya okunamadı.",
                )
            elif a.rule_id in KARARLAR:
                durum, not_ = KARARLAR[a.rule_id]
            else:
                continue
            onceki = a.status
            for adim in (
                ["investigating", durum]
                if durum == "false_positive"
                else ["investigating", "confirmed", durum]
            ):
                db.add(
                    AlertHistory(
                        alert_id=a.id,
                        from_status=onceki,
                        to_status=adim,
                        note=not_ if adim == durum else "",
                        changed_by="analist",
                        changed_at=datetime(2026, 10, 15, 10, tzinfo=UTC),
                    )
                )
                onceki = adim
            a.status = durum
        db.commit()
    motor.dispose()
    return bilgi


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="SIEM'i denemek için sahte demo veritabanı")
    p.add_argument("veritabani", help="oluşturulacak .db dosyası (ör. data/demo.db)")
    p.add_argument(
        "--gun", type=int, default=24, help="normal trafik kaç gün sürsün (varsayılan 24)"
    )
    p.add_argument(
        "--totp",
        action="store_true",
        help="kullanıcılara sabit iki adımlı doğrulama anahtarı kur (otomasyon)",
    )
    p.add_argument("--uzerine", action="store_true", help="dosya varsa sil ve yeniden kur")
    a = p.parse_args(argv)
    hedef = Path(a.veritabani).resolve()
    if hedef.suffix != ".db" or hedef.name.lower().startswith("siem."):
        p.error("demo için .db uzantılı, 'siem.' ile başlamayan bir ad ver (ör. data/demo.db)")
    if hedef.exists() and not a.uzerine:
        p.error(f"{hedef} zaten var (silip yeniden kurmak için --uzerine)")
    # Yalnızca bu demonun kendi dosyaları silinir; ada benzeyen başka dosyaya (yedekler!) dokunulmaz
    for ek in ("", "-wal", "-shm", "-journal", ".giris.json"):
        hedef.with_name(hedef.name + ek).unlink(missing_ok=True)
    hedef.parent.mkdir(parents=True, exist_ok=True)
    bilgi = olustur(hedef, a.gun, a.totp)
    giris = hedef.with_name(hedef.name + ".giris.json")
    giris.write_text(json.dumps(bilgi, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"✅ {hedef}: {bilgi['olay']} olay, {bilgi['alarm']} alarm")
    print(f"   Giriş bilgileri: {giris}  (yalnızca sahte demo hesapları)")


if __name__ == "__main__":
    main()
