"""README ekran görüntüleri: DEMO veriyle çalışan SIEM'den (asla gerçek veriden).

Önce demo veritabanı ve ayrı portlarda bir SIEM (gerçek SIEM 8000/5173'te çalışmaya devam edebilir):
    cd backend
    .venv\\Scripts\\python.exe -m app.tools.demo_veri data\\demo.db --totp --uzerine
    $env:SIEM_DATABASE_URL = "sqlite:///data/demo.db"; $env:SIEM_USE_LOCAL_CONFIG = "false"
    .venv\\Scripts\\python.exe -m uvicorn app.main:app --port 8001
    cd ..\\frontend; $env:SIEM_API_PORT = "8001"; npx vite --port 5175 --strictPort
Sonra (Chrome ve `pip install websocket-client` gerekir):
    python scripts\\demo_ekran_goruntuleri.py backend\\data\\demo.db.giris.json cikti-klasoru
Görüntüleri docs/img/'e kopyalamadan önce gözle bak; meta veri yoktur (Chrome PNG'si).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import websocket  # pip install websocket-client

CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
# (ad, adres, genişlik, yükseklik: 0 = sayfanın tamamı)
GORUNTULER = [
    ("weekly", "#weekly", 1000, 0),
    ("overview", "#overview", 1440, 0),
    ("alerts", "#alerts", 1440, 900),
    ("drawer", "#alerts/2", 1440, 900),
    ("report", "#report/2", 1000, 0),
    ("rules", "#rules", 1440, 900),
]


def totp(anahtar: str, adim: int) -> str:
    """RFC 6238 (SIEM'deki core/mfa.py ile aynı): demo hesabının 6 haneli kodu."""
    ozet = hmac.new(base64.b32decode(anahtar), struct.pack(">Q", adim), hashlib.sha1).digest()
    o = ozet[-1] & 0x0F
    return str((struct.unpack(">I", ozet[o : o + 4])[0] & 0x7FFFFFFF) % 1_000_000).zfill(6)


class Tarayici:
    """Başsız Chrome'u DevTools protokolüyle süren küçük yardımcı."""

    def __init__(self, port: int = 9351):
        self.profil = tempfile.mkdtemp(prefix="siem-chrome-")
        self.surec = subprocess.Popen(  # noqa: S603  (sabit Chrome yolu, sabit bayraklar)
            [
                CHROME,
                "--headless=new",
                "--no-first-run",
                f"--user-data-dir={self.profil}",
                f"--remote-debugging-port={port}",
                "--hide-scrollbars",
                "about:blank",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(40):
            try:
                sekmeler = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json"))  # noqa: S310
                break
            except OSError:
                time.sleep(0.5)
        sayfa = next(s for s in sekmeler if s["type"] == "page")
        self.ws = websocket.create_connection(
            sayfa["webSocketDebuggerUrl"], suppress_origin=True, timeout=60
        )
        self.no = 0

    def komut(self, yontem: str, **p):
        self.no += 1
        self.ws.send(json.dumps({"id": self.no, "method": yontem, "params": p}))
        while True:
            m = json.loads(self.ws.recv())
            if m.get("id") == self.no:
                return m.get("result", {})

    def js(self, ifade: str):
        return (
            self.komut("Runtime.evaluate", expression=ifade, awaitPromise=True, returnByValue=True)
            .get("result", {})
            .get("value")
        )

    def doldur(self, secici: str, deger: str, sira: int = 0) -> None:
        # React kontrollü input: değer, prototipin setter'ıyla verilip 'input' olayı yayınlanmalı
        self.js(f"""(() => {{
          const el = document.querySelectorAll({json.dumps(secici)})[{sira}];
          const yaz = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
          yaz.call(el, {json.dumps(deger)});
          el.dispatchEvent(new Event('input', {{bubbles: true}})); }})()""")

    def tikla(self, yazi: str) -> None:
        self.js(
            "[...document.querySelectorAll('button')]"
            f".find(x => x.innerText.trim() === {json.dumps(yazi)})?.click()"
        )
        time.sleep(1.5)

    def ekran(self, g: int, y: int, olcek: float = 1) -> None:
        self.komut(
            "Emulation.setDeviceMetricsOverride",
            width=g,
            height=y,
            deviceScaleFactor=olcek,
            mobile=False,
        )

    def giris(self, adres: str, kullanici: str, sifre: str, anahtar: str) -> None:
        self.komut("Page.enable")
        self.komut("Network.clearBrowserCookies")
        self.ekran(1440, 900)
        self.komut("Page.navigate", url=adres)
        time.sleep(2.5)
        self.doldur(".login-card input", kullanici, 0)
        self.doldur(".login-card input", sifre, 1)
        self.tikla("Devam")
        self.doldur(".code-input", totp(anahtar, int(time.time() // 30)))
        self.tikla("Giriş yap")
        time.sleep(1.5)
        if "Genel Bakış" not in (self.js("document.body.innerText") or ""):
            raise SystemExit(
                "Giriş olmadı (aynı 30 saniyede ikinci giriş mi? Biraz bekleyip yeniden dene)."
            )

    def kapat(self) -> None:
        self.surec.kill()


def kaydet(t: Tarayici, dosya: Path, kirp: dict | None = None) -> None:
    p = {"format": "png", "captureBeyondViewport": True}
    if kirp:
        p["clip"] = {**kirp, "scale": 1}
    dosya.write_bytes(base64.b64decode(t.komut("Page.captureScreenshot", **p)["data"]))
    print(dosya.name)


def video_kaynaklari(t: Tarayici, adres: str, bilgi: dict, cikti: Path) -> None:
    """Tanıtım videosu (video-kurgu: reklam/siem_tanitim.py) için yüksek çözünürlüklü kaynaklar:
    giriş kartı (şifre, sonra kod rakam rakam yazılırken), genel bakış, kritik alarm paneli,
    haftalık rapor."""
    kod = "481205"  # ekranda yazılıyor gibi görünen kod; gönderilmez
    kart = (
        "(() => { const r = document.querySelector('.login-card').getBoundingClientRect();"
        " return {x: r.x - 24, y: r.y - 24, width: r.width + 48, height: r.height + 48}; })()"
    )
    t.komut("Page.enable")
    t.komut("Network.clearBrowserCookies")
    t.ekran(1440, 900, 2)
    t.komut("Page.navigate", url=adres)
    time.sleep(2.5)
    t.doldur(".login-card input", "demo", 0)
    t.doldur(".login-card input", bilgi["kullanicilar"]["demo"], 1)
    time.sleep(0.4)
    kaydet(t, cikti / "giris-sifre.png", t.js(kart))
    t.tikla("Devam")
    for i in range(len(kod) + 1):
        yazilan = kod[:i]
        t.doldur(".code-input", yazilan[:3] + (" " + yazilan[3:] if len(yazilan) > 3 else ""))
        time.sleep(0.25)
        kaydet(t, cikti / f"giris-kod-{i}.png", t.js(kart))
    t.doldur(".code-input", totp(bilgi["totp"], int(time.time() // 30)))
    t.tikla("Giriş yap")
    time.sleep(1.5)
    for ad, yol, g, tam in [
        ("genel", "#overview", 1440, True),
        ("alarm", "#alerts/2", 1440, False),
        ("haftalik", "#weekly", 1000, True),
    ]:
        t.ekran(g, 900, 1.5)
        t.komut("Page.navigate", url="about:blank")
        t.komut("Page.navigate", url=adres + yol)
        time.sleep(3.5)
        if tam:
            t.ekran(g, int(t.js("document.documentElement.scrollHeight")), 1.5)
            time.sleep(0.8)
        kaydet(t, cikti / f"{ad}.png")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("giris_bilgisi", help="demo_veri'nin yazdığı .giris.json (--totp ile)")
    p.add_argument("cikti", help="görüntülerin yazılacağı klasör")
    p.add_argument("--adres", default="http://127.0.0.1:5175/")
    p.add_argument(
        "--video",
        action="store_true",
        help="README yerine tanıtım videosunun kaynaklarını yakala (video-kurgu)",
    )
    a = p.parse_args()
    bilgi = json.loads(Path(a.giris_bilgisi).read_text(encoding="utf-8"))
    if "totp" not in bilgi:
        sys.exit("Demo veritabanı --totp ile kurulmalı.")
    cikti = Path(a.cikti)
    cikti.mkdir(parents=True, exist_ok=True)
    t = Tarayici()
    try:
        if a.video:
            video_kaynaklari(t, a.adres, bilgi, cikti)
            return
        t.giris(a.adres, "demo", bilgi["kullanicilar"]["demo"], bilgi["totp"])
        for ad, adres, g, y in GORUNTULER:
            t.ekran(g, 900)
            t.komut("Page.navigate", url="about:blank")
            t.komut("Page.navigate", url=a.adres + adres)
            time.sleep(3.5)
            if ad == "rules":
                t.js("document.querySelectorAll('details.rule-sigma').forEach(d => d.open = false)")
            t.ekran(g, int(y or t.js("document.documentElement.scrollHeight")))
            time.sleep(0.8)
            (cikti / f"{ad}.png").write_bytes(
                base64.b64decode(t.komut("Page.captureScreenshot", format="png")["data"])
            )
            print(ad)
    finally:
        t.kapat()


if __name__ == "__main__":
    main()
