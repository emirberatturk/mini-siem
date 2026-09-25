"""İzlenen sitenin yapısına özgü bilgiler.

SIEM'lerde buna "asset context" denir: aynı istek bir sitede önemsiz, diğerinde kritik olabilir.
Değerler config/site_profile.local.yaml'dan okunur; bu dosya git'e girmez, çünkü admin
yolları ve API adları saldırgana harita olur. Dosya yoksa örnek profil kullanılır
(config/site_profile.example.yaml).
"""

from pathlib import Path

import yaml

from app.core.config import PROJECT_ROOT, settings

_CONFIG_DIR = PROJECT_ROOT / "config"


def _load() -> dict:
    local = _CONFIG_DIR / "site_profile.local.yaml"
    path: Path = local if settings.use_local_config and local.exists() else (
        _CONFIG_DIR / "site_profile.example.yaml"
    )
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


_profile = _load()

# Admin girişi: POST <LOGIN_PATH>?type=<LOGIN_TYPE> → 200 başarılı, 401 yanlış şifre, 429 kilit
LOGIN_PATH: str = _profile["login_path"].lower()
LOGIN_TYPE: str = _profile["login_type"]

# Yalnızca oturum açmış admin'in kullanması gereken API türleri
ADMIN_API_TYPES = frozenset(_profile.get("admin_api_types") or [])

# Admin arayüzü sayfaları
ADMIN_PAGES = frozenset(p.lower() for p in _profile.get("admin_pages") or [])

# Formlarında kişisel veri olan sayfalar/API'ler: parametre değerleri HER ZAMAN maskelenir
PII_PAGES = frozenset(p.lower() for p in _profile.get("pii_pages") or [])
PII_API_TYPES = frozenset(_profile.get("pii_api_types") or [])

# Adı kişisel veri/sır taşıdığını belli eden parametreler (her sayfada maskelenir)
SENSITIVE_PARAMS = frozenset(
    {
        "ad", "soyad", "adsoyad", "isim", "name", "fullname",
        "tel", "telefon", "phone", "gsm",
        "email", "eposta", "mail",
        "tc", "tckn", "tcno", "kimlik",
        "password", "pass", "sifre", "parola", "token", "key", "apikey",
        "mesaj", "message", "not", "aciklama", "yorum", "adres", "dogum",
    }
)
