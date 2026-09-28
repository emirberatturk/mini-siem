"""Uygulama ayarları.

Ayarlar koddan değil ortam değişkenlerinden / .env dosyasından okunur (SIEM_ önekiyle).
Böylece gizli anahtarlar asla koda gömülmez.
"""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[3]  # .../siem


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SIEM_", env_file=".env", extra="ignore")

    app_name: str = "Mini-SIEM"
    environment: str = "development"
    database_url: str = "sqlite:///./data/siem.db"
    rules_config: Path = PROJECT_ROOT / "config" / "rules.yaml"
    sigma_rules_dir: Path = PROJECT_ROOT / "config" / "sigma"  # imza kuralları (SigmaHQ)
    # Anomali profili: sitenin yapısını anlattığı için yereldir, git'e girmez
    # (oluşturmak için: python -m app.tools.train_profile <log dosyaları>)
    anomaly_profile: Path = PROJECT_ROOT / "config" / "anomaly_profile.local.json"

    # Oturum ve giriş güvenliği
    session_hours: int = 8  # oturum en fazla bu kadar açık kalır (mutlak süre)
    lockout_attempts: int = 5  # bu kadar hatalı denemeden sonra…
    lockout_minutes: int = 15  # …kullanıcı adı bu süre kilitlenir
    # Secure çerez yalnızca HTTPS'te gönderilir. SIEM şimdilik yerel HTTP'de çalıştığı için
    # kapalı; HTTPS arkasına alınırsa SIEM_COOKIE_SECURE=true yapılmalı.
    cookie_secure: bool = False
    # config/*.local.yaml: siteye özel, git'e girmeyen ayarlar. Testler kapatır (conftest.py).
    use_local_config: bool = True

    # Log yükleme sınırları (kaynak tüketme saldırılarına karşı)
    max_upload_bytes: int = 50 * 1024 * 1024  # yüklenen dosya (sıkıştırılmış hali)
    max_decompressed_bytes: int = 200 * 1024 * 1024  # gzip açıldıktan sonra: gzip bombası koruması
    max_line_length: int = 8192  # Apache'nin varsayılan istek satırı sınırı ~8 KB


settings = Settings()
