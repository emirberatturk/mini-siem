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
    # config/*.local.yaml: siteye özel, git'e girmeyen ayarlar. Testler kapatır (conftest.py).
    use_local_config: bool = True

    # Log yükleme sınırları (kaynak tüketme saldırılarına karşı)
    max_upload_bytes: int = 50 * 1024 * 1024  # yüklenen dosya (sıkıştırılmış hali)
    max_decompressed_bytes: int = 200 * 1024 * 1024  # gzip açıldıktan sonra: gzip bombası koruması
    max_line_length: int = 8192  # Apache'nin varsayılan istek satırı sınırı ~8 KB


settings = Settings()
