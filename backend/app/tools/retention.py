"""Saklama süresini elle uygular (SIEM her açılışta zaten kendisi uygular).

Kullanım (backend klasöründe):
    .venv\\Scripts\\python.exe -m app.tools.retention --deneme   (yalnızca sayar, silmez)
    .venv\\Scripts\\python.exe -m app.tools.retention
"""

from __future__ import annotations

import argparse
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import engine, init_db
from app.privacy.retention import apply_retention, retention_status


def backup_files(db_url: str) -> list[Path]:
    """data/ klasöründeki elle alınmış yedekler: saklama süresi bunlara uygulanmaz."""
    if not db_url.startswith("sqlite:///"):
        return []
    db = Path(db_url.removeprefix("sqlite:///"))
    return sorted(p for p in db.parent.glob(f"{db.name}.yedek*") if p.is_file())


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="KVKK saklama süresini uygula")
    parser.add_argument("--deneme", action="store_true", help="hiçbir şeyi silmeden say")
    parser.add_argument("--gun", type=int, default=settings.retention_days,
                        help=f"saklama süresi (varsayılan {settings.retention_days})")
    args = parser.parse_args(argv)
    if args.gun < 7:
        parser.error("saklama süresi en az 7 gün olmalı")

    init_db(engine)
    r = apply_retention(engine, args.gun, dry_run=args.deneme)
    verb = "silinecek" if r.dry_run else "silindi"
    print(f"Saklama süresi: {args.gun} gün (sınır: {r.cutoff:%d.%m.%Y %H:%M} UTC)")
    print(f"  Olay: {r.events_deleted} {verb}")
    print(f"  Giriş kaydı (SIEM'in kendi): {r.auth_events_deleted} {verb}")
    print(f"  Kapatılmış alarm: {r.alerts_masked} alarmın IP'si "
          f"{'maskelenecek' if r.dry_run else 'maskelendi'}")
    if r.open_alerts_kept:
        print(f"  ⚠ Süresi dolmuş ama AÇIK {r.open_alerts_kept} alarm var: kapatılınca maskelenir.")
    with Session(engine) as db:
        s = retention_status(db, args.gun)
    if s.oldest_event:
        print(f"En eski olay: {s.oldest_event:%d.%m.%Y} → "
              f"{s.next_purge_at:%d.%m.%Y} tarihinde silinir")
    backups = backup_files(settings.database_url)
    if backups:
        print(f"\nNot: data/ klasöründe {len(backups)} yedek dosyası var; saklama süresi yedeklere "
              "uygulanmaz. Artık gerekmeyenleri elle silin:")
        for b in backups:
            print(f"  - {b.name}")


if __name__ == "__main__":
    main()
