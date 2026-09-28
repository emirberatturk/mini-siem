"""Daha önce yüklenmiş log dosyalarını imza (Sigma) kuralları ve anomali profiliyle yeniden tarar.

İmza ve anomali kontrolü ham istek üzerinde yapıldığı için veritabanındaki (maskelenmiş)
kayıtlardan yapılamaz; orijinal log dosyası yeniden okunur. Aynı satır aynı event_key'i
ürettiği için kayıtlar eşleştirilir ve YALNIZCA `signatures` ve `anomalies` sütunları
güncellenir: olaylar, alarmlar, notlar ve geçmiş olduğu gibi kalır. Ham satırlar yalnızca
bellekte işlenir.

Kullanım (backend klasöründe):
    .venv\\Scripts\\python.exe -m app.tools.rescan_signatures ..\\sample_logs\\real\\access_log
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sqlalchemy import bindparam, inspect, literal, select, update
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Event
from app.db.session import engine, init_db
from app.detection import anomaly
from app.detection.engine import run_on_all
from app.ingestion.pipeline import process_lines
from app.ingestion.reader import read_log_lines

_CHUNK = 500


def rescan(paths: list[Path], *, dry_run: bool, bind: Engine | None = None,
           profile: anomaly.Profile | None = None) -> int:
    """Eşleşen kayıtlarda yalnızca signatures ve anomalies sütunlarını günceller."""
    bind = bind or engine
    if not dry_run:
        init_db(bind)  # eski veritabanına eksik sütunları ekler (veri silinmez)
    columns = {c["name"] for c in inspect(bind).get_columns("events")}
    # deneme çalıştırmasında sütun henüz yoksa boş kabul edilir
    sig_col = Event.signatures if "signatures" in columns else literal("")
    anom_col = Event.anomalies if "anomalies" in columns else literal("")
    events = Event.__table__
    with Session(bind) as db:
        total_updates = 0
        for path in paths:
            read = read_log_lines(path.read_bytes(),
                                  max_decompressed=settings.max_decompressed_bytes,
                                  max_line_length=settings.max_line_length)
            found = {e.event_key: (e.signatures, e.anomalies)
                     for e in process_lines(read.lines, profile).events}

            current: dict[str, tuple[str, str]] = {}
            keys = list(found)
            for i in range(0, len(keys), _CHUNK):
                for key, sig, anom in db.execute(
                        select(Event.event_key, sig_col, anom_col)
                        .where(Event.event_key.in_(keys[i:i + _CHUNK]))):
                    current[key] = (sig, anom)

            changes = [{"k": k, "s": found[k][0], "a": found[k][1]}
                       for k in current if current[k] != found[k]]
            print(f"{path.name}: {len(read.lines)} satır · veritabanında {len(current)} · "
                  f"imzalı {sum(1 for s, _ in found.values() if s)} · "
                  f"anomalili {sum(1 for _, a in found.values() if a)} · "
                  f"güncellenecek {len(changes)}"
                  + (f" · veritabanında olmayan {len(found) - len(current)}"
                     if len(found) != len(current) else ""))
            if changes and not dry_run:
                # Yalnızca bu iki sütun yazılır; tek işlem (ya hepsi ya hiçbiri)
                db.connection().execute(
                    update(events).where(events.c.event_key == bindparam("k"))
                    .values(signatures=bindparam("s"), anomalies=bindparam("a")), changes)
                db.commit()
            total_updates += len(changes)

        if dry_run:
            print("Deneme çalıştırması: hiçbir şey değiştirilmedi.")
        elif total_updates:
            result = run_on_all(db)
            print(f"Kurallar çalıştı: {result.created} yeni alarm, {result.updated} güncellenen.")
        return total_updates


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--deneme", action="store_true", help="değiştirmeden sadece raporla")
    args = parser.parse_args(argv)
    missing = [p for p in args.files if not p.is_file()]
    if missing:
        sys.exit(f"Dosya bulunamadı: {', '.join(map(str, missing))}")
    rescan(args.files, dry_run=args.deneme)


if __name__ == "__main__":
    main()
