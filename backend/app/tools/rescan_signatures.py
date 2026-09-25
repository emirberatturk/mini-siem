"""Daha önce yüklenmiş log dosyalarını imza (Sigma) kurallarıyla yeniden tarar.

İmza kontrolü ham istek üzerinde yapıldığı için veritabanındaki (maskelenmiş) kayıtlardan
yapılamaz; orijinal log dosyası yeniden okunur. Aynı satır aynı event_key'i ürettiği için
kayıtlar eşleştirilir ve YALNIZCA `signatures` sütunu güncellenir: olaylar, alarmlar,
notlar ve geçmiş olduğu gibi kalır. Ham satırlar yalnızca bellekte işlenir.

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
from app.detection.engine import run_on_all
from app.ingestion.pipeline import process_lines
from app.ingestion.reader import read_log_lines

_CHUNK = 500


def rescan(paths: list[Path], *, dry_run: bool, bind: Engine | None = None) -> int:
    bind = bind or engine
    if not dry_run:
        init_db(bind)  # eski veritabanına signatures sütununu ekler (veri silinmez)
    has_column = "signatures" in {c["name"] for c in inspect(bind).get_columns("events")}
    sig_col = Event.signatures if has_column else literal("")  # deneme: sütun henüz yoksa
    events = Event.__table__
    with Session(bind) as db:
        total_updates = 0
        for path in paths:
            read = read_log_lines(path.read_bytes(),
                                  max_decompressed=settings.max_decompressed_bytes,
                                  max_line_length=settings.max_line_length)
            found = {e.event_key: e.signatures for e in process_lines(read.lines).events}

            current: dict[str, str] = {}
            keys = list(found)
            for i in range(0, len(keys), _CHUNK):
                current.update(db.execute(
                    select(Event.event_key, sig_col)
                    .where(Event.event_key.in_(keys[i:i + _CHUNK]))).tuples().all())

            changes = [{"k": k, "s": found[k]} for k in current if current[k] != found[k]]
            print(f"{path.name}: {len(read.lines)} satır · veritabanında {len(current)} · "
                  f"imzalı {sum(1 for s in found.values() if s)} · güncellenecek {len(changes)}"
                  + (f" · veritabanında olmayan {len(found) - len(current)}"
                     if len(found) != len(current) else ""))
            if changes and not dry_run:
                # Yalnızca signatures sütunu yazılır; tek işlem (ya hepsi ya hiçbiri)
                db.connection().execute(
                    update(events).where(events.c.event_key == bindparam("k"))
                    .values(signatures=bindparam("s")), changes)
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
