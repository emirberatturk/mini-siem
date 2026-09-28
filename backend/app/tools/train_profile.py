"""Anomali profilini sitenin kendi loglarından öğrenir.

Profil "normal"den öğrenmeli, saldırıdan değil: eğitime yalnızca sunucunun başarılı (2xx)
yanıt verdiği ve hiçbir imzayla eşleşmeyen istekler alınır. 3xx da dışarıda kalır: bot
istekleri de http→https yönlendirmesi (301) alır, bu sayfanın çalıştığını göstermez.

Sınır: her parametreye 200 dönen sayfalar (ör. statik ana sayfa) botların eklediği
parametreleri de "normal" diye öğrenir; bu sayfalarda anomali tespiti zayıftır.

Çıktı yalnızca istatistiktir (parametre değerleri yazılmaz) ama sitenin sayfa/parametre
yapısını anlattığı için yerel bir dosyaya yazılır ve git'e girmez.

Kullanım (backend klasöründe):
    .venv\\Scripts\\python.exe -m app.tools.train_profile <log dosyası> [<log dosyası> …]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app.core.config import settings
from app.detection import anomaly, sigma
from app.ingestion.reader import read_log_lines
from app.parsers import apache


def train_from_logs(paths: list[Path]) -> tuple[anomaly.Profile, dict[str, int]]:
    profile = anomaly.Profile()
    stats = {"satır": 0, "öğrenilen": 0, "başarısız/yönlendirme (2xx değil)": 0,
             "imza eşleşen": 0,
             "ayrıştırılamayan": 0}
    for path in paths:
        read = read_log_lines(path.read_bytes(), max_decompressed=settings.max_decompressed_bytes,
                              max_line_length=settings.max_line_length)
        for line in read.lines:
            stats["satır"] += 1
            req = apache.parse_line(line)
            if req is None:
                stats["ayrıştırılamayan"] += 1
            elif not 200 <= req.status_code < 300:
                stats["başarısız/yönlendirme (2xx değil)"] += 1
            elif sigma.match(line, req):
                stats["imza eşleşen"] += 1
            else:
                profile.learn(req.path, req.query)
                stats["öğrenilen"] += 1
    return profile, stats


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--cikti", type=Path, default=settings.anomaly_profile,
                        help="profil dosyası (varsayılan: config/anomaly_profile.local.json)")
    args = parser.parse_args(argv)
    missing = [p for p in args.files if not p.is_file()]
    if missing:
        sys.exit(f"Dosya bulunamadı: {', '.join(map(str, missing))}")

    profile, stats = train_from_logs(args.files)
    args.cikti.parent.mkdir(parents=True, exist_ok=True)
    profile.save(args.cikti)
    saved = profile.pruned()  # diske yazılanla aynı
    print(" · ".join(f"{k}: {v}" for k, v in stats.items()))
    print(f"Görülen: {len(profile.path_counts)} yol · Kaydedilen (yeterli örnekli): "
          f"{len(saved.path_counts)} yol, {sum(len(p) for p in saved.paths.values())} "
          f"parametre → {args.cikti}")


if __name__ == "__main__":
    main()
