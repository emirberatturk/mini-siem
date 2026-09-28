"""Anomali tespitini (ve imzalarla birlikte kullanımını) CSIC 2010 ile ölçer.

Model normalTrafficTraining.txt'deki normal isteklerden öğrenir, normalTrafficTest.txt ve
anomalousTrafficTest.txt üzerinde sınanır (öğrenme ve sınama verisi ayrı). Access log'un
gördüğü kadarı kullanılır: yöntem, yol ve sorgu; POST gövdesi görünmez.

Kullanım (backend klasöründe):
    .venv\\Scripts\\python.exe -m app.tools.evaluate_anomaly ..\\sample_logs\\datasets\\csic2010
"""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from app.detection import anomaly, sigma
from app.parsers import apache
from app.tools.evaluate_signatures import access_log_line, read_csic

METHODS = ("İmza", "Anomali", "İmza + Anomali")


def split_target(target: str) -> tuple[str, str]:
    parts = urlsplit(target)
    return parts.path, parts.query


def evaluate(folder: Path, settings: anomaly.Settings | None = None) -> dict:
    profile = anomaly.train((split_target(r.target) for r in
                             read_csic(folder / "normalTrafficTraining.txt")), settings)
    stats = {g: {m: Counter() for m in METHODS} for g in ("GET", "Tümü")}
    fp_kinds: Counter[str] = Counter()
    tp_kinds: Counter[str] = Counter()
    for label, filename in (("saldırı", "anomalousTrafficTest.txt"),
                            ("normal", "normalTrafficTest.txt")):
        for r in read_csic(folder / filename):
            line = access_log_line(r)
            req = apache.parse_line(line)
            sig = bool(req and sigma.match(line, req))
            findings = profile.check(*split_target(r.target))
            kinds = Counter(f.rsplit(":", 1)[1] for f in findings)
            (tp_kinds if label == "saldırı" else fp_kinds).update(kinds.keys())
            for method, hit in zip(METHODS, (sig, bool(findings), sig or bool(findings)),
                                   strict=True):
                outcome = {("saldırı", True): "TP", ("saldırı", False): "FN",
                           ("normal", True): "FP", ("normal", False): "TN"}[(label, hit)]
                stats["Tümü"][method][outcome] += 1
                if r.method == "GET":
                    stats["GET"][method][outcome] += 1
    return {"stats": stats, "tp_kinds": tp_kinds, "fp_kinds": fp_kinds,
            "profile_paths": len(profile.paths)}


def rates(c: Counter) -> tuple[float, float, float]:
    attacks, normals = c["TP"] + c["FN"], c["FP"] + c["TN"]
    recall = c["TP"] / attacks if attacks else 0.0
    precision = c["TP"] / (c["TP"] + c["FP"]) if c["TP"] + c["FP"] else 0.0
    fpr = c["FP"] / normals if normals else 0.0
    return recall, precision, fpr


def report(result: dict) -> None:
    print(f"Profil: {result['profile_paths']} yol öğrenildi (yalnızca istatistik)\n")
    for group, by_method in result["stats"].items():
        print(f"[{group}]")
        print(f"  {'Yöntem':16} {'yakalanan':>10} {'yanlış alarm':>13} {'yakalama':>9} "
              f"{'kesinlik':>9} {'YA oranı':>9}")
        for method, c in by_method.items():
            recall, precision, fpr = rates(c)
            print(f"  {method:16} {c['TP']:10} {c['FP']:13} {recall:9.1%} {precision:9.1%} "
                  f"{fpr:9.2%}")
        print()
    print("Saldırılarda görülen sapma türleri:", dict(result["tp_kinds"].most_common()))
    print("Normal isteklerde görülen sapma türleri (yanlış alarm kaynağı):",
          dict(result["fp_kinds"].most_common()))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("folder", type=Path)
    report(evaluate(parser.parse_args(argv).folder))


if __name__ == "__main__":
    main()
