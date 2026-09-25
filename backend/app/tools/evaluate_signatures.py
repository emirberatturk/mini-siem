"""İmza kurallarının başarısını etiketli CSIC 2010 veri setiyle ölçer.

CSIC 2010 ham HTTP istekleri içerir (normal / saldırı olarak etiketli). Her istek, bir Apache
access log satırının göreceği hale çevrilir: yöntem, yol, sorgu ve tarayıcı bilgisi. POST
gövdesi access log'a YAZILMAZ; bu yüzden gövdedeki saldırılar hiçbir log tabanlı kuralla
görülemez. Sonuçlar dürüst olsun diye iki grupta raporlanır: yalnızca GET (log'da görünür)
ve tümü.

Kullanım (backend klasöründe):
    .venv\\Scripts\\python.exe -m app.tools.evaluate_signatures ..\\sample_logs\\datasets\\csic2010
"""

from __future__ import annotations

import argparse
import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from app.detection import sigma
from app.parsers import apache

_REQUEST = re.compile(r"^(GET|POST|PUT) (https?://\S+) HTTP/1\.[01]$")


@dataclass
class Request:
    method: str
    target: str  # yol + ?sorgu (access log'da görünen kısım)
    user_agent: str


def read_csic(path: Path) -> Iterator[Request]:
    current: Request | None = None
    for line in path.read_text(encoding="latin-1").splitlines():
        m = _REQUEST.match(line)
        if m:
            if current:
                yield current
            url = urlsplit(m.group(2))
            target = url.path + (f"?{url.query}" if url.query else "")
            current = Request(m.group(1), target, "")
        elif current and line.lower().startswith("user-agent:"):
            current.user_agent = line.split(":", 1)[1].strip()
    if current:
        yield current


def access_log_line(r: Request) -> str:
    """İsteği, sunucunun yazacağı access log satırına çevirir (yanıt kodu bilinmiyor: 200)."""
    target = r.target.replace('"', "%22")
    ua = r.user_agent.replace('"', '\\"')
    return f'127.0.0.1 - - [01/Jan/2010:00:00:00 +0000] "{r.method} {target} HTTP/1.1" ' \
           f'200 0 "-" "{ua}"'


def evaluate(folder: Path) -> dict:
    stats: dict[str, Counter] = {"GET": Counter(), "Tümü": Counter()}
    per_rule: Counter[str] = Counter()
    for label, filename in (("saldırı", "anomalousTrafficTest.txt"),
                            ("normal", "normalTrafficTest.txt")):
        for r in read_csic(folder / filename):
            line = access_log_line(r)
            req = apache.parse_line(line)
            hit = bool(req and (names := sigma.match(line, req)))
            if hit and label == "saldırı":
                per_rule.update(names)
            outcome = {("saldırı", True): "TP", ("saldırı", False): "FN",
                       ("normal", True): "FP", ("normal", False): "TN"}[(label, hit)]
            stats["Tümü"][outcome] += 1
            if r.method == "GET":
                stats["GET"][outcome] += 1
    return {"stats": stats, "per_rule": per_rule}


def report(result: dict) -> None:
    print(f"{'Grup':6} {'saldırı':>8} {'yakalanan':>10} {'normal':>8} {'yanlış alarm':>13} "
          f"{'yakalama':>9} {'kesinlik':>9} {'YA oranı':>9}")
    for group, c in result["stats"].items():
        attacks, normals = c["TP"] + c["FN"], c["FP"] + c["TN"]
        recall = c["TP"] / attacks if attacks else 0
        precision = c["TP"] / (c["TP"] + c["FP"]) if c["TP"] + c["FP"] else 0
        fpr = c["FP"] / normals if normals else 0
        print(f"{group:6} {attacks:8} {c['TP']:10} {normals:8} {c['FP']:13} "
              f"{recall:9.1%} {precision:9.1%} {fpr:9.2%}")
    print("\nSaldırıları yakalayan kurallar:")
    for name, count in result["per_rule"].most_common():
        print(f"  {name:36} {count}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("folder", type=Path)
    report(evaluate(parser.parse_args(argv).folder))


if __name__ == "__main__":
    main()
