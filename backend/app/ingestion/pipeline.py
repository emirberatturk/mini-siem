"""Ham satırlar → parse → imza + anomali kontrolü → sınıflandır → maskele → normalize olay."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from app.detection import anomaly, sigma
from app.normalization.normalizer import normalize
from app.normalization.schema import NormalizedEvent
from app.parsers import apache


@dataclass
class PipelineResult:
    events: list[NormalizedEvent] = field(default_factory=list)
    failed: int = 0
    redactions: int = 0


def process_lines(lines: list[str], profile: anomaly.Profile | None = None) -> PipelineResult:
    """profile verilmezse yerel anomali profili kullanılır (yoksa anomali kontrolü yapılmaz)."""
    profile = profile or anomaly.default_profile()
    result = PipelineResult()
    seen: Counter[str] = Counter()
    for line in lines:
        req = apache.parse_line(line)
        if req is None:
            result.failed += 1
            continue
        # İmza ve anomali kontrolü maskelemeden ÖNCE, ham istek üzerinde (yalnızca bellekte);
        # olaya yalnızca kural adı / "parametre:tür" yazılır, değerlerin kendisi değil
        event = normalize(line, req, parser="apache_combined", occurrence=seen[line],
                          signatures=sigma.match(line, req),
                          anomalies=profile.check(req.path, req.query) if profile else [])
        seen[line] += 1
        result.redactions += event.redactions
        result.events.append(event)
    return result
