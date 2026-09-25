"""Ham satırlar → parse → imza kontrolü → sınıflandır → maskele → normalize olay."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from app.detection import sigma
from app.normalization.normalizer import normalize
from app.normalization.schema import NormalizedEvent
from app.parsers import apache


@dataclass
class PipelineResult:
    events: list[NormalizedEvent] = field(default_factory=list)
    failed: int = 0
    redactions: int = 0


def process_lines(lines: list[str]) -> PipelineResult:
    result = PipelineResult()
    seen: Counter[str] = Counter()
    for line in lines:
        req = apache.parse_line(line)
        if req is None:
            result.failed += 1
            continue
        # İmza kontrolü maskelemeden ÖNCE, ham istek üzerinde (yalnızca bellekte)
        event = normalize(line, req, parser="apache_combined", occurrence=seen[line],
                          signatures=sigma.match(line, req))
        seen[line] += 1
        result.redactions += event.redactions
        result.events.append(event)
    return result
