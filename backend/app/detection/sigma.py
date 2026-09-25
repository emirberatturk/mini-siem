"""İmza tabanlı tespit: SigmaHQ web sunucusu kurallarının küçük bir alt kümesini çalıştırır.

Kurallar log yüklenirken bellekteki HAM istek üzerinde değerlendirilir (KVKK maskelemesinden
önce), çünkü saldırgan saldırı metnini maskelenen bir alana (ör. email=) koyabilir. Veritabanına
yalnızca eşleşen kuralın adı yazılır; ham istek ve eşleşen metin hiçbir yere kaydedilmez.

Desteklenen Sigma alt kümesi:
- alan eşleşmesi: tam değer ve |contains, |startswith, |endswith (büyük/küçük harf duyarsız)
- anahtar kelime listeleri: log satırının tamamında arama
- koşullar: and, or, not, parantez, "1 of x*", "all of x*", "1 of them", "all of them"
Desteklenmeyen bir yapı görülürse kural hiç yüklenmez: sessizce yanlış çalışmaktansa
eksik olduğu bilinsin.
"""

from __future__ import annotations

import fnmatch
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from urllib.parse import unquote_plus

import yaml

from app.core.config import settings
from app.parsers.apache import ParsedRequest

log = logging.getLogger(__name__)

# SigmaHQ etiketlerinden bilerek ayrıldığımız yerler (ilke: yalnızca birebir örtüşen eşleme).
# ssti: T1221 "Template Injection" Office belgelerine şablon enjeksiyonudur; web sunucusunda
# şablon motoru istismarı ise T1190 (Exploit Public-Facing Application).
MITRE_OVERRIDES = {"ssti": ["T1190"]}

LEVELS = {"informational": "low", "low": "low", "medium": "medium", "high": "high",
          "critical": "critical"}


class SigmaError(ValueError):
    """Kural, desteklenen Sigma alt kümesinin dışında."""


@dataclass(frozen=True)
class RequestView:
    """Bir isteğin kurallara gösterilen hali. Değerler küçük harfe çevrilmiş ve URL
    kodlaması çözülmüş biçimleriyle birlikte tutulur (saldırgan %27 yazarak ' gizleyebilir)."""

    line: tuple[str, ...]
    fields: dict[str, tuple[str, ...]]

    @classmethod
    def build(cls, raw_line: str, req: ParsedRequest) -> RequestView:
        uri = f"{req.path}?{req.query}" if req.query else req.path
        return cls(
            line=_variants(raw_line),
            fields={
                "cs-method": _variants(req.method or ""),
                "cs-uri-stem": _variants(req.path),
                "cs-uri-query": _variants(req.query),
                "cs-uri": _variants(uri),
                "cs-user-agent": _variants(req.user_agent),
                "cs-referer": _variants(req.referrer),
                "sc-status": (str(req.status_code),),
            },
        )


def _variants(value: str) -> tuple[str, ...]:
    once = unquote_plus(value)
    twice = unquote_plus(once)  # çift kodlama: %2527 → %27 → '
    return tuple(dict.fromkeys(v.lower() for v in (value, once, twice)))


Matcher = Callable[[RequestView], bool]

KNOWN_FIELDS = frozenset({"cs-method", "cs-uri-stem", "cs-uri-query", "cs-uri", "cs-user-agent",
                          "cs-referer", "sc-status"})

_MODIFIERS: dict[str, Callable[[str, str], bool]] = {
    "": lambda have, want: have == want,
    "contains": lambda have, want: want in have,
    "startswith": lambda have, want: have.startswith(want),
    "endswith": lambda have, want: have.endswith(want),
}


def _field_matcher(key: str, wanted: object) -> Matcher:
    name, _, modifier = key.partition("|")
    if name not in KNOWN_FIELDS:
        raise SigmaError(f"bilinmeyen alan: {name}")
    if modifier not in _MODIFIERS:
        raise SigmaError(f"desteklenmeyen değiştirici: {key}")
    values = wanted if isinstance(wanted, list) else [wanted]
    if not all(isinstance(v, (str, int)) for v in values):
        raise SigmaError(f"desteklenmeyen değer türü: {key}")
    wants = [str(v).lower() for v in values]
    test = _MODIFIERS[modifier]

    return lambda view: any(test(have, w) for have in view.fields[name] for w in wants)


def _item_matcher(item: object) -> Matcher:
    if isinstance(item, list):  # anahtar kelimeler: satırın herhangi bir yerinde
        if not all(isinstance(k, (str, int)) for k in item):
            raise SigmaError("anahtar kelime listesinde metin olmayan değer")
        words = [str(k).lower() for k in item]
        return lambda view: any(w in line for line in view.line for w in words)
    if isinstance(item, dict):  # alanlar: hepsi sağlanmalı (VE)
        parts = [_field_matcher(k, v) for k, v in item.items()]
        return lambda view: all(p(view) for p in parts)
    raise SigmaError(f"desteklenmeyen tespit öğesi: {type(item).__name__}")


_TOKEN = re.compile(r"\(|\)|[A-Za-z0-9_*]+")


class _Condition:
    """Küçük bir özyinelemeli ayrıştırıcı: or < and < not < (…) / 1 of / all of / isim."""

    def __init__(self, text: str, items: dict[str, Matcher]):
        self.tokens = _TOKEN.findall(text)
        if "".join(self.tokens) != re.sub(r"\s+", "", text):
            raise SigmaError(f"koşul ayrıştırılamadı: {text}")
        self.items, self.pos = items, 0

    def parse(self) -> Matcher:
        m = self._or()
        if self.pos != len(self.tokens):
            raise SigmaError(f"koşulun sonu beklenmiyordu: {self.tokens[self.pos:]}")
        return m

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _take(self) -> str:
        tok = self._peek()
        if tok is None:
            raise SigmaError("koşul yarıda bitti")
        self.pos += 1
        return tok

    def _or(self) -> Matcher:
        parts = [self._and()]
        while self._peek() == "or":
            self._take()
            parts.append(self._and())
        return parts[0] if len(parts) == 1 else (lambda v: any(p(v) for p in parts))

    def _and(self) -> Matcher:
        parts = [self._not()]
        while self._peek() == "and":
            self._take()
            parts.append(self._not())
        return parts[0] if len(parts) == 1 else (lambda v: all(p(v) for p in parts))

    def _not(self) -> Matcher:
        if self._peek() == "not":
            self._take()
            inner = self._not()
            return lambda v: not inner(v)
        return self._atom()

    def _atom(self) -> Matcher:
        tok = self._take()
        if tok == "(":
            inner = self._or()
            if self._take() != ")":
                raise SigmaError("kapanmayan parantez")
            return inner
        if tok in ("1", "all") and self._peek() == "of":
            self._take()
            group = self._select(self._take())
            return (lambda v: any(m(v) for m in group)) if tok == "1" else (
                lambda v: all(m(v) for m in group))
        if tok not in self.items:
            raise SigmaError(f"koşulda bilinmeyen isim: {tok}")
        return self.items[tok]

    def _select(self, pattern: str) -> list[Matcher]:
        names = list(self.items) if pattern == "them" else fnmatch.filter(self.items, pattern)
        if not names:
            raise SigmaError(f"desene uyan öğe yok: {pattern}")
        return [self.items[n] for n in names]


@dataclass(frozen=True)
class SigmaRule:
    name: str  # kısa ad, veritabanına bu yazılır (ör. "sql_injection")
    title: str
    level: str  # low / medium / high / critical
    mitre: list[str] = field(default_factory=list)
    author: str = ""
    sigma_id: str = ""
    matches: Matcher = field(default=lambda _v: False, repr=False, compare=False)


def short_name(path: Path) -> str:
    return path.stem.removeprefix("web_").removesuffix("_in_access_logs")


def parse_rule(data: dict, name: str) -> SigmaRule:
    if (data.get("logsource") or {}).get("category") != "webserver":
        raise SigmaError("yalnızca 'webserver' kategorisindeki kurallar desteklenir")
    detection = dict(data.get("detection") or {})
    condition = detection.pop("condition", None)
    if not isinstance(condition, str):
        raise SigmaError("koşul (condition) tek bir metin olmalı")
    if "timeframe" in detection:
        raise SigmaError("timeframe (toplama) desteklenmiyor")
    items = {k: _item_matcher(v) for k, v in detection.items()}
    matcher = _Condition(condition, items).parse()
    mitre = MITRE_OVERRIDES.get(name) or sorted(
        {t.removeprefix("attack.").upper() for t in data.get("tags", [])
         if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)})
    return SigmaRule(
        name=name, title=str(data.get("title", name)),
        level=LEVELS.get(str(data.get("level", "medium")), "medium"),
        mitre=mitre, author=str(data.get("author", "")), sigma_id=str(data.get("id", "")),
        matches=matcher,
    )


def load_rules(directory: Path) -> list[SigmaRule]:
    rules = []
    for path in sorted(directory.glob("*.yml")):
        try:
            # safe_load: yaml.load() dosyadaki etiketlerle Python nesnesi (ve kod) çalıştırabilir
            rules.append(parse_rule(yaml.safe_load(path.read_text(encoding="utf-8")),
                                    short_name(path)))
        except (SigmaError, yaml.YAMLError) as exc:
            log.warning("Sigma kuralı yüklenmedi: %s (%s)", path.name, exc)
    return rules


@cache
def default_rules() -> tuple[SigmaRule, ...]:
    return tuple(load_rules(settings.sigma_rules_dir))


def match(raw_line: str, req: ParsedRequest,
          rules: tuple[SigmaRule, ...] | list[SigmaRule] | None = None) -> list[str]:
    """Bu istekle eşleşen kuralların kısa adları. Ham istek bellekte kalır, döndürülmez."""
    view = RequestView.build(raw_line, req)
    return [r.name for r in (default_rules() if rules is None else rules) if r.matches(view)]


def rule_by_name() -> dict[str, SigmaRule]:
    return {r.name: r for r in default_rules()}
