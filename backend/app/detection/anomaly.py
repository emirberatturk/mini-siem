"""Anomali tespiti: normal trafikten her (yol, parametre) için bir profil öğrenir, sapanı işaretler.

İmzalar bilinen saldırı kalıplarını arar; parametre kurcalama (geçersiz, çok uzun ya da
beklenmeyen karakterli değer) hiçbir kalıba uymaz. Bu modül "bu parametre normalde nasıl
görünür?" sorusunu öğrenir:
- uzunluk: öğrenilen en uzun değerden belirgin şekilde uzun mu?
- karakter: bu parametrede hiç görülmemiş bir karakter türü var mı? (rakam beklenen yerde ')
- parametre: bu yolda hiç görülmemiş bir parametre adı mı?

KVKK: profil yalnızca istatistik tutar (sayılar, en uzun değer uzunluğu, karakter türü
sayaçları); hiçbir parametre değeri saklanmaz. Kontrol, imzalarda olduğu gibi maskelemeden
önce bellekteki ham istek üzerinde yapılır; veritabanına yalnızca "parametre:tür" yazılır.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from urllib.parse import parse_qsl, unquote_plus

from app.core.config import settings as app_settings
from app.privacy.redactor import redact_text

log = logging.getLogger(__name__)

PROFILE_VERSION = 1


def char_classes(value: str) -> set[str]:
    """Değerdeki karakter türleri. Harf ve rakamlar gruplanır (hangi harf olduğu önemsiz);
    geri kalan her karakter kendi başına bir türdür (' < ; gibi)."""
    out = set()
    for ch in value:
        if ch.isdigit():
            out.add("rakam")
        elif ch.isalpha():
            out.add("harf")
        elif ch == " ":
            out.add("boşluk")
        else:
            out.add(ch)
    return out


def request_params(query: str) -> list[tuple[str, str]]:
    """(ad, çözülmüş değer) çiftleri. Çift URL kodlaması da çözülür (%2527 → ')."""
    return [(k, unquote_plus(v)) for k, v in parse_qsl(query, keep_blank_values=True)]


@dataclass
class ParamProfile:
    n: int = 0
    max_len: int = 0
    chars: dict[str, int] = field(default_factory=dict)  # tür → kaç değerde görüldü

    def learn(self, value: str) -> None:
        self.n += 1
        self.max_len = max(self.max_len, len(value))
        for c in char_classes(value):
            self.chars[c] = self.chars.get(c, 0) + 1


@dataclass
class Settings:
    min_samples: int = 20  # bundan az örneği olan profil hakkında yorum yapılmaz
    length_factor: float = 1.5  # en uzun değerin bu katından uzunsa…
    length_margin: int = 5  # …ve en az bu kadar karakter fazlaysa "uzunluk" anomalisi
    rare_ratio: float = 0.001  # değerlerin bu oranından azında görülen tür "görülmemiş" sayılır
    # Bilinen bir yolda hiç görülmemiş parametre adı. Varsayılan KAPALI: gerçek sitelerde reklam
    # ve analiz araçları (utm_source, fbclid…) sürekli yeni parametre ekler; CSIC 2010'da ise bu
    # bulgu, veri setinin saldırıları üretme biçiminden kalan bir izle (idA, nombreA) şişiyor.
    unknown_params: bool = False


@dataclass
class Profile:
    paths: dict[str, dict[str, ParamProfile]] = field(default_factory=dict)
    path_counts: dict[str, int] = field(default_factory=dict)  # yol başına öğrenilen istek
    settings: Settings = field(default_factory=Settings)

    # ── öğrenme ──────────────────────────────────────────────────────────────
    def learn(self, path: str, query: str) -> None:
        if redact_text(path).count:
            return  # yolun kendisinde kişisel veri var (e-posta, telefon…): hiç öğrenilmez
        key = path.lower()
        self.path_counts[key] = self.path_counts.get(key, 0) + 1
        params = self.paths.setdefault(key, {})
        for name, value in request_params(query):
            params.setdefault(name, ParamProfile()).learn(value)

    # ── kontrol ──────────────────────────────────────────────────────────────
    def check(self, path: str, query: str) -> list[str]:
        """Bu istekteki sapmalar: ["cantidad:uzunluk", "id:karakter", "x:parametre"].
        Değerlerin kendisi döndürülmez."""
        key = path.lower()
        s = self.settings
        if self.path_counts.get(key, 0) < s.min_samples:
            return []  # yolu yeterince tanımıyoruz: yorum yok
        known = self.paths.get(key, {})
        findings: list[str] = []
        for name, value in request_params(query):
            prof = known.get(name)
            if prof is None:
                if s.unknown_params:
                    findings.append(f"{name}:parametre")
                continue
            if prof.n < s.min_samples:
                continue
            if len(value) > prof.max_len * s.length_factor and \
                    len(value) > prof.max_len + s.length_margin:
                findings.append(f"{name}:uzunluk")
            if any(prof.chars.get(c, 0) < prof.n * s.rare_ratio for c in char_classes(value)):
                findings.append(f"{name}:karakter")
        return list(dict.fromkeys(findings))

    def pruned(self) -> Profile:
        """Veri minimizasyonu: yalnızca yorum yapılabilecek kadar örneği olan yollar ve
        parametreler kalır (botların tek seferlik denediği yollar saklanmaz). Tespit sonucu
        değişmez: az örnekli yol/parametre hakkında zaten yorum yapılmıyordu."""
        keep = {p for p, c in self.path_counts.items() if c >= self.settings.min_samples}
        return Profile(
            paths={p: {n: pp for n, pp in params.items() if pp.n >= self.settings.min_samples}
                   for p, params in self.paths.items() if p in keep},
            path_counts={p: c for p, c in self.path_counts.items() if p in keep},
            settings=self.settings,
        )

    # ── dosya ────────────────────────────────────────────────────────────────
    def to_json(self) -> dict:
        return {
            "version": PROFILE_VERSION,
            "note": "Yalnızca istatistik; parametre değerleri saklanmaz (KVKK).",
            "path_counts": self.path_counts,
            "paths": {p: {n: {"n": pp.n, "max_len": pp.max_len, "chars": pp.chars}
                          for n, pp in params.items()}
                      for p, params in self.paths.items()},
        }

    @classmethod
    def from_json(cls, data: dict, settings: Settings | None = None) -> Profile:
        if data.get("version") != PROFILE_VERSION:
            raise ValueError("desteklenmeyen profil sürümü")
        return cls(
            paths={p: {n: ParamProfile(v["n"], v["max_len"], dict(v["chars"]))
                       for n, v in params.items()}
                   for p, params in data["paths"].items()},
            path_counts=dict(data["path_counts"]),
            settings=settings or Settings(),
        )

    def save(self, path: Path) -> None:
        data = self.pruned().to_json()  # diske yalnızca gereken kadarı yazılır
        path.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")

    @classmethod
    def load(cls, path: Path, settings: Settings | None = None) -> Profile:
        return cls.from_json(json.loads(path.read_text(encoding="utf-8")), settings)


@cache
def default_profile() -> Profile | None:
    """Yerel profil (config/anomaly_profile.local.json). Yoksa anomali kontrolü yapılmaz."""
    path = app_settings.anomaly_profile
    if not app_settings.use_local_config or not path.exists():
        return None
    try:
        return Profile.load(path)
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        log.warning("Anomali profili yüklenemedi (%s): kontrol yapılmayacak", exc)
        return None


def train(requests: Iterable[tuple[str, str]], settings: Settings | None = None) -> Profile:
    """(yol, sorgu) çiftlerinden profil öğrenir."""
    profile = Profile(settings=settings or Settings())
    for path, query in requests:
        profile.learn(path, query)
    return profile
