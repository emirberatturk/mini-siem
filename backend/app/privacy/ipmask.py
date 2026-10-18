"""IP adreslerini maskeleme (arayüzdeki lib/mask.ts ile aynı biçim: 93.x.x.x, 2a06:x:x::x).

IP adresi KVKK'ya göre kişisel veridir. Saklama süresi dolan alarmlarda adresin yalnızca ilk
bölümü kalır: hangi ağdan geldiği kabaca bilinir, kime ait olduğu bilinmez.

Metin içindeki adaylar önce kaba bir kalıpla bulunur, sonra ipaddress ile DOĞRULANIR: saat
(13:32:45) ya da onaltılık bir sözcük (cafe) adres sanılıp bozulmaz.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

# Kaba aday: adres olabilecek karakter dizileri. Asıl karar ipaddress doğrulamasında; bu yüzden
# harfe bitişik adresler de (ip2001:db8::1) yakalanır. Maskeli "2a06:x:x::x" içindeki "::"
# ise "belirtilmemiş adres" kontrolüne takılır ve bozulmaz.
_CANDIDATE = re.compile(r"[0-9A-Fa-f:.]{2,}")


def mask_ip(value: str) -> str:
    """Tek bir adres; adres değilse olduğu gibi döner. Maskeli adres tekrar maskelenmez."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return value
    if ip.is_unspecified:  # "::" ya da "0.0.0.0" kimseyi göstermez
        return value
    if ip.version == 4:
        return f"{value.split('.')[0]}.x.x.x"
    return f"{value.split(':')[0] or '0'}:x:x::x"


def _mask_candidate(match: re.Match[str]) -> str:
    token = match.group(0)
    # Baştaki/sondaki nokta ve iki nokta adresin parçası olmayabilir: "adres: 198.51.100.7.",
    # " :198.51.100.7", "IP..198.51.100.7". Önce olduğu gibi denenir ("::1" bozulmasın).
    for lead in dict.fromkeys((0, len(token) - len(token.lstrip(".:")))):
        body = token[lead:]
        for core in dict.fromkeys((body, body.rstrip("."), body.rstrip(".:"))):
            masked = mask_ip(core)
            if masked != core:
                return token[:lead] + masked + body[len(core):]
    return token


def mask_ips(text: str) -> str:
    return _CANDIDATE.sub(_mask_candidate, text)


def mask_deep(value: Any) -> Any:
    """İç içe sözlük/listedeki tüm metin DEĞERLERİNİ maskeler (anahtarlar değişmez)."""
    if isinstance(value, str):
        return mask_ips(value)
    if isinstance(value, list):
        return [mask_deep(v) for v in value]
    if isinstance(value, dict):
        return {k: mask_deep(v) for k, v in value.items()}
    return value
