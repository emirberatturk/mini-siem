"""Apache Combined / Common Log Format parser'ı (cPanel "Raw Access Logs" bu biçimdedir).

    %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
    192.0.2.1 - - [23/Sep/2026:14:00:00 +0300] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0"
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from urllib.parse import unquote, urlsplit

# Apache tırnak içindeki " karakterini \" olarak kaçırır; bu yüzden [^"]* yeterli değil.
_QUOTED = r'"((?:[^"\\]|\\.)*)"'
_LINE = re.compile(
    r"^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "
    + _QUOTED.replace("(", "(?P<request>", 1)
    + r" (?P<status>\d{3}) (?P<size>\d+|-)"
    + r"(?: "
    + _QUOTED.replace("(", "(?P<referrer>", 1)
    + r" "
    + _QUOTED.replace("(", "(?P<ua>", 1)
    + r")?\s*$"
)
_TIME = re.compile(r"^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$")
# strptime'ın %b'si işletim sistemi diline bağlı olabilir; ay adlarını kendimiz çözüyoruz.
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


@dataclass
class ParsedRequest:
    """Parser çıktısı: HENÜZ maskelenmemiş, sadece bellekte yaşar, asla saklanmaz."""

    timestamp: datetime  # UTC
    source_ip: str
    method: str | None
    path: str
    query: str
    protocol: str | None
    status_code: int
    bytes_sent: int
    referrer: str
    user_agent: str


def clean(text: str) -> str:
    """Kontrol karakterlerini görünür hale getirir (\\x1b gibi): terminal/log injection'a karşı."""
    return _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", text)


def parse_time(value: str) -> datetime | None:
    m = _TIME.match(value)
    if not m or m.group(2) not in _MONTHS:
        return None
    day, mon, year, hh, mm, ss, sign, oh, om = m.groups()
    offset = timedelta(hours=int(oh), minutes=int(om)) * (1 if sign == "+" else -1)
    try:
        local = datetime(int(year), _MONTHS[mon], int(day), int(hh), int(mm), int(ss),
                         tzinfo=timezone(offset))
    except ValueError:
        return None
    return local.astimezone(UTC)


def _unescape(value: str) -> str:
    return value.replace('\\"', '"').replace("\\\\", "\\")


def parse_line(line: str) -> ParsedRequest | None:
    m = _LINE.match(line)
    if not m:
        return None

    ts = parse_time(m["time"])
    if ts is None:
        return None
    try:
        ip = str(ipaddress.ip_address(m["ip"]))  # normalize eder; IP değilse reddeder
    except ValueError:
        return None

    method, target, protocol = None, "", None
    request = _unescape(m["request"])
    parts = request.split(" ")
    if len(parts) == 3 and parts[0].isalpha() and parts[0].isupper():
        method, target, protocol = parts
    elif request != "-":
        target = request  # bozuk/ikili istek satırı: tarayıcıların ürettiği bir şey değil

    split = urlsplit(target) if target.startswith(("/", "http://", "https://")) else None
    path = split.path if split else target
    query = split.query if split else ""

    return ParsedRequest(
        timestamp=ts,
        source_ip=ip,
        method=method,
        # Yol, okunabilirlik ve tespit için URL-decode edilir (%2e%2e → ..)
        path=clean(unquote(path, errors="replace"))[:2048] or "/",
        query=query,
        protocol=protocol,
        status_code=int(m["status"]),
        bytes_sent=0 if m["size"] == "-" else int(m["size"]),
        referrer=clean(_unescape(m["referrer"] or "-")),
        user_agent=clean(_unescape(m["ua"] or "-"))[:1024],
    )
