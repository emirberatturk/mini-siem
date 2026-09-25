"""Yüklenen log dosyasını güvenli şekilde satırlara ayırır.

Buraya gelen veri saldırganın kontrolündedir (log satırlarını saldırganın istekleri oluşturur),
bu yüzden dosya adına/uzantısına değil içeriğe bakarız ve her aşamada boyut sınırı uygularız.
"""

from __future__ import annotations

import gzip
import io
import re
import zlib
from dataclasses import dataclass

GZIP_MAGIC = b"\x1f\x8b"
_CHUNK = 64 * 1024

# Biçim tahmini için gevşek kalıplar; asıl ayrıştırma Faz 3'teki parser'larda.
_APACHE_COMBINED = re.compile(r'^\S+ \S+ \S+ \[[^\]]+\] "[^"]*" \d{3} (\d+|-)')
_CSIC_REQUEST = re.compile(r"^(GET|POST|PUT) https?://\S+ HTTP/1\.[01]$")


class IngestError(ValueError):
    """Yüklenen dosya işlenemez."""


class PayloadTooLarge(IngestError):
    pass


class UnsupportedContent(IngestError):
    pass


@dataclass
class ReadResult:
    lines: list[str]
    compressed: bool
    decompressed_bytes: int
    lines_empty: int
    lines_truncated: int
    format_hint: str


def decompress_if_gzip(data: bytes, max_bytes: int) -> tuple[bytes, bool]:
    """Gzip ise parça parça açar; sınır aşılırsa hemen durur (tamamını belleğe açmaz)."""
    if not data.startswith(GZIP_MAGIC):
        return data, False

    out = bytearray()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
            while chunk := gz.read(_CHUNK):
                out += chunk
                if len(out) > max_bytes:
                    raise PayloadTooLarge(
                        f"Açılmış içerik {max_bytes // (1024 * 1024)} MB sınırını aşıyor"
                    )
    except (OSError, EOFError, zlib.error) as exc:
        raise UnsupportedContent("Bozuk gzip dosyası") from exc
    return bytes(out), True


def sniff_format(lines: list[str], sample: int = 50) -> str:
    head = [ln for ln in lines[:sample] if ln]
    if not head:
        return "empty"
    if sum(bool(_APACHE_COMBINED.match(ln)) for ln in head) >= len(head) * 0.8:
        return "apache_combined"
    if _CSIC_REQUEST.match(head[0]):
        return "csic_http"
    return "unknown"


def read_log_lines(data: bytes, *, max_decompressed: int, max_line_length: int) -> ReadResult:
    content, compressed = decompress_if_gzip(data, max_decompressed)

    # Metin dosyasında NUL bayt olmaz; varsa resim/exe gibi ikili bir dosya yüklenmiştir.
    if b"\x00" in content[:8192]:
        raise UnsupportedContent("Dosya metin değil (ikili içerik)")

    text = content.decode("utf-8", errors="replace")

    # str.splitlines() KULLANMIYORUZ: \x0b, \x0c, \x1c,   gibi karakterlerde de satır böler.
    # Saldırgan bunları isteğine koyup log'da sahte satır üretebilir (log injection).
    # Apache her kaydı \n ile bitirir; sadece ona güveniyoruz.
    lines: list[str] = []
    empty = truncated = 0
    for raw in text.split("\n"):
        line = raw.rstrip("\r")
        if not line.strip():
            empty += 1
            continue
        if len(line) > max_line_length:
            line = line[:max_line_length]
            truncated += 1
        lines.append(line)

    if text.endswith("\n") or not text:
        empty -= 1  # dosya sonundaki \n'den (veya boş dosyadan) doğan parça gerçek bir satır değil

    return ReadResult(
        lines=lines,
        compressed=compressed,
        decompressed_bytes=len(content),
        lines_empty=empty,
        lines_truncated=truncated,
        format_hint=sniff_format(lines),
    )
