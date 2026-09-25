import gzip

import pytest

from app.ingestion.reader import (
    PayloadTooLarge,
    UnsupportedContent,
    read_log_lines,
    sniff_format,
)

APACHE_LINE = (
    '192.0.2.10 - - [23/Sep/2026:14:00:00 +0300] "GET /index.html HTTP/1.1" 200 5120 '
    '"-" "Mozilla/5.0"'
)
LIMITS = {"max_decompressed": 1024 * 1024, "max_line_length": 200}


def test_plain_text_lines():
    data = f"{APACHE_LINE}\n{APACHE_LINE}\n".encode()

    result = read_log_lines(data, **LIMITS)

    assert result.lines == [APACHE_LINE, APACHE_LINE]
    assert result.compressed is False
    assert result.lines_empty == 0
    assert result.format_hint == "apache_combined"


def test_gzip_is_detected_by_content_not_filename():
    data = gzip.compress(f"{APACHE_LINE}\n".encode())

    result = read_log_lines(data, **LIMITS)

    assert result.compressed is True
    assert result.lines == [APACHE_LINE]


def test_crlf_and_blank_lines():
    data = f"{APACHE_LINE}\r\n\r\n   \r\n{APACHE_LINE}\r\n".encode()

    result = read_log_lines(data, **LIMITS)

    assert result.lines == [APACHE_LINE, APACHE_LINE]
    assert result.lines_empty == 2


def test_exotic_line_separators_do_not_split_lines():
    # \x0b, \x1c ve   ile sahte satır üretme (log injection) denemesi tek satır kalmalı
    line = "192.0.2.10 a\x0bb\x1cc d"

    result = read_log_lines(f"{line}\n".encode(), **LIMITS)

    assert result.lines == [line]


def test_long_lines_are_truncated():
    data = ("x" * 500 + "\n").encode()

    result = read_log_lines(data, **LIMITS)

    assert len(result.lines[0]) == 200
    assert result.lines_truncated == 1


def test_gzip_bomb_is_rejected():
    # 5 MB sıfır → birkaç KB gzip; açılmış sınır 1 MB
    bomb = gzip.compress(b"A" * 5 * 1024 * 1024)
    assert len(bomb) < 50 * 1024

    with pytest.raises(PayloadTooLarge):
        read_log_lines(bomb, **LIMITS)


def test_binary_file_is_rejected():
    png_header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"

    with pytest.raises(UnsupportedContent):
        read_log_lines(png_header, **LIMITS)


def test_corrupt_gzip_is_rejected():
    with pytest.raises(UnsupportedContent):
        read_log_lines(b"\x1f\x8b\x08\x00bozuk", **LIMITS)


def test_empty_file():
    result = read_log_lines(b"", **LIMITS)

    assert result.lines == []
    assert result.lines_empty == 0
    assert result.format_hint == "empty"


def test_sniff_csic_and_unknown():
    assert sniff_format(["GET http://localhost:8080/tienda1/index.jsp HTTP/1.1"]) == "csic_http"
    assert sniff_format(["merhaba dünya"]) == "unknown"
