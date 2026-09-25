from datetime import UTC, datetime

from app.parsers.apache import parse_line, parse_time


def test_combined_line():
    line = (
        '192.0.2.10 - - [23/Sep/2026:14:30:00 +0300] "GET /blog.html?sayfa=2 HTTP/1.1" '
        '200 5120 "https://www.ornek-klinik.com/" "Mozilla/5.0 (Windows NT 10.0)"'
    )

    req = parse_line(line)

    assert req is not None
    assert req.source_ip == "192.0.2.10"
    assert req.timestamp == datetime(2026, 9, 23, 11, 30, tzinfo=UTC)  # +0300 → UTC
    assert req.method == "GET"
    assert req.path == "/blog.html"
    assert req.query == "sayfa=2"
    assert req.status_code == 200
    assert req.bytes_sent == 5120
    assert req.user_agent == "Mozilla/5.0 (Windows NT 10.0)"


def test_common_format_without_referrer_and_ua():
    req = parse_line('192.0.2.10 - - [23/Sep/2026:14:30:00 +0000] "GET / HTTP/1.0" 304 -')

    assert req is not None
    assert req.bytes_sent == 0
    assert req.user_agent == "-"


def test_escaped_quote_in_user_agent():
    line = (
        '192.0.2.10 - - [23/Sep/2026:14:30:00 +0000] "GET / HTTP/1.1" 200 1 "-" '
        '"Bot \\"v2\\" (test)"'
    )

    req = parse_line(line)

    assert req is not None
    assert req.user_agent == 'Bot "v2" (test)'


def test_ipv6_is_normalized():
    req = parse_line('2001:DB8:0:0::1 - - [23/Sep/2026:14:30:00 +0000] "GET / HTTP/1.1" 200 1')

    assert req is not None
    assert req.source_ip == "2001:db8::1"


def test_malformed_request_line_is_kept_as_path():
    req = parse_line('192.0.2.10 - - [23/Sep/2026:14:30:00 +0000] "\\x16\\x03\\x01" 400 226')

    assert req is not None
    assert req.method is None
    assert req.status_code == 400


def test_control_characters_are_made_visible():
    line = (
        '192.0.2.10 - - [23/Sep/2026:14:30:00 +0000] "GET / HTTP/1.1" 200 1 "-" '
        '"UA\x1b[31mred"'
    )

    req = parse_line(line)

    assert req is not None
    assert "\x1b" not in req.user_agent
    assert "\\x1b" in req.user_agent


def test_garbage_lines_are_rejected():
    assert parse_line("merhaba dünya") is None
    assert parse_line('not-an-ip - - [23/Sep/2026:14:30:00 +0000] "GET / HTTP/1.1" 200 1') is None
    assert parse_line('192.0.2.1 - - [99/Foo/2026:14:30:00 +0000] "GET / HTTP/1.1" 200 1') is None


def test_parse_time_negative_offset():
    assert parse_time("01/Jan/2026:00:00:00 -0500") == datetime(2026, 1, 1, 5, tzinfo=UTC)
