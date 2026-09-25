"""Ölçüm aracı: CSIC biçimini doğru okumalı ve sonucu doğru saymalı (zararsız örneklerle)."""

from urllib.parse import quote

from app.parsers import apache
from app.tools.evaluate_signatures import access_log_line, evaluate, read_csic
from tests.test_sigma import SQLI, first_pattern

GET_BLOCK = """GET http://localhost:8080/tienda1/index.jsp?id=2&q={q} HTTP/1.1
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux)
Host: localhost:8080

"""
POST_BLOCK = """POST http://localhost:8080/tienda1/anadir.jsp HTTP/1.1
User-Agent: Mozilla/5.0
Content-Length: 10

q={q}

"""


def test_reads_requests_and_ignores_post_body(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text(GET_BLOCK.format(q="elma") + POST_BLOCK.format(q="armut"), encoding="latin-1")

    reqs = list(read_csic(f))

    assert [(r.method, r.target) for r in reqs] == [
        ("GET", "/tienda1/index.jsp?id=2&q=elma"), ("POST", "/tienda1/anadir.jsp")]
    assert reqs[0].user_agent.startswith("Mozilla/5.0 (compatible")
    assert apache.parse_line(access_log_line(reqs[0])) is not None


def test_counts_hits_and_false_alarms(tmp_path):
    attack = quote(first_pattern(SQLI), safe="")
    (tmp_path / "anomalousTrafficTest.txt").write_text(
        GET_BLOCK.format(q=attack) + GET_BLOCK.format(q="bozukdeger")
        + POST_BLOCK.format(q=attack), encoding="latin-1")
    (tmp_path / "normalTrafficTest.txt").write_text(
        GET_BLOCK.format(q="elma") * 3, encoding="latin-1")

    result = evaluate(tmp_path)

    assert dict(result["stats"]["GET"]) == {"TP": 1, "FN": 1, "TN": 3}
    assert dict(result["stats"]["Tümü"]) == {"TP": 1, "FN": 2, "TN": 3}  # POST gövdesi görünmez
    assert result["per_rule"] == {"sql_injection": 1}
