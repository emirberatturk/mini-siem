"""İmza bilgisinin API'de görünmesi: olaylar, arama filtresi, genel bakış, kurallar."""

from urllib.parse import quote

from tests.test_sigma import SQLI, first_pattern

ATTACK = quote(first_pattern(SQLI), safe="")
LOG = "\n".join([
    f'203.0.113.10 - - [23/Sep/2026:14:00:00 +0300] "GET /urun.php?id={ATTACK} HTTP/1.1" '
    '403 1 "-" "UA"',
    '192.0.2.10 - - [23/Sep/2026:14:05:00 +0300] "GET /blog.html HTTP/1.1" 200 1 "-" "UA"',
]).encode()


def seed(client):
    assert client.post("/api/v1/ingest/upload", files={"file": ("a.log", LOG)}).status_code == 200


def test_events_carry_signatures_and_can_be_filtered(client):
    seed(client)

    def events(**params):
        r = client.get("/api/v1/events", params=params)
        assert r.status_code == 200, r.text
        return r.json()["items"]

    assert sorted(e["signatures"] for e in events()) == [[], ["sql_injection"]]
    assert [e["source_ip"] for e in events(signature="any")] == ["203.0.113.10"]
    assert len(events(signature="sql_injection")) == 1
    assert events(signature="xss") == []
    assert events(signature="sql_injectio_") == []  # _ joker değil, düz karakter


def test_signature_filter_rejects_odd_input(client):
    for bad in ["sql%", "SQL", "a,b", "x" * 65, "' or 1=1"]:
        r = client.get("/api/v1/events", params={"signature": bad})
        assert r.status_code == 422, bad


def test_overview_lists_signatures_including_blocked(client):
    seed(client)

    [sig] = client.get("/api/v1/stats/overview").json()["top_signatures"]

    assert sig == {"key": "sql_injection", "label": "SQL Injection Strings In URI",
                   "count": 1, "blocked": 1}


def test_rules_endpoint_shows_sigma_rules(client):
    rules = {r["id"]: r for r in client.get("/api/v1/rules").json()}

    sig = rules["SIG-001"]
    assert sig["alert_on"] == "success"
    assert len(sig["signature_rules"]) == 10
    assert all(r["author"] for r in sig["signature_rules"])  # DRL: yazar bilgisi korunur
    assert rules["AUTH-001"]["signature_rules"] == []
