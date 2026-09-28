"""Anomali modeli: öğrenme, sapma türleri, yorum yapmama durumları ve KVKK (değer saklanmaz)."""

import json

from app.detection import anomaly

NORMAL = [("/urun.php", f"id={i}&adet={i % 5 + 1}&renk=kirmizi") for i in range(1, 41)]


def profile(**settings):
    return anomaly.train(NORMAL, anomaly.Settings(**settings))


def test_normal_request_has_no_findings():
    assert profile().check("/urun.php", "id=17&adet=3&renk=mavi") == []


def test_unseen_character_type():
    # id hep rakamdı: harf ve tırnak görülmemiş türler
    assert profile().check("/urun.php", "id=abc") == ["id:karakter"]
    assert profile().check("/urun.php", "id=5%27") == ["id:karakter"]  # URL kodlu tırnak


def test_double_encoding_does_not_hide_characters():
    assert profile().check("/urun.php", "id=5%2527") == ["id:karakter"]


def test_double_encoding_is_decoded_even_where_percent_is_normal():
    # Bu parametrede % normal (ör. "%50 indirim"): tek çözülse "%27" masum görünürdü;
    # iki kez çözülünce ortaya çıkan ' hiç görülmemiş bir tür olmalı
    # (%in onaltılık değil: çift çözümde de "%indirim" olarak kalır → % ve rakam normal)
    p = anomaly.train([("/kampanya.php", f"oran=%25indirim{i}") for i in range(1, 31)])
    assert p.check("/kampanya.php", "oran=%25indirim7") == []
    # tek çözüm: "%27" (% ve rakam, ikisi de normal) · çift çözüm: "'" (hiç görülmemiş)
    assert p.check("/kampanya.php", "oran=%2527") == ["oran:karakter"]


def test_too_long_value():
    # id en fazla 2 haneydi; 40 hanelik sayı karakter olarak normal ama uzunluk olarak değil
    assert profile().check("/urun.php", "id=" + "1" * 40) == ["id:uzunluk"]


def test_short_growth_is_tolerated():
    assert profile().check("/urun.php", "id=123") == []  # 2 → 3 hane: pay içinde


def test_no_opinion_on_unknown_or_rare_paths():
    p = profile()
    assert p.check("/baska.php", "q=<<<") == []  # hiç görülmemiş yol
    rare = anomaly.train([("/az.php", "x=1")] * 5)  # min_samples altında
    assert rare.check("/az.php", "x=<<<") == []


def test_unknown_parameter_is_off_by_default_and_optional():
    assert profile().check("/urun.php", "id=1&utm_source=reklam") == []
    assert profile(unknown_params=True).check("/urun.php", "id=1&utm_source=x") == [
        "utm_source:parametre"]


def test_path_matching_is_case_insensitive():
    assert profile().check("/URUN.PHP", "id=abc") == ["id:karakter"]


def test_profile_roundtrip(tmp_path):
    p = profile()
    f = tmp_path / "profil.local.json"
    p.save(f)
    loaded = anomaly.Profile.load(f)

    assert loaded.check("/urun.php", "id=abc") == ["id:karakter"]
    assert loaded.to_json() == p.to_json()


def test_profile_stores_statistics_not_values():
    marker = "gizli-deger-zzq"
    p = anomaly.train([("/form.php", f"ad={marker}{i}") for i in range(30)])

    dumped = json.dumps(p.to_json(), ensure_ascii=False)
    assert marker not in dumped  # KVKK: değerlerin kendisi hiçbir yerde yok
    assert '"max_len"' in dumped and '"chars"' in dumped


def test_saved_profile_keeps_only_what_is_needed(tmp_path):
    p = anomaly.train(NORMAL + [("/bot-denemesi.php", "x=1")] * 3
                      + [("/urun.php", "nadir=1")] * 2)
    f = tmp_path / "profil.local.json"
    p.save(f)
    data = json.loads(f.read_text(encoding="utf-8"))

    assert list(data["paths"]) == ["/urun.php"]  # 3 kez denenmiş bot yolu saklanmadı
    assert "nadir" not in data["paths"]["/urun.php"]  # 2 örnekli parametre saklanmadı
    loaded = anomaly.Profile.load(f)
    assert loaded.check("/urun.php", "id=abc") == p.check("/urun.php", "id=abc")  # sonuç aynı


def test_paths_containing_personal_data_are_never_learned():
    p = anomaly.train([("/profil/ornek.kisi@example.com", "sekme=1")] * 30
                      + [("/rapor/05551234567", "s=1")] * 30)

    dumped = json.dumps(p.to_json(), ensure_ascii=False)
    assert "example.com" not in dumped and "05551234567" not in dumped
    assert p.check("/profil/ornek.kisi@example.com", "sekme=<<<") == []  # yorum yok


def test_findings_never_contain_values():
    findings = profile().check("/urun.php", "id=05551234567abc")
    assert findings == ["id:uzunluk", "id:karakter"]
    assert all("0555" not in f for f in findings)
