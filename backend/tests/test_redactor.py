"""Tüm kişisel veriler SAHTEDİR: example.com alan adı, 0555 000 00 00, test TC numarası."""

from app.privacy.redactor import (
    MASK,
    is_valid_tckn,
    redact_query,
    redact_referrer,
    redact_text,
)

FAKE_TCKN = "10000000146"  # kontrol haneleri geçerli, yaygın kullanılan test numarası


def test_tckn_checksum():
    assert is_valid_tckn(FAKE_TCKN)
    assert not is_valid_tckn("10000000147")  # son hane yanlış
    assert not is_valid_tckn("01234567890")  # 0 ile başlayamaz


def test_redact_text_finds_email_phone_tckn():
    r = redact_text(f"deneme@example.com 0555 000 00 00 {FAKE_TCKN}")

    assert r.value == f"{MASK} {MASK} {MASK}"
    assert r.count == 3


def test_phone_variants():
    for phone in ["05550000000", "+90 555 000 00 00", "555-000-00-00"]:
        assert redact_text(phone).value == MASK, phone


def test_random_11_digit_number_is_not_masked():
    # Zaman damgası/sipariş no gibi değerler, TC kontrol hanesini tutmadığı için korunur
    assert redact_text("siparis 12345678901").count == 0


def test_pii_page_masks_every_value():
    r = redact_query("/randevu.html", "ad=Deneme+Hasta&tarih=2026-09-24&saat=10:00")

    assert r.value == f"ad={MASK}&tarih={MASK}&saat={MASK}"
    assert r.count == 3


def test_pii_api_type_masks_values_but_keeps_type():
    r = redact_query("/app.php", "type=randevu_olustur&not=dis+agrisi")

    assert r.value == f"type=randevu_olustur&not={MASK}"


def test_sensitive_param_names_masked_on_any_page():
    r = redact_query("/blog.html", "sayfa=2&email=deneme%40example.com&sifre=gizli")

    assert r.value == f"sayfa=2&email={MASK}&sifre={MASK}"


def test_normal_query_untouched():
    r = redact_query("/app.php", "type=musait_saatler&tarih=2026-09-24")

    assert r.value == "type=musait_saatler&tarih=2026-09-24"
    assert r.count == 0


def test_pii_inside_unnamed_value_is_found():
    r = redact_query("/blog.html", "q=ara+05550000000")

    assert r.value == f"q=ara {MASK}"


def test_referrer_query_is_dropped():
    r = redact_referrer("https://www.ornek-klinik.com/randevu.html?tel=05550000000")

    assert r.value == "https://www.ornek-klinik.com/randevu.html"
    assert "0555" not in r.value
