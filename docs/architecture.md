# Mini-SIEM — Mimari

Bir kurumsal web sitesinin teknik güvenlik loglarını izleyen, eğitim amaçlı, siteden tamamen bağımsız bir SIEM.

## Kapsam (basit seviye)

| Var | Yok / ertelendi |
|---|---|
| cPanel "Raw Access Logs" dosyası yükleme + açık veri setleri | Sunucuya ajan kurulumu, syslog, Windows logları |
| Apache access log parser, KVKK maskeleme, SQLite | PostgreSQL, IP takma adlandırma |
| 5 davranış kuralı (1'i korelasyon) | Karmaşık risk skorlama |
| Alert durumları + filtreleme | Kullanıcı yönetimi, RBAC |
| Koyu temalı SOC dashboard + arama | Gelişmiş pivot ekranları |
| MITRE etiketleri, AI asistan (en son) | UEBA, SOAR, threat intel |

## Akış

```
cPanel Raw Access Log (.gz / .log)  veya  açık veri seti
        │  dosya yükleme  (POST /api/v1/ingest/upload)
        ▼
Parser → Privacy (maskeleme) → Normalizer → SQLite
                                               │
                     Detection Engine  ◀───────┤
                     • Pattern   (tek olay — ertelendi, bkz. sapmalar)
                     • Threshold (zaman penceresi: brute-force, 404, tarama)
                     • Correlation (çok aşama: brute-force → başarılı giriş → admin)
                               │
                               ▼
                         Alert Manager  ──▶  REST API  ──▶  React Dashboard
```

## Teknoloji

| Katman | Seçim | Neden |
|---|---|---|
| Backend | Python 3.12 + FastAPI | Otomatik API dokümantasyonu, Pydantic ile girdi doğrulama |
| DB | SQLite + SQLAlchemy 2.0 | Kurulum gerektirmez; ORM sayesinde ileride PostgreSQL'e geçilebilir |
| Frontend | React + Vite + TypeScript | Endüstri standardı; TS, API sözleşme hatalarını derlemede yakalar |
| Test | Pytest + davranış senaryoları + açık veri setleri | Her tespit kuralının pozitif/negatif testi |

Olay alan adları Elastic Common Schema'dan (ECS) esinlenir: `source.ip`, `url.path`, `http.response.status_code` gibi.

## Sitenin giriş mekanizması (salt okunur analiz)

Admin girişi `POST /app.php?type=login` üzerinden yapılır:

| HTTP kodu | Anlamı |
|---|---|
| 200 | Başarılı giriş |
| 401 | Yanlış şifre |
| 429 | Hesap kilitlendi (site tarafında deneme sınırı) |
| 400 | Eksik alan |

Bu kodların hepsi access log'da göründüğü için brute-force ve "başarısız denemeler → başarılı giriş" korelasyonu siteye dokunmadan tespit edilebilir.

Admin sayfaları, admin API türleri ve kişisel veri içeren sayfalar siteye özeldir ve
`config/site_profile.local.yaml` dosyasında tutulur (git'e girmez; örneği: `config/site_profile.example.yaml`).

## Gizlilik (KVKK)

- POST gövdesi hiç toplanmaz (access log'da zaten yoktur).
- Query string değerleri DB'ye maskelenmiş yazılır (tür/`type` parametresi hariç: olay sınıflandırması için gerekli ve kişisel veri değil).
- Randevu, iletişim gibi kişisel veri içeren sayfaların parametre değerleri her zaman maskelenir.
- Telefon, e-posta ve TC Kimlik No kalıpları her alanda taranıp maskelenir.
- AI asistanına ham log gönderilmez, yalnızca maskelenmiş özet gider.

## SIEM'in kendi güvenliği

- Log verisi dashboard'da her zaman metin olarak gösterilir (log üzerinden XSS'e karşı); `dangerouslySetInnerHTML` yasak.
- Parser kontrol karakterlerini temizler (log injection).
- Girdi uzunlukları sınırlıdır (satır 8 KB, path 2 KB, user-agent 1 KB); maskeleme regex'lerinde sınırlı niceleyiciler kullanılır (ReDoS'a karşı).
- Backend yalnızca `127.0.0.1` üzerinde çalışır, internete açılmaz.

## Test stratejisi

- Test senaryolarında yalnızca RFC 5737 dokümantasyon IP blokları kullanılır: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`.
- Canlı siteye hiçbir aktif test yapılmaz. Gerçek loglar yalnızca cPanel'den indirilip pasif olarak analiz edilir.

## Yol haritası

| Faz | İçerik | Durum |
|---|---|---|
| 0 | Mimari ve planlama | ✅ |
| 1 | Proje iskeleti: FastAPI, React+TS, pytest | ✅ |
| 2 | Log yükleme (ingest) + açık veri setleri | ✅ |
| 3 | Parser, normalizasyon, KVKK maskeleme | ✅ |
| 4 | Veritabanı katmanı | ✅ |
| 5 | Davranış tabanlı tespit motoru | ✅ |
| 6 | Alert yönetimi | ✅ |
| 7 | Dashboard | ✅ |
| 8 | Threat hunting / arama | ✅ |
| 9 | MITRE ATT&CK eşlemeleri | ✅ |
| 10 | AI asistan | ⏸ sağlayıcı kararı bekleniyor |
| 11 | Test, sertleştirme, dokümantasyon | ✅ (84 test) |

## Plandan sapmalar ve gerekçeleri

| Plan | Uygulanan | Neden |
|---|---|---|
| Sentetik saldırı logu üretici | Açık veri setleri (Elastic, CSIC 2010) + birim testlerindeki davranış senaryoları | Standart veri setleri tekrarlanabilir ve karşılaştırılabilir; kurallar testlerde pozitif/negatif senaryolarla doğrulanıyor |
| Sunucuda çalışan collector ajanı | Arayüzden dosya yükleme | cPanel paylaşımlı hostingte sunucuya süreç kurulamaz |
| Ham satır hash'i ile tekilleştirme | Satır + dosyadaki tekrar sırası (`event_key`) | Aynı saniyedeki özdeş brute-force denemeleri tek olaya inip saldırıyı küçük gösterirdi |
| Alembic migration | `create_all` | Basit seviye; PostgreSQL'e geçişte eklenecek |
| İmza tabanlı kurallar (SQLi/XSS/cmdi) | Ertelendi | Topluluk kural seti (SigmaHQ) içe aktarılıp CSIC ile ölçülecek |

## Tekilleştirme ve korelasyon

- Bir kural aynı IP için açık bir alert bulursa (son aktiviteden itibaren 1 saat içinde) yeni
  alert açmaz; mevcut alert'i büyütür (olay sayısı, son görülme, önem yükselmesi).
- Aynı veri tekrar tarandığında, bu kurala zaten bağlanmış olaylar yok sayılır. Kapatılmış
  alert'ler bu yüzden kendiliğinden yeniden açılmaz.
- `CORR-001`, başarısız giriş olaylarını, başarılı girişi ve sonraki admin isteklerini tek bir
  kritik alert'te birleştirir. Tek tek gürültü olan olaylar, sıralandığında saldırının başarıya
  ulaştığını gösterir.
