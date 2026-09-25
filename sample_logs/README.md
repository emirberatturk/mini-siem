# Örnek loglar

| Klasör | İçerik | Git'e girer mi? |
|---|---|---|
| `datasets/` | Açık veri setleri (aşağıda) | Hayır (büyük, lisans belirsiz) |
| `real/` | Hosting panelinden indirilen gerçek loglar | **Asla** (IP = kişisel veri) |

## Veri setleri

### Elastic `apache_logs`
- **Kaynak:** https://github.com/elastic/examples/tree/master/Common%20Data%20Formats/apache_logs
- **Dosya:** `datasets/elastic_apache_logs.log` (10.000 satır, Apache Combined Log Format, 2015)
- **Kullanım:** Parser testi, gerçekçi normal trafik ve bot gürültüsü, zaman penceresi kuralları.

### HTTP DATASET CSIC 2010
- **Kaynak:** Information Security Institute, CSIC (İspanya Ulusal Araştırma Konseyi).
  Kopya: https://github.com/msudol/Web-Application-Attack-Datasets
- **Dosyalar:** `datasets/csic2010/normalTrafficTest.txt` (36.000 normal istek),
  `datasets/csic2010/anomalousTrafficTest.txt` (25.065 saldırı isteği)
- **Format:** Ham HTTP istekleri (istek satırı + başlıklar + varsa gövde), boş satırla ayrılmış.
  IP, zaman ve yanıt kodu **yoktur**; etiket, isteğin hangi dosyada olduğundan gelir.
- **Kullanım:** Tek-olay (pattern) kurallarının precision/recall ölçümü.

## Yeniden indirme

```bash
cd sample_logs/datasets
curl -L -o elastic_apache_logs.log "https://raw.githubusercontent.com/elastic/examples/master/Common%20Data%20Formats/apache_logs/apache_logs"
B="https://raw.githubusercontent.com/msudol/Web-Application-Attack-Datasets/master/OriginalDataSets/csic_2010"
mkdir -p csic2010
curl -L -o csic2010/normalTrafficTest.txt "$B/normalTrafficTest.txt"
curl -L -o csic2010/anomalousTrafficTest.txt "$B/anomalousTrafficTest.txt"
```
