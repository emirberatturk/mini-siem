# Mini-SIEM

Gerçek bir kurumsal web sitesinin (bir ortodonti kliniği; PHP, paylaşımlı hosting) sunucu
loglarını toplayan, kişisel verileri maskeleyen, davranış tabanlı kurallarla saldırı tespit eden
ve alarmları bir SOC arayüzünde yöneten, sıfırdan geliştirdiğim eğitim amaçlı bir SIEM.

> **EN:** A small, from-scratch SIEM for a real business website: Apache log ingestion,
> KVKK/GDPR-style PII masking, 7 behavior-based detection rules with MITRE ATT&CK mapping,
> correlation, alert triage workflow and a SOC dashboard. On 2 months of real logs (43,000+
> events) it reduced 88 initial alerts to 3 meaningful ones. Python · FastAPI · React · TypeScript.

![Genel bakış](docs/img/overview.png)

## Gerçek veride öğrendiklerim

İki aylık gerçek sunucu logu (**43.135 olay**) üzerinde çalıştırdığımda:

- **88 alarm → 3 anlamlı alarm.** Trafiğin %95,8'i tek bir IP'den geliyor gibi görünüyordu ve bu
  "tek ziyaretçi" 1.000'den fazla farklı tarayıcı kullanıyordu. Bu IP aslında hosting firmasının
  önündeki **aracı sunucuydu** (proxy): gerçek ziyaretçi IP'si logda yoktu. SIEM'e aracı sunucu
  kavramını ekledim; hacim tabanlı kurallar bu adreste çalışmıyor, giriş kuralları ise alarma
  "aracı sunucu" notu düşüyor.
- **Yavaş saldırılar kısa pencerelere takılmaz.** Bir bot 51 gün boyunca, günde ortalama 13 kez,
  sitede olmayan aynı sayfayı (`/wp-admin/install.php`) aradı. "5 dakikada 20 istek" gibi kurallar
  bunu hiç görmedi; 24 saatlik pencereli yeni bir kural (`RECON-002`) yazdım.
- **Trafiğin ~%28'i gizli dosya arayan botlardı.** `.env` (8.493 istek), `.git`, yedek dosyaları,
  hatta yapay zekâ kodlama araçlarının ayar klasörleri (`.claude`, `.mcp`). Hiçbiri başarılı olmadı.
- **Loglar sadece saldırıyı değil, hatayı da anlatır.** Sitedeki bir yükleme hatasının kök nedenini
  sunucu yanıtlarının bayt boyutundan buldum.

![Alarm detayı](docs/img/drawer.png)

## Özellikler

| Katman | Ne yapıyor |
|---|---|
| **Log toplama** | Apache access log yükleme (düz metin veya `.gz`). Boyut sınırı, gzip bombası koruması, ikili dosya reddi, log injection'a karşı güvenli satır bölme. Aynı dosya iki kez yüklenirse çift kayıt oluşmaz |
| **Ayrıştırma** | Apache Combined/Common format, `\"` kaçışları, IPv6; tüm zamanlar UTC'ye çevrilir. Bozuk satırlar sessizce atılmaz, sayılır |
| **Normalizasyon** | Elastic Common Schema'dan (ECS) esinlenen ortak şema. Giriş API'sinin 200/401/429 yanıtlarından *başarılı giriş / başarısız giriş / hesap kilidi* olayları çıkarılır |
| **KVKK** | Kişisel veri formu olan sayfalarda tüm parametreler, hassas parametre adları (tel, email, şifre…), e-posta, telefon ve TC Kimlik No (kontrol haneli doğrulama) maskelenir |
| **Tespit** | 7 davranış kuralı, kayan pencere mantığı, alarm tekilleştirme; eşikler YAML'da |
| **Korelasyon** | Başarısız denemelerin ardından gelen başarılı giriş **kritik** alarm olur; sonraki admin istekleri kanıta eklenir |
| **Alarm yönetimi** | Yeni → İnceleniyor → Doğrulandı / Yanlış alarm → Çözüldü. Gerekçe yazılmadan kapatılamaz, silinmeyen denetim geçmişi tutulur |
| **SOC arayüzü** | Genel bakış, alarm listesi ve detayı, önerilen inceleme adımları, olay arama (threat hunting), kural ekranı |
| **MITRE ATT&CK** | Yalnızca kuralın anlamıyla birebir örtüşen teknikler eşlenir; örtüşme yoksa eşleme yapılmaz |

### Tespit kuralları

| Kural | Davranış | Önem | MITRE |
|---|---|---|---|
| `AUTH-001` | 10 dk'da ≥5 başarısız giriş (≥20 veya kilitlenme → yüksek) | Orta/Yüksek | T1110.001 |
| `CORR-001` | ≥3 başarısız denemeden sonra aynı IP'den **başarılı** giriş | **Kritik** | T1110, T1078 |
| `AUTH-002` | Bilinen cihaz listesinde olmayan tarayıcıdan **başarılı** admin girişi | Yüksek | T1078 |
| `ADMIN-001` | 10 dk'da ≥3 reddedilen (401/403) admin isteği | Orta | — |
| `RECON-001` | 5 dk'da ≥20 adet 404; ≥15 farklı yol → tarama | Düşük/Orta | T1595.003 |
| `RECON-002` | Aynı var olmayan yola 24 saatte ≥10 istek, günlerce ("low and slow") | Düşük | — |
| `RATE-001` | Dakikada ≥120 istek | Düşük | — |

Elastic'in 10.000 satırlık açık `apache_logs` veri setinde varsayılan eşiklerle **0 yanlış alarm**
çıktı (baseline).

![Kurallar](docs/img/rules.png)

## Kurulum ve çalıştırma

Gereksinimler: Python 3.12, Node.js 20+

```powershell
cd backend
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe -m uvicorn app.main:app --reload   # API: http://127.0.0.1:8000/docs

cd ..\frontend
npm install
npm run dev                                                 # Arayüz: http://127.0.0.1:5173
```

Windows'ta `baslat.bat` ikisini birden başlatır.

### Kendi siten için ayarlar

Siteye özel bilgiler (admin sayfaları, giriş API'si, bilinen cihazlar, aracı sunucu IP'leri)
koddan ayrıdır ve **git'e girmez**, çünkü bu bilgiler saldırgana harita olur:

| Dosya | İçerik |
|---|---|
| `config/site_profile.example.yaml` → `config/site_profile.local.yaml` | Admin sayfaları, giriş API'si, kişisel veri içeren sayfalar |
| `config/rules.yaml` + `config/rules.local.yaml` | Kural eşikleri + bilinen cihazlar ve aracı sunucu IP'leri |

`.local.yaml` dosyası yoksa örnek profil kullanılır.

## Test ve kalite

```powershell
cd backend
.venv\Scripts\python.exe -m pytest        # 93 test
.venv\Scripts\python.exe -m ruff check .  # lint + bandit güvenlik kuralları

cd ..\frontend
npm run build                             # TypeScript tip kontrolü + derleme
npm run lint
```

Testler gerçek veritabanına ve yerel ayarlara dokunmaz. Test verilerinde yalnızca RFC 5737
dokümantasyon IP'leri ve açıkça sahte kişisel veriler bulunur.

## Güvenlik notları

- Sunucular yalnızca `127.0.0.1` üzerinde çalışır. **Kimlik doğrulama yoktur**, internete açılmamalıdır.
- Log verisi saldırgan verisidir: arayüzde her zaman düz metin olarak gösterilir (log üzerinden XSS'e karşı).
- Tüm veritabanı sorguları parametrelidir; YAML dosyaları `safe_load` ile okunur.
- Gerçek loglar, veritabanı ve siteye özel ayarlar repoda yoktur. Ekran görüntülerindeki IP'ler maskelidir.

## Mimari

```
Apache access log  →  Ayrıştırma  →  KVKK maskeleme  →  SQLite
                                                          │
   SOC arayüzü  ←  Alarm yönetimi  ←  Tespit motoru  ←────┘
```

| Klasör | İçerik |
|---|---|
| `backend/app/ingestion` | Güvenli dosya okuma, işlem hattı |
| `backend/app/parsers` | Apache log parser'ı |
| `backend/app/privacy` | KVKK maskeleme |
| `backend/app/normalization` | Ortak olay şeması, olay sınıflandırma |
| `backend/app/detection` | Tespit motoru ve kurallar |
| `backend/app/alerts` | Alarm durum makinesi |
| `backend/app/api/v1` | REST API |
| `frontend/src` | React + TypeScript SOC arayüzü |
| `config/` | Kural eşikleri, örnek site profili |
| `docs/` | [Mimari ve tasarım kararları](docs/architecture.md) |

**Teknolojiler:** Python · FastAPI · SQLAlchemy · SQLite · Pydantic · Pytest · Ruff ·
React · TypeScript · Vite

## Sonraki adımlar

- İmza tabanlı tespit: SigmaHQ kurallarının içe aktarılması, CSIC 2010 veri setiyle precision/recall ölçümü
- Kullanıcı girişi ve rol tabanlı yetki (RBAC), veri saklama süresi (retention)
- Yalnızca maskelenmiş alarm özetleriyle çalışan bir yapay zekâ inceleme asistanı

---

Geliştiren: **Emir Berat Türk** · [LinkedIn](https://www.linkedin.com/in/emirberatturk/)
· Geliştirme sürecinde yapay zekâ kodlama asistanı (Claude Code) kullanıldı.
