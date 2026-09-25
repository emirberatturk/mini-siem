# Sigma kuralları (imza tabanlı tespit)

Bu klasördeki `.yml` dosyaları, güvenlik topluluğunun ortak kural deposu
[SigmaHQ](https://github.com/SigmaHQ/sigma)'dan **değiştirilmeden** alınmıştır
(`rules/web/webserver_generic/`, sürüm `9e543da66cccac3b7d320fa2852057052fee32d9`).

- **Lisans:** [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License)
- **Yazarlar:** her dosyanın `author` alanında belirtilmiştir; bu bilgiler korunmalıdır.

Kurallar, log yüklenirken **bellekteki ham istek** üzerinde çalışır (maskelemeden önce), böylece
kişisel veri maskelemesi saldırılar için bir kör nokta oluşturmaz. Veritabanına yalnızca eşleşen
kuralın adı yazılır; ham istek ve eşleşen saldırı metni hiçbir yere kaydedilmez (KVKK: veri
minimizasyonu).

Yeni kural eklemek: SigmaHQ'dan `webserver` kategorisindeki bir `.yml` dosyasını buraya kopyala.
Desteklenen Sigma alt kümesi için bkz. `backend/app/detection/sigma.py`.
