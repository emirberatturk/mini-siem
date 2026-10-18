from fastapi import APIRouter, Depends

from app.api.v1 import alerts, auth, events, health, ingest, reports, stats

# Her istekte: durum değiştiren isteklerde CSRF başlığı zorunlu
api_router = APIRouter(dependencies=[Depends(auth.csrf_guard)])

# Herkese açık: sağlık kontrolü ve giriş
api_router.include_router(health.router)
api_router.include_router(auth.router)

# Giriş yapmış herkes (analist ve yönetici)
signed_in = [Depends(auth.current_user)]
api_router.include_router(events.router, dependencies=signed_in)
api_router.include_router(alerts.router, dependencies=signed_in)
api_router.include_router(stats.router, dependencies=signed_in)
api_router.include_router(reports.router, dependencies=signed_in)

# Yalnızca yönetici: log yükleme (kuralları yeniden çalıştırma alerts.py içinde)
api_router.include_router(ingest.router, dependencies=[Depends(auth.require_admin)])
