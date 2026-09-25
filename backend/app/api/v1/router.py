from fastapi import APIRouter

from app.api.v1 import alerts, events, health, ingest, stats

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(ingest.router)
api_router.include_router(events.router)
api_router.include_router(alerts.router)
api_router.include_router(stats.router)
