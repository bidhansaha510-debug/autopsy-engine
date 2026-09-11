from fastapi import APIRouter
from backend.api.routes_incidents import router as incidents_router
from backend.api.routes_ingestion import router as ingestion_router
from backend.api.routes_telemetry import router as telemetry_router
from backend.api.routes_topology import router as topology_router
from backend.api.routes_forensics import router as forensics_router
from backend.api.routes_investigation import router as investigation_router
from backend.api.routes_replay import router as replay_router
from backend.api.routes_reports import router as reports_router
from backend.api.routes_codebase import router as codebase_router
from backend.api.routes_connectors import router as connectors_router

api_router = APIRouter(prefix="/api")

api_router.include_router(incidents_router)
api_router.include_router(ingestion_router)
api_router.include_router(codebase_router)
api_router.include_router(connectors_router)
api_router.include_router(telemetry_router)
api_router.include_router(topology_router)
api_router.include_router(forensics_router)
api_router.include_router(investigation_router)
api_router.include_router(replay_router)
api_router.include_router(reports_router)


@api_router.get("/health")
def health_check():
    from backend.ai.ollama_client import OllamaClient
    ollama = OllamaClient()
    return {
        "status": "healthy",
        "service": "Infrastructure Autopsy Forensic Engine",
        "version": "1.0.0",
        "ollama_connected": ollama.is_available(),
        "ollama_model": ollama.model,
    }


@api_router.get("/system/metrics")
def system_metrics():
    return {
        "cpu_usage_pct": 8.4,
        "memory_usage_pct": 24.1,
        "active_forensic_workers": 4,
        "storage_mode": "WAL_SQLITE_POSTGRES_READY",
    }
