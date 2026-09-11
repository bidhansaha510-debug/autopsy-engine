import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from backend.core.config import settings
from backend.core.database import init_db, SessionLocal
from backend.api import api_router
from backend.models import Incident
from backend.replay.engine import IncidentReplayEngine


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize DB schema and auto-migrate columns
    init_db()

    # In demo mode, bootstrap the benchmark incident if the database is fresh
    if settings.ENVIRONMENT == "demo" or settings.AUTO_BOOTSTRAP_DEMO:
        db = SessionLocal()
        try:
            count = db.query(Incident).count()
            if count == 0:
                print("[AUTOPSY] Demo mode active: bootstrapping canonical benchmark scenario...")
                replay = IncidentReplayEngine(db)
                replay.bootstrap_canonical_incident()
        except Exception as e:
            print(f"[AUTOPSY] Demo bootstrap warning: {e}")
        finally:
            db.close()
    else:
        print(f"[AUTOPSY] Operating in {settings.ENVIRONMENT} mode: pristine database ready for live telemetry ingestion.")
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Infrastructure Autopsy — Forensic Incident Reconstruction Platform",
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount REST API
app.include_router(api_router)

# Mount frontend directory for static assets if exists
frontend_dir = os.path.join(os.path.dirname(__file__), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/")
    async def serve_index():
        return FileResponse(os.path.join(frontend_dir, "index.html"))

    @app.get("/favicon.ico", include_in_schema=False)
    async def serve_favicon():
        favicon_path = os.path.join(frontend_dir, "favicon.svg")
        if os.path.exists(favicon_path):
            return FileResponse(favicon_path, media_type="image/svg+xml")
        return FileResponse(os.path.join(frontend_dir, "index.html"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
