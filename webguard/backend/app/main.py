from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# backend/app/main.py -> project root is two levels up
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"

from app.config import settings
from app.database import Base, engine, SessionLocal
from app.models import User, Role
from app.core.security import hash_password
from app.monitor.scheduler import start_scheduler_for_all_active_assets
from app.routers import auth, users, assets, scans, alerts, audit, dashboard


def bootstrap_admin():
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            admin = User(
                email=settings.BOOTSTRAP_ADMIN_EMAIL,
                full_name="Default Admin",
                hashed_password=hash_password(settings.BOOTSTRAP_ADMIN_PASSWORD),
                role=Role.admin,
            )
            db.add(admin)
            db.commit()
            print(f"[WebGuard] Bootstrap admin created: {settings.BOOTSTRAP_ADMIN_EMAIL}")
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    bootstrap_admin()
    start_scheduler_for_all_active_assets()
    yield


app = FastAPI(title=settings.APP_NAME, version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(assets.router)
app.include_router(scans.router)
app.include_router(alerts.router)
app.include_router(audit.router)
app.include_router(dashboard.router)


@app.get("/api/health")
def health():
    return {"status": "ok", "app": settings.APP_NAME}


# Serve the static single-page dashboard (built with vanilla HTML/JS).
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/")
def root():
    return FileResponse(str(FRONTEND_DIR / "index.html"))
