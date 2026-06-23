"""
app.py
======
AI-Proxy v2 — FastAPI application entry point.

Registers middleware and mounts the three routers:
  - routers.auth_routes   — /api/auth/*
  - routers.chat_routes   — /api/chat, /api/features, /api/reset, /api/upload-document
  - routers.admin_routes  — /api/toggle/*, /api/users, /api/alert-settings, /api/security-logs, …

Security pipeline (9 stages):
  Input:    Unicode Firewall → spaCy Rules → ModernBERT → GLiNER PII → Context Relevance
  Output:   spaCy Rules → GLiNER+Llama3.2 Rewriter → Context Relevance
  Document: FileGate → Extract → Normalize → full security scan
"""

import asyncio
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware

import auth
from db import init_db
from routers.auth_routes import router as auth_router
from routers.chat_routes import router as chat_router
from routers.admin_routes import router as admin_router


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialise PostgreSQL tables + TimescaleDB hypertable + seed data
    await init_db()

    # Background task: purge expired / idle sessions every 5 minutes
    async def cleanup_loop():
        while True:
            await asyncio.sleep(300)
            try:
                await auth.purge_expired_sessions()
            except Exception as e:
                print(f"[App] Session cleanup error: {e}")

    asyncio.create_task(cleanup_loop())
    yield


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="AI-Proxy v2", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:5000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(chat_router)
app.include_router(admin_router)

# ── Static / SPA ──────────────────────────────────────────────────────────────
REACT_DIST_PATH = os.path.join(os.path.dirname(__file__), "frontend", "dist")


@app.get("/", response_class=HTMLResponse)
async def index():
    index_path = os.path.join(REACT_DIST_PATH, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    return JSONResponse(status_code=503, content={"detail": "Frontend not built. Run: cd frontend && npm run build"})


@app.get("/{full_path:path}")
async def serve_react_app(full_path: str):
    if full_path.startswith("api"):
        return JSONResponse(status_code=404, content={"detail": "Not found"})
    file_path = os.path.join(REACT_DIST_PATH, full_path)
    if os.path.isfile(file_path):
        return FileResponse(file_path)
    index_path = os.path.join(REACT_DIST_PATH, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    return JSONResponse(status_code=404, content={"detail": "React app not built yet."})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=5000, reload=False)
