from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover
    load_dotenv = None

from backend.routes.endpoints import router as endpoints_router
from backend.routes.scans import router as scans_router
from backend.bootstrap import bootstrap_runtime


# Local dev convenience: load backend/.env if present.
_ROOT = Path(__file__).resolve().parents[1]
_ENV_PATH = _ROOT / "backend" / ".env"
if load_dotenv is not None and _ENV_PATH.exists():
    load_dotenv(str(_ENV_PATH), override=False)


def create_app() -> FastAPI:
    app = FastAPI(title="Endpoint Risk Scanning API")

    allow_origins = os.getenv(
        "CORS_ALLOW_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174",
    ).split(",")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in allow_origins if o.strip()],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(endpoints_router)
    app.include_router(scans_router)

    @app.on_event("startup")
    def _startup_bootstrap() -> None:
        bootstrap_runtime()

    @app.get("/health")
    def health():
        return {"ok": True}

    return app


app = create_app()
