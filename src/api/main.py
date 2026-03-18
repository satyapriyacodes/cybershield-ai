"""
FastAPI Application Entry Point
"""

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from loguru import logger

from src.database.database import init_db
from src.api.routers import logs, detection, anomalies, incidents, chat, dashboard, feedback, reports


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: initialise DB and generate data if needed."""
    logger.info("Starting Multi-Agent Cybersecurity System API...")
    init_db()
    # Generate data if not present
    if not os.path.exists("data/security_logs.csv"):
        logger.info("Generating synthetic security logs...")
        from src.data.log_generator import generate_logs
        generate_logs()
    # Train models if not present
    if not os.path.exists("models/isolation_forest.pkl"):
        logger.info("Training ML models...")
        try:
            from src.ml.trainer import train_pipeline
            train_pipeline()
        except Exception as e:
            logger.warning(f"Model training failed: {e}")
    yield
    logger.info("API shutting down.")


app = FastAPI(
    title="Multi-Agent Cybersecurity System",
    description=(
        "AI-powered cybersecurity monitoring with 5 specialized agents: "
        "Hunter (detection), Analyst (GPT-4 analysis), Responder (actions), "
        "Reporter (metrics), and Watchdog (meta-monitoring)."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS for Streamlit frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(logs.router, prefix="/api/v1", tags=["Logs"])
app.include_router(detection.router, prefix="/api/v1", tags=["Detection"])
app.include_router(anomalies.router, prefix="/api/v1", tags=["Anomalies"])
app.include_router(incidents.router, prefix="/api/v1", tags=["Incidents"])
app.include_router(chat.router, prefix="/api/v1", tags=["Chat"])
app.include_router(dashboard.router, prefix="/api/v1", tags=["Dashboard"])
app.include_router(feedback.router, prefix="/api/v1", tags=["Feedback"])
app.include_router(reports.router, prefix="/api/v1", tags=["Reports"])


@app.get("/", tags=["Health"])
async def root():
    return {
        "name": "Multi-Agent Cybersecurity System",
        "version": "1.0.0",
        "status": "operational",
        "docs": "/docs",
    }


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy"}
