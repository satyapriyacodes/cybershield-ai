"""
Detection router — trigger the full agent pipeline.
"""

import os
import pandas as pd
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from loguru import logger

from src.database.database import get_db
from src.api.schemas import DetectRequest, DetectionResponse
from src.agents.orchestrator import Orchestrator

router = APIRouter()

# Shared orchestrator instance (in-memory state for demo)
_orchestrator: Orchestrator = None


def get_orchestrator(settings=None, api_key=None) -> Orchestrator:
    global _orchestrator
    if _orchestrator is None or api_key:
        _orchestrator = Orchestrator(openai_api_key=api_key, settings=settings)
    return _orchestrator


@router.post("/detect", summary="Trigger full detection pipeline")
async def run_detection(body: DetectRequest, db: Session = Depends(get_db)):
    """
    Run the complete multi-agent detection pipeline on security logs.
    Returns aggregated metrics and anomaly counts.
    """
    # Load logs
    log_path = "data/security_logs.csv"
    if not os.path.exists(log_path):
        from src.data.log_generator import generate_logs
        generate_logs()

    df = pd.read_csv(log_path)
    logs = df.to_dict(orient="records")

    settings = body.settings or {}
    orch = get_orchestrator(settings=settings)

    try:
        result = orch.run_pipeline(logs)
    except Exception as e:
        logger.error(f"Pipeline error: {e}")
        raise HTTPException(status_code=500, detail=f"Pipeline error: {e}")

    return {
        "pipeline_id": result["pipeline_id"],
        "total_logs": result["total_logs"],
        "anomalies_count": len(result["anomalies"]),
        "incidents_count": len(result["incidents"]),
        "response_plans_count": len(result["response_plans"]),
        "elapsed_seconds": result["elapsed_seconds"],
        "watchdog_status": result["watchdog"].get("overall_status", "UNKNOWN"),
        "metrics": result["metrics"],
        "anomalies": result["anomalies"][:50],  # Cap response size
        "incidents": result["incidents"][:50],
        "response_plans": result["response_plans"][:50],
        "executive_summary": result["executive_summary"],
        "watchdog": result["watchdog"],
    }


@router.post("/analyze/{anomaly_id}", summary="Analyse a specific anomaly")
async def analyze_anomaly(anomaly_id: int, body: dict = None, db: Session = Depends(get_db)):
    """Run Analyst on a single anomaly from the database."""
    from src.database.models import Anomaly as AnomalyModel
    from src.agents.analyst_agent import AnalystAgent

    db_anomaly = db.query(AnomalyModel).filter(AnomalyModel.id == anomaly_id).first()
    if not db_anomaly:
        raise HTTPException(status_code=404, detail="Anomaly not found")

    api_key = (body or {}).get("openai_api_key") or os.getenv("OPENAI_API_KEY", "")
    analyst = AnalystAgent(api_key=api_key)

    anomaly_dict = {
        "anomaly_id": f"DB-{db_anomaly.id}",
        "timestamp": db_anomaly.timestamp,
        "anomaly_type": db_anomaly.anomaly_type,
        "ip_address": db_anomaly.ip_address,
        "user": db_anomaly.user,
        "confidence": db_anomaly.confidence,
        "detection_method": db_anomaly.detection_method,
        "reasoning": db_anomaly.reasoning,
        "supporting_evidence": [],
    }

    result = analyst.run(anomaly_dict)
    return result.get("result", {})
