"""
Anomalies router — CRUD for detected anomalies.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, List

from src.database.database import get_db
from src.database.models import Anomaly

router = APIRouter()


@router.get("/anomalies", summary="List all anomalies")
def list_anomalies(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, le=500),
    status: Optional[str] = None,
    risk_type: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(Anomaly)
    if status:
        query = query.filter(Anomaly.status == status.upper())
    if risk_type:
        query = query.filter(Anomaly.anomaly_type.ilike(f"%{risk_type}%"))
    total = query.count()
    items = query.order_by(Anomaly.created_at.desc()).offset(skip).limit(limit).all()

    return {
        "total": total,
        "items": [
            {
                "id": a.id,
                "timestamp": str(a.timestamp),
                "anomaly_type": a.anomaly_type,
                "ip_address": a.ip_address,
                "user": a.user,
                "confidence": a.confidence,
                "detection_method": a.detection_method,
                "reasoning": a.reasoning,
                "status": a.status,
                "created_at": str(a.created_at),
            }
            for a in items
        ],
    }


@router.get("/anomalies/{anomaly_id}", summary="Get specific anomaly")
def get_anomaly(anomaly_id: int, db: Session = Depends(get_db)):
    a = db.query(Anomaly).filter(Anomaly.id == anomaly_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    return {
        "id": a.id,
        "timestamp": str(a.timestamp),
        "anomaly_type": a.anomaly_type,
        "ip_address": a.ip_address,
        "user": a.user,
        "confidence": a.confidence,
        "detection_method": a.detection_method,
        "reasoning": a.reasoning,
        "raw_features": a.raw_features,
        "status": a.status,
        "created_at": str(a.created_at),
    }


@router.patch("/anomalies/{anomaly_id}/status", summary="Update anomaly status")
def update_status(anomaly_id: int, status: str, db: Session = Depends(get_db)):
    a = db.query(Anomaly).filter(Anomaly.id == anomaly_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    a.status = status.upper()
    db.commit()
    return {"id": anomaly_id, "status": a.status}
