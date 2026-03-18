"""
Incidents router.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional

from src.database.database import get_db
from src.database.models import Incident, Anomaly

router = APIRouter()


@router.get("/incidents", summary="List all incidents")
def list_incidents(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, le=500),
    risk_level: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(Incident)
    if risk_level:
        query = query.filter(Incident.risk_level == risk_level.upper())
    if status:
        query = query.filter(Incident.status == status.upper())
    total = query.count()
    items = query.order_by(Incident.created_at.desc()).offset(skip).limit(limit).all()

    return {
        "total": total,
        "items": [
            {
                "id": i.id,
                "anomaly_id": i.anomaly_id,
                "analysis": i.analysis,
                "risk_level": i.risk_level,
                "attack_type": i.attack_type,
                "recommended_actions": i.recommended_actions,
                "action_priority": i.action_priority,
                "responder_actions": i.responder_actions,
                "evidence": i.evidence,
                "status": i.status,
                "created_at": str(i.created_at),
            }
            for i in items
        ],
    }


@router.get("/incidents/{incident_id}", summary="Get specific incident")
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    anomaly = db.query(Anomaly).filter(Anomaly.id == inc.anomaly_id).first()

    return {
        "id": inc.id,
        "anomaly_id": inc.anomaly_id,
        "analysis": inc.analysis,
        "risk_level": inc.risk_level,
        "attack_type": inc.attack_type,
        "recommended_actions": inc.recommended_actions,
        "action_priority": inc.action_priority,
        "responder_actions": inc.responder_actions,
        "evidence": inc.evidence,
        "status": inc.status,
        "created_at": str(inc.created_at),
        "anomaly": {
            "id": anomaly.id if anomaly else None,
            "ip_address": anomaly.ip_address if anomaly else None,
            "user": anomaly.user if anomaly else None,
            "timestamp": str(anomaly.timestamp) if anomaly else None,
            "confidence": anomaly.confidence if anomaly else None,
            "reasoning": anomaly.reasoning if anomaly else None,
        } if anomaly else None,
    }
