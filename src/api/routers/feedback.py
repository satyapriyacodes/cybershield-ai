"""
Feedback router — store analyst corrections for adaptive learning.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime

from src.database.database import get_db
from src.database.models import AgentFeedback, Incident
from src.api.schemas import FeedbackRequest

router = APIRouter()


@router.post("/feedback", summary="Submit analyst feedback on an incident")
def submit_feedback(body: FeedbackRequest, db: Session = Depends(get_db)):
    """Mark an incident as false positive, confirmed threat, or escalate."""
    incident = db.query(Incident).filter(Incident.id == body.incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    feedback = AgentFeedback(
        incident_id=body.incident_id,
        feedback_type=body.feedback_type.upper(),
        analyst_notes=body.analyst_notes,
        analyst_name=body.analyst_name or "Anonymous",
    )
    db.add(feedback)

    # Update incident status based on feedback
    if body.feedback_type.upper() == "FALSE_POSITIVE":
        incident.status = "CLOSED"
    elif body.feedback_type.upper() == "CONFIRMED_THREAT":
        incident.status = "IN_PROGRESS"
    elif body.feedback_type.upper() == "ESCALATE":
        incident.status = "IN_PROGRESS"

    db.commit()
    return {
        "feedback_id": feedback.id,
        "incident_id": body.incident_id,
        "feedback_type": body.feedback_type,
        "status": "saved",
    }


@router.get("/feedback/stats", summary="Get feedback statistics")
def feedback_stats(db: Session = Depends(get_db)):
    """Return false positive rate and feedback summary for adaptive learning display."""
    all_feedback = db.query(AgentFeedback).all()
    total = len(all_feedback)
    if total == 0:
        return {"total": 0, "false_positive_rate": 0.0, "confirmed_threat_rate": 0.0}

    fp = sum(1 for f in all_feedback if f.feedback_type == "FALSE_POSITIVE")
    ct = sum(1 for f in all_feedback if f.feedback_type == "CONFIRMED_THREAT")

    return {
        "total": total,
        "false_positive_count": fp,
        "confirmed_threat_count": ct,
        "escalated_count": total - fp - ct,
        "false_positive_rate": round(fp / total, 3),
        "confirmed_threat_rate": round(ct / total, 3),
    }
