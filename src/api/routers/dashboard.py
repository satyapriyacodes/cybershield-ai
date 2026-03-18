"""
Dashboard metrics router.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from collections import Counter
from datetime import datetime

from src.database.database import get_db
from src.database.models import Anomaly, Incident

router = APIRouter()


@router.get("/dashboard/metrics", summary="Get aggregated dashboard statistics")
def get_dashboard_metrics(db: Session = Depends(get_db)):
    """Return all metrics needed to power the home dashboard."""
    anomalies = db.query(Anomaly).all()
    incidents = db.query(Incident).all()

    by_risk = Counter(i.risk_level for i in incidents)
    by_type = Counter(i.attack_type for i in incidents if i.attack_type)

    all_ips = [a.ip_address for a in anomalies if a.ip_address]
    top_ips = Counter(all_ips).most_common(5)

    # Timeline
    date_counts: dict = {}
    for a in anomalies:
        if a.created_at:
            d = a.created_at.strftime("%Y-%m-%d")
            date_counts[d] = date_counts.get(d, 0) + 1
    timeline = [{"date": d, "count": c} for d, c in sorted(date_counts.items())]

    confidences = [a.confidence for a in anomalies if a.confidence]
    avg_conf = sum(confidences) / len(confidences) if confidences else 0.0

    return {
        "total_threats": len(anomalies),
        "critical_count": by_risk.get("CRITICAL", 0),
        "high_count": by_risk.get("HIGH", 0),
        "medium_count": by_risk.get("MEDIUM", 0),
        "low_count": by_risk.get("LOW", 0),
        "by_risk_level": dict(by_risk),
        "by_attack_type": dict(by_type),
        "top_suspicious_ips": [{"ip": ip, "count": cnt} for ip, cnt in top_ips],
        "timeline": timeline,
        "avg_confidence": round(avg_conf, 3),
        "total_incidents": len(incidents),
        "open_incidents": sum(1 for i in incidents if i.status == "OPEN"),
        "generated_at": datetime.utcnow().isoformat(),
    }
