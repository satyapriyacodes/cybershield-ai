"""
Pydantic schemas for FastAPI request/response validation.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


# ── Request schemas ──────────────────────────────────────

class LogIngestRequest(BaseModel):
    content: str = Field(..., description="Raw log content (CSV/JSON/syslog)")
    format: str = Field(default="csv", description="Log format: csv | json | syslog")


class DetectRequest(BaseModel):
    use_cached: bool = Field(default=True, description="Use existing CSV if available")
    settings: Optional[Dict[str, Any]] = Field(default=None)


class AnalyzeRequest(BaseModel):
    openai_api_key: Optional[str] = None


class ChatRequest(BaseModel):
    agent: str = Field(..., description="Agent name: hunter | analyst | responder | reporter")
    message: str = Field(..., max_length=1000)
    context: Optional[str] = None
    openai_api_key: Optional[str] = None


class FeedbackRequest(BaseModel):
    incident_id: int
    feedback_type: str = Field(..., description="FALSE_POSITIVE | CONFIRMED_THREAT | ESCALATE")
    analyst_notes: Optional[str] = None
    analyst_name: Optional[str] = "Anonymous"


# ── Response schemas ─────────────────────────────────────

class AnomalyResponse(BaseModel):
    id: int
    timestamp: Optional[str]
    anomaly_type: str
    ip_address: Optional[str]
    user: Optional[str]
    confidence: float
    detection_method: Optional[str]
    reasoning: Optional[str]
    status: str
    created_at: Optional[str]


class IncidentResponse(BaseModel):
    id: int
    anomaly_id: int
    analysis: Optional[str]
    risk_level: str
    attack_type: Optional[str]
    recommended_actions: Optional[List]
    action_priority: Optional[str]
    status: str
    created_at: Optional[str]


class DetectionResponse(BaseModel):
    pipeline_id: str
    total_logs: int
    anomalies_count: int
    incidents_count: int
    response_plans_count: int
    elapsed_seconds: float
    watchdog_status: str
    metrics: Dict[str, Any]


class ChatResponse(BaseModel):
    agent: str
    message: str
    response: str


class DashboardMetrics(BaseModel):
    total_threats: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    by_attack_type: Dict[str, int]
    top_suspicious_ips: List[Dict]
    timeline: List[Dict]
    avg_confidence: float
    generated_at: str
