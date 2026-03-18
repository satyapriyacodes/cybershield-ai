"""
Database models for the Multi-Agent Cybersecurity System.
Uses SQLAlchemy ORM with SQLite backend.
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, Text, DateTime,
    ForeignKey, JSON, create_engine
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class LogEntry(Base):
    """Raw and parsed security log entries."""
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    raw_log = Column(Text, nullable=False)
    parsed_data = Column(JSON, nullable=True)
    timestamp = Column(String(50), nullable=True)
    user = Column(String(100), nullable=True)
    ip_address = Column(String(50), nullable=True)
    action = Column(String(100), nullable=True)
    status = Column(String(50), nullable=True)
    location = Column(String(100), nullable=True)
    device = Column(String(100), nullable=True)
    processed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Anomaly(Base):
    """Detected anomalies from the Hunter Agent."""
    __tablename__ = "anomalies"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(String(50), nullable=True)
    anomaly_type = Column(String(100), nullable=False)
    ip_address = Column(String(50), nullable=True)
    user = Column(String(100), nullable=True)
    confidence = Column(Float, nullable=False, default=0.0)
    detection_method = Column(String(50), nullable=True)  # statistical / ml / rule
    reasoning = Column(Text, nullable=True)
    raw_features = Column(JSON, nullable=True)
    status = Column(String(50), default="NEW")  # NEW / ANALYZING / RESOLVED / FALSE_POSITIVE
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    incident = relationship("Incident", back_populates="anomaly", uselist=False)


class Incident(Base):
    """Full analyst investigation of an anomaly."""
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    anomaly_id = Column(Integer, ForeignKey("anomalies.id"), nullable=False)
    analysis = Column(Text, nullable=True)
    risk_level = Column(String(20), nullable=False, default="LOW")  # LOW/MEDIUM/HIGH/CRITICAL
    attack_type = Column(String(100), nullable=True)
    recommended_actions = Column(JSON, nullable=True)
    action_priority = Column(String(20), nullable=True)  # URGENT/HIGH/MEDIUM/LOW
    shap_values = Column(JSON, nullable=True)
    evidence = Column(JSON, nullable=True)
    responder_actions = Column(JSON, nullable=True)
    status = Column(String(50), default="OPEN")  # OPEN / IN_PROGRESS / CLOSED
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    anomaly = relationship("Anomaly", back_populates="incident")
    feedback = relationship("AgentFeedback", back_populates="incident")


class AgentFeedback(Base):
    """Human analyst feedback for adaptive learning."""
    __tablename__ = "agent_feedback"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    feedback_type = Column(String(50), nullable=False)  # FALSE_POSITIVE / CONFIRMED_THREAT / ESCALATE
    analyst_notes = Column(Text, nullable=True)
    analyst_name = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    incident = relationship("Incident", back_populates="feedback")


class AppSettings(Base):
    """Persisted application settings (thresholds, toggles, etc.)"""
    __tablename__ = "app_settings"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, nullable=False)
    value = Column(String(500), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AgentAuditLog(Base):
    """Audit trail for all agent communications."""
    __tablename__ = "agent_audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    agent_name = Column(String(50), nullable=False)
    action = Column(String(200), nullable=False)
    input_data = Column(JSON, nullable=True)
    output_data = Column(JSON, nullable=True)
    duration_ms = Column(Float, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
