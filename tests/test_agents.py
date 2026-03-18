"""
Basic tests for the cybersecurity agents and API.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import pandas as pd

# ── Data layer tests ──────────────────────────────────────────────────────────

def test_log_generator():
    """Test that log generator produces expected output."""
    from src.data.log_generator import generate_logs
    df = generate_logs()
    assert len(df) >= 1000, "Should generate at least 1000 logs"
    assert "timestamp" in df.columns
    assert "anomaly_label" in df.columns
    normal_pct = (df["anomaly_label"] == "normal").mean()
    assert 0.50 <= normal_pct <= 0.99, f"Normal ratio {normal_pct:.0%} out of expected range"


def test_log_parser_csv():
    from src.data.log_parser import parse_logs
    csv = "timestamp,user,ip_address,action,status,location,device,failed_attempts,session_duration_min,bytes_transferred\n2024-01-01T10:00:00,user_001,192.168.1.1,LOGIN,SUCCESS,New York US,Windows 10,0,60,1024"
    records = parse_logs(csv, "csv")
    assert len(records) == 1
    assert records[0]["user"] == "user_001"


def test_log_parser_json():
    from src.data.log_parser import parse_logs
    import json
    data = [{"timestamp": "2024-01-01T10:00:00", "user": "u1", "ip_address": "10.0.0.1",
             "action": "LOGIN", "status": "SUCCESS", "location": "NY", "device": "Win",
             "failed_attempts": 0, "session_duration_min": 30, "bytes_transferred": 500}]
    records = parse_logs(json.dumps(data), "json")
    assert len(records) == 1


# ── Feature engineering tests ─────────────────────────────────────────────────

def test_feature_engineering():
    from src.ml.features import engineer_features
    logs = [{
        "timestamp": "2024-01-01T03:00:00",
        "user": "user_001", "ip_address": "185.220.101.47",
        "action": "LOGIN", "status": "FAILURE",
        "location": "Moscow, Russia", "device": "Windows 10",
        "failed_attempts": 10, "session_duration_min": 5, "bytes_transferred": 100,
    }]
    X = engineer_features(logs)
    assert X["is_anomalous_hour"].iloc[0] == 1
    assert X["is_suspicious_ip"].iloc[0] == 1
    assert X["location_risk"].iloc[0] == 1.0
    assert X["failed_attempts"].iloc[0] == 10


# ── Hunter agent tests ────────────────────────────────────────────────────────

def test_hunter_rule_brute_force():
    """Hunter should detect brute force with >5 failures in 10 min."""
    from src.agents.hunter_agent import HunterAgent
    hunter = HunterAgent(failed_login_threshold=5)
    logs = []
    import datetime
    base = datetime.datetime(2024, 1, 1, 10, 0, 0)
    for i in range(8):
        logs.append({
            "timestamp": (base + datetime.timedelta(seconds=i*30)).isoformat(),
            "user": "attacker",
            "ip_address": "185.220.101.47",
            "action": "LOGIN",
            "status": "FAILURE",
            "location": "Moscow, Russia",
            "device": "Unknown",
            "failed_attempts": i+1,
            "session_duration_min": 0,
            "bytes_transferred": 0,
        })
    anomalies = hunter.process(logs)
    types = [a["anomaly_type"] for a in anomalies]
    assert any("brute" in t for t in types), f"Expected brute_force. Got: {types}"


def test_hunter_unusual_time():
    """Hunter should flag 3AM access."""
    from src.agents.hunter_agent import HunterAgent
    hunter = HunterAgent()
    logs = [{
        "timestamp": "2024-01-01T03:30:00",
        "user": "user_010",
        "ip_address": "192.168.1.50",
        "action": "DATA_EXPORT",
        "status": "SUCCESS",
        "location": "New York, US",
        "device": "Windows 10",
        "failed_attempts": 0,
        "session_duration_min": 120,
        "bytes_transferred": 500000,
    }]
    anomalies = hunter.process(logs)
    types = [a["anomaly_type"] for a in anomalies]
    assert any("unusual" in t for t in types), f"Expected unusual_time. Got: {types}"


# ── Responder tests ───────────────────────────────────────────────────────────

def test_responder_critical():
    from src.agents.responder_agent import ResponderAgent
    r = ResponderAgent()
    plans = r.process({"risk_level": "CRITICAL", "attack_type": "brute_force",
                       "ip_address": "1.2.3.4", "user": "u1", "anomaly_id": "X"})
    assert len(plans) == 1
    assert plans[0]["action_priority"] == "URGENT"
    assert plans[0]["sla_minutes"] == 15


def test_responder_low():
    from src.agents.responder_agent import ResponderAgent
    r = ResponderAgent()
    plans = r.process({"risk_level": "LOW", "attack_type": "statistical_outlier",
                       "ip_address": "192.168.1.1", "user": "u1", "anomaly_id": "Y"})
    assert plans[0]["action_priority"] == "LOW"


# ── Watchdog tests ────────────────────────────────────────────────────────────

def test_watchdog_flag_rate_alert():
    from src.agents.watchdog_agent import WatchdogAgent
    wdg = WatchdogAgent()
    result = wdg.process({
        "total_logs": 100,
        "anomalies": [{}] * 60,  # 60% flag rate → should warn
        "incidents": [],
        "response_plans": [],
    })
    assert result["overall_status"] != "HEALTHY"
    assert result["alert_count"] > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
