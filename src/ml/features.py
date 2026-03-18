"""
Feature Engineering for ML anomaly detection.
Converts raw log records into numerical feature vectors.
"""

import numpy as np
import pandas as pd
from typing import List, Dict, Optional
from datetime import datetime


# Geographic distance approximations (lat/lon centroids)
LOCATION_COORDS = {
    "new york, us": (40.71, -74.01),
    "los angeles, us": (34.05, -118.24),
    "chicago, us": (41.88, -87.63),
    "austin, us": (30.27, -97.74),
    "seattle, us": (47.61, -122.33),
    "bucharest, romania": (44.43, 26.10),
    "moscow, russia": (55.75, 37.62),
    "shanghai, china": (31.23, 121.47),
    "amsterdam, netherlands": (52.37, 4.90),
    "unknown": (0.0, 0.0),
}

SUSPICIOUS_IP_PREFIXES = [
    "185.220", "91.92", "194.165", "103.76", "45.142",
    "95.214", "2.58", "185.234",
]

SUSPICIOUS_LOCATIONS = {
    "romania", "russia", "china", "netherlands"
}


def _haversine_distance(loc1: str, loc2: str) -> float:
    """Approximate geographic distance in km."""
    c1 = LOCATION_COORDS.get(loc1.lower(), (0.0, 0.0))
    c2 = LOCATION_COORDS.get(loc2.lower(), (0.0, 0.0))
    if c1 == (0.0, 0.0) or c2 == (0.0, 0.0):
        return 0.0
    lat1, lon1 = np.radians(c1)
    lat2, lon2 = np.radians(c2)
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = np.sin(dlat / 2) ** 2 + np.cos(lat1) * np.cos(lat2) * np.sin(dlon / 2) ** 2
    c = 2 * np.arcsin(np.sqrt(a))
    return 6371 * c  # km


def _is_suspicious_ip(ip: str) -> int:
    for prefix in SUSPICIOUS_IP_PREFIXES:
        if ip.startswith(prefix):
            return 1
    # Private IP ranges are normal
    parts = ip.split(".")
    if len(parts) == 4:
        first = int(parts[0])
        if first == 10 or first == 172 or first == 192:
            return 0
    return 0


def _hour_of_day(timestamp_str: str) -> int:
    try:
        dt = datetime.fromisoformat(timestamp_str)
        return dt.hour
    except Exception:
        return 12  # default


def _is_anomalous_hour(hour: int) -> int:
    return 1 if 2 <= hour <= 5 else 0


def _location_risk_score(location: str) -> float:
    if not location:
        return 0.0
    loc_lower = location.lower()
    for suspicious in SUSPICIOUS_LOCATIONS:
        if suspicious in loc_lower:
            return 1.0
    return 0.0


def engineer_features(logs: List[Dict]) -> pd.DataFrame:
    """
    Convert list of log dicts to feature matrix.
    Returns DataFrame with feature columns (no target column).
    """
    records = []
    for log in logs:
        ts_str = str(log.get("timestamp", ""))
        hour = _hour_of_day(ts_str)
        location = str(log.get("location", "Unknown"))
        ip = str(log.get("ip_address", "0.0.0.0"))
        failed = int(log.get("failed_attempts", 0) or 0)
        session = float(log.get("session_duration_min", 0) or 0)
        bytes_tx = float(log.get("bytes_transferred", 0) or 0)
        status = str(log.get("status", "UNKNOWN")).upper()
        action = str(log.get("action", "UNKNOWN")).upper()

        feature = {
            "login_hour": hour,
            "is_anomalous_hour": _is_anomalous_hour(hour),
            "failed_attempts": failed,
            "session_duration_min": session,
            "bytes_transferred": bytes_tx,
            "bytes_log": np.log1p(bytes_tx),
            "is_failure": 1 if status == "FAILURE" else 0,
            "is_suspicious_ip": _is_suspicious_ip(ip),
            "location_risk": _location_risk_score(location),
            "is_admin_action": 1 if action in ("ADMIN_PANEL", "PRIVILEGE_ESCALATION") else 0,
            "is_data_export": 1 if action == "DATA_EXPORT" else 0,
        }
        records.append(feature)

    df = pd.DataFrame(records)
    df.fillna(0, inplace=True)
    return df


def engineer_features_from_df(df: pd.DataFrame) -> pd.DataFrame:
    """Convenience wrapper taking a DataFrame of raw logs."""
    logs = df.to_dict(orient="records")
    return engineer_features(logs)


FEATURE_NAMES = [
    "login_hour", "is_anomalous_hour", "failed_attempts",
    "session_duration_min", "bytes_transferred", "bytes_log",
    "is_failure", "is_suspicious_ip", "location_risk",
    "is_admin_action", "is_data_export",
]
