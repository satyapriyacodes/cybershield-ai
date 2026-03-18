"""
Hunter Agent — Detection Engine
Combines statistical z-score analysis, Isolation Forest, Random Forest,
and rule-based pattern matching to detect anomalies.
"""

import os
import sys
import numpy as np
import pandas as pd
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime
from loguru import logger

from src.agents.base_agent import BaseAgent
from src.ml.features import engineer_features, engineer_features_from_df, FEATURE_NAMES
from src.ml.isolation_forest import IsolationForestDetector
from src.ml.random_forest import RandomForestDetector


@dataclass
class AnomalyResult:
    anomaly_id: str
    timestamp: str
    anomaly_type: str
    ip_address: str
    user: str
    confidence: float  # 0.0 – 1.0
    detection_method: str  # statistical | ml_isolation | ml_random_forest | rule_based | combined
    reasoning: str
    raw_features: Dict[str, Any] = field(default_factory=dict)
    supporting_evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


class HunterAgent(BaseAgent):
    """Detects anomalies using three complementary methods."""

    def __init__(
        self,
        z_score_threshold: float = 3.0,
        failed_login_threshold: int = 5,
        unusual_hour_start: int = 2,
        unusual_hour_end: int = 5,
        contamination: float = 0.10,
    ):
        super().__init__("Hunter")
        self.z_threshold = z_score_threshold
        self.failed_login_threshold = failed_login_threshold
        self.unusual_hour_start = unusual_hour_start
        self.unusual_hour_end = unusual_hour_end
        self.contamination = contamination

        # ML models (loaded lazily)
        self._if_detector: Optional[IsolationForestDetector] = None
        self._rf_detector: Optional[RandomForestDetector] = None

    # ──────────────────────────────────────────────
    # Model loading
    # ──────────────────────────────────────────────

    def _load_models(self, X: pd.DataFrame, y: Optional[pd.Series] = None):
        self._if_detector = IsolationForestDetector(contamination=self.contamination)
        if os.path.exists("models/isolation_forest.pkl"):
            self._if_detector.load()
        else:
            self._if_detector.train(X)
            self._if_detector.save()

        self._rf_detector = RandomForestDetector()
        if os.path.exists("models/random_forest.pkl") and os.path.exists("models/label_encoder.pkl"):
            self._rf_detector.load()
        else:
            if y is not None:
                self._rf_detector.train(X, y)
                self._rf_detector.save()

    # ──────────────────────────────────────────────
    # Detection methods
    # ──────────────────────────────────────────────

    def _statistical_detection(self, X: pd.DataFrame, df_raw: pd.DataFrame) -> List[AnomalyResult]:
        """Z-score anomaly detection on numerical features."""
        results = []
        numeric_cols = ["failed_attempts", "bytes_transferred", "session_duration_min"]
        existing = [c for c in numeric_cols if c in X.columns]
        if not existing:
            return results

        z_scores = (X[existing] - X[existing].mean()) / (X[existing].std() + 1e-9)

        for i, row in z_scores.iterrows():
            flagged_feats = [(col, float(z)) for col, z in row.items() if abs(z) > self.z_threshold]
            if not flagged_feats:
                continue

            raw = df_raw.iloc[i] if i < len(df_raw) else {}
            confidence = min(0.95, 0.5 + 0.15 * len(flagged_feats))
            evidence = [f"{feat}: z={z:.2f}" for feat, z in flagged_feats]
            reasoning = f"Statistical anomaly: {'; '.join(evidence)}"

            results.append(AnomalyResult(
                anomaly_id=f"STAT-{i:04d}",
                timestamp=str(raw.get("timestamp", datetime.utcnow().isoformat())),
                anomaly_type="statistical_outlier",
                ip_address=str(raw.get("ip_address", "unknown")),
                user=str(raw.get("user", "unknown")),
                confidence=round(confidence, 3),
                detection_method="statistical",
                reasoning=reasoning,
                raw_features=dict(X.iloc[i]),
                supporting_evidence=evidence,
            ))
        return results

    def _ml_detection(self, X: pd.DataFrame, df_raw: pd.DataFrame) -> List[AnomalyResult]:
        """ML-based detection using Isolation Forest + Random Forest."""
        results = []
        if self._if_detector is None:
            return results

        try:
            if_labels, if_scores = self._if_detector.predict(X)
        except Exception as e:
            logger.warning(f"IsolationForest predict failed: {e}")
            return results

        # RF predictions (optional)
        rf_classes: Optional[List[str]] = None
        rf_confidences: Optional[np.ndarray] = None
        if self._rf_detector is not None and self._rf_detector.model is not None:
            try:
                rf_classes, rf_confidences = self._rf_detector.predict_attack_type(X)
            except Exception as e:
                logger.warning(f"RandomForest predict failed: {e}")

        for i, (lbl, score) in enumerate(zip(if_labels, if_scores)):
            if lbl != -1:
                continue  # Not flagged by Isolation Forest
            raw = df_raw.iloc[i] if i < len(df_raw) else {}

            # Combine with RF to determine attack type
            attack_type = "ml_anomaly"
            confidence = float(score)
            method = "ml_isolation"

            if rf_classes is not None and rf_confidences is not None:
                rf_class = rf_classes[i]
                rf_conf = float(rf_confidences[i])
                if rf_class != "normal" and rf_conf > 0.4:
                    attack_type = rf_class
                    confidence = round((confidence + rf_conf) / 2, 3)
                    method = "combined"

            top_feats = [f for f in FEATURE_NAMES if float(X.iloc[i].get(f, 0)) > 0.5]
            evidence = [f"High {f}: {X.iloc[i][f]:.2f}" for f in top_feats[:3]]
            reasoning = (
                f"ML detected anomaly (IF score={score:.2f}). "
                f"Attack type: {attack_type}. "
                f"Key features: {', '.join(top_feats[:3]) or 'multiple sparse signals'}"
            )

            results.append(AnomalyResult(
                anomaly_id=f"ML-{i:04d}",
                timestamp=str(raw.get("timestamp", datetime.utcnow().isoformat())),
                anomaly_type=attack_type,
                ip_address=str(raw.get("ip_address", "unknown")),
                user=str(raw.get("user", "unknown")),
                confidence=round(min(0.99, confidence), 3),
                detection_method=method,
                reasoning=reasoning,
                raw_features=dict(X.iloc[i]),
                supporting_evidence=evidence,
            ))
        return results

    def _rule_based_detection(self, df_raw: pd.DataFrame) -> List[AnomalyResult]:
        """Rule-based pattern matching."""
        results = []

        # Group by (user, ~5-minute windows) for brute force detection
        df = df_raw.copy()
        df["ts"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df["window"] = df["ts"].dt.floor("10min")

        if "user" in df.columns and "status" in df.columns:
            login_fails = (
                df[df["status"].str.upper() == "FAILURE"]
                .groupby(["user", "window"])
                .size()
                .reset_index(name="fail_count")
            )
            for _, row in login_fails[login_fails["fail_count"] >= self.failed_login_threshold].iterrows():
                matching = df[(df["user"] == row["user"]) & (df["window"] == row["window"])]
                ip = str(matching["ip_address"].iloc[0]) if not matching.empty else "unknown"
                ts = str(row["window"])

                results.append(AnomalyResult(
                    anomaly_id=f"RULE-BF-{len(results):04d}",
                    timestamp=ts,
                    anomaly_type="brute_force",
                    ip_address=ip,
                    user=str(row["user"]),
                    confidence=min(0.95, 0.6 + min(0.05 * (row["fail_count"] - self.failed_login_threshold), 0.35)),
                    detection_method="rule_based",
                    reasoning=f"Brute force detected: {int(row['fail_count'])} failed logins in 10-minute window for user {row['user']}",
                    supporting_evidence=[f"Failed attempts: {int(row['fail_count'])} (threshold: {self.failed_login_threshold})"],
                ))

        # Unusual hours rule
        if "ts" in df.columns:
            night_mask = df["ts"].dt.hour.between(self.unusual_hour_start, self.unusual_hour_end)
            night_rows = df[night_mask]
            for _, row in night_rows.iterrows():
                hour = row["ts"].hour if pd.notna(row["ts"]) else -1
                results.append(AnomalyResult(
                    anomaly_id=f"RULE-UH-{len(results):04d}",
                    timestamp=str(row.get("timestamp", "")),
                    anomaly_type="unusual_time",
                    ip_address=str(row.get("ip_address", "unknown")),
                    user=str(row.get("user", "unknown")),
                    confidence=0.75,
                    detection_method="rule_based",
                    reasoning=f"Access at unusual hour: {hour:02d}:00 (policy: 2AM-5AM flagged)",
                    supporting_evidence=[f"Access time: {hour:02d}:xx AM is outside business hours"],
                ))

        # Geographic impossibility (suspicious IPs from known bad prefixes)
        SUSPICIOUS_PREFIXES = ["185.220", "91.92", "194.165", "103.76", "45.142", "95.214", "2.58", "185.234"]
        if "ip_address" in df.columns:
            for _, row in df.iterrows():
                ip = str(row.get("ip_address", ""))
                if any(ip.startswith(pfx) for pfx in SUSPICIOUS_PREFIXES):
                    results.append(AnomalyResult(
                        anomaly_id=f"RULE-GEO-{len(results):04d}",
                        timestamp=str(row.get("timestamp", "")),
                        anomaly_type="geo_anomaly",
                        ip_address=ip,
                        user=str(row.get("user", "unknown")),
                        confidence=0.72,
                        detection_method="rule_based",
                        reasoning=f"Geographic anomaly: IP {ip} originates from a high-risk region",
                        supporting_evidence=[
                            f"IP {ip} is associated with known suspicious regions/exit nodes",
                            f"Location: {row.get('location', 'Unknown')}",
                        ],
                    ))

        return results

    # ──────────────────────────────────────────────
    # Main process
    # ──────────────────────────────────────────────

    def process(self, input_data: Any) -> List[Dict]:
        """
        input_data: list of log dicts OR a pd.DataFrame
        Returns list of AnomalyResult dicts.
        """
        if isinstance(input_data, pd.DataFrame):
            df_raw = input_data
        elif isinstance(input_data, list):
            df_raw = pd.DataFrame(input_data)
        else:
            raise ValueError("HunterAgent.process() expects list[dict] or pd.DataFrame")

        if df_raw.empty:
            logger.warning("Hunter: empty input, nothing to process.")
            return []

        # Engineer features
        X = engineer_features_from_df(df_raw)

        # Load ML models
        y = df_raw.get("anomaly_label") if "anomaly_label" in df_raw.columns else None
        self._load_models(X, y)

        # Run all three detection methods
        stat_anomalies = self._statistical_detection(X, df_raw)
        ml_anomalies = self._ml_detection(X, df_raw)
        rule_anomalies = self._rule_based_detection(df_raw)

        all_anomalies = stat_anomalies + ml_anomalies + rule_anomalies

        # Deduplicate by (user, timestamp, type) keeping highest confidence
        seen: Dict[str, AnomalyResult] = {}
        for a in all_anomalies:
            key = f"{a.user}|{a.timestamp[:16]}|{a.anomaly_type}"
            if key not in seen or a.confidence > seen[key].confidence:
                seen[key] = a

        final = sorted(seen.values(), key=lambda x: x.confidence, reverse=True)
        logger.info(f"[Hunter] Detected {len(final)} unique anomalies from {len(df_raw)} logs.")
        return [a.to_dict() for a in final]
