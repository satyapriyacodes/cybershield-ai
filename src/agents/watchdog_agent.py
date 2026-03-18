"""
Watchdog Agent — Meta-monitoring of other agents.
Detects behavioural anomalies in agent outputs (false-positive explosions, risk drift, etc.)
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from loguru import logger

from src.agents.base_agent import BaseAgent


ALERT_THRESHOLDS = {
    "hunter_flag_rate_max": 0.50,      # Hunter shouldn't flag >50% of logs
    "hunter_flag_rate_spike_factor": 3.0,  # 3x increase = warning
    "critical_ratio_max": 0.40,         # >40% CRITICAL = analyst drift
    "low_confidence_max": 0.35,         # avg confidence <35% = suspicious
}


class WatchdogAgent(BaseAgent):
    """Monitors the 4 main agents for meta-level anomalies."""

    def __init__(self):
        super().__init__("Watchdog")
        self._history: List[Dict] = []

    def _check_hunter_flag_rate(self, total_logs: int, total_anomalies: int) -> Optional[str]:
        if total_logs == 0:
            return None
        rate = total_anomalies / total_logs
        if rate > ALERT_THRESHOLDS["hunter_flag_rate_max"]:
            return (
                f"⚠️ WARNING: Hunter flagging rate is {rate:.0%} "
                f"(threshold: {ALERT_THRESHOLDS['hunter_flag_rate_max']:.0%}). "
                f"Possible false-positive explosion or adversarial input."
            )

        # Check spike vs history
        if self._history:
            prev_rate = self._history[-1].get("hunter_flag_rate", rate)
            if prev_rate > 0 and rate / prev_rate > ALERT_THRESHOLDS["hunter_flag_rate_spike_factor"]:
                pct = (rate / prev_rate - 1) * 100
                return (
                    f"⚠️ WARNING: Hunter Agent flagging rate increased {pct:.0f}% vs last run "
                    f"({prev_rate:.0%} → {rate:.0%}). Possible adversarial attack on detection pipeline."
                )
        return None

    def _check_analyst_risk_drift(self, incidents: List[Dict]) -> Optional[str]:
        if not incidents:
            return None
        critical_count = sum(1 for i in incidents if i.get("risk_level") == "CRITICAL")
        ratio = critical_count / len(incidents)
        if ratio > ALERT_THRESHOLDS["critical_ratio_max"]:
            return (
                f"⚠️ WARNING: Analyst classified {ratio:.0%} of incidents as CRITICAL "
                f"(threshold: {ALERT_THRESHOLDS['critical_ratio_max']:.0%}). "
                f"Risk level drift detected — analyst calibration may be off."
            )
        return None

    def _check_confidence_drift(self, incidents: List[Dict]) -> Optional[str]:
        if not incidents:
            return None
        confidences = [
            i.get("confidence_breakdown", {}).get("final_confidence", 0.5) for i in incidents
        ]
        avg = sum(confidences) / len(confidences)
        if avg < ALERT_THRESHOLDS["low_confidence_max"]:
            return (
                f"⚠️ WARNING: Average detection confidence is {avg:.0%} "
                f"(threshold: {ALERT_THRESHOLDS['low_confidence_max']:.0%}). "
                f"Low confidence detections dominate — consider retraining models."
            )
        return None

    def _check_responder_completeness(self, incidents: List[Dict], plans: List[Dict]) -> Optional[str]:
        if len(incidents) > 0 and len(plans) == 0:
            return "⚠️ WARNING: Responder produced no action plans despite active incidents."
        missed = len(incidents) - len(plans)
        if incidents and missed > len(incidents) * 0.2:
            return f"⚠️ WARNING: Responder missed response plans for {missed}/{len(incidents)} incidents."
        return None

    def process(self, input_data: Any) -> Dict:
        """
        input_data: dict with keys:
          - total_logs: int
          - anomalies: list (from Hunter)
          - incidents: list (from Analyst)
          - response_plans: list (from Responder)
        Returns: dict with watchdog_alerts list and overall_status.
        """
        total_logs = input_data.get("total_logs", 0) if isinstance(input_data, dict) else 0
        anomalies = input_data.get("anomalies", []) if isinstance(input_data, dict) else []
        incidents = input_data.get("incidents", []) if isinstance(input_data, dict) else []
        plans = input_data.get("response_plans", []) if isinstance(input_data, dict) else []

        alerts = []

        warn = self._check_hunter_flag_rate(total_logs, len(anomalies))
        if warn:
            alerts.append({"level": "WARNING", "source": "Hunter", "message": warn})

        warn = self._check_analyst_risk_drift(incidents)
        if warn:
            alerts.append({"level": "WARNING", "source": "Analyst", "message": warn})

        warn = self._check_confidence_drift(incidents)
        if warn:
            alerts.append({"level": "WARNING", "source": "Hunter/ML", "message": warn})

        warn = self._check_responder_completeness(incidents, plans)
        if warn:
            alerts.append({"level": "WARNING", "source": "Responder", "message": warn})

        # Record this run for spike detection
        self._history.append({
            "hunter_flag_rate": len(anomalies) / max(total_logs, 1),
            "timestamp": datetime.utcnow().isoformat(),
        })
        self._history = self._history[-10:]  # Keep last 10 runs

        overall = "HEALTHY" if not alerts else ("DEGRADED" if len(alerts) < 3 else "CRITICAL")

        for alert in alerts:
            logger.warning(f"[Watchdog] {alert['source']}: {alert['message']}")

        return {
            "overall_status": overall,
            "watchdog_alerts": alerts,
            "alert_count": len(alerts),
            "agents_monitored": ["Hunter", "Analyst", "Responder", "Reporter"],
            "checked_at": datetime.utcnow().isoformat(),
            "stats": {
                "total_logs": total_logs,
                "anomalies_detected": len(anomalies),
                "incidents_analysed": len(incidents),
                "response_plans": len(plans),
            },
        }
