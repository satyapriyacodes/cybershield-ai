"""
Responder Agent — Action Recommender
Maps risk levels to prioritised response plans and simulates automated actions.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from loguru import logger

from src.agents.base_agent import BaseAgent


# Action playbooks by risk level
PLAYBOOKS = {
    "CRITICAL": {
        "priority": "URGENT",
        "automated_actions": [
            "🚫 Block IP address at firewall (immediate)",
            "🔒 Force password reset for affected user",
            "📧 Alert security team (P1 incident)",
            "🔇 Isolate affected endpoint from network",
            "📋 Preserve forensic evidence (memory dump, logs)",
            "🔍 Escalate to CISO and legal team",
        ],
        "manual_actions": [
            "Conduct post-incident forensic analysis",
            "Review all user activity for past 30 days",
            "Brief executive leadership",
            "Notify affected users and reset credentials",
        ],
        "sla_minutes": 15,
    },
    "HIGH": {
        "priority": "HIGH",
        "automated_actions": [
            "🚫 Block IP address at firewall",
            "📧 Alert security team (P2 incident)",
            "📈 Increase monitoring level for affected user",
            "📋 Create incident ticket",
        ],
        "manual_actions": [
            "Review user's recent activity logs",
            "Verify with user if activity was legitimate",
            "Consider temporary account suspension",
        ],
        "sla_minutes": 60,
    },
    "MEDIUM": {
        "priority": "MEDIUM",
        "automated_actions": [
            "🏷️ Flag incident for analyst review",
            "📋 Log incident in SIEM",
            "📈 Increase logging verbosity for user/IP",
        ],
        "manual_actions": [
            "Schedule review within 24 hours",
            "Check for related incidents",
        ],
        "sla_minutes": 240,
    },
    "LOW": {
        "priority": "LOW",
        "automated_actions": [
            "📋 Log incident for records",
            "📊 Update baseline behaviour profile",
        ],
        "manual_actions": [
            "Review during weekly security meeting",
        ],
        "sla_minutes": 1440,
    },
}


class ResponderAgent(BaseAgent):
    """Recommends and simulates response actions based on threat analysis."""

    def __init__(self):
        super().__init__("Responder")

    def _build_response_plan(self, incident: Dict) -> Dict:
        risk_level = str(incident.get("risk_level", "LOW")).upper()
        if risk_level not in PLAYBOOKS:
            risk_level = "LOW"

        playbook = PLAYBOOKS[risk_level]
        attack_type = incident.get("attack_type", "Unknown")
        ip = incident.get("ip_address", "N/A")
        user = incident.get("user", "N/A")
        anomaly_id = incident.get("anomaly_id", incident.get("original_anomaly", {}).get("anomaly_id", ""))

        # Build dynamic reasoning
        reasoning = (
            f"Risk Level {risk_level} detected for {attack_type}. "
            f"Affected user: {user}, Source IP: {ip}. "
            f"SLA: Respond within {playbook['sla_minutes']} minutes."
        )

        return {
            "anomaly_id": anomaly_id,
            "risk_level": risk_level,
            "action_priority": playbook["priority"],
            "attack_type": attack_type,
            "automated_actions": playbook["automated_actions"],
            "manual_actions": playbook["manual_actions"],
            "sla_minutes": playbook["sla_minutes"],
            "reasoning": reasoning,
            "response_timestamp": datetime.utcnow().isoformat(),
            "simulated": True,
            "affected_user": user,
            "source_ip": ip,
        }

    def process(self, input_data: Any) -> List[Dict]:
        """
        input_data: list of incident dicts from Analyst
        Returns list of response plan dicts.
        """
        if isinstance(input_data, dict):
            input_data = [input_data]
        if not input_data:
            return []

        results = []
        for incident in input_data:
            plan = self._build_response_plan(incident)
            results.append(plan)

        # Sort by priority
        priority_order = {"URGENT": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        results.sort(key=lambda x: priority_order.get(x["action_priority"], 99))

        logger.info(f"[Responder] Generated {len(results)} response plans.")
        return results

    def chat(self, question: str, context: Optional[str] = None) -> str:
        ctx = context or "You have access to all recent incident response plans."
        return (
            f"As the Responder agent, here's my guidance: {ctx}\n\n"
            f"For your question '{question}': I recommend reviewing the response plans "
            f"for each incident and prioritising URGENT/HIGH priority items first. "
            f"All automated actions shown are simulated — actual blocking requires firewall access."
        )
