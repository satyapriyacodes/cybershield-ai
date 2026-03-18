"""
Analyst Agent — GPT-4 Explanation Engine
Receives anomaly dicts from Hunter and produces risk assessments,
attack classifications, and plain-English explanations.
"""

import os
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from loguru import logger

from src.agents.base_agent import BaseAgent

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False


RISK_RULES = {
    "brute_force": ("HIGH", "Credential Attack"),
    "unusual_time": ("MEDIUM", "Suspicious Access"),
    "geo_anomaly": ("HIGH", "Geographic Anomaly"),
    "impossible_travel": ("CRITICAL", "Account Compromise"),
    "privilege_escalation": ("CRITICAL", "Insider Threat"),
    "statistical_outlier": ("MEDIUM", "Behavioural Anomaly"),
    "ml_anomaly": ("MEDIUM", "ML-Detected Anomaly"),
    "combined": ("HIGH", "Multi-Signal Threat"),
}


def _fallback_analysis(anomaly: Dict) -> Dict:
    """Rule-based fallback when OpenAI is unavailable."""
    atype = str(anomaly.get("anomaly_type", "unknown"))
    risk_level, attack_label = RISK_RULES.get(atype, ("MEDIUM", "Unknown Threat"))
    confidence = float(anomaly.get("confidence", 0.5))
    
    # Upgrade risk based on confidence
    if confidence > 0.90 and risk_level == "HIGH":
        risk_level = "CRITICAL"
    elif confidence < 0.55 and risk_level in ("HIGH", "CRITICAL"):
        risk_level = "MEDIUM"

    analysis_text = (
        f"**{attack_label}** detected against user '{anomaly.get('user', 'unknown')}' "
        f"from IP {anomaly.get('ip_address', 'N/A')}.\n\n"
        f"**Detection:** {anomaly.get('reasoning', 'No reasoning provided.')}\n\n"
        f"**Risk Assessment:** {risk_level} — confidence {confidence:.0%}.\n\n"
        f"**Evidence:** {'; '.join(anomaly.get('supporting_evidence', [])) or 'See detection reasoning.'}\n\n"
        f"**Recommendation:** Immediate investigation required for {risk_level} threats. "
        f"Review associated logs and user account activity."
    )

    return {
        "anomaly_id": anomaly.get("anomaly_id", ""),
        "risk_level": risk_level,
        "attack_type": attack_label,
        "analysis": analysis_text,
        "evidence": anomaly.get("supporting_evidence", []),
        "confidence_breakdown": {
            "detection_confidence": confidence,
            "risk_multiplier": 1.0,
            "final_confidence": round(confidence, 3),
        },
        "reasoning_chain": [
            f"1. Hunter detected {atype} via {anomaly.get('detection_method', 'unknown')} method",
            f"2. Confidence score: {confidence:.0%}",
            f"3. Risk mapped to {risk_level} based on attack pattern",
            f"4. Supporting evidence: {len(anomaly.get('supporting_evidence', []))} indicators",
        ],
        "comparison_to_normal": "Normal users exhibit 0-1 failed logins per session during business hours from known IPs.",
        "generated_by": "rule_based_fallback",
    }


class AnalystAgent(BaseAgent):
    """Generates human-readable threat analysis using GPT-4."""

    def __init__(self, api_key: Optional[str] = None):
        super().__init__("Analyst")
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self._client: Optional[Any] = None
        if OPENAI_AVAILABLE and self.api_key and self.api_key.startswith("sk-"):
            try:
                self._client = OpenAI(api_key=self.api_key)
                logger.info("[Analyst] OpenAI client initialised.")
            except Exception as e:
                logger.warning(f"[Analyst] OpenAI init failed: {e}")
        else:
            logger.info("[Analyst] Running in fallback mode (no OpenAI key).")

    def _gpt_analyse(self, anomaly: Dict) -> Dict:
        """Call GPT-4 to generate analysis."""
        if self._client is None:
            return _fallback_analysis(anomaly)

        system_prompt = """You are an expert cybersecurity analyst. 
Analyse security anomalies and provide structured JSON responses.
Be precise, evidence-based, and explain technical findings in clear language.
Always respond with valid JSON matching the schema provided."""

        user_prompt = f"""Analyse this security anomaly and respond with JSON:

ANOMALY:
{json.dumps(anomaly, indent=2)}

Respond with this exact JSON schema:
{{
  "risk_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "attack_type": "descriptive attack type name",
  "analysis": "plain English explanation (2-3 paragraphs)",
  "evidence": ["evidence point 1", "evidence point 2"],
  "confidence_breakdown": {{
    "detection_confidence": 0.0-1.0,
    "risk_multiplier": 1.0,
    "final_confidence": 0.0-1.0
  }},
  "reasoning_chain": ["step 1", "step 2", "step 3"],
  "comparison_to_normal": "how this compares to normal behaviour",
  "generated_by": "gpt4"
}}"""

        try:
            response = self._client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.2,
                max_tokens=800,
                response_format={"type": "json_object"},
            )
            content = response.choices[0].message.content
            result = json.loads(content)
            result["anomaly_id"] = anomaly.get("anomaly_id", "")
            return result
        except Exception as e:
            logger.warning(f"[Analyst] GPT-4 call failed: {e}. Using fallback.")
            return _fallback_analysis(anomaly)

    def process(self, input_data: Any) -> List[Dict]:
        """
        input_data: list of anomaly dicts from Hunter
        Returns list of incident analysis dicts.
        """
        if isinstance(input_data, dict):
            input_data = [input_data]

        if not input_data:
            return []

        results = []
        for anomaly in input_data:
            logger.debug(f"[Analyst] Analysing {anomaly.get('anomaly_id', '?')}")
            analysis = self._gpt_analyse(anomaly)
            # Merge anomaly metadata into analysis result
            analysis["original_anomaly"] = anomaly
            analysis["timestamp"] = anomaly.get("timestamp", datetime.utcnow().isoformat())
            analysis["ip_address"] = anomaly.get("ip_address", "")
            analysis["user"] = anomaly.get("user", "")
            results.append(analysis)

        logger.info(f"[Analyst] Analysed {len(results)} anomalies.")
        return results

    def chat(self, question: str, context: Optional[str] = None) -> str:
        """Chat interface for the Analyst agent."""
        if self._client is None:
            return (
                "I'm the Analyst agent. I assess threats detected by Hunter and classify them by risk level. "
                "For full AI analysis, please configure your OpenAI API key in Settings."
            )
        system = (
            "You are the Analyst agent in a cybersecurity monitoring system. "
            "You explain threats, risk assessments, and attack patterns in clear language. "
            f"Context: {context or 'No specific context provided.'}"
        )
        try:
            resp = self._client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "system", "content": system}, {"role": "user", "content": question}],
                temperature=0.4,
                max_tokens=500,
            )
            return resp.choices[0].message.content
        except Exception as e:
            return f"[Analyst] Error: {e}"
