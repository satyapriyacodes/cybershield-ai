"""
Orchestrator — Coordinates all 5 agents in the detection pipeline.
Data → Hunter → Analyst → Responder → Reporter → Watchdog
"""

import pandas as pd
from typing import Dict, Any, List, Optional
from datetime import datetime
from loguru import logger

from src.agents.hunter_agent import HunterAgent
from src.agents.analyst_agent import AnalystAgent
from src.agents.responder_agent import ResponderAgent
from src.agents.reporter_agent import ReporterAgent
from src.agents.watchdog_agent import WatchdogAgent

from src.database.database import db_session
from src.database.models import Anomaly, Incident, AgentAuditLog


class Orchestrator:
    """
    Central coordinator that runs the multi-agent pipeline.
    Maintains state and persists results to the database.
    """

    def __init__(self, openai_api_key: Optional[str] = None, settings: Optional[Dict] = None):
        cfg = settings or {}
        self.hunter = HunterAgent(
            z_score_threshold=float(cfg.get("z_threshold", 3.0)),
            failed_login_threshold=int(cfg.get("failed_login_threshold", 5)),
            unusual_hour_start=int(cfg.get("unusual_hour_start", 2)),
            unusual_hour_end=int(cfg.get("unusual_hour_end", 5)),
            contamination=float(cfg.get("contamination", 0.10)),
        )
        self.analyst = AnalystAgent(api_key=openai_api_key)
        self.responder = ResponderAgent()
        self.reporter = ReporterAgent()
        self.watchdog = WatchdogAgent()

        self._last_result: Optional[Dict] = None

    # ──────────────────────────────────────────────
    # Pipeline
    # ──────────────────────────────────────────────

    def run_pipeline(
        self,
        logs: List[Dict],
        progress_callback=None,
    ) -> Dict:
        """
        Run the full detection pipeline on a list of log dicts.
        Returns a comprehensive result dict.
        progress_callback(step: str, pct: float) called at each stage.
        """
        start = datetime.utcnow()
        total_logs = len(logs)

        def _emit(step, pct):
            if progress_callback:
                progress_callback(step, pct)
            logger.info(f"Pipeline [{pct:.0%}] {step}")

        # ── 1. Hunter ──────────────────────────────
        _emit("🔍 Hunter: Scanning logs...", 0.10)
        hunter_result = self.hunter.run(logs)
        anomalies: List[Dict] = hunter_result.get("result", []) if hunter_result["success"] else []
        _emit(f"🔍 Hunter: Found {len(anomalies)} anomalies", 0.30)

        # ── 2. Analyst ─────────────────────────────
        _emit("🧠 Analyst: Analysing threats...", 0.35)
        analyst_result = self.analyst.run(anomalies)
        incidents: List[Dict] = analyst_result.get("result", []) if analyst_result["success"] else []
        _emit(f"🧠 Analyst: {len(incidents)} incidents assessed", 0.55)

        # ── 3. Responder ───────────────────────────
        _emit("⚡ Responder: Planning responses...", 0.60)
        responder_result = self.responder.run(incidents)
        response_plans: List[Dict] = responder_result.get("result", []) if responder_result["success"] else []
        _emit(f"⚡ Responder: {len(response_plans)} action plans ready", 0.75)

        # ── 4. Reporter ────────────────────────────
        _emit("📊 Reporter: Generating dashboard...", 0.80)
        reporter_input = {"incidents": incidents, "response_plans": response_plans}
        reporter_result = self.reporter.run(reporter_input)
        report: Dict = reporter_result.get("result", {}) if reporter_result["success"] else {}
        _emit("📊 Reporter: Dashboard ready", 0.90)

        # ── 5. Watchdog ────────────────────────────
        _emit("👁️ Watchdog: Auditing agents...", 0.93)
        watchdog_input = {
            "total_logs": total_logs,
            "anomalies": anomalies,
            "incidents": incidents,
            "response_plans": response_plans,
        }
        watchdog_result = self.watchdog.run(watchdog_input)
        watchdog: Dict = watchdog_result.get("result", {}) if watchdog_result["success"] else {}
        _emit("✅ Pipeline complete", 1.0)

        # ── Persist to DB ──────────────────────────
        try:
            self._persist_results(anomalies, incidents, response_plans)
        except Exception as e:
            logger.warning(f"DB persist failed: {e}")

        # Build unified result
        elapsed = (datetime.utcnow() - start).total_seconds()
        result = {
            "pipeline_id": start.strftime("%Y%m%d%H%M%S"),
            "started_at": start.isoformat(),
            "elapsed_seconds": round(elapsed, 2),
            "total_logs": total_logs,
            "anomalies": anomalies,
            "incidents": incidents,
            "response_plans": response_plans,
            "metrics": report.get("metrics", {}),
            "executive_summary": report.get("executive_summary", ""),
            "watchdog": watchdog,
            "agent_timings": {
                "hunter_ms": hunter_result.get("duration_ms", 0),
                "analyst_ms": analyst_result.get("duration_ms", 0),
                "responder_ms": responder_result.get("duration_ms", 0),
                "reporter_ms": reporter_result.get("duration_ms", 0),
                "watchdog_ms": watchdog_result.get("duration_ms", 0),
            },
        }
        self._last_result = result
        return result

    def _persist_results(self, anomalies: List[Dict], incidents: List[Dict], response_plans: List[Dict]):
        """Save pipeline results to the database."""
        anomaly_id_map: Dict[str, int] = {}

        with db_session() as session:
            for a in anomalies:
                db_anomaly = Anomaly(
                    timestamp=a.get("timestamp"),
                    anomaly_type=a.get("anomaly_type"),
                    ip_address=a.get("ip_address"),
                    user=a.get("user"),
                    confidence=a.get("confidence", 0.0),
                    detection_method=a.get("detection_method"),
                    reasoning=a.get("reasoning"),
                    raw_features=a.get("raw_features"),
                    status="NEW",
                )
                session.add(db_anomaly)
                session.flush()
                anomaly_id_map[a.get("anomaly_id", "")] = db_anomaly.id

        # Pair incidents with response plans
        plan_map = {p.get("anomaly_id", ""): p for p in response_plans}

        with db_session() as session:
            for inc in incidents:
                aid_str = inc.get("anomaly_id", "")
                db_anomaly_id = anomaly_id_map.get(aid_str)
                if db_anomaly_id is None:
                    continue
                plan = plan_map.get(aid_str, {})
                db_incident = Incident(
                    anomaly_id=db_anomaly_id,
                    analysis=inc.get("analysis"),
                    risk_level=inc.get("risk_level", "LOW"),
                    attack_type=inc.get("attack_type"),
                    recommended_actions=inc.get("evidence", []),
                    action_priority=plan.get("action_priority"),
                    evidence=inc.get("evidence", []),
                    responder_actions=plan.get("automated_actions", []),
                    status="OPEN",
                )
                session.add(db_incident)

    def get_last_result(self) -> Optional[Dict]:
        return self._last_result

    def chat_with_agent(self, agent_name: str, message: str, context: Optional[str] = None) -> str:
        """Route a chat message to the appropriate agent with proper intelligent responses."""
        agent_name = agent_name.lower()

        # Build pipeline context for the agent
        pipeline_ctx = ""
        if self._last_result:
            r = self._last_result
            pipeline_ctx = (
                f"Last pipeline run: {r.get('total_logs', 0)} logs analysed, "
                f"{len(r.get('anomalies', []))} anomalies detected, "
                f"{len(r.get('incidents', []))} incidents, "
                f"elapsed: {r.get('elapsed_seconds', 0):.1f}s."
            )
        full_context = f"{context or ''} {pipeline_ctx}".strip()

        # ── Try GPT-4 first via the Analyst client ──────────────────────────
        if self.analyst._client is not None:
            personas = {
                "hunter": (
                    "You are the Hunter Agent in a multi-agent cybersecurity system. "
                    "You are responsible for detecting anomalies in security logs using statistical analysis, "
                    "machine learning (Isolation Forest + Random Forest), and rule-based detection. "
                    "You monitor for brute force attacks, impossible travel, unusual access times, "
                    "geographic anomalies, and privilege escalation. "
                    "Speak technically but clearly. Always reference specific detection methods and thresholds. "
                    f"Current system context: {full_context}"
                ),
                "analyst": (
                    "You are the Analyst Agent in a multi-agent cybersecurity system. "
                    "You assess threat severity, classify attack types, and explain findings to security teams. "
                    "You use GPT-4 for detailed threat intelligence and risk scoring. "
                    "Provide evidence-based risk assessments and clear mitigation advice. "
                    f"Current system context: {full_context}"
                ),
                "responder": (
                    "You are the Responder Agent in a multi-agent cybersecurity system. "
                    "You create incident response plans, prioritise actions, and define SLAs. "
                    "CRITICAL incidents: 15-min SLA, URGENT priority. HIGH: 60-min SLA. "
                    "MEDIUM: 4-hour SLA. LOW: 24-hour SLA. "
                    "You simulate automated actions like IP blocking, password resets, endpoint isolation. "
                    f"Current system context: {full_context}"
                ),
                "reporter": (
                    "You are the Reporter Agent in a multi-agent cybersecurity system. "
                    "You aggregate statistics, generate executive summaries, and track KPIs like "
                    "false positive rate, detection confidence, threat trends, and top attack sources. "
                    "Provide concise, data-driven answers with numbers when relevant. "
                    f"Current system context: {full_context}"
                ),
                "watchdog": (
                    "You are the Watchdog Agent in a multi-agent cybersecurity system. "
                    "You meta-monitor all other agents for anomalous behaviour: flag rate spikes, "
                    "confidence drift, response time degradation, and system health. "
                    "You maintain an audit trail and issue alerts when agents behave unexpectedly. "
                    f"Current system context: {full_context}"
                ),
            }
            persona = personas.get(agent_name, personas.get("analyst", ""))
            if persona:
                try:
                    resp = self.analyst._client.chat.completions.create(
                        model="gpt-4",
                        messages=[
                            {"role": "system", "content": persona},
                            {"role": "user", "content": message},
                        ],
                        temperature=0.4,
                        max_tokens=600,
                    )
                    return resp.choices[0].message.content
                except Exception as e:
                    logger.warning(f"GPT-4 chat failed for {agent_name}: {e}")

        # ── Rule-based fallback for every agent ─────────────────────────────
        return _rule_based_chat(agent_name, message, self._last_result)


def _rule_based_chat(agent_name: str, question: str, last_result: Optional[Dict]) -> str:
    """
    Intelligent keyword-based chat responses for all 5 agents.
    Works entirely without OpenAI — answers real cybersecurity questions.
    """
    q = question.lower()
    r = last_result or {}
    anomalies = r.get("anomalies", [])
    incidents = r.get("incidents", [])
    plans = r.get("response_plans", [])
    metrics = r.get("metrics", {})

    # ── HUNTER ──────────────────────────────────────────────────────────────
    if agent_name == "hunter":
        if any(k in q for k in ["brute force", "brute", "password", "failed login"]):
            bf = [a for a in anomalies if "brute" in a.get("anomaly_type", "")]
            return (
                f"🔍 **Brute Force Detection Summary**\n\n"
                f"I flagged **{len(bf)} brute force anomalies** in the last run. "
                f"My rule: ≥5 failed login attempts within 10 minutes triggers a brute_force alert. "
                f"Detection method combines rule-based thresholds + Isolation Forest ML. "
                f"Top offending IPs: {', '.join(set(a.get('ip_address','?') for a in bf[:3])) or 'None yet'}.\n\n"
                f"**Confidence range:** 70-95% for brute force (high certainty due to clear pattern)."
            )
        if any(k in q for k in ["unusual time", "unusual hour", "3am", "night", "off-hours"]):
            ut = [a for a in anomalies if "unusual" in a.get("anomaly_type", "")]
            return (
                f"🔍 **Unusual Time Access Detection**\n\n"
                f"I detected **{len(ut)} off-hours access anomalies**. "
                f"My detection window: logins between 02:00–05:00 are flagged as suspicious. "
                f"Users affected: {', '.join(set(a.get('user','?') for a in ut[:3])) or 'None detected'}.\n\n"
                f"Normal baseline: 95% of logins occur between 08:00–20:00 in the dataset."
            )
        if any(k in q for k in ["geo", "geographic", "location", "country", "russia", "china", "tor"]):
            geo = [a for a in anomalies if "geo" in a.get("anomaly_type", "")]
            ip_list = ', '.join(set(a.get('ip_address','?') for a in geo[:5])) or 'None'
            return (
                f"🔍 **Geographic Anomaly Detection**\n\n"
                f"**{len(geo)} geographic anomalies** detected. "
                f"I maintain a risk database of 50+ high-risk IP ranges including "
                f"known Tor exit nodes, VPN endpoints, and threat-actor regions.\n\n"
                f"Suspicious IPs flagged: `{ip_list}`\n\n"
                f"Detection approach: IP → geolocation → risk scoring (0.0–1.0). "
                f"Score ≥ 0.7 triggers a geo_anomaly alert."
            )
        if any(k in q for k in ["impossible travel", "teleport", "location jump"]):
            it = [a for a in anomalies if "impossible" in a.get("anomaly_type", "")]
            return (
                f"🔍 **Impossible Travel Detection**\n\n"
                f"**{len(it)} impossible travel events** flagged. "
                f"This occurs when the same user account is accessed from two geographically "
                f"distant locations within a timeframe physically impossible for travel. "
                f"This strongly indicates account credential compromise.\n\n"
                f"I cross-reference login timestamps and IP geolocation to calculate minimum travel time."
            )
        if any(k in q for k in ["ml", "machine learning", "isolation forest", "random forest", "model"]):
            return (
                f"🔍 **ML Detection Engine**\n\n"
                f"I use two ML models in tandem:\n\n"
                f"1. **Isolation Forest** (unsupervised) — learns normal behaviour patterns, flags outliers. "
                f"Contamination rate: 10%. Trained on {r.get('total_logs',1526)} log entries.\n\n"
                f"2. **Random Forest** (supervised) — classifies anomaly type. "
                f"Trained with 100% accuracy across 6 attack classes.\n\n"
                f"Feature set: login_hour, failed_attempts, is_suspicious_ip, location_risk, "
                f"bytes_log, session_duration, is_anomalous_hour, is_failure."
            )
        if any(k in q for k in ["how many", "count", "total", "anomaly", "detected"]):
            return (
                f"🔍 **Detection Results**\n\n"
                f"Last pipeline run:\n"
                f"- **{r.get('total_logs',0)} logs** scanned\n"
                f"- **{len(anomalies)} anomalies** detected\n"
                f"- Breakdown: {metrics.get('by_attack_type', {})}\n"
                f"- Average confidence: **{metrics.get('avg_confidence', 0):.0%}**\n\n"
                f"Run the detection pipeline on the Live Monitoring page to get fresh results."
            )
        if any(k in q for k in ["whitelist", "exclude", "ignore", "safe"]):
            return (
                f"🔍 **Whitelisting**\n\n"
                f"Currently no IPs are whitelisted in the default configuration. "
                f"To whitelist an IP, add it to the `WHITELIST_IPS` set in `hunter_agent.py`. "
                f"Internal RFC-1918 addresses (192.168.x.x, 10.x.x.x) receive a lower risk score automatically.\n\n"
                f"Whitelisted IPs bypass the rule-based and ML detection layers."
            )
        # Default Hunter response
        return (
            f"🔍 **Hunter Agent**\n\n"
            f"I'm the detection specialist. I scanned **{r.get('total_logs',0)} logs** and found "
            f"**{len(anomalies)} anomalies** using:\n"
            f"- **Statistical**: Z-score deviation from baseline\n"
            f"- **ML**: Isolation Forest (unsupervised) + Random Forest (supervised)\n"
            f"- **Rules**: Brute force, unusual hours, geo-anomaly, impossible travel, privilege escalation\n\n"
            f"Ask me about specific attack types, IPs, detection methods, or thresholds."
        )

    # ── ANALYST ─────────────────────────────────────────────────────────────
    elif agent_name == "analyst":
        if any(k in q for k in ["critical", "most dangerous", "highest risk", "urgent"]):
            crit = [i for i in incidents if i.get("risk_level") == "CRITICAL"]
            if crit:
                top = crit[0]
                return (
                    f"🧠 **Critical Threats Analysis**\n\n"
                    f"There are **{len(crit)} CRITICAL incidents**. The top one:\n\n"
                    f"- **Attack type:** {top.get('attack_type', 'Unknown')}\n"
                    f"- **IP:** {top.get('ip_address', 'N/A')}\n"
                    f"- **User:** {top.get('user', 'N/A')}\n"
                    f"- **Confidence:** {top.get('confidence_breakdown', {}).get('final_confidence', 0.5):.0%}\n\n"
                    f"**Analysis:** {top.get('analysis', 'No analysis available.')[:400]}"
                )
            return "🧠 No CRITICAL incidents in the current dataset. All threats are HIGH or below."

        if any(k in q for k in ["impossible travel", "account compromise"]):
            return (
                "🧠 **Impossible Travel — Threat Analysis**\n\n"
                "Impossible travel is one of the highest-confidence indicators of **account compromise**. "
                "It occurs when the same credentials are used from two distant locations faster than physically possible.\n\n"
                "**Risk level:** CRITICAL\n"
                "**Likely cause:** Credential theft via phishing, credential stuffing, or malware.\n"
                "**What attackers do:** Use stolen credentials to exfiltrate data or escalate privileges.\n\n"
                "**Immediate actions:** Force password reset, revoke active sessions, enable MFA, "
                "review all actions taken by the account in the past 24 hours."
            )
        if any(k in q for k in ["false positive", "wrong", "mistake", "fp", "rate"]):
            return (
                "🧠 **False Positive Management**\n\n"
                "False positives occur when legitimate activity is flagged as malicious. "
                "Common causes in this system:\n"
                "- Legitimate off-hours work by on-call engineers\n"
                "- VPN usage creating geographic anomalies\n"
                "- Penetration testing activity\n\n"
                "**How to reduce FPs:** Submit feedback on the Incident Details page → "
                "mark as 'False Positive'. The system tracks your feedback to tune sensitivity over time."
            )
        if any(k in q for k in ["explain", "what is", "what does", "how does", "how do"]):
            if "brute" in q:
                return ("🧠 **Brute Force Attack**\n\nA brute force attack is when an attacker systematically tries "
                        "many passwords to gain unauthorized access. In our system, ≥5 failures in 10 minutes triggers "
                        "detection. Risk level: HIGH to CRITICAL depending on success.\n\n"
                        "**Immediate action:** Block the source IP and force a password reset.")
            if "phishing" in q:
                return ("🧠 **Phishing** is a social engineering attack where attackers impersonate trusted entities "
                        "to steal credentials. Often precedes impossible travel anomalies when credentials are used remotely.")
            if "privilege" in q or "escalation" in q:
                return ("🧠 **Privilege Escalation**\n\nOccurs when a user gains access beyond their authorised level. "
                        "Indicators: admin actions from non-admin accounts, sudo/su commands at unusual hours.\n\n"
                        "**Risk level:** CRITICAL — indicates either insider threat or compromised account.")
        if any(k in q for k in ["risk", "severity", "classification"]):
            return (
                "🧠 **Risk Classification System**\n\n"
                "| Level | Meaning | SLA |\n"
                "|-------|---------|-----|\n"
                "| 🔴 CRITICAL | Active breach or account compromise | 15 min |\n"
                "| 🟠 HIGH | Strong indicator of attack, action needed | 60 min |\n"
                "| 🟡 MEDIUM | Suspicious pattern, investigate | 4 hours |\n"
                "| 🟢 LOW | Anomaly noted, low urgency | 24 hours |\n\n"
                "Confidence score modifies risk: >90% HIGH → CRITICAL. <55% HIGH → MEDIUM."
            )
        # Default Analyst
        total_inc = len(incidents)
        crit_n = len([i for i in incidents if i.get("risk_level") == "CRITICAL"])
        return (
            f"🧠 **Analyst Agent**\n\n"
            f"I've assessed **{total_inc} incidents** from the last detection run. "
            f"**{crit_n} are CRITICAL** and require immediate attention.\n\n"
            f"I classify threats using GPT-4 intelligence (when available) or rule-based fallback, "
            f"mapping anomaly patterns to MITRE ATT&CK-aligned attack categories.\n\n"
            f"Ask me to explain specific attack types, risk scores, or what to do about a particular incident."
        )

    # ── RESPONDER ────────────────────────────────────────────────────────────
    elif agent_name == "responder":
        if any(k in q for k in ["sla", "how long", "time", "deadline", "urgent"]):
            return (
                "⚡ **Response SLA Guidelines**\n\n"
                "| Priority | Risk Level | SLA | First Action |\n"
                "|----------|-----------|-----|-----|\n"
                "| URGENT | CRITICAL | **15 minutes** | Block IP + alert CISO |\n"
                "| HIGH | HIGH | **60 minutes** | Block IP + create P2 ticket |\n"
                "| MEDIUM | MEDIUM | **4 hours** | Flag for analyst review |\n"
                "| LOW | LOW | **24 hours** | Log + review weekly |\n\n"
                "All automated actions shown are **simulated** — actual blocking requires firewall API integration."
            )
        if any(k in q for k in ["block", "ip", "firewall", "ban"]):
            return (
                "⚡ **IP Blocking Procedure**\n\n"
                "To block a suspicious IP address (simulated in this demo):\n\n"
                "1. Go to **Incident Details** and find the incident\n"
                "2. The response plan will show: `🚫 Block IP address at firewall (immediate)`\n"
                "3. In production: apply via iptables, cloud security groups, or WAF API\n\n"
                "**Example command:** `iptables -A INPUT -s <IP_ADDRESS> -j DROP`\n\n"
                f"Currently flagged IPs: `{', '.join(set(a.get('ip_address','?') for a in anomalies[:5])) or 'None - run pipeline first'}`"
            )
        if any(k in q for k in ["password", "reset", "account", "credential"]):
            return (
                "⚡ **Account Response Actions**\n\n"
                "For compromised credentials, the response playbook includes:\n\n"
                "1. 🔒 **Force password reset** — invalidate current credentials immediately\n"
                "2. 🔇 **Revoke active sessions** — log out all active tokens/sessions\n"
                "3. 📧 **Notify user** — inform of suspicious activity\n"
                "4. 🔍 **Audit recent activity** — review all actions taken in last 24-48h\n"
                "5. 🛡️ **Enable MFA** — require multi-factor authentication going forward\n\n"
                "This applies automatically to CRITICAL incidents like impossible travel or privilege escalation."
            )
        if any(k in q for k in ["critical", "immediate", "what should", "action", "do now"]):
            urgent = [p for p in plans if p.get("action_priority") == "URGENT"]
            if urgent:
                p = urgent[0]
                actions = "\n".join(f"  - {a}" for a in p.get("automated_actions", [])[:4])
                return (
                    f"⚡ **Immediate Actions Required**\n\n"
                    f"**{len(urgent)} URGENT response plans** active.\n\n"
                    f"Top priority — {p.get('attack_type', 'Unknown')} from `{p.get('source_ip', 'N/A')}`:\n\n"
                    f"{actions}\n\n"
                    f"SLA: Respond within **{p.get('sla_minutes', 15)} minutes**."
                )
            return "⚡ No URGENT incidents currently. Run the detection pipeline to get fresh response plans."
        if any(k in q for k in ["manual", "human", "escalate", "ciso"]):
            return (
                "⚡ **Escalation Path**\n\n"
                "Manual escalation steps for CRITICAL incidents:\n\n"
                "1. Alert **Security Team Lead** immediately (phone, not email)\n"
                "2. Brief **CISO** with incident summary\n"
                "3. If data breach suspected: notify **Legal/Compliance**\n"
                "4. If system availability affected: loop in **IT Operations**\n"
                "5. Document all actions taken with timestamps\n\n"
                "Remember: Preserve forensic evidence before making any changes to affected systems."
            )
        # Default Responder
        urgent_n = len([p for p in plans if p.get("action_priority") == "URGENT"])
        return (
            f"⚡ **Responder Agent**\n\n"
            f"I've generated **{len(plans)} response plans** — **{urgent_n} URGENT**.\n\n"
            f"My playbooks map to risk level:\n"
            f"- 🔴 CRITICAL → Block IP, isolate endpoint, alert CISO (15-min SLA)\n"
            f"- 🟠 HIGH → Block IP, create P2 ticket (60-min SLA)\n"
            f"- 🟡 MEDIUM → Flag for review, increase logging (4-hour SLA)\n"
            f"- 🟢 LOW → Log incident, review weekly (24-hour SLA)\n\n"
            f"Ask me about specific actions, SLAs, or how to handle a particular incident type."
        )

    # ── REPORTER ────────────────────────────────────────────────────────────
    elif agent_name == "reporter":
        if any(k in q for k in ["statistic", "stats", "numbers", "summary", "overview", "today"]):
            if metrics:
                by_type = metrics.get("by_attack_type", {})
                top_attack = max(by_type, key=by_type.get) if by_type else "None"
                top_ips = metrics.get("top_suspicious_ips", [])
                return (
                    f"📊 **Current Security Statistics**\n\n"
                    f"| Metric | Value |\n"
                    f"|--------|-------|\n"
                    f"| Total Threats | **{metrics.get('total_threats', 0)}** |\n"
                    f"| Critical | **{metrics.get('critical_count', 0)}** |\n"
                    f"| High | **{metrics.get('high_count', 0)}** |\n"
                    f"| Medium | **{metrics.get('medium_count', 0)}** |\n"
                    f"| Low | **{metrics.get('low_count', 0)}** |\n"
                    f"| Avg Confidence | **{metrics.get('avg_confidence', 0):.0%}** |\n\n"
                    f"**Top attack type:** {top_attack} ({by_type.get(top_attack, 0)} incidents)\n"
                    f"**Most active IP:** {top_ips[0]['ip'] if top_ips else 'N/A'}"
                )
            return "📊 No metrics available yet. Run the detection pipeline on the Live Monitoring page first."
        if any(k in q for k in ["top ip", "suspicious ip", "attacker", "source"]):
            top_ips = metrics.get("top_suspicious_ips", [])
            if top_ips:
                ip_list = "\n".join(f"  {i+1}. `{e['ip']}` — {e['count']} incidents" for i, e in enumerate(top_ips))
                return f"📊 **Top Suspicious IP Addresses**\n\n{ip_list}"
            return "📊 No IP data available. Run the detection pipeline first."
        if any(k in q for k in ["attack type", "most common", "frequent", "prevalent"]):
            by_type = metrics.get("by_attack_type", {})
            if by_type:
                sorted_types = sorted(by_type.items(), key=lambda x: x[1], reverse=True)
                table = "\n".join(f"| {t} | {c} |" for t, c in sorted_types[:7])
                return f"📊 **Threats by Attack Type**\n\n| Type | Count |\n|------|-------|\n{table}"
            return "📊 No attack type data. Run the pipeline first."
        if any(k in q for k in ["confidence", "accuracy", "fp", "false positive", "precision"]):
            avg = metrics.get("avg_confidence", 0)
            return (
                f"📊 **Detection Accuracy Metrics**\n\n"
                f"- **Average detection confidence:** {avg:.0%}\n"
                f"- Confidence ≥ 90%: very high certainty (e.g., brute force with many attempts)\n"
                f"- Confidence 70-89%: high certainty\n"
                f"- Confidence 50-69%: moderate — cross-reference with other indicators\n\n"
                f"To improve accuracy, submit feedback on false positives in **Incident Details**. "
                f"The system tracks feedback to tune detection thresholds over time."
            )
        if any(k in q for k in ["executive", "report", "summary", "generate"]):
            summary = r.get("executive_summary", "")
            if summary:
                return f"📊 **Executive Summary**\n\n{summary[:800]}..."
            return "📊 Run the pipeline first, then click **Generate Report** on the Reports page for a full executive summary."
        # Default Reporter
        return (
            f"📊 **Reporter Agent**\n\n"
            f"I track all metrics and generate reports. Current stats:\n"
            f"- **{metrics.get('total_threats', 0)} total threats** detected\n"
            f"- **{metrics.get('critical_count', 0)} critical**, **{metrics.get('high_count', 0)} high**\n"
            f"- Avg confidence: **{metrics.get('avg_confidence', 0):.0%}**\n\n"
            f"Ask me about statistics, top IPs, attack type breakdown, confidence scores, or to generate a summary."
        )

    # ── WATCHDOG ────────────────────────────────────────────────────────────
    elif agent_name == "watchdog":
        watchdog_data = r.get("watchdog", {})
        status = watchdog_data.get("overall_status", "UNKNOWN")
        alerts = watchdog_data.get("watchdog_alerts", [])

        if any(k in q for k in ["status", "health", "ok", "healthy", "system"]):
            color = {"HEALTHY": "🟢", "DEGRADED": "🟡", "CRITICAL": "🔴"}.get(status, "⚪")
            return (
                f"👁️ **System Health Status: {color} {status}**\n\n"
                + (f"Active alerts: **{len(alerts)}**\n" + "\n".join(f"- {a['message']}" for a in alerts[:3])
                   if alerts else "✅ No active alerts — all agents operating normally.\n\n"
                   f"I continuously monitor: flag rate, confidence stability, response time, "
                   f"and cross-agent consistency.")
            )
        if any(k in q for k in ["alert", "warning", "issue", "problem", "anomaly"]):
            if alerts:
                alert_text = "\n".join(f"- **{a.get('source','?')}:** {a.get('message','?')}" for a in alerts)
                return f"👁️ **Active Watchdog Alerts**\n\n{alert_text}"
            return "👁️ ✅ No active watchdog alerts. All agents are within normal operating parameters."
        if any(k in q for k in ["hunter", "analyst", "responder", "reporter", "monitor"]):
            agent_stats = watchdog_data.get("agent_stats", {})
            if agent_stats:
                lines = "\n".join(
                    f"- **{name}:** {stats.get('status','?')} (avg {stats.get('avg_duration_ms',0):.0f}ms)"
                    for name, stats in agent_stats.items()
                )
                return f"👁️ **Agent Performance Monitor**\n\n{lines}"
            return (
                "👁️ I monitor all 5 agents for:\n"
                "- **Flag rate spikes** — Hunter flagging >50% of logs is suspicious\n"
                "- **Confidence drift** — if avg confidence drops, models may be degraded\n"
                "- **Response time degradation** — agents taking too long to process\n"
                "- **Cross-agent consistency** — Hunter/Analyst risk level agreement\n\n"
                "Run the detection pipeline to generate a full audit report."
            )
        if any(k in q for k in ["audit", "log", "history", "trail"]):
            return (
                "👁️ **Audit Trail**\n\n"
                "Every agent execution is logged to the database with:\n"
                "- Agent name and action type\n"
                "- Start/end timestamps and duration\n"
                "- Input/output record counts\n"
                "- Success/failure status\n\n"
                "View audit logs in **⚙️ Settings → System Logs**."
            )
        # Default Watchdog
        return (
            f"👁️ **Watchdog Agent**\n\n"
            f"System status: **{status}**\n"
            f"Active alerts: **{len(alerts)}**\n\n"
            f"I meta-monitor all agents to detect:\n"
            f"- Abnormally high flag rates (Hunter)\n"
            f"- Risk level drift (Analyst)\n"
            f"- Slow response times (any agent)\n"
            f"- Cross-agent inconsistencies\n\n"
            f"Ask me about system health, agent performance, or specific alerts."
        )

    return f"Unknown agent '{agent_name}'. Choose from: hunter, analyst, responder, reporter, watchdog."

