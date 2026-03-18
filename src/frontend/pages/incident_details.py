"""
Page 4: Incident Details — Full incident table with filters and CSV export.
"""

import streamlit as st
import pandas as pd
import io
from src.frontend.components.cards import section_header, risk_badge


def _load_incidents() -> list:
    """Load incidents from session state or DB."""
    if "pipeline_result" in st.session_state:
        return st.session_state.pipeline_result.get("incidents", [])
    try:
        from src.database.database import SessionLocal
        from src.database.models import Incident, Anomaly
        db = SessionLocal()
        items = db.query(Incident).order_by(Incident.created_at.desc()).limit(200).all()
        anomalies = {a.id: a for a in db.query(Anomaly).all()}
        db.close()
        result = []
        for i in items:
            a = anomalies.get(i.anomaly_id)
            result.append({
                "id": i.id,
                "timestamp": str(i.created_at)[:19],
                "risk_level": i.risk_level,
                "attack_type": i.attack_type or "Unknown",
                "ip_address": a.ip_address if a else "N/A",
                "user": a.user if a else "N/A",
                "analysis": i.analysis or "",
                "recommended_actions": i.recommended_actions or [],
                "responder_actions": i.responder_actions or [],
                "evidence": i.evidence or [],
                "action_priority": i.action_priority or "LOW",
                "status": i.status,
                "confidence_breakdown": {"final_confidence": a.confidence if a else 0.5},
                "anomaly_id": a.anomaly_id if a else "N/A",
                "reasoning_chain": [],
            })
        return result
    except Exception:
        return []


def show():
    section_header("📋 Incident Details", "All detected incidents with full investigation reports")

    incidents = _load_incidents()

    if not incidents:
        st.info("No incidents found. Run the detection pipeline on the **Live Monitoring** page first.")
        return

    df_display = pd.DataFrame([{
        "ID": i.get("id", idx),
        "Timestamp": i.get("timestamp", "")[:19],
        "Attack Type": i.get("attack_type", "Unknown"),
        "Risk Level": i.get("risk_level", "LOW"),
        "IP Address": i.get("ip_address", "N/A"),
        "User": i.get("user", "N/A"),
        "Status": i.get("status", "OPEN"),
        "Confidence": f"{i.get('confidence_breakdown', {}).get('final_confidence', 0.5):.0%}",
    } for idx, i in enumerate(incidents)])

    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        risk_filter = st.multiselect("Risk Level", ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                                      default=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    with col2:
        type_filter = st.text_input("Attack Type Filter", "")
    with col3:
        status_filter = st.multiselect("Status", ["OPEN", "IN_PROGRESS", "CLOSED"], default=["OPEN", "IN_PROGRESS", "CLOSED"])

    # Apply filters
    filtered = [
        i for i in incidents
        if i.get("risk_level", "LOW") in risk_filter
        and (not type_filter or type_filter.lower() in i.get("attack_type", "").lower())
        and i.get("status", "OPEN") in status_filter
    ]

    st.markdown(f"**{len(filtered)} incidents** matching filters")

    # Export button
    if filtered:
        export_df = pd.DataFrame([{
            "ID": i.get("id", ""), "Timestamp": i.get("timestamp", ""),
            "Attack Type": i.get("attack_type", ""), "Risk Level": i.get("risk_level", ""),
            "IP Address": i.get("ip_address", ""), "User": i.get("user", ""),
            "Analysis": i.get("analysis", ""), "Status": i.get("status", ""),
        } for i in filtered])
        csv = export_df.to_csv(index=False)
        st.download_button("📥 Export to CSV", data=csv, file_name="incidents.csv", mime="text/csv")

    st.markdown("---")

    # Display incidents
    for i, inc in enumerate(filtered[:50]):
        rl = inc.get("risk_level", "LOW")
        risk_color = {"CRITICAL": "#dc2626", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}.get(rl, "#6b7280")
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(rl, "⚪")

        with st.expander(f"{emoji} [{rl}] {inc.get('attack_type','Unknown')} | IP: {inc.get('ip_address','N/A')} | {inc.get('timestamp','')[:16]}"):
            tab1, tab2, tab3, tab4 = st.tabs(["🧠 Analysis", "⚡ Response", "🔍 Evidence", "📝 Feedback"])

            with tab1:
                col_a, col_b = st.columns([2, 1])
                with col_a:
                    st.markdown(inc.get("analysis", "No analysis available"))
                with col_b:
                    st.markdown(f"**Risk Level:** `{rl}`")
                    st.markdown(f"**Attack Type:** `{inc.get('attack_type','Unknown')}`")
                    st.markdown(f"**Priority:** `{inc.get('action_priority','LOW')}`")
                    conf = inc.get("confidence_breakdown", {}).get("final_confidence", 0.5)
                    st.progress(conf, text=f"Confidence: {conf:.0%}")

                if inc.get("reasoning_chain"):
                    st.markdown("**Reasoning Chain:**")
                    for step in inc["reasoning_chain"]:
                        st.markdown(f"- {step}")

            with tab2:
                actions = inc.get("responder_actions") or inc.get("recommended_actions", [])
                if actions:
                    st.markdown("**Automated Actions (Simulated):**")
                    for a in actions:
                        st.markdown(f"- {a}")
                else:
                    st.info("No response actions planned.")

            with tab3:
                evidence = inc.get("evidence", [])
                if evidence:
                    for ev in evidence:
                        st.markdown(f"- {ev}")
                else:
                    st.info("No evidence links available.")

            with tab4:
                _feedback_ui(inc, i)


def _feedback_ui(inc: dict, idx: int):
    """Feedback buttons for adaptive learning."""
    st.markdown("**Mark this incident:**")
    col1, col2, col3 = st.columns(3)
    inc_id = inc.get("id", idx)

    if hasattr(inc_id, '__int__') and isinstance(inc_id, int) and inc_id > 0:
        with col1:
            if st.button("✅ Confirmed Threat", key=f"ct_{idx}"):
                _save_feedback(inc_id, "CONFIRMED_THREAT")
                st.success("Marked as confirmed threat.")
        with col2:
            if st.button("❌ False Positive", key=f"fp_{idx}"):
                _save_feedback(inc_id, "FALSE_POSITIVE")
                st.info("Marked as false positive.")
        with col3:
            if st.button("⬆️ Escalate", key=f"esc_{idx}"):
                _save_feedback(inc_id, "ESCALATE")
                st.warning("Escalated.")
    else:
        st.info("Feedback available for DB-persisted incidents.")


def _save_feedback(incident_id: int, feedback_type: str):
    try:
        from src.database.database import db_session
        from src.database.models import AgentFeedback
        with db_session() as db:
            fb = AgentFeedback(incident_id=incident_id, feedback_type=feedback_type, analyst_name="UI User")
            db.add(fb)
    except Exception as e:
        pass  # In-memory results don't have DB IDs
