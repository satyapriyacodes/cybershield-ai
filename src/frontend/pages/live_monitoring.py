"""
Page 2: Live Monitoring — Run detection pipeline with live progress.
"""

import sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import streamlit as st
import time
import pandas as pd
import os
from src.frontend.components.cards import section_header, agent_status_card, info_box
from src.frontend.components.charts import risk_pie_chart


def show():
    section_header("🔍 Live Monitoring", "Trigger the multi-agent detection pipeline")

    # Settings from session
    settings = st.session_state.get("detection_settings", {})
    api_key = st.session_state.get("openai_api_key", os.getenv("OPENAI_API_KEY", ""))

    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown("""
        <div style="background:#1e293b;border-radius:12px;padding:1.5rem;margin-bottom:1rem">
            <h3 style="color:#38bdf8;margin:0 0 .5rem">Pipeline Overview</h3>
            <p style="color:#94a3b8;margin:0">The detection pipeline runs all 5 agents in sequence.
            Logs are loaded, Hunter scans for anomalies, Analyst assesses threats via GPT-4,
            Responder plans responses, Reporter generates metrics, and Watchdog audits everything.</p>
        </div>""", unsafe_allow_html=True)

    with col2:
        log_path = "data/security_logs.csv"
        if os.path.exists(log_path):
            df_preview = pd.read_csv(log_path)
            st.metric("Logs Available", len(df_preview))
        else:
            st.metric("Logs Available", "—")
            if st.button("📝 Generate Logs First"):
                with st.spinner("Generating synthetic logs..."):
                    from src.data.log_generator import generate_logs
                    generate_logs()
                st.success("✅ Logs generated!")
                st.rerun()

    # ── Detection trigger ─────────────────────────────────────────────
    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        run_btn = st.button("🚀 Run Full Detection Pipeline", type="primary", use_container_width=True)
    with col_btn2:
        if "pipeline_result" in st.session_state:
            if st.button("🔄 Clear Results", use_container_width=True):
                del st.session_state["pipeline_result"]
                st.rerun()

    if not run_btn:
        # Show previous result if available
        if "pipeline_result" in st.session_state:
            _show_results(st.session_state.pipeline_result)
        else:
            _show_agent_status_idle()
        return

    # ── Run pipeline ──────────────────────────────────────────────────
    progress_bar = st.progress(0)
    status_text = st.empty()
    agents_container = st.empty()

    agent_states = {
        "Hunter": {"icon": "🔍", "state": "Waiting...", "complete": False, "detail": ""},
        "Analyst": {"icon": "🧠", "state": "Waiting...", "complete": False, "detail": ""},
        "Responder": {"icon": "⚡", "state": "Waiting...", "complete": False, "detail": ""},
        "Reporter": {"icon": "📊", "state": "Waiting...", "complete": False, "detail": ""},
        "Watchdog": {"icon": "👁️", "state": "Waiting...", "complete": False, "detail": ""},
    }

    def render_agents():
        with agents_container.container():
            for name, s in agent_states.items():
                agent_status_card(name, s["icon"], s["state"], s["detail"], s["complete"])

    def progress_cb(step: str, pct: float):
        progress_bar.progress(pct)
        status_text.markdown(f'<p style="color:#38bdf8;font-weight:600">{step}</p>', unsafe_allow_html=True)

        if "Hunter" in step or "Hunter" in step:
            if "Found" in step:
                agent_states["Hunter"]["state"] = step
                agent_states["Hunter"]["complete"] = True
            else:
                agent_states["Hunter"]["state"] = "Scanning logs..."
            render_agents()
        if "Analyst" in step:
            if "assessed" in step:
                agent_states["Analyst"]["state"] = step
                agent_states["Analyst"]["complete"] = True
            else:
                agent_states["Analyst"]["state"] = "Analysing threats..."
            render_agents()
        if "Responder" in step:
            if "plans" in step:
                agent_states["Responder"]["state"] = step
                agent_states["Responder"]["complete"] = True
            else:
                agent_states["Responder"]["state"] = "Planning responses..."
            render_agents()
        if "Reporter" in step:
            if "ready" in step:
                agent_states["Reporter"]["state"] = "Dashboard generated ✓"
                agent_states["Reporter"]["complete"] = True
            else:
                agent_states["Reporter"]["state"] = "Generating metrics..."
            render_agents()
        if "Watchdog" in step or "complete" in step.lower():
            agent_states["Watchdog"]["state"] = "Audit complete ✓"
            agent_states["Watchdog"]["complete"] = True
            render_agents()

    # Load logs
    status_text.markdown('<p style="color:#38bdf8">Loading logs...</p>', unsafe_allow_html=True)
    df = pd.read_csv("data/security_logs.csv")
    logs = df.to_dict(orient="records")

    # Run orchestrator
    from src.agents.orchestrator import Orchestrator
    orch = Orchestrator(openai_api_key=api_key, settings=settings)

    try:
        result = orch.run_pipeline(logs, progress_callback=progress_cb)
        st.session_state["pipeline_result"] = result
        progress_bar.progress(1.0)
        st.balloons()
        _show_results(result)
    except Exception as e:
        st.error(f"Pipeline error: {e}")


def _show_agent_status_idle():
    """Show idle agent status cards before running."""
    st.markdown("### Agent Status")
    agents = [("Hunter", "🔍", "Ready"), ("Analyst", "🧠", "Ready"),
              ("Responder", "⚡", "Ready"), ("Reporter", "📊", "Ready"), ("Watchdog", "👁️", "Ready")]
    for name, icon, state in agents:
        agent_status_card(name, icon, state)


def _show_results(result: dict):
    """Display pipeline results."""
    metrics = result.get("metrics", {})
    watchdog = result.get("watchdog", {})

    st.success(f"✅ Pipeline complete in {result.get('elapsed_seconds', 0):.1f}s")

    # Watchdog alerts
    wdg_alerts = watchdog.get("watchdog_alerts", [])
    for alert in wdg_alerts:
        st.warning(f"**{alert['source']}:** {alert['message']}")

    # Summary metrics
    cols = st.columns(4)
    with cols[0]: st.metric("Logs Scanned", result.get("total_logs", 0))
    with cols[1]: st.metric("Anomalies", len(result.get("anomalies", [])))
    with cols[2]: st.metric("Incidents", len(result.get("incidents", [])))
    with cols[3]: st.metric("Actions", len(result.get("response_plans", [])))

    # Tabs for results
    tab1, tab2, tab3 = st.tabs(["🚨 Anomalies", "📋 Incidents", "⚡ Response Plans"])

    with tab1:
        anomalies = result.get("anomalies", [])
        if anomalies:
            df_a = pd.DataFrame(anomalies)[["anomaly_id","timestamp","anomaly_type","ip_address","user","confidence","detection_method"]]
            df_a["confidence"] = df_a["confidence"].apply(lambda x: f"{x:.0%}")
            st.dataframe(df_a, use_container_width=True, hide_index=True)
        else:
            st.info("No anomalies detected.")

    with tab2:
        incidents = result.get("incidents", [])
        if incidents:
            for inc in incidents[:20]:
                rl = inc.get("risk_level", "LOW")
                color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(rl, "⚪")
                with st.expander(f"{color} [{rl}] {inc.get('attack_type','Unknown')} — {inc.get('ip_address','N/A')}"):
                    st.markdown(inc.get("analysis", "No analysis available"))
                    if inc.get("reasoning_chain"):
                        st.markdown("**Reasoning chain:**")
                        for step in inc.get("reasoning_chain", []):
                            st.markdown(f"- {step}")
        else:
            st.info("No incidents analysed.")

    with tab3:
        plans = result.get("response_plans", [])
        if plans:
            for plan in plans[:20]:
                priority = plan.get("action_priority", "LOW")
                with st.expander(f"[{priority}] {plan.get('attack_type','Unknown')} — {plan.get('source_ip','N/A')}"):
                    st.markdown(f"**SLA:** {plan.get('sla_minutes')} minutes")
                    st.markdown("**Automated Actions (simulated):**")
                    for action in plan.get("automated_actions", []):
                        st.markdown(f"- {action}")
                    if plan.get("manual_actions"):
                        st.markdown("**Manual Actions:**")
                        for action in plan.get("manual_actions", []):
                            st.markdown(f"- {action}")
        else:
            st.info("No response plans generated.")
