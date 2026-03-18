"""
Page 7: Settings — API key, thresholds, toggles, system logs.
"""

import streamlit as st
import os
from src.frontend.components.cards import section_header, info_box


def show():
    section_header("⚙️ Settings", "Configure detection parameters and system preferences")

    tabs = st.tabs(["🔑 API & Authentication", "🎛️ Detection Settings", "📧 Alert Simulation", "📝 System Logs"])

    # ── Tab 1: API Key ──────────────────────────────────────────────
    with tabs[0]:
        st.markdown("### OpenAI API Configuration")
        info_box("Your API key is stored only in session memory and never persisted to disk.", "info")

        current_key = st.session_state.get("openai_api_key", os.getenv("OPENAI_API_KEY", ""))
        masked = f"sk-...{current_key[-4:]}" if len(current_key) > 8 else "Not set"

        st.markdown(f"**Current key:** `{masked}`")
        new_key = st.text_input("Enter OpenAI API Key (sk-...)", type="password", placeholder="sk-...")

        if st.button("💾 Save API Key"):
            if new_key.startswith("sk-"):
                st.session_state["openai_api_key"] = new_key
                st.success("✅ API key saved to session.")
            else:
                st.error("Invalid key format. Must start with 'sk-'")

        st.markdown("---")
        st.markdown("### API Mode")
        use_gpt = st.toggle("Enable GPT-4 Analysis (Analyst Agent)", value=bool(current_key))
        st.caption("When disabled, the system uses rule-based fallback analysis (no API costs).")
        if use_gpt and not current_key:
            info_box("⚠️ GPT-4 is enabled but no API key is set. Add your key above.", "warning")

    # ── Tab 2: Detection Settings ──────────────────────────────────
    with tabs[1]:
        st.markdown("### Detection Sensitivity")

        col1, col2 = st.columns(2)
        with col1:
            z_threshold = st.slider("Z-Score Threshold (Statistical)", 1.0, 5.0,
                                    float(st.session_state.get("z_threshold", 3.0)), 0.1)
            failed_threshold = st.slider("Failed Login Threshold (Brute Force)", 3, 20,
                                          int(st.session_state.get("failed_login_threshold", 5)))
        with col2:
            contamination = st.slider("ML Contamination Rate", 0.01, 0.30,
                                       float(st.session_state.get("contamination", 0.10)), 0.01)
            unusual_start = st.slider("Unusual Hour Start", 0, 6,
                                       int(st.session_state.get("unusual_hour_start", 2)))

        st.markdown("### Detection Method Toggle")
        mcol1, mcol2, mcol3 = st.columns(3)
        with mcol1:
            use_stat = st.checkbox("Statistical (Z-Score)", value=True)
        with mcol2:
            use_ml = st.checkbox("Machine Learning (IF + RF)", value=True)
        with mcol3:
            use_rules = st.checkbox("Rule-Based Patterns", value=True)

        if st.button("💾 Save Detection Settings"):
            st.session_state.update({
                "z_threshold": z_threshold,
                "failed_login_threshold": failed_threshold,
                "contamination": contamination,
                "unusual_hour_start": unusual_start,
                "detection_settings": {
                    "z_threshold": z_threshold,
                    "failed_login_threshold": failed_threshold,
                    "contamination": contamination,
                    "unusual_hour_start": unusual_start,
                    "use_statistical": use_stat,
                    "use_ml": use_ml,
                    "use_rules": use_rules,
                }
            })
            st.success("✅ Detection settings saved.")

        # Adaptive learning stats
        st.markdown("---")
        st.markdown("### 📈 Adaptive Learning Stats")
        try:
            from src.database.database import SessionLocal
            from src.database.models import AgentFeedback
            db = SessionLocal()
            all_fb = db.query(AgentFeedback).all()
            db.close()
            total_fb = len(all_fb)
            fp_count = sum(1 for f in all_fb if f.feedback_type == "FALSE_POSITIVE")
            fp_rate = fp_count / total_fb if total_fb > 0 else 0.0
            st.metric("Total Feedback Items", total_fb)
            st.metric("False Positive Rate", f"{fp_rate:.0%}")
            st.caption("Submit feedback on incidents to improve detection accuracy over time.")
        except Exception:
            st.info("No feedback data available yet. Mark incidents on the Incident Details page.")

    # ── Tab 3: Alert Simulation ─────────────────────────────────────
    with tabs[2]:
        st.markdown("### Email Alert Simulation")
        info_box("This is a simulation — no actual emails are sent.", "info")

        email = st.text_input("Security Team Email", value="security@company.com")
        min_risk = st.selectbox("Minimum Risk Level to Alert", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], index=2)

        if st.button("🔔 Test Alert"):
            st.success(f"✅ [SIMULATED] Alert would be sent to {email} for {min_risk}+ threats.")
            st.code(f"""
Subject: [CyberShield AI] Security Alert — {min_risk} Threat Detected
To: {email}
Body: A {min_risk} security incident has been detected. Please review the dashboard.
      URL: http://localhost:8501
            """)

    # ── Tab 4: System Logs ──────────────────────────────────────────
    with tabs[3]:
        st.markdown("### System Audit Logs")
        try:
            from src.database.database import SessionLocal
            from src.database.models import AgentAuditLog
            db = SessionLocal()
            audit_logs = db.query(AgentAuditLog).order_by(AgentAuditLog.created_at.desc()).limit(50).all()
            db.close()
            if audit_logs:
                for log in audit_logs:
                    st.markdown(f"""
                    <div style="background:#1e293b;border-radius:6px;padding:.5rem 1rem;margin:.2rem 0;font-size:.8rem">
                        <span style="color:#38bdf8">[{log.agent_name}]</span>
                        <span style="color:#94a3b8"> {str(log.created_at)[:19]}</span>
                        <span style="color:#e2e8f0"> {log.action}</span>
                        <span style="color:#64748b"> ({log.duration_ms:.0f}ms)</span>
                    </div>""", unsafe_allow_html=True)
            else:
                st.info("No audit logs yet. Run the detection pipeline to generate logs.")
        except Exception as e:
            st.info(f"Audit logs unavailable: {e}")

        # Data generation
        st.markdown("---")
        st.markdown("### 🔄 Data Management")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("📝 Regenerate Synthetic Logs"):
                with st.spinner("Generating..."):
                    from src.data.log_generator import generate_logs
                    generate_logs()
                st.success("✅ New synthetic logs generated.")
        with col2:
            if st.button("🤖 Retrain ML Models"):
                with st.spinner("Training models..."):
                    try:
                        from src.ml.trainer import train_pipeline
                        train_pipeline()
                        st.success("✅ Models retrained and saved.")
                    except Exception as e:
                        st.error(f"Training failed: {e}")
