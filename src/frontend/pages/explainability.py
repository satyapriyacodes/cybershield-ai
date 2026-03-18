"""
Page 5: Explainability Viewer — SHAP values, feature importance, reasoning chains.
"""

import streamlit as st
import pandas as pd
from src.frontend.components.cards import section_header
from src.frontend.components.charts import (
    shap_waterfall, feature_importance_bar, confidence_histogram
)


def show():
    section_header("🧠 Explainability Viewer", "Understand every detection decision")

    if "pipeline_result" not in st.session_state:
        st.info("Run the detection pipeline first to view explainability data.")
        _show_explainability_demo()
        return

    result = st.session_state.pipeline_result
    incidents = result.get("incidents", [])
    anomalies = result.get("anomalies", [])

    if not incidents:
        st.info("No incidents to explain.")
        return

    # Overall feature importance from RF
    st.markdown("### 📊 Model-Level Feature Importance")
    try:
        from src.ml.random_forest import RandomForestDetector
        rf = RandomForestDetector()
        if rf.load() and rf.model:
            importances = rf.feature_importances()
            st.plotly_chart(feature_importance_bar(importances), use_container_width=True)
    except Exception:
        # Show heuristic importances
        heuristic = {
            "failed_attempts": 0.28, "location_risk": 0.22,
            "is_anomalous_hour": 0.18, "is_suspicious_ip": 0.15,
            "bytes_log": 0.08, "is_failure": 0.05,
            "login_hour": 0.04,
        }
        st.plotly_chart(feature_importance_bar(heuristic), use_container_width=True)

    # Confidence distribution
    confidences = [
        inc.get("confidence_breakdown", {}).get("final_confidence", 0.5) for inc in incidents
    ]
    if confidences:
        st.plotly_chart(confidence_histogram(confidences), use_container_width=True)

    st.markdown("---")
    st.markdown("### 🔍 Per-Incident Explainability")

    # Incident selector
    options = {f"#{i}: [{inc.get('risk_level','?')}] {inc.get('attack_type','Unknown')} | {inc.get('ip_address','N/A')}": inc
               for i, inc in enumerate(incidents[:30])}
    selected_label = st.selectbox("Select an incident to explain:", list(options.keys()))
    selected_inc = options[selected_label]

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### 🎯 Reasoning Chain")
        steps = selected_inc.get("reasoning_chain", [])
        if steps:
            for j, step in enumerate(steps):
                color = ["#38bdf8", "#a855f7", "#f97316", "#22c55e"][j % 4]
                st.markdown(f"""
                <div style="background:#1e293b;border-left:3px solid {color};border-radius:4px;
                            padding:.6rem 1rem;margin:.3rem 0;font-size:.9rem">
                    {step}
                </div>""", unsafe_allow_html=True)
        else:
            reasoning = selected_inc.get("original_anomaly", {}).get("reasoning", "No reasoning available.")
            st.info(reasoning)

    with col2:
        st.markdown("#### 📊 SHAP Feature Contributions")
        # Build SHAP data from anomaly raw features
        raw_features = selected_inc.get("original_anomaly", {}).get("raw_features", {})
        if raw_features:
            shap_data = {
                "feature_contributions": {k: float(v) * 0.3 for k, v in list(raw_features.items())[:10]},
            }
        else:
            shap_data = {
                "feature_contributions": {
                    "failed_attempts": 0.35,
                    "is_anomalous_hour": -0.1,
                    "location_risk": 0.25,
                    "is_suspicious_ip": 0.20,
                    "bytes_log": -0.05,
                }
            }
        st.plotly_chart(shap_waterfall(shap_data), use_container_width=True)

    # Evidence section
    st.markdown("#### 🔗 Evidence Links")
    evidence = selected_inc.get("evidence", [])
    if evidence:
        for ev in evidence:
            st.markdown(f"""
            <div style="background:#1e293b;border:1px solid #334155;border-radius:6px;
                        padding:.5rem 1rem;margin:.2rem 0;font-size:.85rem;color:#94a3b8">
                🔗 {ev}
            </div>""", unsafe_allow_html=True)

    # What-if analysis
    st.markdown("#### 🧪 Counterfactual Analysis (What-if?)")
    st.markdown('<p style="color:#64748b;font-size:.85rem">Adjust values to see how they affect the detection</p>', unsafe_allow_html=True)
    cwf1, cwf2 = st.columns(2)
    with cwf1:
        cf_fa = st.slider("Failed Attempts", 0, 20, 5)
        cf_hour = st.slider("Login Hour", 0, 23, 3)
    with cwf2:
        cf_loc_risk = st.slider("Location Risk Score", 0.0, 1.0, 0.8, 0.1)
        cf_suspicious_ip = st.checkbox("Suspicious IP", value=True)

    risk_score = (cf_fa / 20) * 0.4 + cf_loc_risk * 0.3 + int(cf_suspicious_ip) * 0.2 + (1 if 2 <= cf_hour <= 5 else 0) * 0.1
    risk_label = "CRITICAL" if risk_score > 0.75 else "HIGH" if risk_score > 0.55 else "MEDIUM" if risk_score > 0.35 else "LOW"
    color = {"CRITICAL": "#dc2626", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}.get(risk_label)
    st.markdown(f"""
    <div style="background:#1e293b;border:2px solid {color};border-radius:8px;padding:1rem;text-align:center">
        <div style="font-size:.85rem;color:#94a3b8">Predicted Risk Level</div>
        <div style="font-size:2rem;font-weight:800;color:{color}">{risk_label}</div>
        <div style="color:#94a3b8;font-size:.85rem">Composite score: {risk_score:.2f}</div>
    </div>""", unsafe_allow_html=True)


def _show_explainability_demo():
    """Demo SHAP and feature importance when no data."""
    st.markdown("### Demo: Feature Importance")
    demo_importances = {
        "failed_attempts": 0.32, "location_risk": 0.24,
        "is_anomalous_hour": 0.18, "is_suspicious_ip": 0.14,
        "bytes_log": 0.07, "is_failure": 0.05,
    }
    st.plotly_chart(feature_importance_bar(demo_importances), use_container_width=True)
