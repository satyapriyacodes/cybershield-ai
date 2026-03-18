"""
Page 1: Home Dashboard
"""

import sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import streamlit as st
import pandas as pd
from src.frontend.components.cards import metric_card, threat_feed_item, section_header
from src.frontend.components.charts import (
    risk_pie_chart, threat_timeline_chart, attack_type_bar_chart, geo_scatter_map
)


def _get_metrics():
    """Get metrics from session state or DB."""
    if "pipeline_result" in st.session_state:
        return st.session_state.pipeline_result.get("metrics", {})
    # Try DB
    try:
        from src.database.database import SessionLocal
        from src.database.models import Anomaly, Incident
        from collections import Counter
        from datetime import datetime
        db = SessionLocal()
        anomalies = db.query(Anomaly).all()
        incidents = db.query(Incident).all()
        db.close()
        by_risk = Counter(i.risk_level for i in incidents)
        by_type = Counter(i.attack_type for i in incidents if i.attack_type)
        all_ips = [a.ip_address for a in anomalies if a.ip_address]
        top_ips = Counter(all_ips).most_common(5)
        date_counts = {}
        for a in anomalies:
            if a.created_at:
                d = a.created_at.strftime("%Y-%m-%d")
                date_counts[d] = date_counts.get(d, 0) + 1
        return {
            "total_threats": len(anomalies), "critical_count": by_risk.get("CRITICAL", 0),
            "high_count": by_risk.get("HIGH", 0), "medium_count": by_risk.get("MEDIUM", 0),
            "low_count": by_risk.get("LOW", 0), "by_risk_level": dict(by_risk),
            "by_attack_type": dict(by_type),
            "top_suspicious_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
            "timeline": [{"date": d, "count": c} for d, c in sorted(date_counts.items())],
            "avg_confidence": 0.75,
        }
    except Exception:
        return {}


def show():
    section_header("🏠 Home Dashboard", "Real-time threat overview and key metrics")

    metrics = _get_metrics()

    if not metrics:
        st.info("🟡 No detection data yet. Go to **Live Monitoring** to run the pipeline.")
        _show_demo_dashboard()
        return

    # ── Metric Cards ────────────────────────────────────────────────
    cols = st.columns(4)
    with cols[0]:
        metric_card("Total Threats", metrics.get("total_threats", 0), icon="🚨", color="#38bdf8")
    with cols[1]:
        metric_card("Critical", metrics.get("critical_count", 0), icon="🔴", color="#dc2626")
    with cols[2]:
        metric_card("High", metrics.get("high_count", 0), icon="🟠", color="#f97316")
    with cols[3]:
        metric_card("Avg Confidence", f"{metrics.get('avg_confidence', 0):.0%}", icon="🎯", color="#a855f7")

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Row 1: Pie + Timeline ────────────────────────────────────────
    col1, col2 = st.columns([1, 2])
    with col1:
        by_risk = metrics.get("by_risk_level", {})
        if by_risk:
            st.plotly_chart(risk_pie_chart(by_risk), use_container_width=True)
    with col2:
        timeline = metrics.get("timeline", [])
        st.plotly_chart(threat_timeline_chart(timeline), use_container_width=True)

    # ── Row 2: Attack types + Threat feed ───────────────────────────
    col3, col4 = st.columns([2, 1])
    with col3:
        by_type = metrics.get("by_attack_type", {})
        if by_type:
            st.plotly_chart(attack_type_bar_chart(by_type), use_container_width=True)

    with col4:
        section_header("🎯 Top Suspicious IPs")
        for entry in metrics.get("top_suspicious_ips", []):
            st.markdown(f"""
            <div style="background:#1e293b;border-left:3px solid #dc2626;border-radius:6px;
                        padding:.5rem 1rem;margin:.2rem 0;display:flex;justify-content:space-between">
                <span style="font-family:monospace;color:#e2e8f0">{entry['ip']}</span>
                <span style="color:#dc2626;font-weight:700">{entry['count']}</span>
            </div>""", unsafe_allow_html=True)

    # ── Geo Map ──────────────────────────────────────────────────────
    top_ips = metrics.get("top_suspicious_ips", [])
    if top_ips:
        st.plotly_chart(geo_scatter_map(top_ips), use_container_width=True)

    # ── Recent Threat Feed ───────────────────────────────────────────
    if "pipeline_result" in st.session_state:
        section_header("📡 Live Threat Feed", "Most recent detections")
        incidents = st.session_state.pipeline_result.get("incidents", [])
        for inc in incidents[:10]:
            threat_feed_item(
                timestamp=inc.get("timestamp", "N/A"),
                ip=inc.get("ip_address", "N/A"),
                attack_type=inc.get("attack_type", "Unknown"),
                risk_level=inc.get("risk_level", "LOW"),
                confidence=inc.get("confidence_breakdown", {}).get("final_confidence", 0.5),
            )


def _show_demo_dashboard():
    """Show demo charts when no data is available."""
    section_header("📊 Demo Data Preview", "Run detection to see real results")
    demo_risk = {"CRITICAL": 5, "HIGH": 12, "MEDIUM": 24, "LOW": 38}
    demo_timeline = [{"date": f"2024-01-{i+1:02d}", "count": i+3} for i in range(20)]
    col1, col2 = st.columns(2)
    with col1:
        st.plotly_chart(risk_pie_chart(demo_risk), use_container_width=True)
    with col2:
        st.plotly_chart(threat_timeline_chart(demo_timeline), use_container_width=True)
