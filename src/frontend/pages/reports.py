"""
Page 6: Reports — Generate and download security reports.
"""

import streamlit as st
from datetime import datetime, timedelta
import requests
import os
from src.frontend.components.cards import section_header

RISK_COLOURS = {"CRITICAL": "#dc2626", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}


def show():
    section_header("📄 Reports", "Generate professional security reports")

    col1, col2 = st.columns([1, 2])
    with col1:
        report_type = st.selectbox("Report Type", [
            "Executive Summary",
            "Technical Deep-Dive",
            "Compliance Format",
        ])
        fmt = st.radio("Format", ["HTML", "Plain Text"])
        date_range = st.date_input("Date Range", value=(
            datetime.now().date() - timedelta(days=30),
            datetime.now().date(),
        ))

    with col2:
        st.markdown("""
        <div style="background:#1e293b;border-radius:12px;padding:1.5rem">
            <h4 style="color:#38bdf8">Report Types</h4>
            <table style="width:100%;color:#94a3b8;font-size:.85rem">
                <tr><td style="padding:.3rem 0"><b style="color:#e2e8f0">Executive Summary</b></td>
                    <td>1-page non-technical overview for leadership</td></tr>
                <tr><td style="padding:.3rem 0"><b style="color:#e2e8f0">Technical Deep-Dive</b></td>
                    <td>Full analysis with attack vectors and ML metrics</td></tr>
                <tr><td style="padding:.3rem 0"><b style="color:#e2e8f0">Compliance Format</b></td>
                    <td>Audit-ready format with evidence chains</td></tr>
            </table>
        </div>""", unsafe_allow_html=True)

    st.markdown("---")

    col_gen1, col_gen2 = st.columns(2)
    with col_gen1:
        generate_btn = st.button("🔄 Generate Report", type="primary", use_container_width=True)
    with col_gen2:
        download_api = st.button("📡 Generate via API", use_container_width=True)

    if generate_btn:
        _generate_from_session(report_type, fmt)

    if download_api:
        _generate_from_api(fmt)


def _generate_from_session(report_type: str, fmt: str):
    """Generate report from in-memory session data."""
    if "pipeline_result" not in st.session_state:
        st.warning("Run detection first to generate a report.")
        return

    result = st.session_state.pipeline_result
    incidents = result.get("incidents", [])
    metrics = result.get("metrics", {})
    summary = result.get("executive_summary", "")

    if fmt == "Plain Text":
        st.text_area("Report", summary, height=400)
        st.download_button("📥 Download Text Report", data=summary,
                          file_name=f"cybersecurity_report_{datetime.now().strftime('%Y%m%d_%H%M')}.txt",
                          mime="text/plain")
    else:
        html = _build_html_report(metrics, summary, incidents, report_type)
        st.markdown(html, unsafe_allow_html=True)
        st.download_button("📥 Download HTML Report", data=html,
                          file_name=f"cybersecurity_report_{datetime.now().strftime('%Y%m%d_%H%M')}.html",
                          mime="text/html")


def _generate_from_api(fmt: str):
    """Fetch report from FastAPI backend."""
    api_url = os.getenv("API_BASE_URL", "http://localhost:8000")
    try:
        resp = requests.get(
            f"{api_url}/api/v1/reports/generate?fmt={fmt.lower().replace(' ', '')}",
            timeout=15
        )
        if resp.status_code == 200:
            content = resp.text
            ext = "html" if fmt == "HTML" else "txt"
            st.download_button("📥 Download Report", data=content,
                              file_name=f"report_{datetime.now().strftime('%Y%m%d')}.{ext}",
                              mime="text/html" if fmt == "HTML" else "text/plain")
            if fmt == "HTML":
                st.markdown(content, unsafe_allow_html=True)
            else:
                st.text_area("Report", content, height=400)
        else:
            st.error(f"API error: {resp.status_code}. Make sure the FastAPI server is running.")
    except Exception as e:
        st.error(f"Could not reach API: {e}")
        st.info("💡 Start the API server: `uvicorn src.api.main:app --port 8000`")


def _build_html_report(metrics: dict, summary: str, incidents: list, report_type: str) -> str:
    total = metrics.get("total_threats", len(incidents))
    critical = metrics.get("critical_count", 0)
    high = metrics.get("high_count", 0)
    avg_conf = metrics.get("avg_confidence", 0)

    # Build rows without nested f-string dict literals
    rows_parts = []
    for i, inc in enumerate(incidents[:20]):
        rl = inc.get("risk_level", "LOW")
        colour = RISK_COLOURS.get(rl, "#6b7280")
        atype = inc.get("attack_type", "N/A")
        ip = inc.get("ip_address", "N/A")
        rows_parts.append(
            f"<tr><td>{i + 1}</td><td>{atype}</td>"
            f"<td style='color:{colour}'>{rl}</td><td>{ip}</td></tr>"
        )
    rows = "".join(rows_parts)
    summary_trunc = summary[:2000]

    return f"""
    <div style="background:#1e293b;border-radius:12px;padding:2rem;color:#e2e8f0">
        <h2 style="color:#38bdf8">&#128737; {report_type}</h2>
        <p style="color:#64748b">Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin:1.5rem 0">
            <div style="background:#0f172a;border-radius:8px;padding:1rem;text-align:center">
                <div style="font-size:1.8rem;font-weight:800;color:#38bdf8">{total}</div>
                <div style="font-size:.75rem;color:#64748b">TOTAL</div>
            </div>
            <div style="background:#0f172a;border-radius:8px;padding:1rem;text-align:center">
                <div style="font-size:1.8rem;font-weight:800;color:#dc2626">{critical}</div>
                <div style="font-size:.75rem;color:#64748b">CRITICAL</div>
            </div>
            <div style="background:#0f172a;border-radius:8px;padding:1rem;text-align:center">
                <div style="font-size:1.8rem;font-weight:800;color:#f97316">{high}</div>
                <div style="font-size:.75rem;color:#64748b">HIGH</div>
            </div>
            <div style="background:#0f172a;border-radius:8px;padding:1rem;text-align:center">
                <div style="font-size:1.8rem;font-weight:800;color:#a855f7">{avg_conf:.0%}</div>
                <div style="font-size:.75rem;color:#64748b">CONFIDENCE</div>
            </div>
        </div>
        <h3 style="color:#94a3b8">Summary</h3>
        <pre style="background:#0f172a;border-radius:8px;padding:1rem;white-space:pre-wrap;font-size:.85rem;color:#e2e8f0">{summary_trunc}</pre>
        <h3 style="color:#94a3b8">Recent Incidents</h3>
        <table style="width:100%;border-collapse:collapse">
            <thead><tr style="background:#0f172a">
                <th style="padding:.5rem;text-align:left">#</th>
                <th>Type</th><th>Risk</th><th>IP</th>
            </tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </div>"""
