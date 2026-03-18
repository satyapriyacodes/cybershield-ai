"""
Reports router — generate HTML/text reports for download.
"""

from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy.orm import Session
from datetime import datetime

from src.database.database import get_db
from src.database.models import Anomaly, Incident
from src.agents.reporter_agent import ReporterAgent

router = APIRouter()


def _build_html_report(metrics: dict, summary: str, incidents: list) -> str:
    """Generate a styled HTML report."""
    rows = ""
    for inc in incidents[:50]:
        risk = inc.get("risk_level", "LOW")
        colour = {"CRITICAL": "#dc2626", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}.get(risk, "#6b7280")
        rows += f"""
        <tr>
            <td>{inc.get('id','')}</td>
            <td>{inc.get('attack_type','N/A')}</td>
            <td><span style="color:{colour};font-weight:700">{risk}</span></td>
            <td>{str(inc.get('created_at',''))[:10]}</td>
            <td>{inc.get('status','OPEN')}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Cybersecurity Report — {datetime.utcnow().strftime('%Y-%m-%d')}</title>
  <style>
    body {{ font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }}
    h1 {{ color: #38bdf8; }} h2 {{ color: #94a3b8; border-bottom: 1px solid #334155; padding-bottom: .5rem; }}
    .card {{ background: #1e293b; border-radius: 12px; padding: 1.5rem; margin: 1rem 0; }}
    .metric {{ display: inline-block; text-align: center; margin: 1rem; }}
    .metric .value {{ font-size: 2rem; font-weight: 800; color: #38bdf8; }}
    .metric .label {{ font-size: 0.8rem; color: #64748b; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th {{ background: #1e40af; padding: .75rem; text-align: left; }}
    td {{ padding: .6rem; border-bottom: 1px solid #334155; }}
    pre {{ background: #1e293b; padding: 1rem; border-radius: 8px; white-space: pre-wrap; font-size: .85rem; }}
  </style>
</head>
<body>
  <h1>🛡️ Multi-Agent Cybersecurity Report</h1>
  <p>Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
  <div class="card">
    <div class="metric"><div class="value">{metrics.get('total_threats',0)}</div><div class="label">TOTAL THREATS</div></div>
    <div class="metric"><div class="value" style="color:#dc2626">{metrics.get('critical_count',0)}</div><div class="label">CRITICAL</div></div>
    <div class="metric"><div class="value" style="color:#f97316">{metrics.get('high_count',0)}</div><div class="label">HIGH</div></div>
    <div class="metric"><div class="value" style="color:#eab308">{metrics.get('medium_count',0)}</div><div class="label">MEDIUM</div></div>
    <div class="metric"><div class="value" style="color:#22c55e">{metrics.get('low_count',0)}</div><div class="label">LOW</div></div>
  </div>
  <h2>Executive Summary</h2>
  <div class="card"><pre>{summary}</pre></div>
  <h2>Recent Incidents</h2>
  <div class="card">
    <table>
      <thead><tr><th>#</th><th>Attack Type</th><th>Risk</th><th>Date</th><th>Status</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
  <p style="color:#475569;font-size:.8rem;text-align:center">
    Multi-Agent Cybersecurity System © {datetime.utcnow().year}
  </p>
</body>
</html>"""
    return html


@router.get("/reports/generate", summary="Generate HTML/text security report")
def generate_report(
    fmt: str = Query("html", description="Output format: html | text"),
    db: Session = Depends(get_db),
):
    """Generate and return a security report based on current DB state."""
    anomalies = db.query(Anomaly).order_by(Anomaly.created_at.desc()).limit(200).all()
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).limit(200).all()

    # Build reporter input
    inc_dicts = [
        {
            "id": i.id,
            "risk_level": i.risk_level,
            "attack_type": i.attack_type,
            "created_at": str(i.created_at),
            "status": i.status,
            "confidence_breakdown": {"final_confidence": 0.75},
            "ip_address": "",
        }
        for i in incidents
    ]

    reporter = ReporterAgent()
    result = reporter.process({"incidents": inc_dicts, "response_plans": []})
    metrics = result.get("metrics", {})
    summary = result.get("executive_summary", "No data available.")

    if fmt == "html":
        html = _build_html_report(metrics, summary, inc_dicts)
        return HTMLResponse(content=html)
    else:
        return PlainTextResponse(content=summary)
