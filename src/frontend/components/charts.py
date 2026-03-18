"""
Reusable Plotly chart builders for the Streamlit dashboard.
"""

import plotly.graph_objects as go
import plotly.express as px
from typing import Dict, List, Optional

# Dark theme colors
BG_COLOR = "#0f172a"
CARD_COLOR = "#1e293b"
ACCENT = "#38bdf8"
COLORS = ["#38bdf8", "#f97316", "#a855f7", "#22c55e", "#eab308", "#ec4899", "#06b6d4"]

RISK_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#22c55e",
}


def _dark_layout(**kwargs):
    base = dict(
        paper_bgcolor=CARD_COLOR,
        plot_bgcolor=CARD_COLOR,
        font=dict(color="#e2e8f0", family="Inter, sans-serif", size=13),
        title_font=dict(color="#f1f5f9", size=15, family="Inter, sans-serif"),
        margin=dict(l=20, r=20, t=45, b=20),
    )
    # Ensure axis labels/ticks are always visible
    for ax_key in ("xaxis", "yaxis"):
        if ax_key in kwargs:
            ax = kwargs[ax_key]
            ax.setdefault("color", "#94a3b8")
            ax.setdefault("title_font", dict(color="#cbd5e1"))
            ax.setdefault("tickfont", dict(color="#94a3b8"))
        else:
            kwargs[ax_key] = dict(
                color="#94a3b8",
                title_font=dict(color="#cbd5e1"),
                tickfont=dict(color="#94a3b8"),
                gridcolor="#334155",
            )
    base.update(kwargs)
    return base



def risk_pie_chart(by_risk: Dict[str, int]) -> go.Figure:
    """Donut chart of threats by risk level."""
    labels = list(by_risk.keys())
    values = list(by_risk.values())
    colours = [RISK_COLORS.get(l, "#6b7280") for l in labels]

    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.55,
        marker=dict(colors=colours, line=dict(color=BG_COLOR, width=2)),
        textinfo="label+percent",
        textfont=dict(size=13),
    ))
    fig.update_layout(
        **_dark_layout(title="Threats by Risk Level", showlegend=True),
        legend=dict(orientation="h", yanchor="bottom", y=-0.2),
    )
    return fig


def threat_timeline_chart(timeline: List[Dict]) -> go.Figure:
    """Line chart of threat detections over time."""
    if not timeline:
        fig = go.Figure()
        fig.update_layout(**_dark_layout(title="Threat Timeline (No Data)"))
        return fig

    dates = [t["date"] for t in timeline]
    counts = [t["count"] for t in timeline]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=dates, y=counts,
        mode="lines+markers",
        line=dict(color=ACCENT, width=2.5),
        marker=dict(size=6, color=ACCENT),
        fill="tozeroy",
        fillcolor="rgba(56,189,248,0.1)",
        name="Threats",
    ))
    fig.update_layout(**_dark_layout(
        title="Daily Threat Timeline",
        xaxis=dict(title="Date", gridcolor="#334155"),
        yaxis=dict(title="Threats", gridcolor="#334155"),
    ))
    return fig


def attack_type_bar_chart(by_type: Dict[str, int]) -> go.Figure:
    """Horizontal bar chart of threats by type."""
    if not by_type:
        return go.Figure().update_layout(**_dark_layout(title="Threats by Type (No Data)"))

    sorted_items = sorted(by_type.items(), key=lambda x: x[1])
    labels = [i[0] for i in sorted_items]
    values = [i[1] for i in sorted_items]

    fig = go.Figure(go.Bar(
        x=values, y=labels, orientation="h",
        marker=dict(
            color=values,
            colorscale=[[0, "#1e40af"], [0.5, "#7c3aed"], [1, "#dc2626"]],
        ),
        text=values, textposition="outside",
    ))
    fig.update_layout(**_dark_layout(
        title="Threats by Attack Type",
        xaxis=dict(title="Count", gridcolor="#334155"),
        yaxis=dict(gridcolor="#334155"),
        height=max(300, len(labels) * 40),
    ))
    return fig


def confidence_histogram(confidences: List[float]) -> go.Figure:
    """Histogram of detection confidence scores."""
    fig = go.Figure(go.Histogram(
        x=confidences, nbinsx=20,
        marker=dict(color=ACCENT, line=dict(color=BG_COLOR, width=1)),
    ))
    fig.update_layout(**_dark_layout(
        title="Detection Confidence Distribution",
        xaxis=dict(title="Confidence Score", gridcolor="#334155"),
        yaxis=dict(title="Count", gridcolor="#334155"),
    ))
    return fig


def feature_importance_bar(importances: Dict[str, float]) -> go.Figure:
    """Bar chart of ML feature importances."""
    sorted_items = sorted(importances.items(), key=lambda x: x[1], reverse=True)
    labels = [i[0] for i in sorted_items]
    values = [i[1] for i in sorted_items]

    fig = go.Figure(go.Bar(
        x=labels, y=values,
        marker=dict(color=COLORS[:len(labels)]),
        text=[f"{v:.3f}" for v in values],
        textposition="outside",
    ))
    fig.update_layout(**_dark_layout(
        title="Feature Importance (Random Forest)",
        xaxis=dict(title="Feature", tickangle=30),
        yaxis=dict(title="Importance", gridcolor="#334155"),
    ))
    return fig


def shap_waterfall(shap_data: Dict) -> go.Figure:
    """SHAP waterfall chart showing feature contributions."""
    contributions = shap_data.get("feature_contributions", {})
    if not contributions:
        return go.Figure().update_layout(**_dark_layout(title="SHAP Values (No data)"))

    items = list(contributions.items())[:10]
    features = [i[0] for i in items]
    values = [i[1] for i in items]
    colours = ["#22c55e" if v < 0 else "#dc2626" for v in values]

    fig = go.Figure(go.Bar(
        x=features, y=values,
        marker=dict(color=colours),
        text=[f"{v:+.3f}" for v in values],
        textposition="outside",
    ))
    fig.update_layout(**_dark_layout(
        title="SHAP Feature Contributions (red = pushes toward anomaly)",
        xaxis=dict(tickangle=30),
        yaxis=dict(title="Contribution", gridcolor="#334155"),
        shapes=[dict(type="line", x0=-0.5, x1=len(features)-0.5, y0=0, y1=0,
                     line=dict(color="#94a3b8", dash="dash", width=1))],
    ))
    return fig


def geo_scatter_map(ips_data: List[Dict]) -> go.Figure:
    """Placeholder geographic scatter map using known suspicious IPs."""
    # Associate suspicious IPs with approximate coords
    ip_coords = {
        "185.220.101.47": (48.85, 2.35, "Paris (Tor)"),
        "91.92.248.11": (44.43, 26.10, "Bucharest, Romania"),
        "194.165.16.100": (55.75, 37.62, "Moscow, Russia"),
        "103.76.228.50": (31.23, 121.47, "Shanghai, China"),
        "45.142.212.100": (52.37, 4.90, "Amsterdam"),
        "95.214.55.0": (50.08, 14.44, "Prague"),
        "2.58.56.201": (44.43, 26.10, "Bucharest"),
        "185.234.218.21": (55.75, 37.62, "Moscow"),
    }

    lats, lons, texts, sizes = [], [], [], []
    for entry in ips_data:
        ip = entry.get("ip", "")
        count = entry.get("count", 1)
        coords = ip_coords.get(ip)
        if coords:
            lats.append(coords[0])
            lons.append(coords[1])
            texts.append(f"{ip}<br>{coords[2]}<br>Count: {count}")
            sizes.append(min(40, 10 + count * 5))

    fig = go.Figure(go.Scattergeo(
        lat=lats, lon=lons,
        text=texts, mode="markers",
        marker=dict(size=sizes, color="#dc2626", opacity=0.8, line=dict(color="#fff", width=1)),
        hovertemplate="%{text}<extra></extra>",
    ))
    fig.update_layout(
        title="Attack Source Locations",
        geo=dict(
            showland=True, landcolor="#1e293b",
            showocean=True, oceancolor="#0f172a",
            showcountries=True, countrycolor="#334155",
            bgcolor=BG_COLOR,
        ),
        paper_bgcolor=CARD_COLOR,
        font=dict(color="#e2e8f0"),
        height=400,
        margin=dict(l=0, r=0, t=40, b=0),
    )
    return fig
