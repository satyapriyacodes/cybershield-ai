"""
Reusable UI card components styled for the dark cybersecurity theme.
"""

import streamlit as st
from typing import Optional


RISK_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
RISK_COLOR = {"CRITICAL": "#dc2626", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}


def metric_card(label: str, value, delta: str = None, icon: str = "📊", color: str = "#38bdf8"):
    """Styled metric card in a container."""
    delta_html = f'<div style="font-size:0.75rem;color:#64748b">{delta}</div>' if delta else ""
    st.markdown(f"""
    <div style="
        background:linear-gradient(135deg,#1e293b,#0f172a);
        border:1px solid #334155;
        border-left: 4px solid {color};
        border-radius:12px;
        padding:1.2rem 1.5rem;
        text-align:center;
        height:130px;
        display:flex;
        flex-direction:column;
        justify-content:center;
    ">
        <div style="font-size:1.8rem;margin-bottom:2px">{icon}</div>
        <div style="font-size:1.8rem;font-weight:800;color:{color}">{value}</div>
        <div style="font-size:0.8rem;color:#94a3b8;text-transform:uppercase;letter-spacing:1px">{label}</div>
        {delta_html}
    </div>
    """, unsafe_allow_html=True)


def risk_badge(risk_level: str) -> str:
    """Return HTML badge for a risk level."""
    color = RISK_COLOR.get(risk_level.upper(), "#6b7280")
    emoji = RISK_EMOJI.get(risk_level.upper(), "⚪")
    return f'<span style="background:{color}22;color:{color};padding:2px 10px;border-radius:20px;font-weight:600;font-size:0.8rem;border:1px solid {color}">{emoji} {risk_level}</span>'


def agent_status_card(name: str, icon: str, state: str, detail: str = "", complete: bool = False):
    """Show an agent's current status."""
    color = "#22c55e" if complete else "#38bdf8"
    bg = "#052e16" if complete else "#0c1e2b"
    border = "#22c55e" if complete else "#334155"
    status_icon = "✅" if complete else "⏳"
    st.markdown(f"""
    <div style="background:{bg};border:1px solid {border};border-radius:10px;padding:1rem 1.5rem;margin:.4rem 0;display:flex;align-items:center;gap:1rem">
        <div style="font-size:1.5rem">{icon}</div>
        <div style="flex:1">
            <div style="font-weight:700;color:{color}">{name}</div>
            <div style="font-size:0.85rem;color:#94a3b8">{state}</div>
            {f'<div style="font-size:0.78rem;color:#64748b">{detail}</div>' if detail else ''}
        </div>
        <div style="font-size:1.3rem">{status_icon}</div>
    </div>
    """, unsafe_allow_html=True)


def threat_feed_item(timestamp: str, ip: str, attack_type: str, risk_level: str, confidence: float):
    """A single item in the real-time threat feed."""
    color = RISK_COLOR.get(risk_level.upper(), "#6b7280")
    bar_width = int(confidence * 100)
    st.markdown(f"""
    <div style="background:#1e293b;border-left:3px solid {color};border-radius:6px;padding:.7rem 1rem;margin:.25rem 0">
        <div style="display:flex;justify-content:space-between;align-items:center">
            <span style="font-size:.8rem;color:#64748b">{timestamp[:19]}</span>
            <span style="color:{color};font-weight:600;font-size:.8rem">{risk_level}</span>
        </div>
        <div style="color:#e2e8f0;font-weight:600;margin:.2rem 0">{attack_type}</div>
        <div style="color:#64748b;font-size:.8rem">IP: {ip}</div>
        <div style="background:#334155;border-radius:3px;height:4px;margin-top:.5rem">
            <div style="background:{color};width:{bar_width}%;height:100%;border-radius:3px"></div>
        </div>
        <div style="font-size:.7rem;color:#64748b;text-align:right">{confidence:.0%} confidence</div>
    </div>
    """, unsafe_allow_html=True)


def section_header(title: str, subtitle: str = ""):
    """Page section header."""
    st.markdown(f"""
    <div style="margin-bottom:1.5rem">
        <h2 style="color:#38bdf8;margin:0;font-size:1.5rem">{title}</h2>
        {f'<p style="color:#64748b;margin:.2rem 0 0">{subtitle}</p>' if subtitle else ''}
    </div>
    """, unsafe_allow_html=True)


def info_box(text: str, level: str = "info"):
    """Coloured info/warning/error box."""
    colors = {
        "info": ("#0ea5e9", "#0c4a6e"),
        "warning": ("#f59e0b", "#451a03"),
        "error": ("#ef4444", "#450a0a"),
        "success": ("#22c55e", "#052e16"),
    }
    c, bg = colors.get(level, colors["info"])
    st.markdown(f"""
    <div style="background:{bg};border:1px solid {c};border-radius:8px;padding:.75rem 1rem;margin:.5rem 0;color:{c}">
        {text}
    </div>""", unsafe_allow_html=True)
