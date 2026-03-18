"""
Streamlit Multi-Page App Entry Point
"""

import sys
import os
from pathlib import Path

# ── Ensure project root is ALWAYS on sys.path ──────────────────────────────
# This works regardless of how streamlit is invoked
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # ultraviolet-granule/
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import streamlit as st

# ── Page configuration ──────────────────────────────────────────────────
st.set_page_config(
    page_title="CyberShield AI — Multi-Agent Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Global CSS ───────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;800&display=swap');

/* ── Base ── */
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
    background-color: #0f172a;
    color: #e2e8f0;
}

/* ── Force main content background to match dark theme ── */
.main .block-container {
    background-color: #0f172a !important;
    padding-top: 2rem;
}
.stApp {
    background-color: #0f172a !important;
}

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0f172a 0%, #1e293b 100%);
    border-right: 1px solid #334155;
}
section[data-testid="stSidebar"] .stRadio label {
    color: #cbd5e1 !important;
    font-weight: 500 !important;
    font-size: 0.95rem !important;
}
section[data-testid="stSidebar"] .stRadio label:hover {
    color: #f1f5f9 !important;
}
section[data-testid="stSidebar"] .stCaption,
section[data-testid="stSidebar"] p {
    color: #94a3b8 !important;
}

/* ── Hide Streamlit branding ── */
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}

/* ── Buttons ── */
.stButton > button {
    background: linear-gradient(135deg, #1d4ed8, #7c3aed);
    color: white;
    border: none;
    border-radius: 8px;
    font-weight: 600;
    transition: all 0.2s;
}
.stButton > button:hover {
    background: linear-gradient(135deg, #2563eb, #8b5cf6);
    transform: translateY(-1px);
    box-shadow: 0 4px 15px rgba(99, 102, 241, 0.4);
}

/* ── Tabs ── */
.stTabs [data-baseweb="tab"] { color: #94a3b8; font-weight: 600; }
.stTabs [aria-selected="true"] { color: #38bdf8 !important; border-bottom-color: #38bdf8 !important; }
.stTabs [data-baseweb="tab-list"] { background: transparent !important; }

/* ── Forms & inputs ── */
.streamlit-expanderHeader { background: #1e293b; border-radius: 8px; color: #e2e8f0 !important; }
.stTextInput input, .stTextArea textarea {
    background: #1e293b; color: #e2e8f0; border: 1px solid #334155; border-radius: 8px;
}
.stSelectbox div[data-baseweb="select"] { background: #1e293b; border-color: #334155; }
.stSelectbox div[data-baseweb="select"] * { color: #e2e8f0 !important; }
.stMultiSelect div[data-baseweb="select"] { background: #1e293b; border-color: #334155; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #0f172a; }
::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }

/* ── Metrics ── */
.stProgress > div > div { background: #38bdf8; }
[data-testid="stMetricValue"] { color: #38bdf8; font-weight: 800; }
[data-testid="stMetricLabel"] { color: #94a3b8 !important; }

/* ── General text contrast fixes ── */
p, li, span, label { color: #e2e8f0; }
.stMarkdown p { color: #e2e8f0; }
h1, h2, h3, h4, h5, h6 { color: #f1f5f9; }
.stCaption { color: #94a3b8 !important; }

/* ── DataFrames and tables ── */
.stDataFrame thead th { background: #1e293b !important; color: #e2e8f0 !important; }
.stDataFrame tbody td { color: #cbd5e1 !important; }

/* ── Info / warning / error boxes ── */
.stAlert { border-radius: 8px; }
div[data-testid="stInfo"] { background: #1e3a5f; color: #93c5fd !important; border-color: #3b82f6; }
div[data-testid="stInfo"] * { color: #bfdbfe !important; }
div[data-testid="stWarning"] { background: #451a03; color: #fbbf24 !important; }
div[data-testid="stWarning"] * { color: #fde68a !important; }
div[data-testid="stSuccess"] { background: #052e16; color: #4ade80 !important; }
div[data-testid="stSuccess"] * { color: #86efac !important; }
div[data-testid="stError"] { background: #450a0a; color: #f87171 !important; }
div[data-testid="stError"] * { color: #fca5a5 !important; }

/* ── Slider ── */
.stSlider [data-baseweb="slider"] div { color: #e2e8f0 !important; }
.stSlider label { color: #cbd5e1 !important; }

/* ── Radio (sidebar nav) ── */
div[data-testid="stRadio"] label { color: #cbd5e1 !important; }
div[data-testid="stRadio"] p { color: #cbd5e1 !important; }

/* ── Plotly chart containers ── */
.js-plotly-plot .plotly .gtitle { fill: #e2e8f0 !important; }
</style>
""", unsafe_allow_html=True)


# ── Sidebar Navigation ───────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="text-align:center;padding:1.5rem 0 1rem">
        <div style="font-size:2.5rem">🛡️</div>
        <div style="font-size:1.2rem;font-weight:800;color:#38bdf8">CyberShield AI</div>
        <div style="font-size:0.75rem;color:#64748b">Multi-Agent Security System</div>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("---")

    page = st.radio(
        "Navigation",
        options=[
            "🏠 Home Dashboard",
            "🔍 Live Monitoring",
            "💬 Chat with Agents",
            "📋 Incident Details",
            "🧠 Explainability",
            "📄 Reports",
            "⚙️ Settings",
        ],
        label_visibility="collapsed",
    )

    st.markdown("---")

    # System status indicator
    if "pipeline_result" in st.session_state:
        result = st.session_state.pipeline_result
        watchdog = result.get("watchdog", {})
        wstatus = watchdog.get("overall_status", "UNKNOWN")
        color = {"HEALTHY": "#22c55e", "DEGRADED": "#eab308", "CRITICAL": "#dc2626"}.get(wstatus, "#94a3b8")
        st.markdown(f"""
        <div style="background:#1e293b;border-radius:8px;padding:.75rem 1rem;margin:.5rem 0">
            <div style="font-size:.7rem;color:#64748b;text-transform:uppercase">SYSTEM STATUS</div>
            <div style="color:{color};font-weight:700;font-size:.9rem">● {wstatus}</div>
        </div>""", unsafe_allow_html=True)

        r = st.session_state.pipeline_result
        metrics = r.get("metrics", {})
        st.markdown(f"""
        <div style="background:#1e293b;border-radius:8px;padding:.75rem 1rem">
            <div style="font-size:.7rem;color:#64748b;text-transform:uppercase;margin-bottom:.5rem;letter-spacing:.05em">LAST RUN</div>
            <div style="font-size:.85rem;color:#cbd5e1">🚨 {metrics.get('total_threats',0)} threats</div>
            <div style="font-size:.85rem;color:#f87171">🔴 {metrics.get('critical_count',0)} critical</div>
            <div style="font-size:.85rem;color:#94a3b8">📊 {r.get('total_logs',0)} logs scanned</div>
        </div>""", unsafe_allow_html=True)

    else:
        st.markdown("""
        <div style="background:#1e293b;border-radius:8px;padding:.75rem 1rem;margin:.5rem 0">
            <div style="font-size:.7rem;color:#64748b;text-transform:uppercase">SYSTEM STATUS</div>
            <div style="color:#94a3b8;font-weight:700;font-size:.9rem">● IDLE</div>
        </div>""", unsafe_allow_html=True)
        st.caption("Run detection on Live Monitoring to start.")


# ── Route to page ────────────────────────────────────────────────────────

def _load_page(page_name):
    """Safe page loader with visible error messages."""
    try:
        if page_name == "home":
            from src.frontend.pages.home_dashboard import show
            show()
        elif page_name == "monitoring":
            from src.frontend.pages.live_monitoring import show
            show()
        elif page_name == "chat":
            from src.frontend.pages.chat_agents import show
            show()
        elif page_name == "incidents":
            from src.frontend.pages.incident_details import show
            show()
        elif page_name == "explain":
            from src.frontend.pages.explainability import show
            show()
        elif page_name == "reports":
            from src.frontend.pages.reports import show
            show()
        elif page_name == "settings":
            from src.frontend.pages.settings import show
            show()
    except Exception as e:
        import traceback
        st.error(f"❌ Page error: {e}")
        with st.expander("Debug traceback"):
            st.code(traceback.format_exc())


if "🏠" in page:
    _load_page("home")
elif "🔍" in page:
    _load_page("monitoring")
elif "💬" in page:
    _load_page("chat")
elif "📋" in page:
    _load_page("incidents")
elif "🧠" in page:
    _load_page("explain")
elif "📄" in page:
    _load_page("reports")
elif "⚙️" in page:
    _load_page("settings")
