"""
Page 3: Chat with Agents
"""

import streamlit as st
import os
from src.frontend.components.cards import section_header

AGENT_INFO = {
    "Hunter": {
        "icon": "🔍",
        "color": "#38bdf8",
        "description": "Detection specialist. Ask about specific IPs, anomalies, or why something was flagged.",
        "sample_questions": [
            "Why did you flag IP 185.220.101.47?",
            "What detection methods flagged the most anomalies?",
            "Explain the brute force detections",
            "Which IPs are in your whitelist?",
        ],
    },
    "Analyst": {
        "icon": "🧠",
        "color": "#a855f7",
        "description": "Threat intelligence expert. Ask for explanations, risk context, and attack pattern analysis.",
        "sample_questions": [
            "Explain the last critical threat",
            "What is impossible travel and how dangerous is it?",
            "Which attack type poses the highest risk today?",
            "Why was this classified as HIGH and not CRITICAL?",
        ],
    },
    "Responder": {
        "icon": "⚡",
        "color": "#f97316",
        "description": "Response and remediation expert. Ask about action plans, priorities, and mitigation.",
        "sample_questions": [
            "What actions should I take for incident #5?",
            "How do I block a suspicious IP?",
            "What's the SLA for CRITICAL incidents?",
            "Which incidents need immediate attention?",
        ],
    },
    "Reporter": {
        "icon": "📊",
        "color": "#22c55e",
        "description": "Statistics and reporting agent. Ask for summaries, trends, and metrics.",
        "sample_questions": [
            "Show me today's statistics",
            "What is the false positive rate this week?",
            "Which attack type is most common?",
            "Generate an executive summary",
        ],
    },
}


def show():
    section_header("💬 Chat with Agents", "Interact with each AI agent directly")

    # Agent selector
    col1, col2 = st.columns([1, 3])
    with col1:
        selected_agent = st.selectbox(
            "Select Agent",
            list(AGENT_INFO.keys()),
            format_func=lambda x: f"{AGENT_INFO[x]['icon']} {x}",
        )

    agent = AGENT_INFO[selected_agent]

    # Agent info card
    with col2:
        st.markdown(f"""
        <div style="background:#1e293b;border-left:4px solid {agent['color']};
                    border-radius:8px;padding:1rem 1.5rem;margin-top:.5rem">
            <div style="font-size:1.1rem;font-weight:700;color:{agent['color']}">{agent['icon']} {selected_agent} Agent</div>
            <div style="color:#94a3b8;font-size:.9rem">{agent['description']}</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("---")

    # Chat history
    chat_key = f"chat_history_{selected_agent}"
    if chat_key not in st.session_state:
        st.session_state[chat_key] = []

    # Sample question chips
    st.markdown("**💡 Quick questions:**")
    sample_cols = st.columns(2)
    for i, q in enumerate(agent["sample_questions"]):
        with sample_cols[i % 2]:
            if st.button(q, key=f"chip_{selected_agent}_{i}", use_container_width=True):
                st.session_state[f"pending_message_{selected_agent}"] = q

    st.markdown("---")

    # Chat interface
    chat_container = st.container()
    with chat_container:
        for msg in st.session_state[chat_key]:
            if msg["role"] == "user":
                st.markdown(f"""
                <div style="display:flex;justify-content:flex-end;margin:.5rem 0">
                    <div style="background:#1d4ed8;border-radius:12px 12px 2px 12px;
                                padding:.75rem 1.2rem;max-width:70%;color:#fff">
                        {msg['content']}
                    </div>
                </div>""", unsafe_allow_html=True)
            else:
                # Render agent reply with markdown support
                st.markdown(f"""
                <div style="display:flex;justify-content:flex-start;margin:.5rem 0;align-items:flex-start">
                    <div style="margin-right:.6rem;font-size:1.5rem;padding-top:.2rem">{agent['icon']}</div>
                    <div style="background:#1e293b;border:1px solid #334155;border-left:3px solid {agent['color']};
                                border-radius:2px 12px 12px 12px;padding:.75rem 1.2rem;max-width:80%;
                                color:#e2e8f0;flex:1">
                </div>""", unsafe_allow_html=True)
                # Use st.markdown for true markdown rendering inside the bubble
                with st.container():
                    st.markdown(
                        f'<div style="background:#1e293b;border-left:3px solid {agent["color"]};'
                        f'border-radius:2px 12px 12px 12px;padding:.75rem 1.2rem;'
                        f'margin:.25rem 0 .5rem 2rem;color:#e2e8f0">\n\n'
                        + msg["content"]
                        + "\n\n</div>",
                        unsafe_allow_html=True,
                    )


    # Message input
    pending = st.session_state.pop(f"pending_message_{selected_agent}", None)
    user_input = st.chat_input(f"Ask {selected_agent} a question...", key=f"input_{selected_agent}")
    message = pending or user_input

    if message:
        st.session_state[chat_key].append({"role": "user", "content": message})

        with st.spinner(f"{agent['icon']} {selected_agent} is thinking..."):
            api_key = st.session_state.get("openai_api_key", os.getenv("OPENAI_API_KEY", ""))
            result = st.session_state.get("pipeline_result")
            context = (
                f"Last pipeline ran: {result.get('total_logs', 0)} logs, "
                f"{len(result.get('incidents', []))} incidents."
                if result else None
            )

            try:
                from src.agents.orchestrator import Orchestrator, _rule_based_chat
                # Try GPT-4 via Orchestrator if key available
                orch = Orchestrator(openai_api_key=api_key)
                # Inject pipeline data so agents can reference real results
                if result:
                    orch._last_result = result
                response = orch.chat_with_agent(selected_agent.lower(), message, context)
            except Exception as e:
                # Pure fallback — always works
                try:
                    from src.agents.orchestrator import _rule_based_chat
                    response = _rule_based_chat(selected_agent.lower(), message, result)
                except Exception as e2:
                    response = f"⚠️ Agent temporarily unavailable: {e2}"

        st.session_state[chat_key].append({"role": "assistant", "content": response})
        st.rerun()

    # Clear chat
    if st.session_state[chat_key]:
        if st.button("🗑️ Clear Chat", key=f"clear_{selected_agent}"):
            st.session_state[chat_key] = []
            st.rerun()

