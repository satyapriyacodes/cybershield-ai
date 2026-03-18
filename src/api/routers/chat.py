"""
Chat router — agent chat interface.
"""

import os
from fastapi import APIRouter, Depends
from src.api.schemas import ChatRequest, ChatResponse
from src.agents.orchestrator import Orchestrator

router = APIRouter()
_orchestrator: Orchestrator = None


def _get_orch(api_key=None) -> Orchestrator:
    global _orchestrator
    if _orchestrator is None or api_key:
        _orchestrator = Orchestrator(openai_api_key=api_key or os.getenv("OPENAI_API_KEY", ""))
    return _orchestrator


@router.post("/chat", response_model=ChatResponse, summary="Chat with a specific agent")
async def chat_with_agent(body: ChatRequest):
    """Send a message to one of the AI agents and get a response."""
    orch = _get_orch(body.openai_api_key)
    response = orch.chat_with_agent(body.agent, body.message, body.context)
    return ChatResponse(agent=body.agent, message=body.message, response=response)
