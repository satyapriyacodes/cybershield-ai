"""
Abstract base class for all cybersecurity agents.
Provides logging, JSON message passing, and audit trail.
"""

import time
import json
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from datetime import datetime
from loguru import logger


class BaseAgent(ABC):
    """All agents inherit from this class."""

    def __init__(self, name: str):
        self.name = name
        self._audit_log: list = []
        logger.info(f"[{self.name}] Agent initialised.")

    @abstractmethod
    def process(self, input_data: Any) -> Any:
        """Main entry point for agent processing."""
        ...

    def _record(self, action: str, input_data: Any = None, output_data: Any = None, duration_ms: float = 0.0):
        """Log an agent action for the audit trail."""
        entry = {
            "agent": self.name,
            "action": action,
            "input": input_data,
            "output": output_data,
            "duration_ms": round(duration_ms, 2),
            "timestamp": datetime.utcnow().isoformat(),
        }
        self._audit_log.append(entry)

        # Optionally persist to DB
        try:
            from src.database.database import db_session
            from src.database.models import AgentAuditLog

            def _serialise(obj):
                try:
                    json.dumps(obj)
                    return obj
                except (TypeError, ValueError):
                    return str(obj)

            with db_session() as session:
                log = AgentAuditLog(
                    agent_name=self.name,
                    action=action,
                    input_data=_serialise(input_data),
                    output_data=_serialise(output_data),
                    duration_ms=duration_ms,
                )
                session.add(log)
        except Exception as e:
            logger.debug(f"Audit DB write skipped: {e}")

    def run(self, input_data: Any) -> Dict[str, Any]:
        """Wrap process() with timing and audit logging."""
        start = time.time()
        logger.info(f"[{self.name}] Starting processing...")
        try:
            result = self.process(input_data)
            duration = (time.time() - start) * 1000
            self._record("process", input_data=None, output_data=None, duration_ms=duration)
            logger.success(f"[{self.name}] Completed in {duration:.0f}ms")
            return {"success": True, "agent": self.name, "result": result, "duration_ms": duration}
        except Exception as e:
            duration = (time.time() - start) * 1000
            logger.error(f"[{self.name}] Error: {e}")
            return {"success": False, "agent": self.name, "error": str(e), "duration_ms": duration}

    def get_audit_log(self) -> list:
        return self._audit_log

    def status_message(self, state: str) -> str:
        icons = {"scanning": "🔍", "analyzing": "🧠", "planning": "⚡", "generating": "📊", "watching": "👁️"}
        icon = icons.get(state.split()[0].lower(), "⚙️")
        return f"{icon} {self.name}: {state}"
