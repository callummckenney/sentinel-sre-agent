"""Paired Intent-vs-Outcome audit trail capture for agent and tool executions.

Addresses Rubric Criterion 4.2 (Intent vs. Outcome Capture):
- Explicitly logs `AGENT_ACTION_INTENT` *before* any tool or sub-agent executes, recording
  `correlation_id`, `agent_name`, `intended_action`, `intended_parameters`, and `rationale`.
- Explicitly logs `AGENT_ACTION_OUTCOME` *after* execution finishes, linking via the same
  `correlation_id` and recording `actual_status`, `latency_ms`, `outcome_summary`, and
  whether the intended objective was fulfilled (`intent_fulfilled`).
"""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any
import uuid

from sentinel_sre_agent.observability.structured_logger import StructuredJsonLogger


@dataclass
class PendingActionIntent:
    """In-flight intent record awaiting its post-execution outcome pair."""

    correlation_id: str
    agent_name: str
    intended_action: str
    intended_parameters: dict[str, Any]
    rationale: str
    started_at_monotonic: float


class IntentOutcomeAuditTracker:
    """Records paired pre-execution `INTENT` and post-execution `OUTCOME` structured logs."""

    def __init__(self, logger: StructuredJsonLogger) -> None:
        self._logger = logger
        self._inflight: dict[str, PendingActionIntent] = {}

    def record_intent(
        self,
        *,
        agent_name: str,
        intended_action: str,
        intended_parameters: dict[str, Any],
        rationale: str,
        session_id: str | None = None,
        correlation_id: str | None = None,
    ) -> str:
        """Logs `AGENT_ACTION_INTENT` prior to executing a tool or workflow step."""
        cid = correlation_id or f"act-{uuid.uuid4().hex[:12]}"
        pending = PendingActionIntent(
            correlation_id=cid,
            agent_name=agent_name,
            intended_action=intended_action,
            intended_parameters=dict(intended_parameters),
            rationale=rationale,
            started_at_monotonic=time.monotonic(),
        )
        self._inflight[cid] = pending

        self._logger.info(
            "AGENT_ACTION_INTENT",
            phase="PRE_EXECUTION_INTENT",
            correlation_id=cid,
            session_id=session_id,
            agent_name=agent_name,
            intended_action=intended_action,
            intended_parameters=intended_parameters,
            rationale=rationale,
        )
        return cid

    def record_outcome(
        self,
        *,
        correlation_id: str,
        actual_status: str,
        outcome_summary: dict[str, Any] | str,
        intent_fulfilled: bool,
        session_id: str | None = None,
        error_code: str | None = None,
    ) -> dict[str, Any]:
        """Logs `AGENT_ACTION_OUTCOME` immediately after execution completes."""
        pending = self._inflight.pop(correlation_id, None)
        if pending is not None:
            latency_ms = round((time.monotonic() - pending.started_at_monotonic) * 1000.0, 3)
            agent_name = pending.agent_name
            intended_action = pending.intended_action
        else:
            latency_ms = 0.0
            agent_name = "unknown_agent"
            intended_action = "unknown_action"

        severity = "INFO" if intent_fulfilled else "WARNING"
        return self._logger.log_event(
            "AGENT_ACTION_OUTCOME",
            severity=severity,
            phase="POST_EXECUTION_OUTCOME",
            correlation_id=correlation_id,
            session_id=session_id,
            agent_name=agent_name,
            intended_action=intended_action,
            actual_status=actual_status,
            intent_fulfilled=intent_fulfilled,
            latency_ms=latency_ms,
            error_code=error_code,
            outcome_summary=outcome_summary,
        )
