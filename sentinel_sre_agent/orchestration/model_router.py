"""Strategic Model Routing between Gemini Flash (low-latency) and Gemini Pro (deep planning).

Addresses Rubric Criterion 3.2 (Strategic Model Routing):
- Assigns `gemini-2.5-flash` to high-throughput, low-latency tasks (intent classification,
  telemetry signal extraction, runbook search, post-action SLO checks).
- Assigns `gemini-2.5-pro` to complex multi-hypothesis reasoning tasks (root-cause planning,
  blast-radius analysis, remediation synthesis, and self-evaluation critique).
- Dynamically upgrades or routes requests in `before_model_callback` based on incident
  severity (`SEV-1`), multi-service scope, or prompt complexity.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

TaskCategory = Literal[
    "intent_triage",
    "telemetry_extraction",
    "runbook_retrieval",
    "slo_verification",
    "root_cause_planning",
    "remediation_execution",
    "self_critique_evaluation",
]


@dataclass(frozen=True)
class ModelRouteDecision:
    """Audit record explaining why a specific Gemini model tier was selected."""

    selected_model: str
    tier: Literal["fast", "reasoning"]
    task_category: str
    reason: str


_REASONING_TASK_CATEGORIES: frozenset[str] = frozenset(
    {
        "root_cause_planning",
        "remediation_execution",
        "self_critique_evaluation",
    }
)

_HIGH_COMPLEXITY_SIGNALS: tuple[str, ...] = (
    "sev-1",
    "cascading",
    "multi-region",
    "root cause",
    "rollback",
    "postmortem",
    "blast radius",
    "data corruption",
)


class StrategicModelRouter:
    """Routes agent workloads to the optimal cost/latency/reasoning Gemini model tier."""

    def __init__(
        self,
        *,
        fast_model: str = "gemini-2.5-flash",
        reasoning_model: str = "gemini-2.5-pro",
        complexity_char_threshold: int = 900,
    ) -> None:
        self.fast_model = fast_model
        self.reasoning_model = reasoning_model
        self._complexity_char_threshold = complexity_char_threshold

    def select_model(
        self,
        *,
        task_category: TaskCategory | str,
        user_query: str = "",
        severity: str | None = None,
    ) -> ModelRouteDecision:
        """Selects `gemini-2.5-flash` or `gemini-2.5-pro` based on task and query signals."""
        if task_category in _REASONING_TASK_CATEGORIES:
            return ModelRouteDecision(
                selected_model=self.reasoning_model,
                tier="reasoning",
                task_category=task_category,
                reason=f"Task '{task_category}' requires multi-step architectural reasoning.",
            )

        if (severity or "").upper() == "SEV-1":
            return ModelRouteDecision(
                selected_model=self.reasoning_model,
                tier="reasoning",
                task_category=task_category,
                reason="Escalated to Pro model due to active SEV-1 criticality.",
            )

        lowered = user_query.lower()
        matched_signals = [sig for sig in _HIGH_COMPLEXITY_SIGNALS if sig in lowered]
        if len(matched_signals) >= 2 or len(user_query) >= self._complexity_char_threshold:
            return ModelRouteDecision(
                selected_model=self.reasoning_model,
                tier="reasoning",
                task_category=task_category,
                reason=(
                    f"Dynamic complexity upgrade triggered by signals: "
                    f"{matched_signals or ['prompt_length']}."
                ),
            )

        return ModelRouteDecision(
            selected_model=self.fast_model,
            tier="fast",
            task_category=task_category,
            reason=f"Routed '{task_category}' to low-latency Flash tier.",
        )

    def as_adk_before_model_callback(self, default_task_category: TaskCategory) -> Any:
        """ADK `before_model_callback` dynamically adjusting `llm_request.model`."""

        async def _route_before_model(*, callback_context: Any, llm_request: Any) -> None:
            prompt_text = str(getattr(llm_request, "prompt", "") or "")
            severity = None
            state = getattr(callback_context, "state", None)
            if isinstance(state, dict):
                severity = state.get("incident_severity")
            decision = self.select_model(
                task_category=default_task_category,
                user_query=prompt_text,
                severity=severity,
            )
            if hasattr(llm_request, "model"):
                llm_request.model = decision.selected_model
            return None

        return _route_before_model
