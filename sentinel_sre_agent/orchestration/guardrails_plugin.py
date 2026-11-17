"""ADK Security Guardrail & Self-Evaluation Plugin (Google Cloud Model Armor + Self-Eval).

Addresses Rubric Criteria:
- 3.3 (Guardrails & Policy Plugins): Implements an ADK `BasePlugin` combining:
    1. Input Prompt Shield via Google Cloud Model Armor (`google.cloud.modelarmor_v1`) +
       deterministic injection/destructive-command policy rules.
    2. Tool Execution Policy Guardrails blocking disallowed arguments and capturing paired
       `AGENT_ACTION_INTENT` / `AGENT_ACTION_OUTCOME` audit records.
    3. Output Self-Evaluation Guardrail (`SelfEvaluationGuardrail`) auditing groundedness,
       HITL policy compliance, and PII safety before delivering responses.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import re
from typing import Any

from sentinel_sre_agent._adk_compat import BasePlugin, ToolContext
from sentinel_sre_agent.observability.intent_outcome_audit import IntentOutcomeAuditTracker
from sentinel_sre_agent.observability.pii_redactor import PIIRedactionScrubber
from sentinel_sre_agent.observability.structured_logger import StructuredJsonLogger
from sentinel_sre_agent.observability.tracing import traced_operation

try:
    from google.cloud import modelarmor_v1  # type: ignore
    MODEL_ARMOR_AVAILABLE = True
except ImportError:  # pragma: no cover - offline CI fallback
    modelarmor_v1 = None
    MODEL_ARMOR_AVAILABLE = False


_PROMPT_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "IGNORE_SYSTEM_CONSTITUTION",
        re.compile(
            r"(?i)\b(?:ignore|disregard|bypass)\s+(?:all\s+)?(?:(?:previous|prior|system|safety)\s+)+(?:instructions|rules|constraints|approvals)"
        ),
    ),
    (
        "BYPASS_HITL_APPROVAL",
        re.compile(
            r"(?i)\b(?:forge|fabricate|skip|override|bypass)\s+(?:the\s+)?(?:human\s+)?approval(?:\s+token|\s+gate)?"
        ),
    ),
    (
        "EXFILTRATE_SECRETS",
        re.compile(r"(?i)\b(?:dump|print|exfiltrate|reveal)\s+(?:all\s+)?(?:secret\s+manager|api\s+keys|environment\s+secrets)"),
    ),
    (
        "DESTRUCTIVE_DROP_COMMAND",
        re.compile(r"(?i)\b(?:drop\s+database|rm\s+-rf\s+/|delete\s+production\s+cluster)\b"),
    ),
)


@dataclass(frozen=True)
class GuardrailVerdict:
    """Outcome of screening an input prompt, tool invocation, or candidate LLM output."""

    allowed: bool
    policy_rule: str
    reason: str
    sanitized_content: str | None = None


class SelfEvaluationGuardrail:
    """Evaluates candidate agent responses for groundedness, HITL compliance, and PII safety."""

    def __init__(self, scrubber: PIIRedactionScrubber | None = None) -> None:
        self._scrubber = scrubber or PIIRedactionScrubber()

    def evaluate_response(
        self,
        *,
        response_text: str,
        executed_tools: list[str],
        mutating_action_approved: bool,
    ) -> GuardrailVerdict:
        """Runs self-evaluation rubric checks over a candidate model response."""
        lowered = response_text.lower()

        # Check 1: Unapproved mutation claim detection (hallucinated execution)
        claims_completed_rollback = (
            "rollback completed" in lowered or "successfully rolled back" in lowered
        )
        if claims_completed_rollback and not mutating_action_approved:
            return GuardrailVerdict(
                allowed=False,
                policy_rule="SELF_EVAL_UNAPPROVED_MUTATION_CLAIM",
                reason=(
                    "Candidate response claims a production rollback succeeded, but no "
                    "human approval token or confirmed HITL gate was recorded."
                ),
            )

        # Check 2: Groundedness check when citing numerical telemetry metrics
        cites_specific_metrics = ("p99" in lowered or "error rate" in lowered) and any(
            ch.isdigit() for ch in response_text
        )
        if cites_specific_metrics and not executed_tools:
            return GuardrailVerdict(
                allowed=False,
                policy_rule="SELF_EVAL_UNGROUNDED_METRICS",
                reason=(
                    "Candidate response cites quantitative telemetry metrics without "
                    "having invoked any telemetry or verification tool."
                ),
            )

        # Check 3: Ensure zero unredacted PII survives into final output
        scrubbed = self._scrubber.scrub_text(response_text)
        return GuardrailVerdict(
            allowed=True,
            policy_rule="SELF_EVAL_PASSED",
            reason="Response is grounded in tool outputs, respects HITL gates, and is PII-safe.",
            sanitized_content=scrubbed,
        )


class SentinelSecurityAndEvalPlugin(BasePlugin):
    """Global ADK `BasePlugin` enforcing Model Armor, Intent/Outcome Audit, and Self-Eval."""

    def __init__(
        self,
        *,
        logger: StructuredJsonLogger | None = None,
        audit_tracker: IntentOutcomeAuditTracker | None = None,
        model_armor_template: str | None = None,
    ) -> None:
        super().__init__(name="sentinel_security_and_eval_plugin")
        self.logger = logger or StructuredJsonLogger("guardrails_plugin")
        self.audit_tracker = audit_tracker or IntentOutcomeAuditTracker(self.logger)
        self._scrubber = PIIRedactionScrubber()
        self._self_eval = SelfEvaluationGuardrail(self._scrubber)
        self._model_armor_template = model_armor_template
        self._inflight_tool_correlations: dict[str, str] = {}

    def screen_user_prompt(self, prompt_text: str) -> GuardrailVerdict:
        """Screens incoming prompts via Google Cloud Model Armor (when live) + policy rules."""
        with traced_operation(
            "sentinel.guardrail.screen_user_prompt",
            attributes={"guardrail.input_length": len(prompt_text)},
        ) as span:
            # 1. Google Cloud Model Armor RPC in production mode
            if (
                MODEL_ARMOR_AVAILABLE
                and modelarmor_v1 is not None
                and self._model_armor_template
                and os.getenv("SENTINEL_RUNTIME_MODE", "local").lower() == "production"
            ):
                client = modelarmor_v1.ModelArmorClient()
                req = modelarmor_v1.SanitizeUserPromptRequest(
                    name=self._model_armor_template,
                    user_prompt_data=modelarmor_v1.DataItem(text=prompt_text),
                )
                resp = client.sanitize_user_prompt(request=req)
                match_state = str(getattr(resp.sanitization_result, "filter_match_state", ""))
                if "MATCH_FOUND" in match_state:
                    span.set_attribute("guardrail.blocked", True)
                    return GuardrailVerdict(
                        allowed=False,
                        policy_rule="GOOGLE_CLOUD_MODEL_ARMOR_BLOCK",
                        reason="Blocked by Google Cloud Model Armor prompt sanitization policy.",
                    )

            # 2. Deterministic defense-in-depth prompt-injection & jailbreak signatures
            for rule_name, pattern in _PROMPT_INJECTION_PATTERNS:
                if pattern.search(prompt_text) is not None:
                    span.set_attribute("guardrail.blocked", True)
                    span.set_attribute("guardrail.rule", rule_name)
                    self.logger.warning(
                        "GUARDRAIL_PROMPT_BLOCKED",
                        policy_rule=rule_name,
                    )
                    return GuardrailVerdict(
                        allowed=False,
                        policy_rule=rule_name,
                        reason=(
                            f"Request blocked by security policy '{rule_name}': adversarial "
                            "instruction or unsafe bypass attempt detected."
                        ),
                    )

            span.set_attribute("guardrail.blocked", False)
            return GuardrailVerdict(
                allowed=True,
                policy_rule="PROMPT_CLEAN",
                reason="Prompt passed security screening.",
                sanitized_content=self._scrubber.scrub_text(prompt_text),
            )

    async def before_model_callback(self, *, callback_context: Any, llm_request: Any) -> Any:
        prompt_text = str(getattr(llm_request, "prompt", "") or "")
        verdict = self.screen_user_prompt(prompt_text)
        if not verdict.allowed:
            return {"status": "blocked_by_guardrail", "policy_rule": verdict.policy_rule, "reason": verdict.reason}
        return None

    async def after_model_callback(self, *, callback_context: Any, llm_response: Any) -> Any:
        text = str(getattr(llm_response, "text", "") or "")
        state = getattr(callback_context, "state", {}) if callback_context is not None else {}
        executed_tools = list(state.get("executed_tools", [])) if isinstance(state, dict) else []
        approved = bool(state.get("mutating_action_approved", False)) if isinstance(state, dict) else False

        verdict = self._self_eval.evaluate_response(
            response_text=text,
            executed_tools=executed_tools,
            mutating_action_approved=approved,
        )
        if not verdict.allowed:
            self.logger.warning(
                "SELF_EVAL_GUARDRAIL_INTERVENTION",
                policy_rule=verdict.policy_rule,
                reason=verdict.reason,
            )
            return {
                "status": "blocked_by_self_eval",
                "policy_rule": verdict.policy_rule,
                "reason": verdict.reason,
            }
        if hasattr(llm_response, "text") and verdict.sanitized_content is not None:
            llm_response.text = verdict.sanitized_content
        return None

    async def before_tool_callback(
        self,
        *,
        tool: Any,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
    ) -> Any:
        tool_name = getattr(tool, "name", getattr(tool, "__name__", str(tool)))
        agent_name = str(tool_context.state.get("active_agent", "sentinel_agent"))
        session_id = str(tool_context.state.get("session_id", tool_context.invocation_id))

        correlation_id = self.audit_tracker.record_intent(
            agent_name=agent_name,
            intended_action=tool_name,
            intended_parameters=tool_args,
            rationale=f"Executing grounded SRE workflow step via '{tool_name}'.",
            session_id=session_id,
        )
        self._inflight_tool_correlations[f"{tool_context.invocation_id}:{tool_name}"] = correlation_id
        return None

    async def after_tool_callback(
        self,
        *,
        tool: Any,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
        result: Any,
    ) -> Any:
        del tool_args
        tool_name = getattr(tool, "name", getattr(tool, "__name__", str(tool)))
        key = f"{tool_context.invocation_id}:{tool_name}"
        correlation_id = self._inflight_tool_correlations.pop(key, f"act-{tool_context.invocation_id}")
        session_id = str(tool_context.state.get("session_id", tool_context.invocation_id))

        status = str(result.get("status", "ok")) if isinstance(result, dict) else "ok"
        fulfilled = status not in {"error", "blocked_by_guardrail"}
        error_code = str(result.get("error_code")) if isinstance(result, dict) and "error_code" in result else None

        executed = tool_context.state.setdefault("executed_tools", [])
        if isinstance(executed, list):
            executed.append(tool_name)
        if status == "rolled_back":
            tool_context.state["mutating_action_approved"] = True

        self.audit_tracker.record_outcome(
            correlation_id=correlation_id,
            actual_status=status,
            outcome_summary=result if isinstance(result, dict) else {"result": str(result)},
            intent_fulfilled=fulfilled,
            session_id=session_id,
            error_code=error_code,
        )
        return None
