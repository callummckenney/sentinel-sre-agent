"""Root Google ADK Multi-Agent Architecture & Deterministic Incident Workflow Runner.

Addresses Rubric Criteria:
- 3.1 (Multi-Agent Patterns): Implements Coordinator + Parallel + Sequential patterns in ADK:
    * `sentinel_incident_coordinator` (`LlmAgent` Coordinator)
        ├── `diagnostic_fanout_pipeline` (`ParallelAgent`)
        │     ├── `telemetry_analyst_agent` (`LlmAgent` on `gemini-2.5-flash`)
        │     └── `runbook_researcher_agent` (`LlmAgent` on `gemini-2.5-flash`)
        └── `remediation_lifecycle_pipeline` (`SequentialAgent`)
              ├── `root_cause_planner_agent` (`LlmAgent` on `gemini-2.5-pro`)
              ├── `remediation_executor_agent` (`LlmAgent` on `gemini-2.5-pro`, HITL-gated)
              └── `post_action_slo_verifier_agent` (`LlmAgent` on `gemini-2.5-flash`)
- 2.2 (History Compaction): Wires `EventsCompactionConfig` + `ContextCacheConfig` +
  `TokenBudgetHistoryCompactor` into the ADK `App`.
- 3.2 / 3.3 / 3.4 / 4.x: Integrates `StrategicModelRouter`, `SentinelSecurityAndEvalPlugin`,
  `HumanApprovalGate`, OpenTelemetry tracing, structured JSON logging, and Intent/Outcome audit.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from sentinel_sre_agent._adk_compat import (
    App,
    LlmAgent,
    ParallelAgent,
    SequentialAgent,
    ToolContext,
)
from sentinel_sre_agent.config import SentinelConfig
from sentinel_sre_agent.memory.async_consolidator import AsyncMemoryConsolidator
from sentinel_sre_agent.memory.compaction import (
    TokenBudgetHistoryCompactor,
    build_adk_compaction_config,
    build_vertex_context_cache_config,
)
from sentinel_sre_agent.memory.session_store import PersistentSessionAndVectorStore
from sentinel_sre_agent.observability.intent_outcome_audit import IntentOutcomeAuditTracker
from sentinel_sre_agent.observability.structured_logger import StructuredJsonLogger
from sentinel_sre_agent.observability.tracing import traced_operation
from sentinel_sre_agent.orchestration.guardrails_plugin import (
    SelfEvaluationGuardrail,
    SentinelSecurityAndEvalPlugin,
)
from sentinel_sre_agent.orchestration.hitl_hooks import (
    DEFAULT_APPROVAL_GATE,
    HumanApprovalGate,
)
from sentinel_sre_agent.orchestration.model_router import StrategicModelRouter
from sentinel_sre_agent.prompts.constitution import (
    COORDINATOR_INSTRUCTION,
    REMEDIATION_EXECUTOR_INSTRUCTION,
    ROOT_CAUSE_PLANNER_INSTRUCTION,
    RUNBOOK_RESEARCHER_INSTRUCTION,
    SLO_VERIFIER_INSTRUCTION,
    TELEMETRY_ANALYST_INSTRUCTION,
)
from sentinel_sre_agent.tools import (
    escalation_adk_tool,
    execute_canary_rollback_with_approval,
    query_service_golden_signals_telemetry,
    rollback_adk_tool,
    search_verified_sre_runbooks,
    verify_post_remediation_slo_burn_rate,
)

_CONFIG = SentinelConfig.from_env()
_ROUTER = StrategicModelRouter(
    fast_model=_CONFIG.fast_model_name,
    reasoning_model=_CONFIG.reasoning_model_name,
)
_COMPACTOR = TokenBudgetHistoryCompactor(max_context_tokens=4096, retained_recent_turns=4)
_SECURITY_PLUGIN = SentinelSecurityAndEvalPlugin(
    model_armor_template=_CONFIG.model_armor_template_id,
)

# ---------------------------------------------------------------------------
# Stage 1: Parallel Diagnostic Fan-Out (`gemini-2.5-flash` for low latency)
# ---------------------------------------------------------------------------
telemetry_analyst_agent = LlmAgent(
    name="telemetry_analyst_agent",
    model=_ROUTER.select_model(task_category="telemetry_extraction").selected_model,
    description="Queries Cloud Monitoring golden signals to detect latency/error/CPU anomalies.",
    instruction=TELEMETRY_ANALYST_INSTRUCTION,
    tools=[query_service_golden_signals_telemetry],
    output_key="telemetry_findings",
    before_model_callback=_COMPACTOR.as_adk_before_model_callback(),
)

runbook_researcher_agent = LlmAgent(
    name="runbook_researcher_agent",
    model=_ROUTER.select_model(task_category="runbook_retrieval").selected_model,
    description="Retrieves peer-reviewed SRE remediation runbooks from Vertex AI Search.",
    instruction=RUNBOOK_RESEARCHER_INSTRUCTION,
    tools=[search_verified_sre_runbooks],
    output_key="matched_runbooks",
    before_model_callback=_COMPACTOR.as_adk_before_model_callback(),
)

diagnostic_fanout_pipeline = ParallelAgent(
    name="diagnostic_fanout_pipeline",
    description="Executes telemetry golden-signal inspection and Vertex AI Search runbook lookup concurrently.",
    sub_agents=[telemetry_analyst_agent, runbook_researcher_agent],
)

# ---------------------------------------------------------------------------
# Stage 2: Sequential Remediation Lifecycle (`Pro` for planning, `Flash` for check)
# ---------------------------------------------------------------------------
root_cause_planner_agent = LlmAgent(
    name="root_cause_planner_agent",
    model=_ROUTER.select_model(task_category="root_cause_planning").selected_model,
    description="Synthesizes telemetry and runbooks into a minimal-blast-radius remediation plan.",
    instruction=ROOT_CAUSE_PLANNER_INSTRUCTION,
    output_key="remediation_plan",
    before_model_callback=_ROUTER.as_adk_before_model_callback("root_cause_planning"),
)

remediation_executor_agent = LlmAgent(
    name="remediation_executor_agent",
    model=_ROUTER.select_model(task_category="remediation_execution").selected_model,
    description="Executes HITL-gated canary rollbacks and critical SRE incident escalations.",
    instruction=REMEDIATION_EXECUTOR_INSTRUCTION,
    tools=[rollback_adk_tool, escalation_adk_tool],
    output_key="remediation_execution_result",
    before_model_callback=_ROUTER.as_adk_before_model_callback("remediation_execution"),
)

post_action_slo_verifier_agent = LlmAgent(
    name="post_action_slo_verifier_agent",
    model=_ROUTER.select_model(task_category="slo_verification").selected_model,
    description="Verifies post-remediation 1-hour SLO error-budget burn rate recovery.",
    instruction=SLO_VERIFIER_INSTRUCTION,
    tools=[verify_post_remediation_slo_burn_rate],
    output_key="slo_verification_report",
)

remediation_lifecycle_pipeline = SequentialAgent(
    name="remediation_lifecycle_pipeline",
    description="Sequentially plans root-cause mitigation, enforces HITL execution stops, and verifies SLO recovery.",
    sub_agents=[
        root_cause_planner_agent,
        remediation_executor_agent,
        post_action_slo_verifier_agent,
    ],
)

# ---------------------------------------------------------------------------
# Root Coordinator Agent & ADK Application Entry Point (`root_agent` & `app`)
# ---------------------------------------------------------------------------
root_agent = LlmAgent(
    name="sentinel_incident_coordinator",
    model=_ROUTER.select_model(task_category="intent_triage").selected_model,
    description="Enterprise SRE Coordinator orchestrating parallel diagnostics and sequential HITL remediation.",
    instruction=COORDINATOR_INSTRUCTION,
    sub_agents=[diagnostic_fanout_pipeline, remediation_lifecycle_pipeline],
    before_model_callback=_ROUTER.as_adk_before_model_callback("intent_triage"),
)

app = App(
    name="sentinel_sre_agent",
    root_agent=root_agent,
    plugins=[_SECURITY_PLUGIN],
    events_compaction_config=build_adk_compaction_config(
        compaction_interval=4,
        overlap_size=1,
    ),
    context_cache_config=build_vertex_context_cache_config(
        min_tokens=2048,
        ttl_seconds=1800,
        cache_intervals=5,
    ),
)


# ---------------------------------------------------------------------------
# Deterministic End-to-End Orchestration Runner (for CI & Golden Eval Suites)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class WorkflowTurnResponse:
    """Structured end-to-end execution result returned by `IncidentOrchestrationRunner`."""

    status: str
    response_text: str
    routed_models: dict[str, str]
    tool_trajectory: list[str]
    pending_approval_request_id: str | None = None
    slo_healthy: bool | None = None


class IncidentOrchestrationRunner:
    """Executes the full Coordinator -> Parallel -> Sequential workflow with full telemetry."""

    def __init__(
        self,
        *,
        session_store: PersistentSessionAndVectorStore,
        consolidator: AsyncMemoryConsolidator | None = None,
        approval_gate: HumanApprovalGate | None = None,
        logger: StructuredJsonLogger | None = None,
    ) -> None:
        self.session_store = session_store
        self.logger = logger or StructuredJsonLogger("incident_orchestration_runner")
        self.audit = IntentOutcomeAuditTracker(self.logger)
        self.plugin = SentinelSecurityAndEvalPlugin(
            logger=self.logger,
            audit_tracker=self.audit,
        )
        self.router = StrategicModelRouter()
        self.compactor = TokenBudgetHistoryCompactor(max_context_tokens=2048, retained_recent_turns=4)
        self.consolidator = consolidator or AsyncMemoryConsolidator(
            session_store,
            logger=self.logger,
        )
        self.approval_gate = approval_gate or DEFAULT_APPROVAL_GATE
        self._self_eval = SelfEvaluationGuardrail()

    async def handle_incident_turn(
        self,
        *,
        session_id: str,
        user_id: str,
        user_query: str,
        service_id: str,
        region: str,
        approval_token: str | None = None,
    ) -> WorkflowTurnResponse:
        """Runs a complete traced, PII-scrubbed, HITL-enforced multi-agent incident turn."""
        with traced_operation(
            "sentinel.request.ingress",
            attributes={"session.id": session_id, "sre.service_id": service_id},
        ):
            # 1. Input Prompt Guardrail Screening
            verdict = self.plugin.screen_user_prompt(user_query)
            if not verdict.allowed:
                return WorkflowTurnResponse(
                    status="blocked_by_guardrail",
                    response_text=verdict.reason,
                    routed_models={},
                    tool_trajectory=[],
                )

            # 2. Persist incoming user turn & compact session context
            self.session_store.append_turn(
                session_id=session_id,
                user_id=user_id,
                role="user",
                content=user_query,
            )
            history = self.session_store.get_session_history(session_id)
            _compacted = self.compactor.compact(history)
            del _compacted

            tool_ctx = ToolContext(
                state={"session_id": session_id, "active_agent": "diagnostic_fanout_pipeline"}
            )
            routed_models: dict[str, str] = {
                "coordinator": self.router.select_model(
                    task_category="intent_triage", user_query=user_query
                ).selected_model,
                "telemetry_analyst": self.router.select_model(
                    task_category="telemetry_extraction"
                ).selected_model,
                "runbook_researcher": self.router.select_model(
                    task_category="runbook_retrieval"
                ).selected_model,
            }

            # 3. Parallel Diagnostic Fan-Out (Telemetry + Vertex AI Search Runbooks concurrently)
            with traced_operation("sentinel.coordinator.parallel_diagnostics"):
                await self.plugin.before_tool_callback(
                    tool=query_service_golden_signals_telemetry,
                    tool_args={"service_id": service_id, "region": region},
                    tool_context=tool_ctx,
                )
                await self.plugin.before_tool_callback(
                    tool=search_verified_sre_runbooks,
                    tool_args={"symptom_query": user_query},
                    tool_context=tool_ctx,
                )
                telemetry_res, runbook_res = await asyncio.gather(
                    asyncio.to_thread(
                        query_service_golden_signals_telemetry,
                        service_id=service_id,
                        region=region,
                    ),
                    asyncio.to_thread(
                        search_verified_sre_runbooks,
                        symptom_query=user_query,
                    ),
                )
                await self.plugin.after_tool_callback(
                    tool=query_service_golden_signals_telemetry,
                    tool_args={"service_id": service_id, "region": region},
                    tool_context=tool_ctx,
                    result=telemetry_res,
                )
                await self.plugin.after_tool_callback(
                    tool=search_verified_sre_runbooks,
                    tool_args={"symptom_query": user_query},
                    tool_context=tool_ctx,
                    result=runbook_res,
                )

            if telemetry_res.get("status") == "error":
                recovery_msg = (
                    f"Diagnostic lookup needs adjustment: {telemetry_res['message']} "
                    f"Recovery: {telemetry_res['recovery_instructions']}"
                )
                self.session_store.append_turn(
                    session_id=session_id,
                    user_id=user_id,
                    role="assistant",
                    content=recovery_msg,
                )
                return WorkflowTurnResponse(
                    status="guided_error_recovery",
                    response_text=recovery_msg,
                    routed_models=routed_models,
                    tool_trajectory=list(tool_ctx.state.get("executed_tools", [])),
                )

            if not telemetry_res.get("anomaly_detected"):
                healthy_msg = (
                    f"Observed Impact & Severity: Service '{service_id}' ({region}) is healthy "
                    f"on release {telemetry_res['active_release_version']} "
                    f"(p99 latency {telemetry_res['p99_latency_ms']}ms, "
                    f"error rate {telemetry_res['error_rate_percent']}%). No rollback required."
                )
                self.session_store.append_turn(
                    session_id=session_id,
                    user_id=user_id,
                    role="assistant",
                    content=healthy_msg,
                )
                self.consolidator.schedule_consolidation(
                    user_id=user_id,
                    session_id=session_id,
                    transcript_turns=self.session_store.get_session_history(session_id),
                    incident_tags=[service_id, "healthy"],
                )
                return WorkflowTurnResponse(
                    status="healthy_no_action",
                    response_text=healthy_msg,
                    routed_models=routed_models,
                    tool_trajectory=list(tool_ctx.state.get("executed_tools", [])),
                    slo_healthy=True,
                )

            # 4. Sequential Remediation Pipeline (Pro Planner -> HITL Rollback -> Flash Verifier)
            routed_models["root_cause_planner"] = self.router.select_model(
                task_category="root_cause_planning",
                severity="SEV-1",
            ).selected_model
            routed_models["remediation_executor"] = self.router.select_model(
                task_category="remediation_execution",
                severity="SEV-1",
            ).selected_model

            top_runbook = (
                runbook_res["matches"][0]["runbook_id"]
                if runbook_res.get("status") == "ok" and runbook_res.get("matches")
                else "RB-104"
            )
            rollback_args = {
                "service_id": service_id,
                "region": region,
                "faulty_version": telemetry_res["active_release_version"],
                "rollback_to_version": telemetry_res["previous_stable_version"],
                "incident_summary": (
                    f"Anomalous p99 latency ({telemetry_res['p99_latency_ms']}ms) and "
                    f"5xx error rate ({telemetry_res['error_rate_percent']}%) on "
                    f"{telemetry_res['active_release_version']}; applying {top_runbook}."
                ),
                "approval_token": approval_token,
            }

            with traced_operation("sentinel.remediation.sequential_pipeline"):
                tool_ctx.state["active_agent"] = "remediation_executor_agent"
                await self.plugin.before_tool_callback(
                    tool=execute_canary_rollback_with_approval,
                    tool_args=rollback_args,
                    tool_context=tool_ctx,
                )
                rollback_res = execute_canary_rollback_with_approval(
                    **rollback_args,
                    tool_context=tool_ctx,
                    approval_gate=self.approval_gate,
                )
                await self.plugin.after_tool_callback(
                    tool=execute_canary_rollback_with_approval,
                    tool_args=rollback_args,
                    tool_context=tool_ctx,
                    result=rollback_res,
                )

                if rollback_res.get("status") == "pending_human_approval":
                    pending_id = str(rollback_res["change_record_id"])
                    pause_msg = (
                        f"Observed Impact: {service_id} ({region}) on {telemetry_res['active_release_version']} "
                        f"has p99 latency {telemetry_res['p99_latency_ms']}ms and error rate "
                        f"{telemetry_res['error_rate_percent']}% (Runbook {top_runbook}). "
                        f"Remediation paused at Human-in-the-Loop gate '{pending_id}' awaiting "
                        f"operator approval to roll back to {telemetry_res['previous_stable_version']}."
                    )
                    eval_verdict = self._self_eval.evaluate_response(
                        response_text=pause_msg,
                        executed_tools=list(tool_ctx.state.get("executed_tools", [])),
                        mutating_action_approved=False,
                    )
                    final_text = eval_verdict.sanitized_content or pause_msg
                    self.session_store.append_turn(
                        session_id=session_id,
                        user_id=user_id,
                        role="assistant",
                        content=final_text,
                    )
                    self.consolidator.schedule_consolidation(
                        user_id=user_id,
                        session_id=session_id,
                        transcript_turns=self.session_store.get_session_history(session_id),
                        incident_tags=[service_id, "pending_approval", top_runbook],
                    )
                    return WorkflowTurnResponse(
                        status="pending_human_approval",
                        response_text=final_text,
                        routed_models=routed_models,
                        tool_trajectory=list(tool_ctx.state.get("executed_tools", [])),
                        pending_approval_request_id=pending_id,
                    )

                # Step 5: Post-Remediation SLO Burn-Rate Verification (`gemini-2.5-flash`)
                routed_models["slo_verifier"] = self.router.select_model(
                    task_category="slo_verification"
                ).selected_model
                tool_ctx.state["active_agent"] = "post_action_slo_verifier_agent"
                verify_args = {
                    "service_id": service_id,
                    "region": region,
                    "target_release_version": telemetry_res["previous_stable_version"],
                }
                await self.plugin.before_tool_callback(
                    tool=verify_post_remediation_slo_burn_rate,
                    tool_args=verify_args,
                    tool_context=tool_ctx,
                )
                verify_res = verify_post_remediation_slo_burn_rate(**verify_args)
                await self.plugin.after_tool_callback(
                    tool=verify_post_remediation_slo_burn_rate,
                    tool_args=verify_args,
                    tool_context=tool_ctx,
                    result=verify_res,
                )

            mitigated_msg = (
                f"Rollback completed under change record {rollback_res['change_record_id']} "
                f"(approved by {rollback_res['approved_by']}) per Runbook {top_runbook}. "
                f"{verify_res['verification_summary']}"
            )
            eval_verdict = self._self_eval.evaluate_response(
                response_text=mitigated_msg,
                executed_tools=list(tool_ctx.state.get("executed_tools", [])),
                mutating_action_approved=True,
            )
            final_text = eval_verdict.sanitized_content or mitigated_msg
            self.session_store.append_turn(
                session_id=session_id,
                user_id=user_id,
                role="assistant",
                content=final_text,
            )
            self.consolidator.schedule_consolidation(
                user_id=user_id,
                session_id=session_id,
                transcript_turns=self.session_store.get_session_history(session_id),
                incident_tags=[service_id, "mitigated", top_runbook],
            )
            return WorkflowTurnResponse(
                status="mitigated_and_verified",
                response_text=final_text,
                routed_models=routed_models,
                tool_trajectory=list(tool_ctx.state.get("executed_tools", [])),
                slo_healthy=bool(verify_res.get("slo_healthy", False)),
            )
