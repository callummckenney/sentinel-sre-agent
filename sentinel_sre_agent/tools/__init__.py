"""Domain-specific SRE diagnostic, knowledge, and HITL-gated remediation tools."""

from sentinel_sre_agent.tools.knowledge_tools import search_verified_sre_runbooks
from sentinel_sre_agent.tools.remediation_tools import (
    create_critical_incident_escalation,
    escalation_adk_tool,
    execute_canary_rollback_with_approval,
    rollback_adk_tool,
)
from sentinel_sre_agent.tools.telemetry_tools import (
    query_service_golden_signals_telemetry,
    record_local_release_override,
    reset_local_release_overrides,
    verify_post_remediation_slo_burn_rate,
)

ALL_TOOL_FUNCTIONS = (
    query_service_golden_signals_telemetry,
    verify_post_remediation_slo_burn_rate,
    search_verified_sre_runbooks,
    execute_canary_rollback_with_approval,
    create_critical_incident_escalation,
)

__all__ = [
    "ALL_TOOL_FUNCTIONS",
    "create_critical_incident_escalation",
    "escalation_adk_tool",
    "execute_canary_rollback_with_approval",
    "query_service_golden_signals_telemetry",
    "record_local_release_override",
    "reset_local_release_overrides",
    "rollback_adk_tool",
    "search_verified_sre_runbooks",
    "verify_post_remediation_slo_burn_rate",
]
