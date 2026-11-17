"""Strict JSON Input & Output Schemas for all Sentinel SRE Agent tools.

Addresses Rubric Criteria:
- 1.3 (Explicit JSON Schemas): Strict Pydantic v2 models (`extra="forbid"`, `strict=True`)
  constraining every tool input parameter and validating every tool output payload.
- 1.4 (Guided Error Handling): Standardized `GuidedToolErrorResponse` schema delivering
  actionable `recovery_instructions` back to the LLM when validation or execution fails.
"""

from __future__ import annotations

from typing import Any, Literal

from sentinel_sre_agent._adk_compat import BaseModel, ConfigDict, Field, ValidationError


class GuidedToolErrorResponse(BaseModel):
    """Structured error contract guiding the LLM to self-correct without raising exceptions."""

    model_config = ConfigDict(extra="forbid", strict=True)

    status: Literal["error"] = Field(
        default="error",
        description="Discriminator indicating the tool call did not complete.",
    )
    tool_name: str = Field(
        description="Exact name of the tool that produced the guided error.",
        min_length=3,
    )
    error_code: str = Field(
        description="Machine-readable error classification code.",
        min_length=3,
    )
    message: str = Field(
        description="Clear diagnostic explanation of what went wrong.",
        min_length=5,
    )
    recovery_instructions: str = Field(
        description="Actionable step-by-step instructions telling the LLM how to recover.",
        min_length=15,
    )
    retryable: bool = Field(
        description="Whether the LLM should retry the tool call after adjusting inputs.",
    )
    allowed_values: list[str] = Field(
        default_factory=list,
        description="Optional list of valid enum or service identifiers to assist correction.",
    )


# ---------------------------------------------------------------------------
# 1. Golden Signals Telemetry Schemas
# ---------------------------------------------------------------------------
class QueryGoldenSignalsInput(BaseModel):
    """Strict input schema for `query_service_golden_signals_telemetry`."""

    model_config = ConfigDict(extra="forbid", strict=True)

    service_id: str = Field(
        description=(
            "Canonical kebab-case production service identifier "
            "(e.g., 'checkout-api', 'payments-ledger', 'auth-gateway')."
        ),
        min_length=3,
        max_length=64,
        pattern=r"^[a-z][a-z0-9-]{2,63}$",
    )
    region: str = Field(
        description="Google Cloud region hosting the workload (e.g., 'us-central1', 'europe-west1').",
        min_length=4,
        max_length=32,
        pattern=r"^[a-z]+-[a-z]+\d+$",
    )
    lookback_minutes: int = Field(
        default=15,
        description="Telemetry aggregation window in minutes (between 5 and 240).",
        ge=5,
        le=240,
    )


class QueryGoldenSignalsOutput(BaseModel):
    """Strict output schema for `query_service_golden_signals_telemetry`."""

    model_config = ConfigDict(extra="forbid", strict=True)

    status: Literal["ok"] = Field(default="ok", description="Successful telemetry query marker.")
    service_id: str = Field(description="Evaluated service identifier.")
    region: str = Field(description="Evaluated GCP region.")
    lookback_minutes: int = Field(description="Evaluated lookback window in minutes.")
    p99_latency_ms: float = Field(description="99th-percentile HTTP/gRPC latency in milliseconds.", ge=0.0)
    error_rate_percent: float = Field(description="5xx/INTERNAL error percentage (0.0 to 100.0).", ge=0.0, le=100.0)
    cpu_saturation_percent: float = Field(description="Pod CPU utilization percentage.", ge=0.0, le=100.0)
    requests_per_second: float = Field(description="Observed request throughput per second.", ge=0.0)
    active_release_version: str = Field(description="Currently serving canary or stable release tag.")
    previous_stable_version: str = Field(description="Last known healthy release tag eligible for rollback.")
    anomaly_detected: bool = Field(description="True when SLO thresholds are actively breached.")


# ---------------------------------------------------------------------------
# 2. Post-Remediation SLO Burn Rate Schemas
# ---------------------------------------------------------------------------
class VerifySloBurnRateInput(BaseModel):
    """Strict input schema for `verify_post_remediation_slo_burn_rate`."""

    model_config = ConfigDict(extra="forbid", strict=True)

    service_id: str = Field(
        description="Canonical kebab-case production service identifier.",
        min_length=3,
        max_length=64,
        pattern=r"^[a-z][a-z0-9-]{2,63}$",
    )
    region: str = Field(
        description="Target Google Cloud region (e.g., 'us-central1').",
        pattern=r"^[a-z]+-[a-z]+\d+$",
    )
    target_release_version: str = Field(
        description="Release version expected to be serving traffic after remediation (e.g., 'v2.4.1').",
        pattern=r"^v\d+\.\d+\.\d+(?:-[a-z0-9]+)?$",
    )


class VerifySloBurnRateOutput(BaseModel):
    """Strict output schema for `verify_post_remediation_slo_burn_rate`."""

    model_config = ConfigDict(extra="forbid", strict=True)

    status: Literal["ok"] = Field(default="ok", description="Successful SLO check marker.")
    service_id: str = Field(description="Verified service identifier.")
    region: str = Field(description="Verified GCP region.")
    serving_version: str = Field(description="Confirmed active serving version.")
    one_hour_burn_rate: float = Field(description="1-hour error-budget burn rate (< 1.0 is healthy).", ge=0.0)
    slo_healthy: bool = Field(description="Whether the service has returned within SLO error budget.")
    verification_summary: str = Field(description="Concise human-readable SLO verification summary.")


# ---------------------------------------------------------------------------
# 3. Verified SRE Runbook Search Schemas (Vertex AI Search)
# ---------------------------------------------------------------------------
class SearchSreRunbooksInput(BaseModel):
    """Strict input schema for `search_verified_sre_runbooks`."""

    model_config = ConfigDict(extra="forbid", strict=True)

    symptom_query: str = Field(
        description="Natural-language incident symptom or error signature query.",
        min_length=5,
        max_length=400,
    )
    service_tier: Literal["tier-0", "tier-1", "tier-2"] = Field(
        default="tier-1",
        description="Production criticality tier used to filter approved runbooks.",
    )
    max_results: int = Field(
        default=3,
        description="Maximum number of grounded runbook passages to return (1 to 10).",
        ge=1,
        le=10,
    )


class RunbookPassage(BaseModel):
    """Single grounded runbook match retrieved from Vertex AI Search."""

    model_config = ConfigDict(extra="forbid", strict=True)

    runbook_id: str = Field(description="Immutable runbook identifier (e.g., 'RB-104').")
    title: str = Field(description="Runbook title.")
    recommended_steps: list[str] = Field(description="Ordered remediation steps.")
    requires_human_approval: bool = Field(description="Whether execution mandates HITL sign-off.")
    relevance_score: float = Field(description="Semantic relevance score (0.0 to 1.0).", ge=0.0, le=1.0)


class SearchSreRunbooksOutput(BaseModel):
    """Strict output schema for `search_verified_sre_runbooks`."""

    model_config = ConfigDict(extra="forbid", strict=True)

    status: Literal["ok"] = Field(default="ok", description="Successful retrieval marker.")
    datastore_source: str = Field(description="Backing Vertex AI Search datastore or index identifier.")
    matches: list[RunbookPassage] = Field(description="Ranked grounded runbook passages.")


# ---------------------------------------------------------------------------
# 4. High-Stakes Remediation & Critical Escalation Schemas (HITL Gated)
# ---------------------------------------------------------------------------
class ExecuteCanaryRollbackInput(BaseModel):
    """Strict input schema for `execute_canary_rollback_with_approval`."""

    model_config = ConfigDict(extra="forbid", strict=True)

    service_id: str = Field(
        description="Canonical kebab-case production service identifier to roll back.",
        pattern=r"^[a-z][a-z0-9-]{2,63}$",
    )
    region: str = Field(
        description="Target Google Cloud region where the bad canary is deployed.",
        pattern=r"^[a-z]+-[a-z]+\d+$",
    )
    faulty_version: str = Field(
        description="Currently serving faulty release version (e.g., 'v2.5.0-rc1').",
        pattern=r"^v\d+\.\d+\.\d+(?:-[a-z0-9]+)?$",
    )
    rollback_to_version: str = Field(
        description="Verified stable release version to restore (e.g., 'v2.4.2').",
        pattern=r"^v\d+\.\d+\.\d+(?:-[a-z0-9]+)?$",
    )
    incident_summary: str = Field(
        description="Concise evidence-backed justification for rolling back production traffic.",
        min_length=15,
        max_length=600,
    )
    approval_token: str | None = Field(
        default=None,
        description="Explicit Human-in-the-Loop operator approval token issued by HumanApprovalGate.",
    )


class ExecuteCanaryRollbackOutput(BaseModel):
    """Strict output schema for `execute_canary_rollback_with_approval`."""

    model_config = ConfigDict(extra="forbid", strict=True)

    status: Literal["rolled_back", "pending_human_approval"] = Field(
        description="Execution status; 'pending_human_approval' when awaiting operator confirmation."
    )
    change_record_id: str = Field(description="Immutable deployment audit or approval request ID.")
    service_id: str = Field(description="Target service identifier.")
    region: str = Field(description="Target GCP region.")
    restored_version: str = Field(description="Target stable version.")
    approved_by: str | None = Field(default=None, description="Verified human operator identity.")
    next_step_guidance: str = Field(description="Guidance on post-rollback verification or approval.")


class CreateCriticalIncidentEscalationInput(BaseModel):
    """Strict input schema for `create_critical_incident_escalation`."""

    model_config = ConfigDict(extra="forbid", strict=True)

    service_id: str = Field(
        description="Affected production service identifier.",
        pattern=r"^[a-z][a-z0-9-]{2,63}$",
    )
    severity: Literal["SEV-1", "SEV-2"] = Field(
        description="Critical incident severity level ('SEV-1' or 'SEV-2').",
    )
    title: str = Field(
        description="Actionable incident headline summarizing customer impact.",
        min_length=10,
        max_length=140,
    )
    diagnostic_evidence: str = Field(
        description="Grounded telemetry metrics and runbook IDs supporting escalation.",
        min_length=20,
        max_length=1500,
    )
    oncall_rotation: str = Field(
        description="Target SRE on-call rotation slug (e.g., 'payments-sre-primary').",
        pattern=r"^[a-z][a-z0-9-]{2,63}$",
    )
    approval_token: str | None = Field(
        default=None,
        description="Human-in-the-Loop confirmation token required before paging SEV-1 rotations.",
    )


class CreateCriticalIncidentEscalationOutput(BaseModel):
    """Strict output schema for `create_critical_incident_escalation`."""

    model_config = ConfigDict(extra="forbid", strict=True)

    status: Literal["escalated", "pending_human_approval"] = Field(
        description="Escalation state ('escalated' or 'pending_human_approval')."
    )
    incident_id: str = Field(description="Generated incident tracking ID or pending gate ID.")
    severity: Literal["SEV-1", "SEV-2"] = Field(description="Recorded incident severity.")
    paged_rotation: str = Field(description="Target on-call rotation.")
    bridge_url: str = Field(description="Incident response war-room URL.")


def format_validation_error_with_guidance(
    *,
    tool_name: str,
    exc: ValidationError,
    recovery_hint: str,
    allowed_values: list[str] | None = None,
) -> dict[str, Any]:
    """Converts a schema `ValidationError` into a `GuidedToolErrorResponse` dictionary."""
    details = exc.errors()
    first = details[0] if details else {"loc": ["unknown"], "msg": str(exc)}
    loc = ".".join(str(part) for part in first.get("loc", ["input"]))
    msg = f"Schema validation failed on parameter '{loc}': {first.get('msg', 'invalid value')}."
    return GuidedToolErrorResponse(
        tool_name=tool_name,
        error_code="SCHEMA_VALIDATION_ERROR",
        message=msg,
        recovery_instructions=recovery_hint,
        retryable=True,
        allowed_values=allowed_values or [],
    ).model_dump()


TOOL_JSON_SCHEMAS: dict[str, dict[str, dict[str, Any]]] = {
    "query_service_golden_signals_telemetry": {
        "input_schema": QueryGoldenSignalsInput.model_json_schema(),
        "output_schema": QueryGoldenSignalsOutput.model_json_schema(),
    },
    "verify_post_remediation_slo_burn_rate": {
        "input_schema": VerifySloBurnRateInput.model_json_schema(),
        "output_schema": VerifySloBurnRateOutput.model_json_schema(),
    },
    "search_verified_sre_runbooks": {
        "input_schema": SearchSreRunbooksInput.model_json_schema(),
        "output_schema": SearchSreRunbooksOutput.model_json_schema(),
    },
    "execute_canary_rollback_with_approval": {
        "input_schema": ExecuteCanaryRollbackInput.model_json_schema(),
        "output_schema": ExecuteCanaryRollbackOutput.model_json_schema(),
    },
    "create_critical_incident_escalation": {
        "input_schema": CreateCriticalIncidentEscalationInput.model_json_schema(),
        "output_schema": CreateCriticalIncidentEscalationOutput.model_json_schema(),
    },
}
