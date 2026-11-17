"""Unit tests for Category 1: Tool & Interface Design (20 pts).

Verifies:
- 1.1 Comprehensive Tool Docstrings (purpose, Args, Returns on every tool)
- 1.2 Descriptive Naming (domain-specific action verbs, no generic names)
- 1.3 Explicit JSON Schemas (strict input/output schemas, extra='forbid')
- 1.4 Guided Error Handling (actionable recovery_instructions instead of exceptions)
"""

from __future__ import annotations

import inspect
import unittest

from sentinel_sre_agent._adk_compat import ValidationError
from sentinel_sre_agent.schemas.tool_contracts import (
    QueryGoldenSignalsInput,
    TOOL_JSON_SCHEMAS,
)
from sentinel_sre_agent.tools import (
    ALL_TOOL_FUNCTIONS,
    create_critical_incident_escalation,
    execute_canary_rollback_with_approval,
    query_service_golden_signals_telemetry,
    reset_local_release_overrides,
    search_verified_sre_runbooks,
    verify_post_remediation_slo_burn_rate,
)


class TestToolAndInterfaceDesign(unittest.TestCase):
    def setUp(self) -> None:
        reset_local_release_overrides()

    def test_all_tools_have_comprehensive_docstrings_and_specific_names(self) -> None:
        generic_banned = {"run", "execute", "update_jira", "get_data", "helper", "do_work"}
        for fn in ALL_TOOL_FUNCTIONS:
            self.assertNotIn(fn.__name__, generic_banned)
            self.assertGreaterEqual(len(fn.__name__.split("_")), 3)
            doc = inspect.getdoc(fn) or ""
            self.assertGreater(len(doc), 180, f"Docstring too brief on {fn.__name__}")
            self.assertIn("Args:", doc, f"Missing Args section on {fn.__name__}")
            self.assertIn("Returns:", doc, f"Missing Returns section on {fn.__name__}")

    def test_explicit_json_schemas_enforce_strict_constraints_and_forbid_extra(self) -> None:
        self.assertEqual(len(TOOL_JSON_SCHEMAS), 5)
        for tool_name, pair in TOOL_JSON_SCHEMAS.items():
            in_schema = pair["input_schema"]
            out_schema = pair["output_schema"]
            self.assertEqual(in_schema["type"], "object", tool_name)
            self.assertFalse(in_schema.get("additionalProperties", True), tool_name)
            self.assertEqual(out_schema["type"], "object", tool_name)
            self.assertFalse(out_schema.get("additionalProperties", True), tool_name)

        with self.assertRaises(ValidationError):
            QueryGoldenSignalsInput(
                service_id="checkout-api",
                region="us-central1",
                unexpected_hallucinated_param="bad",  # type: ignore[call-arg]
            )

    def test_guided_error_handling_on_invalid_inputs_and_missing_resources(self) -> None:
        # 1. Invalid service_id pattern returns GuidedToolErrorResponse instead of crashing
        bad_pattern = query_service_golden_signals_telemetry(
            service_id="INVALID UPPERCASE!!",
            region="us-central1",
        )
        self.assertEqual(bad_pattern["status"], "error")
        self.assertEqual(bad_pattern["error_code"], "SCHEMA_VALIDATION_ERROR")
        self.assertIn("query_service_golden_signals_telemetry", bad_pattern["recovery_instructions"])
        self.assertTrue(bad_pattern["retryable"])

        # 2. Unknown deployment returns guided recovery listing valid deployments
        not_found = query_service_golden_signals_telemetry(
            service_id="nonexistent-service",
            region="us-central1",
        )
        self.assertEqual(not_found["status"], "error")
        self.assertEqual(not_found["error_code"], "SERVICE_REGION_NOT_FOUND")
        self.assertIn("checkout-api@us-central1", not_found["recovery_instructions"])

        # 3. Identical faulty and rollback versions return guided self-correction
        same_ver = execute_canary_rollback_with_approval(
            service_id="checkout-api",
            region="us-central1",
            faulty_version="v2.4.2",
            rollback_to_version="v2.4.2",
            incident_summary="Attempting rollback with identical version tags.",
        )
        self.assertEqual(same_ver["status"], "error")
        self.assertEqual(same_ver["error_code"], "IDENTICAL_ROLLBACK_VERSION")
        self.assertIn("previous_stable_version", same_ver["recovery_instructions"])

        # 4. Unmatched runbook query guides LLM to broaden symptom keywords
        no_rb = search_verified_sre_runbooks(symptom_query="quantum flux capacitor")
        self.assertEqual(no_rb["status"], "error")
        self.assertEqual(no_rb["error_code"], "NO_MATCHING_RUNBOOKS")
        self.assertIn("latency", no_rb["recovery_instructions"])

        # 5. Valid SEV-2 escalation executes cleanly without error
        sev2 = create_critical_incident_escalation(
            service_id="checkout-api",
            severity="SEV-2",
            title="Elevated checkout canary latency in us-central1",
            diagnostic_evidence="p99_latency_ms=1840.5ms and error_rate=14.2% per RB-104.",
            oncall_rotation="checkout-sre-primary",
        )
        self.assertEqual(sev2["status"], "escalated")
        self.assertTrue(sev2["incident_id"].startswith("INC-"))

        # 6. Valid SLO check returns structured schema
        slo = verify_post_remediation_slo_burn_rate(
            service_id="payments-ledger",
            region="us-central1",
            target_release_version="v4.0.9",
        )
        self.assertEqual(slo["status"], "ok")
        self.assertIn("one_hour_burn_rate", slo)


if __name__ == "__main__":
    unittest.main()
