"""Unit tests for Category 4: Observability & Tracing (20 pts).

Verifies:
- 4.1 Structured JSON Logging (no print() statements in source; rich metadata JSON logs)
- 4.2 Intent vs. Outcome Capture (paired AGENT_ACTION_INTENT & AGENT_ACTION_OUTCOME records)
- 4.3 Distributed Tracing (OpenTelemetry linked parent-child spans across request lifecycle)
- 4.4 PII Redaction (emails, SSNs, phones, credit cards, bearer tokens, IPs scrubbed)
"""

from __future__ import annotations

import ast
from pathlib import Path
import unittest

from sentinel_sre_agent.observability import (
    InMemorySpanRecorder,
    IntentOutcomeAuditTracker,
    PIIRedactionScrubber,
    StructuredJsonLogger,
    configure_distributed_tracing,
    traced_operation,
)


class TestObservabilityAndTracing(unittest.TestCase):
    def test_zero_print_calls_across_entire_agent_package(self) -> None:
        pkg_root = Path(__file__).resolve().parents[1] / "sentinel_sre_agent"
        offenders: list[str] = []
        for py_file in sorted(pkg_root.rglob("*.py")):
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "print"
                ):
                    offenders.append(f"{py_file.name}:{node.lineno}")
        self.assertEqual(offenders, [], f"Found raw print() calls: {offenders}")

    def test_distributed_tracing_links_parent_child_spans_and_correlates_json_logs(self) -> None:
        recorder = InMemorySpanRecorder()
        configure_distributed_tracing(service_name="sentinel-test", recorder=recorder)
        logger = StructuredJsonLogger("tracing_test", project_id="demo-proj")

        with traced_operation("sentinel.request.root", attributes={"query.id": "q-1"}):
            with traced_operation("sentinel.tool.child", attributes={"tool.name": "telemetry"}):
                log_entry = logger.info("Executing child tool", step=1)

        spans = recorder.get_finished_spans()
        self.assertEqual(len(spans), 2)
        child_span, root_span = spans[0], spans[1]
        self.assertEqual(child_span.name, "sentinel.tool.child")
        self.assertEqual(root_span.name, "sentinel.request.root")
        self.assertEqual(child_span.trace_id_hex, root_span.trace_id_hex)
        self.assertEqual(child_span.parent_span_id_hex, root_span.span_id_hex)

        # Structured log automatically carries trace_id & span_id matching child span
        self.assertEqual(log_entry["trace_id"], child_span.trace_id_hex)
        self.assertEqual(log_entry["span_id"], child_span.span_id_hex)
        self.assertIn("logging.googleapis.com/trace", log_entry)

    def test_intent_vs_outcome_audit_pairs_share_correlation_id(self) -> None:
        logger = StructuredJsonLogger("audit_test")
        tracker = IntentOutcomeAuditTracker(logger)

        cid = tracker.record_intent(
            agent_name="telemetry_analyst_agent",
            intended_action="query_service_golden_signals_telemetry",
            intended_parameters={"service_id": "checkout-api", "region": "us-central1"},
            rationale="Inspect golden signals for reported 5xx spike.",
            session_id="sess-audit-1",
        )
        tracker.record_outcome(
            correlation_id=cid,
            actual_status="ok",
            outcome_summary={"anomaly_detected": True},
            intent_fulfilled=True,
            session_id="sess-audit-1",
        )

        records = logger.records
        self.assertEqual(len(records), 2)
        intent_rec, outcome_rec = records[0], records[1]
        self.assertEqual(intent_rec["event"], "AGENT_ACTION_INTENT")
        self.assertEqual(outcome_rec["event"], "AGENT_ACTION_OUTCOME")
        self.assertEqual(
            intent_rec["metadata"]["correlation_id"],
            outcome_rec["metadata"]["correlation_id"],
        )
        self.assertTrue(outcome_rec["metadata"]["intent_fulfilled"])
        self.assertGreaterEqual(outcome_rec["metadata"]["latency_ms"], 0.0)

    def test_pii_redactor_scrubs_all_sensitive_entities_in_logs_and_payloads(self) -> None:
        scrubber = PIIRedactionScrubber()
        raw = (
            "Customer john.smith@corp.example reported SSN 123-45-6789, "
            "phone (415) 555-0199, IP 10.24.88.12, and header Bearer tok_live_998877."
        )
        cleaned = scrubber.scrub_text(raw)
        self.assertNotIn("john.smith@corp.example", cleaned)
        self.assertNotIn("123-45-6789", cleaned)
        self.assertNotIn("555-0199", cleaned)
        self.assertNotIn("10.24.88.12", cleaned)
        self.assertNotIn("tok_live_998877", cleaned)
        self.assertIn("[REDACTED_EMAIL]", cleaned)
        self.assertIn("[REDACTED_SSN]", cleaned)
        self.assertIn("[REDACTED_PHONE]", cleaned)
        self.assertIn("[REDACTED_IPV4]", cleaned)
        self.assertIn("[REDACTED_BEARER_TOKEN]", cleaned)

        nested = scrubber.scrub_payload(
            {"authorization": "secret-header", "notes": ["Reach ops@example.org"]}
        )
        self.assertEqual(nested["authorization"], "[REDACTED_SENSITIVE_FIELD]")
        self.assertEqual(nested["notes"][0], "Reach [REDACTED_EMAIL]")


if __name__ == "__main__":
    unittest.main()
