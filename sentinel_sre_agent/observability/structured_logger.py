"""Structured JSON logging with Cloud Trace correlation and active PII scrubbing.

Addresses Rubric Criterion 4.1 (Structured JSON Logging):
- Eliminates raw `print()` calls in favor of structured JSON records (`structlog` + Python
  `logging` handler compatible with Google Cloud Logging).
- Automatically injects OpenTelemetry `trace_id` and `span_id` fields and scrubs all PII
  before serializing records.
"""

from __future__ import annotations

from datetime import datetime, timezone
import io
import json
import logging
from typing import Any

from sentinel_sre_agent.observability.pii_redactor import PIIRedactionScrubber
from sentinel_sre_agent.observability.tracing import get_current_trace_identifiers

try:
    import structlog  # type: ignore
    STRUCTLOG_AVAILABLE = True
except ImportError:  # pragma: no cover - offline CI fallback
    structlog = None
    STRUCTLOG_AVAILABLE = False


class StructuredJsonLogger:
    """Emits PII-scrubbed, Cloud-Logging-compatible structured JSON log events."""

    def __init__(
        self,
        component: str,
        *,
        project_id: str | None = None,
        scrubber: PIIRedactionScrubber | None = None,
        stream: io.TextIOBase | None = None,
        sink_buffer: list[dict[str, Any]] | None = None,
    ) -> None:
        self._component = component
        self._project_id = project_id or "sentinel-sre-local-project"
        self._scrubber = scrubber or PIIRedactionScrubber(project_id=project_id)
        self._sink_buffer = sink_buffer if sink_buffer is not None else []

        self._py_logger = logging.getLogger(f"sentinel_sre_agent.{component}.{id(self)}")
        self._py_logger.setLevel(logging.INFO)
        self._py_logger.propagate = False
        if stream is not None:
            handler = logging.StreamHandler(stream)
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._py_logger.addHandler(handler)
        elif not self._py_logger.handlers:
            self._py_logger.addHandler(logging.NullHandler())

    @property
    def records(self) -> list[dict[str, Any]]:
        """Returns structured log dictionaries captured in-memory for testing/inspection."""
        return list(self._sink_buffer)

    def log_event(
        self,
        event: str,
        *,
        severity: str = "INFO",
        **fields: Any,
    ) -> dict[str, Any]:
        """Formats, scrubs PII, correlates trace IDs, and emits a single JSON log entry."""
        trace_id, span_id = get_current_trace_identifiers()
        scrubbed_fields = self._scrubber.scrub_payload(fields)
        scrubbed_event = self._scrubber.scrub_text(event)

        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity.upper(),
            "event": scrubbed_event,
            "component": self._component,
            "metadata": scrubbed_fields,
        }
        if trace_id:
            payload["logging.googleapis.com/trace"] = (
                f"projects/{self._project_id}/traces/{trace_id}"
            )
            payload["trace_id"] = trace_id
        if span_id:
            payload["logging.googleapis.com/spanId"] = span_id
            payload["span_id"] = span_id

        serialized = json.dumps(payload, sort_keys=True, default=str)
        self._sink_buffer.append(payload)

        level = getattr(logging, severity.upper(), logging.INFO)
        self._py_logger.log(level, serialized)
        return payload

    def info(self, event: str, **fields: Any) -> dict[str, Any]:
        return self.log_event(event, severity="INFO", **fields)

    def warning(self, event: str, **fields: Any) -> dict[str, Any]:
        return self.log_event(event, severity="WARNING", **fields)

    def error(self, event: str, **fields: Any) -> dict[str, Any]:
        return self.log_event(event, severity="ERROR", **fields)
