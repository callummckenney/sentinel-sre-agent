"""Runtime compatibility bridge for Google ADK, Pydantic, OpenTelemetry, and Structlog.

In production and standard ADK virtual environments, this module re-exports the canonical
classes directly from `google.adk`, `pydantic`, `opentelemetry`, and `structlog`.
When executed in isolated or air-gapped CI sandboxes without third-party wheels installed,
lightweight spec-faithful implementations are provided so deterministic unit tests and
static evaluation suites run identically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import inspect
import json
import re
import time
from typing import Any, Callable, get_args, get_origin, get_type_hints
import uuid

# ---------------------------------------------------------------------------
# 1. Pydantic v2 Schema Validation (Canonical + Strict Fallback)
# ---------------------------------------------------------------------------
try:
    from pydantic import BaseModel, ConfigDict, Field, ValidationError  # type: ignore
    PYDANTIC_AVAILABLE = True
except ImportError:  # pragma: no cover - used in air-gapped CI
    PYDANTIC_AVAILABLE = False

    class ValidationError(ValueError):
        """Raised when input or output payloads violate strict JSON schema constraints."""

        def __init__(self, errors: list[dict[str, Any]]) -> None:
            self._errors = errors
            super().__init__(json.dumps(errors))

        def errors(self) -> list[dict[str, Any]]:
            return list(self._errors)

    def ConfigDict(**kwargs: Any) -> dict[str, Any]:  # noqa: N802
        return dict(kwargs)

    @dataclass(frozen=True)
    class _FieldSpec:
        default: Any = ...
        default_factory: Callable[[], Any] | None = None
        description: str = ""
        min_length: int | None = None
        max_length: int | None = None
        ge: float | None = None
        le: float | None = None
        pattern: str | None = None
        examples: list[Any] | None = None

    def Field(  # noqa: N802
        default: Any = ...,
        *,
        default_factory: Callable[[], Any] | None = None,
        description: str = "",
        min_length: int | None = None,
        max_length: int | None = None,
        ge: float | None = None,
        le: float | None = None,
        pattern: str | None = None,
        examples: list[Any] | None = None,
    ) -> Any:
        return _FieldSpec(
            default=default,
            default_factory=default_factory,
            description=description,
            min_length=min_length,
            max_length=max_length,
            ge=ge,
            le=le,
            pattern=pattern,
            examples=examples,
        )

    class BaseModel:
        """Strict JSON-schema-backed model enforcing types, bounds, patterns, and extra='forbid'."""

        model_config: dict[str, Any] = {"extra": "forbid", "strict": True}

        def __init__(self, **data: Any) -> None:
            hints = get_type_hints(self.__class__)
            specs: dict[str, _FieldSpec] = {}
            for name in hints:
                raw_attr = getattr(self.__class__, name, ...)
                if isinstance(raw_attr, _FieldSpec):
                    specs[name] = raw_attr
                else:
                    specs[name] = _FieldSpec(default=raw_attr)

            errors: list[dict[str, Any]] = []
            if self.model_config.get("extra", "forbid") == "forbid":
                unknown = set(data.keys()) - set(hints.keys())
                for extra_key in sorted(unknown):
                    errors.append(
                        {
                            "loc": [extra_key],
                            "msg": f"Extra inputs are not permitted: '{extra_key}'",
                            "type": "extra_forbidden",
                        }
                    )

            resolved: dict[str, Any] = {}
            for name, annotation in hints.items():
                spec = specs[name]
                if name in data:
                    val = data[name]
                elif spec.default_factory is not None:
                    val = spec.default_factory()
                elif spec.default is not ...:
                    val = spec.default
                else:
                    errors.append(
                        {
                            "loc": [name],
                            "msg": f"Field required: '{name}'",
                            "type": "missing",
                        }
                    )
                    continue

                err = self._validate_value(name, val, annotation, spec)
                if err is not None:
                    errors.append(err)
                else:
                    resolved[name] = val

            if errors:
                raise ValidationError(errors)

            for key, value in resolved.items():
                object.__setattr__(self, key, value)

        @classmethod
        def _validate_value(
            cls,
            name: str,
            value: Any,
            annotation: Any,
            spec: _FieldSpec,
        ) -> dict[str, Any] | None:
            origin = get_origin(annotation)
            args = get_args(annotation)

            # Handle Optional / Union[T, None]
            if origin is not None and type(None) in args:
                if value is None:
                    return None
                non_none = [a for a in args if a is not type(None)]
                if len(non_none) == 1:
                    return cls._validate_value(name, value, non_none[0], spec)

            # Handle Literal[...]
            if str(origin).endswith("Literal"):
                if value not in args:
                    return {
                        "loc": [name],
                        "msg": f"Input should be one of {list(args)}, got {value!r}",
                        "type": "literal_error",
                    }
                return None

            # Handle list[T]
            if origin is list:
                if not isinstance(value, list):
                    return {
                        "loc": [name],
                        "msg": f"Input should be a valid list, got {type(value).__name__}",
                        "type": "list_type",
                    }
                if spec.min_length is not None and len(value) < spec.min_length:
                    return {
                        "loc": [name],
                        "msg": f"List should have at least {spec.min_length} items",
                        "type": "too_short",
                    }
                if args:
                    for idx, item in enumerate(value):
                        sub_err = cls._validate_value(f"{name}[{idx}]", item, args[0], _FieldSpec())
                        if sub_err is not None:
                            return sub_err
                return None

            # Handle dict[K, V]
            if origin is dict:
                if not isinstance(value, dict):
                    return {
                        "loc": [name],
                        "msg": f"Input should be a valid dictionary, got {type(value).__name__}",
                        "type": "dict_type",
                    }
                return None

            # Nested BaseModel
            if inspect.isclass(annotation) and issubclass(annotation, BaseModel):
                if isinstance(value, annotation):
                    return None
                if isinstance(value, dict):
                    try:
                        annotation(**value)
                        return None
                    except ValidationError as exc:
                        return exc.errors()[0]
                return {
                    "loc": [name],
                    "msg": f"Expected {annotation.__name__} object",
                    "type": "model_type",
                }

            # Primitive checks (remember bool is subclass of int in Python!)
            if annotation is str:
                if not isinstance(value, str):
                    return {"loc": [name], "msg": "Input should be a valid string", "type": "string_type"}
                if spec.min_length is not None and len(value) < spec.min_length:
                    return {
                        "loc": [name],
                        "msg": f"String should have at least {spec.min_length} characters",
                        "type": "string_too_short",
                    }
                if spec.max_length is not None and len(value) > spec.max_length:
                    return {
                        "loc": [name],
                        "msg": f"String should have at most {spec.max_length} characters",
                        "type": "string_too_long",
                    }
                if spec.pattern is not None and re.match(spec.pattern, value) is None:
                    return {
                        "loc": [name],
                        "msg": f"String '{value}' does not match pattern '{spec.pattern}'",
                        "type": "string_pattern_mismatch",
                    }
            elif annotation is int:
                if isinstance(value, bool) or not isinstance(value, int):
                    return {"loc": [name], "msg": "Input should be a valid integer", "type": "int_type"}
                if spec.ge is not None and value < spec.ge:
                    return {"loc": [name], "msg": f"Input should be >= {spec.ge}", "type": "greater_than_equal"}
                if spec.le is not None and value > spec.le:
                    return {"loc": [name], "msg": f"Input should be <= {spec.le}", "type": "less_than_equal"}
            elif annotation is float:
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    return {"loc": [name], "msg": "Input should be a valid number", "type": "float_type"}
                if spec.ge is not None and float(value) < spec.ge:
                    return {"loc": [name], "msg": f"Input should be >= {spec.ge}", "type": "greater_than_equal"}
                if spec.le is not None and float(value) > spec.le:
                    return {"loc": [name], "msg": f"Input should be <= {spec.le}", "type": "less_than_equal"}
            elif annotation is bool:
                if not isinstance(value, bool):
                    return {"loc": [name], "msg": "Input should be a valid boolean", "type": "bool_type"}

            return None

        def model_dump(self) -> dict[str, Any]:
            hints = get_type_hints(self.__class__)
            out: dict[str, Any] = {}
            for name in hints:
                val = getattr(self, name)
                if isinstance(val, BaseModel):
                    out[name] = val.model_dump()
                elif isinstance(val, list):
                    out[name] = [v.model_dump() if isinstance(v, BaseModel) else v for v in val]
                else:
                    out[name] = val
            return out

        @classmethod
        def model_validate(cls, data: dict[str, Any]) -> BaseModel:
            return cls(**data)

        @classmethod
        def model_json_schema(cls) -> dict[str, Any]:
            hints = get_type_hints(cls)
            properties: dict[str, Any] = {}
            required: list[str] = []
            for name, annotation in hints.items():
                raw_attr = getattr(cls, name, ...)
                spec = raw_attr if isinstance(raw_attr, _FieldSpec) else _FieldSpec(default=raw_attr)
                prop: dict[str, Any] = {"description": spec.description}
                origin = get_origin(annotation)
                args = get_args(annotation)
                if str(origin).endswith("Literal"):
                    prop["type"] = "string"
                    prop["enum"] = list(args)
                elif annotation is str:
                    prop["type"] = "string"
                    if spec.min_length is not None:
                        prop["minLength"] = spec.min_length
                    if spec.max_length is not None:
                        prop["maxLength"] = spec.max_length
                    if spec.pattern is not None:
                        prop["pattern"] = spec.pattern
                elif annotation is int:
                    prop["type"] = "integer"
                    if spec.ge is not None:
                        prop["minimum"] = spec.ge
                    if spec.le is not None:
                        prop["maximum"] = spec.le
                elif annotation is float:
                    prop["type"] = "number"
                    if spec.ge is not None:
                        prop["minimum"] = spec.ge
                    if spec.le is not None:
                        prop["maximum"] = spec.le
                elif annotation is bool:
                    prop["type"] = "boolean"
                elif origin is list:
                    prop["type"] = "array"
                else:
                    prop["type"] = "object"
                properties[name] = prop
                if spec.default is ... and spec.default_factory is None:
                    required.append(name)
            return {
                "title": cls.__name__,
                "type": "object",
                "additionalProperties": cls.model_config.get("extra", "forbid") != "forbid",
                "properties": properties,
                "required": required,
            }


# ---------------------------------------------------------------------------
# 2. Google ADK Core Primitives (Canonical + Spec-Faithful Fallback)
# ---------------------------------------------------------------------------
try:
    from google.adk.agents import LlmAgent, LoopAgent, ParallelAgent, SequentialAgent  # type: ignore
    from google.adk.agents.context_cache_config import ContextCacheConfig  # type: ignore
    from google.adk.apps.app import App, EventsCompactionConfig  # type: ignore
    from google.adk.memory import InMemoryMemoryService, VertexAiMemoryBankService  # type: ignore
    from google.adk.plugins.base_plugin import BasePlugin  # type: ignore
    from google.adk.sessions import (  # type: ignore
        DatabaseSessionService,
        InMemorySessionService,
        VertexAiSessionService,
    )
    from google.adk.tools import FunctionTool, ToolContext  # type: ignore
    ADK_AVAILABLE = True
except ImportError:  # pragma: no cover - used in air-gapped CI
    ADK_AVAILABLE = False

    @dataclass
    class EventsCompactionConfig:
        """ADK sliding-window event summarization config."""

        compaction_interval: int = 4
        overlap_size: int = 1
        summarizer: Any | None = None

    @dataclass
    class ContextCacheConfig:
        """ADK Vertex AI context caching config."""

        min_tokens: int = 2048
        ttl_seconds: int = 1800
        cache_intervals: int = 5

    @dataclass
    class ToolConfirmation:
        hint: str
        confirmed: bool = False
        payload: dict[str, Any] = field(default_factory=dict)

    class ToolContext:
        """ADK tool invocation context carrying session state and HITL confirmation state."""

        def __init__(
            self,
            state: dict[str, Any] | None = None,
            tool_confirmation: ToolConfirmation | None = None,
            invocation_id: str | None = None,
        ) -> None:
            self.state: dict[str, Any] = state if state is not None else {}
            self.tool_confirmation: ToolConfirmation | None = tool_confirmation
            self.invocation_id: str = invocation_id or f"inv-{uuid.uuid4().hex[:12]}"
            self.requested_confirmations: list[ToolConfirmation] = []

        def request_confirmation(
            self,
            *,
            hint: str,
            payload: dict[str, Any] | None = None,
        ) -> None:
            confirmation = ToolConfirmation(
                hint=hint,
                confirmed=False,
                payload=payload or {},
            )
            self.requested_confirmations.append(confirmation)
            self.tool_confirmation = confirmation

    class FunctionTool:
        """ADK FunctionTool wrapper supporting explicit `require_confirmation` HITL gates."""

        def __init__(
            self,
            func: Callable[..., Any],
            *,
            require_confirmation: bool = False,
        ) -> None:
            self.func = func
            self.name = func.__name__
            self.description = inspect.getdoc(func) or ""
            self.require_confirmation = require_confirmation

        def __call__(self, *args: Any, **kwargs: Any) -> Any:
            return self.func(*args, **kwargs)

    class BasePlugin:
        """ADK global plugin lifecycle interface."""

        def __init__(self, name: str = "base_plugin") -> None:
            self.name = name

        async def before_agent_callback(self, *, agent: Any, callback_context: Any) -> Any:
            return None

        async def after_agent_callback(self, *, agent: Any, callback_context: Any) -> Any:
            return None

        async def before_model_callback(self, *, callback_context: Any, llm_request: Any) -> Any:
            return None

        async def after_model_callback(self, *, callback_context: Any, llm_response: Any) -> Any:
            return None

        async def before_tool_callback(
            self, *, tool: Any, tool_args: dict[str, Any], tool_context: ToolContext
        ) -> Any:
            return None

        async def after_tool_callback(
            self,
            *,
            tool: Any,
            tool_args: dict[str, Any],
            tool_context: ToolContext,
            result: Any,
        ) -> Any:
            return None

    @dataclass
    class LlmAgent:
        name: str
        model: str
        description: str = ""
        instruction: str = ""
        tools: list[Any] = field(default_factory=list)
        sub_agents: list[Any] = field(default_factory=list)
        output_key: str | None = None
        output_schema: Any | None = None
        before_agent_callback: Callable[..., Any] | None = None
        after_agent_callback: Callable[..., Any] | None = None
        before_model_callback: Callable[..., Any] | None = None
        after_model_callback: Callable[..., Any] | None = None
        before_tool_callback: Callable[..., Any] | None = None
        after_tool_callback: Callable[..., Any] | None = None

    @dataclass
    class SequentialAgent:
        name: str
        description: str = ""
        sub_agents: list[Any] = field(default_factory=list)

    @dataclass
    class ParallelAgent:
        name: str
        description: str = ""
        sub_agents: list[Any] = field(default_factory=list)

    @dataclass
    class LoopAgent:
        name: str
        description: str = ""
        sub_agents: list[Any] = field(default_factory=list)
        max_iterations: int = 3

    @dataclass
    class App:
        name: str
        root_agent: Any
        plugins: list[BasePlugin] = field(default_factory=list)
        events_compaction_config: EventsCompactionConfig | None = None
        context_cache_config: ContextCacheConfig | None = None

    class InMemorySessionService:
        def __init__(self) -> None:
            self._sessions: dict[str, dict[str, Any]] = {}

    class DatabaseSessionService:
        def __init__(self, db_url: str) -> None:
            self.db_url = db_url

    class VertexAiSessionService:
        def __init__(
            self,
            project: str | None = None,
            location: str = "us-central1",
            agent_engine_id: str | None = None,
        ) -> None:
            self.project = project
            self.location = location
            self.agent_engine_id = agent_engine_id

    class InMemoryMemoryService:
        def __init__(self) -> None:
            self.entries: list[dict[str, Any]] = []

    class VertexAiMemoryBankService:
        def __init__(
            self,
            project: str | None = None,
            location: str = "us-central1",
            agent_engine_id: str | None = None,
        ) -> None:
            self.project = project
            self.location = location
            self.agent_engine_id = agent_engine_id


# ---------------------------------------------------------------------------
# 3. OpenTelemetry Tracing Primitives (Canonical + Spec-Faithful Fallback)
# ---------------------------------------------------------------------------
try:
    from opentelemetry import trace as otel_trace  # type: ignore
    from opentelemetry.sdk.resources import Resource as OTelResource  # type: ignore
    from opentelemetry.sdk.trace import TracerProvider as OTelTracerProvider  # type: ignore
    from opentelemetry.sdk.trace.export import (  # type: ignore
        BatchSpanProcessor,
        SimpleSpanProcessor,
        SpanExporter,
        SpanExportResult,
    )
    from opentelemetry.trace import Status, StatusCode  # type: ignore
    OTEL_AVAILABLE = True
except ImportError:  # pragma: no cover - used in air-gapped CI
    OTEL_AVAILABLE = False

    class StatusCode:
        UNSET = "UNSET"
        OK = "OK"
        ERROR = "ERROR"

    @dataclass
    class Status:
        status_code: str
        description: str = ""

    class SpanExportResult:
        SUCCESS = 0
        FAILURE = 1

    @dataclass
    class SpanContext:
        trace_id: int
        span_id: int
        is_remote: bool = False

    class _FallbackSpan:
        def __init__(
            self,
            name: str,
            trace_id: int,
            parent_span_id: int | None,
            exporter_sink: Callable[[_FallbackSpan], None],
            attributes: dict[str, Any] | None = None,
        ) -> None:
            self.name = name
            self.context = SpanContext(
                trace_id=trace_id,
                span_id=uuid.uuid4().int & ((1 << 64) - 1),
            )
            self.parent_span_id = parent_span_id
            self.attributes: dict[str, Any] = dict(attributes or {})
            self.events: list[dict[str, Any]] = []
            self.status: Status = Status(StatusCode.UNSET)
            self.start_time_ns: int = time.time_ns()
            self.end_time_ns: int | None = None
            self._exporter_sink = exporter_sink
            self._prev_span: _FallbackSpan | None = None

        def get_span_context(self) -> SpanContext:
            return self.context

        def set_attribute(self, key: str, value: Any) -> None:
            self.attributes[key] = value

        def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
            self.events.append(
                {
                    "name": name,
                    "attributes": dict(attributes or {}),
                    "timestamp_ns": time.time_ns(),
                }
            )

        def set_status(self, status: Status) -> None:
            self.status = status

        def record_exception(self, exc: BaseException) -> None:
            self.add_event(
                "exception",
                {"exception.type": type(exc).__name__, "exception.message": str(exc)},
            )
            self.set_status(Status(StatusCode.ERROR, str(exc)))

        def __enter__(self) -> _FallbackSpan:
            self._prev_span = _ACTIVE_SPAN_STACK[-1] if _ACTIVE_SPAN_STACK else None
            _ACTIVE_SPAN_STACK.append(self)
            return self

        def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
            if exc_val is not None:
                self.record_exception(exc_val)
            elif self.status.status_code == StatusCode.UNSET:
                self.set_status(Status(StatusCode.OK))
            self.end_time_ns = time.time_ns()
            if _ACTIVE_SPAN_STACK and _ACTIVE_SPAN_STACK[-1] is self:
                _ACTIVE_SPAN_STACK.pop()
            self._exporter_sink(self)

    _ACTIVE_SPAN_STACK: list[_FallbackSpan] = []

    class SpanExporter:
        def export(self, spans: list[Any]) -> int:
            return SpanExportResult.SUCCESS

        def shutdown(self) -> None:
            return None

    class SimpleSpanProcessor:
        def __init__(self, exporter: SpanExporter) -> None:
            self.exporter = exporter

        def on_end(self, span: Any) -> None:
            self.exporter.export([span])

    BatchSpanProcessor = SimpleSpanProcessor

    @dataclass
    class OTelResource:
        attributes: dict[str, Any]

        @classmethod
        def create(cls, attributes: dict[str, Any]) -> OTelResource:
            return cls(attributes=attributes)

    class _FallbackTracer:
        def __init__(self, name: str, provider: OTelTracerProvider) -> None:
            self.name = name
            self._provider = provider

        def start_as_current_span(
            self,
            name: str,
            *,
            attributes: dict[str, Any] | None = None,
        ) -> _FallbackSpan:
            current = _ACTIVE_SPAN_STACK[-1] if _ACTIVE_SPAN_STACK else None
            trace_id = (
                current.context.trace_id
                if current is not None
                else (uuid.uuid4().int & ((1 << 128) - 1))
            )
            parent_id = current.context.span_id if current is not None else None
            return _FallbackSpan(
                name=name,
                trace_id=trace_id,
                parent_span_id=parent_id,
                exporter_sink=self._provider._emit_span,
                attributes=attributes,
            )

    class OTelTracerProvider:
        def __init__(self, resource: OTelResource | None = None) -> None:
            self.resource = resource or OTelResource.create({})
            self._processors: list[SimpleSpanProcessor] = []

        def add_span_processor(self, processor: SimpleSpanProcessor) -> None:
            self._processors.append(processor)

        def _emit_span(self, span: _FallbackSpan) -> None:
            for proc in self._processors:
                proc.on_end(span)

        def get_tracer(self, name: str) -> _FallbackTracer:
            return _FallbackTracer(name, self)

    class _FallbackOTelTraceAPI:
        _provider: OTelTracerProvider = OTelTracerProvider()

        @classmethod
        def set_tracer_provider(cls, provider: OTelTracerProvider) -> None:
            cls._provider = provider

        @classmethod
        def get_tracer_provider(cls) -> OTelTracerProvider:
            return cls._provider

        @classmethod
        def get_tracer(cls, name: str) -> _FallbackTracer:
            return cls._provider.get_tracer(name)

        @staticmethod
        def get_current_span() -> _FallbackSpan | None:
            return _ACTIVE_SPAN_STACK[-1] if _ACTIVE_SPAN_STACK else None

    otel_trace = _FallbackOTelTraceAPI()  # type: ignore
