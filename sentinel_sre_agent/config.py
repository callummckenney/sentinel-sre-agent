"""Centralized, typed runtime configuration for Sentinel SRE Agent.

All sensitive credentials (database URLs, PagerDuty integration keys, deployment controller
tokens) are referenced solely by Secret Manager Secret ID and resolved just-in-time via
`SecretManagerResolver`.
"""

from __future__ import annotations

from dataclasses import dataclass
import os

from sentinel_sre_agent.security.secret_manager import SecretManagerResolver


@dataclass(frozen=True)
class SentinelConfig:
    """Immutable runtime settings populated from non-secret environment variables."""

    project_id: str
    location: str
    runtime_mode: str  # "production" | "local"
    agent_engine_id: str
    vertex_search_datastore_id: str
    model_armor_template_id: str
    dlp_deidentify_template_id: str
    session_db_url_secret_id: str
    pagerduty_secret_id: str
    deploy_controller_secret_id: str
    fast_model_name: str = "gemini-2.5-flash"
    reasoning_model_name: str = "gemini-2.5-pro"
    otel_service_name: str = "sentinel-sre-agent"

    @classmethod
    def from_env(cls) -> SentinelConfig:
        project_id = os.getenv("GOOGLE_CLOUD_PROJECT", "sentinel-sre-local-project")
        location = os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1")
        runtime_mode = os.getenv("SENTINEL_RUNTIME_MODE", "local").lower()
        return cls(
            project_id=project_id,
            location=location,
            runtime_mode=runtime_mode,
            agent_engine_id=os.getenv("GOOGLE_CLOUD_AGENT_ENGINE_ID", ""),
            vertex_search_datastore_id=os.getenv(
                "VERTEX_SEARCH_DATASTORE_ID", "sentinel-sre-runbooks-ds"
            ),
            model_armor_template_id=os.getenv(
                "MODEL_ARMOR_TEMPLATE_ID",
                f"projects/{project_id}/locations/{location}/templates/sentinel-guardrail-template",
            ),
            dlp_deidentify_template_id=os.getenv(
                "DLP_DEIDENTIFY_TEMPLATE_ID",
                f"projects/{project_id}/locations/{location}/deidentifyTemplates/sentinel-pii-scrubber",
            ),
            session_db_url_secret_id=os.getenv(
                "SESSION_DB_URL_SECRET_ID", "sentinel-session-db-url"
            ),
            pagerduty_secret_id=os.getenv(
                "PAGERDUTY_INTEGRATION_SECRET_ID", "sentinel-pagerduty-routing-key"
            ),
            deploy_controller_secret_id=os.getenv(
                "DEPLOY_CONTROLLER_SECRET_ID", "sentinel-deploy-controller-token"
            ),
            otel_service_name=os.getenv("OTEL_SERVICE_NAME", "sentinel-sre-agent"),
        )

    def create_secret_resolver(self) -> SecretManagerResolver:
        """Builds a SecretManagerResolver; uses safe ephemeral test values only in `local` mode."""
        if self.runtime_mode == "local":
            ephemeral_map = {
                self.session_db_url_secret_id: "sqlite+aiosqlite:///tmp/sentinel_sessions.db",
                self.pagerduty_secret_id: "ephemeral-local-pd-routing-ref",
                self.deploy_controller_secret_id: "ephemeral-local-deploy-ref",
            }
            return SecretManagerResolver(
                self.project_id,
                ephemeral_provider=lambda sid, _ver: ephemeral_map.get(
                    sid, f"ephemeral-local-{sid}"
                ),
            )
        return SecretManagerResolver(self.project_id)
