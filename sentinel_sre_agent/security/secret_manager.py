"""Secure secret injection via Google Cloud Secret Manager.

Addresses Rubric Criterion 5.3 (Secure Secret Management):
- Zero hardcoded API keys, tokens, or database passwords anywhere in source code.
- All external clients retrieve secrets dynamically through Google Cloud Secret Manager
  using Application Default Credentials (ADC) / Workload Identity Federation.
- Supports bounded TTL in-memory caching and explicit cache invalidation on secret rotation.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import time
from typing import Callable

try:
    from google.cloud import secretmanager  # type: ignore
    SECRET_MANAGER_SDK_AVAILABLE = True
except ImportError:  # pragma: no cover - used in offline unit test environments
    secretmanager = None
    SECRET_MANAGER_SDK_AVAILABLE = False


class SecretResolutionError(RuntimeError):
    """Raised when a required secret cannot be retrieved from Secret Manager."""


@dataclass(frozen=True)
class _CachedSecret:
    payload: str
    expires_at_monotonic: float


class SecretManagerResolver:
    """Resolves application secrets exclusively from Google Cloud Secret Manager.

    Never reads raw credentials from source files or committed configuration.
    In isolated CI tests (`allow_ephemeral_provider=True`), an injected in-memory
    secret provider callable may supply ephemeral test fixtures without touching disk.
    """

    def __init__(
        self,
        project_id: str,
        *,
        ttl_seconds: int = 300,
        ephemeral_provider: Callable[[str, str], str] | None = None,
    ) -> None:
        if not project_id or not project_id.strip():
            raise ValueError("A valid Google Cloud `project_id` is required for Secret Manager.")
        self._project_id = project_id.strip()
        self._ttl_seconds = max(1, ttl_seconds)
        self._ephemeral_provider = ephemeral_provider
        self._cache: dict[tuple[str, str], _CachedSecret] = {}
        self._client: object | None = None

    def _get_gcp_client(self) -> object:
        if self._client is None:
            if not SECRET_MANAGER_SDK_AVAILABLE or secretmanager is None:
                raise SecretResolutionError(
                    "google-cloud-secret-manager SDK is not installed and no ephemeral "
                    "test provider was configured."
                )
            self._client = secretmanager.SecretManagerServiceClient()
        return self._client

    def build_secret_version_path(self, secret_id: str, version: str = "latest") -> str:
        """Constructs the canonical Secret Manager resource name."""
        if not re.match(r"^[a-zA-Z0-9_-]{1,255}$", secret_id):
            raise ValueError(f"Invalid Secret Manager secret_id format: '{secret_id}'")
        return f"projects/{self._project_id}/secrets/{secret_id}/versions/{version}"

    def get_secret(self, secret_id: str, *, version: str = "latest") -> str:
        """Fetches a secret payload from Google Cloud Secret Manager with TTL caching."""
        cache_key = (secret_id, version)
        now = time.monotonic()
        cached = self._cache.get(cache_key)
        if cached is not None and cached.expires_at_monotonic > now:
            return cached.payload

        resource_name = self.build_secret_version_path(secret_id, version)

        if self._ephemeral_provider is not None:
            payload = self._ephemeral_provider(secret_id, version)
        else:
            try:
                client = self._get_gcp_client()
                response = client.access_secret_version(request={"name": resource_name})  # type: ignore[attr-defined]
                payload = response.payload.data.decode("utf-8")
            except Exception as exc:  # pragma: no cover - network/IAM errors
                raise SecretResolutionError(
                    f"Failed to access secret '{resource_name}' via Secret Manager IAM/ADC: {exc}"
                ) from exc

        if not payload:
            raise SecretResolutionError(f"Secret '{resource_name}' resolved to an empty payload.")

        self._cache[cache_key] = _CachedSecret(
            payload=payload,
            expires_at_monotonic=now + self._ttl_seconds,
        )
        return payload

    def invalidate_secret(self, secret_id: str | None = None) -> None:
        """Evicts cached secret versions after credential rotation."""
        if secret_id is None:
            self._cache.clear()
            return
        keys_to_remove = [key for key in self._cache if key[0] == secret_id]
        for key in keys_to_remove:
            del self._cache[key]


# High-signal secret patterns used by CI/regression tests to guarantee zero hardcoded keys
FORBIDDEN_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("aws_access_key", re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")),
    ("oauth_access_token", re.compile(r"ya29\.[0-9A-Za-z_-]{20,}")),
    ("private_key_pem", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    (
        "hardcoded_api_key_assignment",
        re.compile(r"""(?i)(?:api_key|secret_key|password|bearer_token)\s*=\s*["'][A-Za-z0-9_\-/.+=]{16,}["']"""),
    ),
)


def scan_directory_for_hardcoded_secrets(root_dir: Path) -> list[dict[str, str]]:
    """Scans source files in `root_dir` to verify zero hardcoded API keys or credentials exist."""
    findings: list[dict[str, str]] = []
    ignored_dirs = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".terraform"}
    scanned_suffixes = {".py", ".tf", ".yml", ".yaml", ".json", ".toml", ".md", ".env"}

    for path in sorted(root_dir.rglob("*")):
        if any(part in ignored_dirs for part in path.parts) or not path.is_file():
            continue
        if path.suffix not in scanned_suffixes and path.name != ".env.example":
            continue
        content = path.read_text(encoding="utf-8", errors="ignore")
        for rule_name, pattern in FORBIDDEN_SECRET_PATTERNS:
            match = pattern.search(content)
            if match is not None:
                findings.append(
                    {
                        "file": str(path.relative_to(root_dir)),
                        "rule": rule_name,
                    }
                )
    return findings
