"""Security and secret management package for Sentinel SRE Agent."""

from sentinel_sre_agent.security.secret_manager import (
    SecretManagerResolver,
    SecretResolutionError,
    scan_directory_for_hardcoded_secrets,
)

__all__ = [
    "SecretManagerResolver",
    "SecretResolutionError",
    "scan_directory_for_hardcoded_secrets",
]
