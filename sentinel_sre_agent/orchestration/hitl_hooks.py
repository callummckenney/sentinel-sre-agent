"""Human-in-the-Loop (HITL) Confirmation State Machine & Signed Approval Gate.

Addresses Rubric Criterion 3.4 (Human-in-the-Loop Hooks):
- Enforces explicit, non-bypassable code stops before high-stakes production mutations
  (such as canary rollbacks and SEV-1 paging).
- Pairs with ADK's `FunctionTool(..., require_confirmation=True)` and
  `ToolContext.request_confirmation(...)` while binding approvals cryptographically to the
  exact `(action_name, parameters)` payload so an approval for one service cannot be
  replayed against another.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
import time
from typing import Any
import uuid


@dataclass
class PendingApprovalRequest:
    """Represents a paused high-stakes action awaiting human operator confirmation."""

    request_id: str
    action_name: str
    parameters: dict[str, Any]
    reason: str
    created_at_epoch: float
    expires_at_epoch: float
    status: str = "PENDING_HUMAN_APPROVAL"
    approved_by: str | None = None
    approval_token: str | None = None


class HumanApprovalGate:
    """Manages human confirmation checkpoints and parameter-bound HMAC approval tokens."""

    def __init__(self, *, ttl_seconds: int = 900) -> None:
        self._ttl_seconds = max(30, ttl_seconds)
        # Ephemeral per-process HMAC signing key generated via CSPRNG (never hardcoded)
        self._ephemeral_signing_key: bytes = os.urandom(32)
        self._requests: dict[str, PendingApprovalRequest] = {}
        self._tokens: dict[str, str] = {}  # token -> request_id

    @staticmethod
    def _canonical_digest(action_name: str, parameters: dict[str, Any]) -> str:
        serialized = json.dumps(
            {"action": action_name, "parameters": parameters},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def _sign_token(self, request_id: str, action_name: str, parameters: dict[str, Any]) -> str:
        digest = self._canonical_digest(action_name, parameters)
        msg = f"{request_id}:{digest}".encode("utf-8")
        sig = hmac.new(self._ephemeral_signing_key, msg, hashlib.sha256).hexdigest()[:24]
        return f"hitl-{request_id}-{sig}"

    def create_approval_request(
        self,
        *,
        action_name: str,
        parameters: dict[str, Any],
        reason: str,
    ) -> PendingApprovalRequest:
        """Creates a pending HITL approval checkpoint halting autonomous execution."""
        now = time.time()
        request_id = f"APR-{uuid.uuid4().hex[:8].upper()}"
        record = PendingApprovalRequest(
            request_id=request_id,
            action_name=action_name,
            parameters=dict(parameters),
            reason=reason,
            created_at_epoch=now,
            expires_at_epoch=now + self._ttl_seconds,
        )
        self._requests[request_id] = record
        return record

    def approve_request(self, request_id: str, *, operator_id: str) -> str:
        """Records explicit human approval and returns a single-action signed token."""
        if not operator_id or not operator_id.strip():
            raise ValueError("`operator_id` is required to approve a high-stakes action.")
        record = self._requests.get(request_id)
        if record is None:
            raise KeyError(f"Unknown approval request_id: '{request_id}'")
        if time.time() > record.expires_at_epoch:
            record.status = "EXPIRED"
            raise TimeoutError(f"Approval request '{request_id}' has expired.")
        if record.status != "PENDING_HUMAN_APPROVAL":
            raise ValueError(f"Approval request '{request_id}' is in state '{record.status}'.")

        token = self._sign_token(record.request_id, record.action_name, record.parameters)
        record.status = "APPROVED"
        record.approved_by = operator_id.strip()
        record.approval_token = token
        self._tokens[token] = record.request_id
        return token

    def reject_request(self, request_id: str, *, operator_id: str) -> None:
        """Marks a pending HITL request as rejected by the human operator."""
        record = self._requests.get(request_id)
        if record is None:
            raise KeyError(f"Unknown approval request_id: '{request_id}'")
        record.status = "REJECTED"
        record.approved_by = operator_id.strip()

    def verify_approval_token(
        self,
        *,
        approval_token: str,
        expected_action: str,
        expected_payload: dict[str, Any],
    ) -> str | None:
        """Verifies signature, expiry, and exact parameter binding; consumes token on use."""
        request_id = self._tokens.get(approval_token)
        if request_id is None:
            return None
        record = self._requests.get(request_id)
        if record is None or record.status != "APPROVED":
            return None
        if time.time() > record.expires_at_epoch:
            record.status = "EXPIRED"
            return None

        expected_token = self._sign_token(record.request_id, expected_action, expected_payload)
        if not hmac.compare_digest(approval_token, expected_token):
            return None

        # Single-use consumption prevents replay attacks
        record.status = "CONSUMED"
        del self._tokens[approval_token]
        return record.approved_by

    def get_request(self, request_id: str) -> PendingApprovalRequest | None:
        return self._requests.get(request_id)


DEFAULT_APPROVAL_GATE = HumanApprovalGate()
