# Optional 3-Minute Video Walkthrough Script (Sentinel SRE Agent)

Use this concise script if you choose to record the optional public YouTube walkthrough video for the submission portal.

## 0:00 – 0:35 | Problem & Solution
- **Problem**: During production outages, SREs lose critical time manually correlating Cloud Monitoring golden signals, hunting for approved runbooks, scrubbing customer PII from logs, and safely gating production rollbacks.
- **Solution**: **Sentinel SRE** is an Enterprise Multi-Agent System built with the **Google Agent Development Kit (ADK)** and **Vertex AI Agent Engine** that automates concurrent triage and grounds every mitigation in peer-reviewed runbooks while enforcing cryptographic Human-in-the-Loop stops before any production mutation.

## 0:35 – 1:35 | Architecture & AgentOps Highlights
Show `sentinel_sre_agent/agent.py` and `README.md`:
1. **Multi-Agent Patterns & Model Routing**: `sentinel_incident_coordinator` fans out concurrently via an ADK `ParallelAgent` (`telemetry_analyst_agent` + `runbook_researcher_agent` on `gemini-2.5-flash` + Vertex AI Search), then hands off to a `SequentialAgent` (`root_cause_planner_agent` and `remediation_executor_agent` on `gemini-2.5-pro`, followed by `post_action_slo_verifier_agent` on `gemini-2.5-flash`).
2. **Context, Persistent Memory & Async Consolidation**: `EventsCompactionConfig` + Vertex `ContextCacheConfig` + `TokenBudgetHistoryCompactor` manage context bloat, while `AsyncMemoryConsolidator` writes PII-scrubbed vector memories in a background `asyncio.Queue` without blocking UI turns.
3. **Safety, HITL & Guardrails**: `SentinelSecurityAndEvalPlugin` screens prompts via Google Cloud Model Armor, logs paired `AGENT_ACTION_INTENT` / `AGENT_ACTION_OUTCOME` events with OpenTelemetry spans, enforces `HumanApprovalGate` + `require_confirmation=True` on rollbacks, and runs `SelfEvaluationGuardrail` before output.

## 1:35 – 2:30 | Live Terminal Demo & Golden Evaluation Suite
Run in terminal:
```bash
# 1. Run all unit, security, observability & golden-dataset regression tests
python3 -m unittest discover -s tests -p "test_*.py" -v

# 2. Launch interactive ADK UI (when in ADK virtualenv)
adk web .
```
Walk through `golden_01_canary_hitl_pause` (pausing `checkout-api` rollback from `v2.5.0-rc1` -> `v2.4.2` at the HITL gate) and `golden_02_approved_rollback_and_slo_verification` (human operator approves, rollback executes, and `verify_post_remediation_slo_burn_rate` confirms 1h SLO burn drops to `0.35x HEALTHY`).

## 2:30 – 3:00 | Terraform IaC & Secret Manager Hygiene
Briefly show `terraform/main.tf`, `terraform/iam.tf`, and `sentinel_sre_agent/security/secret_manager.py` demonstrating declarative provisioning of Vertex AI Search, Cloud SQL, Cloud DLP, and Secret Manager with zero hardcoded credentials.
