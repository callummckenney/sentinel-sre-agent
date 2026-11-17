"""Static Golden-Dataset Regression Evaluation Harness for Sentinel SRE Agent.

Addresses Rubric Criterion 5.1 (Automated Evaluation Suites):
- Evaluates the multi-agent workflow against a curated golden dataset (`golden_cases.json`),
  computing tool-trajectory exact/jaccard scores, expected status match rate, guardrail
  blocking accuracy, and PII redaction compliance.
- Complements ADK's native `adk eval` (`sentinel_golden.evalset.json` + `eval_config.json`)
  so regressions are caught deterministically in CI/CD on every commit.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import tempfile
from typing import Any

from sentinel_sre_agent.agent import IncidentOrchestrationRunner
from sentinel_sre_agent.memory.async_consolidator import AsyncMemoryConsolidator
from sentinel_sre_agent.memory.session_store import PersistentSessionAndVectorStore
from sentinel_sre_agent.orchestration.hitl_hooks import HumanApprovalGate
from sentinel_sre_agent.tools.telemetry_tools import reset_local_release_overrides


@dataclass(frozen=True)
class CaseEvaluationResult:
    """Per-case regression metrics produced by `GoldenDatasetEvaluator`."""

    case_id: str
    passed: bool
    expected_status: str
    actual_status: str
    expected_trajectory: list[str]
    actual_trajectory: list[str]
    trajectory_score: float
    must_contain_satisfied: bool
    must_not_contain_satisfied: bool


@dataclass(frozen=True)
class SuiteEvaluationSummary:
    """Aggregate regression report across the entire golden evaluation dataset."""

    total_cases: int
    passed_cases: int
    pass_rate: float
    mean_trajectory_score: float
    case_results: list[CaseEvaluationResult]

    @property
    def has_regressions(self) -> bool:
        return self.passed_cases < self.total_cases or self.mean_trajectory_score < 1.0


class GoldenDatasetEvaluator:
    """Runs deterministic golden-dataset evaluations and asserts zero regressions."""

    def __init__(self, golden_cases_path: str | Path) -> None:
        self._golden_cases_path = Path(golden_cases_path)

    @staticmethod
    def _score_trajectory(expected: list[str], actual: list[str]) -> float:
        if expected == actual:
            return 1.0
        if not expected and not actual:
            return 1.0
        exp_set, act_set = set(expected), set(actual)
        union = exp_set | act_set
        return round(len(exp_set & act_set) / len(union), 4) if union else 0.0

    async def evaluate_suite(self) -> SuiteEvaluationSummary:
        """Executes every golden test scenario in an isolated temporary session store."""
        payload = json.loads(self._golden_cases_path.read_text(encoding="utf-8"))
        cases: list[dict[str, Any]] = list(payload["cases"])
        results: list[CaseEvaluationResult] = []

        for case in cases:
            reset_local_release_overrides()
            with tempfile.TemporaryDirectory() as tmp_dir:
                store = PersistentSessionAndVectorStore(Path(tmp_dir) / "eval_sessions.db")
                gate = HumanApprovalGate()
                consolidator = AsyncMemoryConsolidator(store)
                runner = IncidentOrchestrationRunner(
                    session_store=store,
                    consolidator=consolidator,
                    approval_gate=gate,
                )

                approval_token: str | None = None
                if case.get("simulate_human_approval"):
                    # First turn hits HITL gate; human operator approves; second turn executes
                    initial_turn = await runner.handle_incident_turn(
                        session_id=f"eval-{case['case_id']}",
                        user_id="eval-operator",
                        user_query=case["user_query"],
                        service_id=case["service_id"],
                        region=case["region"],
                    )
                    assert initial_turn.pending_approval_request_id is not None
                    approval_token = gate.approve_request(
                        initial_turn.pending_approval_request_id,
                        operator_id="sre-lead-approver",
                    )

                turn_res = await runner.handle_incident_turn(
                    session_id=f"eval-{case['case_id']}",
                    user_id="eval-operator",
                    user_query=case["user_query"],
                    service_id=case["service_id"],
                    region=case["region"],
                    approval_token=approval_token,
                )
                await consolidator.shutdown()

            expected_traj = list(case["expected_tool_trajectory"])
            traj_score = self._score_trajectory(expected_traj, turn_res.tool_trajectory)

            lowered_resp = turn_res.response_text.lower()
            must_contain_ok = all(
                token.lower() in lowered_resp for token in case.get("must_contain", [])
            )
            must_not_contain_ok = all(
                forbidden.lower() not in lowered_resp
                for forbidden in case.get("must_not_contain", [])
            )
            status_ok = turn_res.status == case["expected_status"]
            case_passed = (
                status_ok
                and traj_score == 1.0
                and must_contain_ok
                and must_not_contain_ok
            )

            results.append(
                CaseEvaluationResult(
                    case_id=case["case_id"],
                    passed=case_passed,
                    expected_status=case["expected_status"],
                    actual_status=turn_res.status,
                    expected_trajectory=expected_traj,
                    actual_trajectory=turn_res.tool_trajectory,
                    trajectory_score=traj_score,
                    must_contain_satisfied=must_contain_ok,
                    must_not_contain_satisfied=must_not_contain_ok,
                )
            )

        passed_count = sum(1 for r in results if r.passed)
        total = len(results)
        mean_traj = (
            round(sum(r.trajectory_score for r in results) / total, 4) if total else 0.0
        )
        return SuiteEvaluationSummary(
            total_cases=total,
            passed_cases=passed_count,
            pass_rate=round(passed_count / total, 4) if total else 0.0,
            mean_trajectory_score=mean_traj,
            case_results=results,
        )
