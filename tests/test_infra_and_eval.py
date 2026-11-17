"""Unit & Regression tests for Category 5: Infrastructure & CI/CD (15 pts).

Verifies:
- 5.1 Automated Evaluation Suites (GoldenDatasetEvaluator passes 100% of golden scenarios
  and ADK `sentinel_golden.evalset.json` conforms to schema)
- 5.2 Infrastructure as Code (Terraform IaC resources, variables, IAM least privilege, CI)
- 5.3 Secure Secret Management (SecretManagerResolver caching/rotation + zero hardcoded keys)
"""

from __future__ import annotations

import json
from pathlib import Path
import unittest

from sentinel_sre_agent.evaluation import GoldenDatasetEvaluator
from sentinel_sre_agent.security import (
    SecretManagerResolver,
    SecretResolutionError,
    scan_directory_for_hardcoded_secrets,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


class TestInfraSecretsAndGoldenEvaluation(unittest.IsolatedAsyncioTestCase):
    async def test_golden_dataset_regression_suite_passes_all_cases(self) -> None:
        golden_path = REPO_ROOT / "tests" / "eval" / "golden_cases.json"
        evaluator = GoldenDatasetEvaluator(golden_path)
        summary = await evaluator.evaluate_suite()

        self.assertEqual(summary.total_cases, 5)
        self.assertFalse(
            summary.has_regressions,
            f"Golden dataset regression detected: {summary.case_results}",
        )
        self.assertEqual(summary.pass_rate, 1.0)
        self.assertEqual(summary.mean_trajectory_score, 1.0)

    def test_adk_evalset_json_structure_is_valid(self) -> None:
        evalset_file = REPO_ROOT / "tests" / "eval" / "sentinel_golden.evalset.json"
        payload = json.loads(evalset_file.read_text(encoding="utf-8"))
        self.assertIn("evals", payload)
        self.assertGreaterEqual(len(payload["evals"]), 2)
        for item in payload["evals"]:
            self.assertIn("eval_id", item)
            self.assertIn("conversation", item)

    def test_terraform_iac_and_ci_workflow_completeness(self) -> None:
        tf_dir = REPO_ROOT / "terraform"
        for expected_tf in ("versions.tf", "variables.tf", "main.tf", "iam.tf", "outputs.tf"):
            self.assertTrue((tf_dir / expected_tf).is_file(), f"Missing {expected_tf}")

        main_tf = (tf_dir / "main.tf").read_text(encoding="utf-8")
        self.assertIn("google_discovery_engine_data_store", main_tf)
        self.assertIn("google_sql_database_instance", main_tf)
        self.assertIn("google_secret_manager_secret", main_tf)
        self.assertIn("google_data_loss_prevention_deidentify_template", main_tf)

        iam_tf = (tf_dir / "iam.tf").read_text(encoding="utf-8")
        self.assertIn("roles/secretmanager.secretAccessor", iam_tf)
        self.assertNotIn("roles/owner", iam_tf)
        self.assertNotIn("roles/editor", iam_tf)

        ci_yml = REPO_ROOT / ".github" / "workflows" / "agentops-ci.yml"
        self.assertTrue(ci_yml.is_file())

    def test_secret_manager_resolver_and_zero_hardcoded_secrets_in_repo(self) -> None:
        calls = 0

        def fake_provider(secret_id: str, version: str) -> str:
            nonlocal calls
            calls += 1
            return f"resolved-{secret_id}-{version}-{calls}"

        resolver = SecretManagerResolver(
            "sentinel-prod-proj",
            ttl_seconds=120,
            ephemeral_provider=fake_provider,
        )
        self.assertEqual(
            resolver.build_secret_version_path("sentinel-session-db-url"),
            "projects/sentinel-prod-proj/secrets/sentinel-session-db-url/versions/latest",
        )
        first = resolver.get_secret("sentinel-session-db-url")
        second = resolver.get_secret("sentinel-session-db-url")
        self.assertEqual(first, second)
        self.assertEqual(calls, 1, "TTL cache should avoid duplicate Secret Manager RPCs")

        resolver.invalidate_secret("sentinel-session-db-url")
        rotated = resolver.get_secret("sentinel-session-db-url")
        self.assertNotEqual(first, rotated)

        empty_resolver = SecretManagerResolver(
            "sentinel-prod-proj",
            ephemeral_provider=lambda _s, _v: "",
        )
        with self.assertRaises(SecretResolutionError):
            empty_resolver.get_secret("empty-secret")

        findings = scan_directory_for_hardcoded_secrets(REPO_ROOT)
        self.assertEqual(findings, [], f"Hardcoded secret violation(s) found: {findings}")


if __name__ == "__main__":
    unittest.main()
