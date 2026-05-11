import json
import tempfile
import unittest
from pathlib import Path

import yaml


class TrendSummaryTests(unittest.TestCase):
    def test_trend_summary_counts_rules_severities_adapters_baseline_states_and_owners(self):
        from agent_config_linter.cli import run

        repo_root = Path(__file__).resolve().parents[1]
        config_path = repo_root / "tests" / "fixtures" / "phase7" / "trend-risk.yaml"
        baseline_path = repo_root / "tests" / "fixtures" / "phase7" / "trend-baseline.json"

        exit_code, output = run(["--trend-summary", "--baseline", str(baseline_path), str(config_path)])

        payload = json.loads(output)
        self.assertEqual(exit_code, 0)
        trend = payload["trend_summary"]
        self.assertEqual(trend["schema_version"], "0.1")
        self.assertEqual(trend["total_files"], 1)
        self.assertEqual(trend["total_active_findings"], 2)
        self.assertEqual(trend["total_suppressed_findings"], 1)
        self.assertEqual(trend["counts_by_rule"]["ACL-001"], 1)
        self.assertEqual(trend["counts_by_rule"]["ACL-013"], 1)
        self.assertEqual(trend["counts_by_severity"], {"critical": 0, "high": 2, "low": 0, "medium": 0})
        self.assertEqual(trend["counts_by_confidence"], {"high": 2, "low": 0, "medium": 0})
        self.assertEqual(trend["counts_by_adapter"], {"generic": 2})
        self.assertEqual(trend["counts_by_path_prefix"], {"trend-risk.yaml": 2})
        self.assertEqual(trend["baseline_state"], {"active": 1, "expired": 0, "stale": 0, "suppressed": 1})
        self.assertEqual(trend["counts_by_owner"], {"security-team": {"active": 1, "expired": 0, "stale": 0, "suppressed": 1}})


class PolicyDriftTests(unittest.TestCase):
    def test_policy_drift_reports_unknown_missing_and_stale_references_and_can_fail(self):
        from agent_config_linter.cli import run

        repo_root = Path(__file__).resolve().parents[1]
        policy_path = repo_root / "tests" / "fixtures" / "phase7" / "drift-policy.json"
        config_path = repo_root / "tests" / "fixtures" / "phase7" / "trend-risk.yaml"

        exit_code, output = run(["--policy", str(policy_path), "--check-policy-drift", "--fail-on-policy-drift", str(config_path)])

        payload = json.loads(output)
        self.assertEqual(exit_code, 1)
        drift = payload["policy_drift"]
        self.assertTrue(drift["failed"])
        self.assertEqual(drift["current_policy_bundle_version"], "0.2.0")
        self.assertEqual(drift["policy_bundle_version"], "0.1.0")
        self.assertIn("policy_bundle_version", drift["stale_fields"])
        self.assertIn({"field": "severity_overrides.ACL-999", "rule": "ACL-999"}, drift["unknown_rules"])
        self.assertIn("ACL-014", drift["missing_rules"])

    def test_example_policy_has_metadata_and_no_policy_drift(self):
        from agent_config_linter.cli import run

        repo_root = Path(__file__).resolve().parents[1]
        policy_path = repo_root / "examples" / "agent-config-linter-policy.json"
        config_path = repo_root / "tests" / "fixtures" / "phase7" / "trend-risk.yaml"

        exit_code, output = run(["--policy", str(policy_path), "--check-policy-drift", "--fail-on-policy-drift", str(config_path)])

        payload = json.loads(output)
        self.assertEqual(exit_code, 0)
        self.assertFalse(payload["policy_drift"]["failed"])
        self.assertEqual(payload["policy_drift"]["missing_rules"], [])
        self.assertEqual(payload["policy_drift"]["unknown_rules"], [])
        self.assertEqual(payload["policy_drift"]["stale_fields"], [])

    def test_policy_drift_validates_new_policy_metadata_fields(self):
        from agent_config_linter.cli import run

        repo_root = Path(__file__).resolve().parents[1]
        config_path = repo_root / "tests" / "fixtures" / "phase7" / "trend-risk.yaml"
        invalid_policies = [
            ({"metadata": []}, "metadata"),
            ({"metadata": {"policy_bundle_version": 2}}, "metadata.policy_bundle_version"),
            ({"covered_rules": "ACL-001"}, "covered_rules"),
            ({"covered_rules": [{}]}, "covered_rules[0]"),
            ({"severity_overrides": {1: "high", "1": "high"}}, "severity_overrides.1"),
        ]

        for policy, field in invalid_policies:
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory() as tmpdir:
                    policy_path = Path(tmpdir) / "policy.json"
                    if field == "severity_overrides.1":
                        policy_path = Path(tmpdir) / "policy.yaml"
                        policy_path.write_text("severity_overrides:\n  1: high\n  '1': high\n")
                    else:
                        policy_path.write_text(json.dumps(policy))
                    exit_code, output = run(["--policy", str(policy_path), "--check-policy-drift", str(config_path)])
                payload = json.loads(output)
                self.assertEqual(exit_code, 2)
                self.assertEqual(payload["errors"][0]["field"], field)

    def test_fail_on_policy_drift_implies_check_policy_drift(self):
        from agent_config_linter.cli import run

        repo_root = Path(__file__).resolve().parents[1]
        policy_path = repo_root / "tests" / "fixtures" / "phase7" / "drift-policy.json"
        config_path = repo_root / "tests" / "fixtures" / "phase7" / "trend-risk.yaml"

        exit_code, output = run(["--policy", str(policy_path), "--fail-on-policy-drift", str(config_path)])

        payload = json.loads(output)
        self.assertEqual(exit_code, 1)
        self.assertTrue(payload["policy_drift"]["failed"])


class WorkflowGovernanceTests(unittest.TestCase):
    def test_project_workflows_have_no_unexpected_write_permissions(self):
        repo_root = Path(__file__).resolve().parents[1]
        workflow_paths = sorted((repo_root / ".github" / "workflows").glob("*.yml"))
        self.assertGreaterEqual(len(workflow_paths), 3)
        allowed_write_permissions = {
            "agent-config-linter-code-scanning.yml": {"security-events"},
            "release.yml": {"id-token"},
        }

        for workflow_path in workflow_paths:
            workflow = yaml.safe_load(workflow_path.read_text())
            for job_name, job in workflow.get("jobs", {}).items():
                permissions = job.get("permissions", {})
                self.assertNotEqual(permissions, "write-all", f"{workflow_path.name}:{job_name}")
                for permission, scope in permissions.items():
                    if scope == "write":
                        allowed = allowed_write_permissions.get(workflow_path.name, set())
                        self.assertIn(permission, allowed, f"{workflow_path.name}:{job_name}:{permission}")

    def test_code_scanning_workflow_documents_permissions_and_uploads_sarif(self):
        repo_root = Path(__file__).resolve().parents[1]
        workflow_path = repo_root / ".github" / "workflows" / "agent-config-linter-code-scanning.yml"
        text = workflow_path.read_text()
        workflow = yaml.safe_load(text)
        job = workflow["jobs"]["agent-config-linter"]

        self.assertIn("security-events: write", text)
        self.assertIn("Permission rationale", text)
        self.assertEqual(job["permissions"], {"contents": "read", "security-events": "write"})
        self.assertIn("agent-config-lint . --format sarif", text)
        self.assertIn("github/codeql-action/upload-sarif@v4", text)
        self.assertIn("sarif_file: agent-config-linter.sarif", text)


if __name__ == "__main__":
    unittest.main()
