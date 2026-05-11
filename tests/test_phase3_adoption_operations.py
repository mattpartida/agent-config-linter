import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


class Phase3AdoptionOperationsTests(unittest.TestCase):
    def test_baseline_owner_and_expiration_reporting_can_fail_only_expired(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "agent.json"
            config_path.write_text(json.dumps({"tools": {"shell": True}, "model": "small-local-7b"}))
            baseline_path = root / "baseline.json"
            baseline_path.write_text(
                json.dumps(
                    {
                        "suppressions": [
                            {
                                "path": str(config_path),
                                "rule_id": "ACL-001",
                                "owner": "platform-security",
                                "ticket": "SEC-101",
                                "expires_at": "2099-01-01",
                            },
                            {
                                "path": str(config_path),
                                "rule_id": "ACL-009",
                                "owner": "ml-platform",
                                "ticket": "ML-9",
                                "expires_at": "2000-01-01",
                            },
                            {
                                "path": str(config_path),
                                "rule_id": "ACL-999",
                                "owner": "platform-security",
                                "ticket": "SEC-999",
                                "expires_at": "2099-01-01",
                            },
                        ]
                    }
                )
            )

            stale_exit, stale_output = run(
                [str(config_path), "--baseline", str(baseline_path), "--fail-on-stale-baseline", "--format", "json"]
            )
            expired_exit, expired_output = run(
                [str(config_path), "--baseline", str(baseline_path), "--fail-on-expired-baseline", "--format", "json"]
            )

        stale_parsed = json.loads(stale_output)
        expired_parsed = json.loads(expired_output)

        self.assertEqual(stale_exit, 1)
        self.assertEqual(expired_exit, 1)
        self.assertEqual(stale_parsed["baseline"]["expired_count"], 1)
        self.assertEqual(stale_parsed["baseline"]["stale_count"], 1)
        self.assertEqual(stale_parsed["baseline"]["stale_suppressions"][0]["rule_id"], "ACL-999")
        self.assertEqual(stale_parsed["baseline"]["expired_suppressions"][0]["rule_id"], "ACL-009")
        self.assertEqual(
            stale_parsed["baseline"]["owner_summary"]["platform-security"],
            {"active": 1, "expired": 0, "stale": 1, "total": 2},
        )
        self.assertEqual(
            stale_parsed["baseline"]["owner_summary"]["ml-platform"],
            {"active": 0, "expired": 1, "stale": 0, "total": 1},
        )
        self.assertEqual(expired_parsed["baseline"]["expired_suppressions"][0]["expires_at"], "2000-01-01")

    def test_fail_on_expired_baseline_does_not_fail_merely_stale_baseline(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "agent.json"
            config_path.write_text(json.dumps({"tools": {"shell": True}}))
            baseline_path = root / "baseline.json"
            baseline_path.write_text(
                json.dumps(
                    {
                        "suppressions": [
                            {"path": str(config_path), "rule_id": "ACL-001", "owner": "sec", "ticket": "SEC-1"},
                            {"path": str(config_path), "rule_id": "ACL-999", "owner": "sec", "ticket": "SEC-2"},
                        ]
                    }
                )
            )

            exit_code, output = run([str(config_path), "--baseline", str(baseline_path), "--fail-on-expired-baseline", "--format", "json"])

        parsed = json.loads(output)
        self.assertEqual(exit_code, 0)
        self.assertEqual(parsed["baseline"]["expired_count"], 0)
        self.assertEqual(parsed["baseline"]["stale_count"], 1)

    def test_example_policy_bundles_validate_and_strict_bundle_gates_high_findings(self):
        from agent_config_linter.cli import run

        policy_dir = ROOT / "examples" / "policies"
        expected = {"local-dev.yaml", "staged-ci.yaml", "strict-ci.yaml"}
        self.assertEqual({path.name for path in policy_dir.glob("*.yaml")}, expected)

        for policy_name in expected:
            policy_path = policy_dir / policy_name
            with self.subTest(policy=policy_name):
                policy = yaml.safe_load(policy_path.read_text())
                self.assertIn("description", policy)
                with tempfile.TemporaryDirectory() as tmpdir:
                    config_path = Path(tmpdir) / "agent.json"
                    config_path.write_text(json.dumps({"tools": {"shell": True}, "model": "small-local-7b"}))
                    exit_code, output = run([str(config_path), "--policy", str(policy_path), "--format", "json"])
                self.assertEqual(exit_code, 0, output)

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "agent.json"
            config_path.write_text(json.dumps({"tools": {"shell": True}}))
            exit_code, output = run(
                [str(config_path), "--policy", str(policy_dir / "strict-ci.yaml"), "--fail-on", "high", "--format", "json"]
            )

        self.assertEqual(exit_code, 1)
        self.assertEqual(json.loads(output)["exit_policy"], {"fail_on": "high", "failed": True})

    def test_github_action_examples_have_least_privilege_permissions_and_current_actions(self):
        workflow_dir = ROOT / "examples" / "github-actions"
        expected = {
            "code-scanning.yml",
            "pr-summary.yml",
            "staged-enforcement.yml",
            "baseline-cleanup.yml",
            "trend-summary-artifact.yml",
        }
        self.assertEqual({path.name for path in workflow_dir.glob("*.yml")}, expected)

        for workflow_path in workflow_dir.glob("*.yml"):
            with self.subTest(workflow=workflow_path.name):
                text = workflow_path.read_text()
                parsed = yaml.safe_load(text)
                permissions = parsed.get("permissions", {})
                self.assertNotIn("write-all", text)
                self.assertNotIn("upload-sarif@v3", text)
                self.assertIn("contents", permissions)
                self.assertEqual(permissions["contents"], "read")

        code_scanning = (workflow_dir / "code-scanning.yml").read_text()
        self.assertIn("security-events: write", code_scanning)
        self.assertIn("agent-config-lint . --format sarif > agent-config-linter.sarif", code_scanning)
        self.assertIn("github/codeql-action/upload-sarif@v4", code_scanning)
        self.assertIn("sarif_file: agent-config-linter.sarif", code_scanning)

        pr_summary = (workflow_dir / "pr-summary.yml").read_text()
        self.assertIn("--format github-markdown --summary-only", pr_summary)
        self.assertIn("GITHUB_STEP_SUMMARY", pr_summary)
        self.assertIn("pull-requests: write", pr_summary)
        self.assertIn("ENABLE_PR_COMMENT", pr_summary)

        staged = (workflow_dir / "staged-enforcement.yml").read_text()
        self.assertIn("--policy examples/policies/staged-ci.yaml", staged)
        self.assertIn("--min-severity medium --fail-on high", staged)

        cleanup = (workflow_dir / "baseline-cleanup.yml").read_text()
        self.assertIn("--baseline agent-config-linter-baseline.json", cleanup)
        self.assertIn("--fail-on-stale-baseline", cleanup)
        self.assertIn("--fail-on-expired-baseline", cleanup)

    def test_phase3_docs_are_marked_shipped_and_review_commands_are_copy_pasteable(self):
        roadmap = (ROOT / "docs" / "roadmap.md").read_text()
        readme = (ROOT / "README.md").read_text()
        baseline_docs = (ROOT / "docs" / "baseline-review.md").read_text()
        policy_docs = (ROOT / "docs" / "policy-schema.md").read_text()

        self.assertIn("Phase 3 status: Shipped", roadmap)
        self.assertIn("examples/policies/strict-ci.yaml", readme)
        self.assertIn("examples/github-actions/code-scanning.yml", readme)
        self.assertIn("--fail-on-expired-baseline", readme)
        self.assertIn("agent-config-lint configs/ --baseline agent-config-linter-baseline.json --fail-on-expired-baseline --format json", baseline_docs)
        self.assertIn("Owner review", baseline_docs)
        self.assertIn("examples/policies/local-dev.yaml", policy_docs)

    def test_example_workflows_cli_smoke_commands_have_valid_syntax(self):
        # Keep example commands runnable as local smoke checks without invoking GitHub-only upload actions.
        completed = subprocess.run(
            [sys.executable, "-m", "agent_config_linter.cli", "examples/high-risk-agent.json", "--policy", "examples/policies/staged-ci.yaml", "--min-severity", "medium", "--format", "json"],
            cwd=ROOT,
            env={**dict(), "PYTHONPATH": str(ROOT / "src")},
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout)


if __name__ == "__main__":
    unittest.main()
