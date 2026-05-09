import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class RoadmapCompletionTests(unittest.TestCase):
    def test_release_hardening_docs_and_smoke_script_exist(self):
        changelog = (ROOT / "CHANGELOG.md").read_text()
        security = ROOT / "SECURITY.md"
        smoke = ROOT / "scripts" / "install-smoke.py"
        release_workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()

        self.assertIn("regression fixture corpus", changelog)
        self.assertIn("roadmap", changelog.lower())
        self.assertTrue(security.exists())
        self.assertIn("vulnerability", security.read_text().lower())
        self.assertTrue(smoke.exists())
        smoke_text = smoke.read_text()
        self.assertIn("python -m build", smoke_text)
        self.assertIn("agent-config-lint", smoke_text)
        self.assertIn("id-token: write", release_workflow)
        self.assertIn("scripts/install-smoke.py", release_workflow)

    def test_github_markdown_and_summary_only_output_are_pr_friendly(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "agent.json"
            config_path.write_text(json.dumps({"tools": {"shell": True}, "model": "small-local-7b"}))

            exit_code, output = run([str(config_path), "--format", "github-markdown", "--summary-only"])

        self.assertEqual(exit_code, 0)
        self.assertIn("## agent-config-linter summary", output)
        self.assertIn("| File | Risk | Score | Critical | High | Medium | Low |", output)
        self.assertIn("agent.json", output)
        self.assertNotIn("| Rule | Severity | Finding | Title |", output)
        self.assertNotIn("No findings.", output)
        self.assertLess(len(output.splitlines()), 20)

    def test_pr_comment_example_does_not_require_write_permissions_by_default(self):
        workflow = ROOT / "examples" / "github-actions-pr-summary.yml"

        self.assertTrue(workflow.exists())
        text = workflow.read_text()
        self.assertIn("--format github-markdown --summary-only", text)
        self.assertIn("GITHUB_STEP_SUMMARY", text)
        self.assertIn("pull-requests: write", text)
        self.assertIn("ENABLE_PR_COMMENT", text)

    def test_rule_registry_contains_shell_rule_and_preserves_output(self):
        from agent_config_linter.linter import lint_config
        from agent_config_linter.rules import RULE_REGISTRY

        self.assertIn("shell_enabled", RULE_REGISTRY)
        rule = RULE_REGISTRY["shell_enabled"]
        self.assertEqual(rule.rule_id, "ACL-001")
        self.assertEqual(rule.default_severity, "high")
        self.assertTrue(callable(rule.collect_evidence))

        report = lint_config({"tools": {"shell": True}})
        shell_finding = next(finding for finding in report["findings"] if finding["id"] == "shell_enabled")
        self.assertEqual(shell_finding["rule_id"], "ACL-001")
        self.assertEqual(shell_finding["rule_name"], "shell-enabled")
        self.assertEqual(shell_finding["severity"], "high")
        self.assertEqual(shell_finding["title"], "Shell execution is enabled")
        self.assertEqual(shell_finding["evidence_paths"], ["tools.shell"])

    def test_rule_registry_docs_include_builtin_rule_checklist_without_plugins(self):
        docs = ROOT / "docs" / "rule-registry.md"

        self.assertTrue(docs.exists())
        text = docs.read_text().lower()
        self.assertIn("built-in rule checklist", text)
        self.assertIn("stable rule id", text)
        self.assertIn("third-party rules", text)
        self.assertIn("plugin loading is intentionally out of scope", text)

    def test_built_wheel_smoke_runs_version_in_clean_environment(self):
        smoke = ROOT / "scripts" / "install-smoke.py"
        if not smoke.exists():
            self.fail("scripts/install-smoke.py is required")

        completed = subprocess.run(
            [sys.executable, str(smoke)],
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        self.assertEqual(completed.returncode, 0, completed.stdout)
        self.assertIn("agent-config-linter", completed.stdout)


if __name__ == "__main__":
    unittest.main()
