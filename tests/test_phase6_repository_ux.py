import json
import tempfile
import unittest
from pathlib import Path


class RepositoryScanTests(unittest.TestCase):
    def test_repo_scan_reports_discovery_ignored_paths_parser_failures_and_adapters(self):
        from agent_config_linter.cli import run

        repo_root = Path(__file__).resolve().parents[1]
        fixture_root = repo_root / "tests" / "fixtures" / "repo-scan"

        exit_code, output = run(["--repo-scan", str(fixture_root)])

        payload = json.loads(output)
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["schema_version"], "0.1")
        self.assertEqual(payload["errors"], [])
        self.assertIn("scan", payload)
        self.assertIn(".github/workflows/risky-agent.yml", payload["scan"]["discovered_files"])
        self.assertIn(".cursor/safe-agent.yaml", payload["scan"]["discovered_files"])
        self.assertIn("vendor/ignored-agent.yaml", payload["scan"]["ignored_paths"])
        self.assertEqual(payload["scan"]["parser_failures"][0]["path"], "deploy/malformed-agent.yaml")
        adapters = {report["path"]: report["schema"]["adapter"] for report in payload["files"]}
        self.assertEqual(adapters[".github/workflows/risky-agent.yml"], "github_actions")
        self.assertEqual(adapters[".cursor/safe-agent.yaml"], "cursor")

    def test_repo_scan_does_not_follow_symlinked_configs_outside_repo_root(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            repo_root = temp_root / "repo"
            repo_root.mkdir()
            outside_config = temp_root / "outside.yaml"
            outside_config.write_text("tools:\n  shell:\n    enabled: true\n")
            symlink = repo_root / "linked-outside.yaml"
            try:
                symlink.symlink_to(outside_config)
            except OSError as exc:
                self.skipTest(f"symlinks unavailable on this platform: {exc}")

            exit_code, output = run(["--repo-scan", str(repo_root)])

        payload = json.loads(output)
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["files"], [])
        self.assertNotIn("linked-outside.yaml", payload["scan"]["discovered_files"])
        self.assertIn("linked-outside.yaml", payload["scan"]["ignored_paths"])


class ExplainOutputTests(unittest.TestCase):
    def test_explain_outputs_one_deterministic_finding_with_docs_and_suppression_guidance(self):
        from agent_config_linter.cli import run

        repo_root = Path(__file__).resolve().parents[1]
        config_path = repo_root / "tests" / "fixtures" / "regression" / "risky-weak-approval-gates.yaml"

        exit_code, output = run(["--explain", "ACL-001", str(config_path)])

        payload = json.loads(output)
        self.assertEqual(exit_code, 0)
        self.assertEqual(len(payload["explanations"]), 1)
        explanation = payload["explanations"][0]
        self.assertEqual(explanation["rule_id"], "ACL-001")
        self.assertEqual(explanation["finding_id"], "shell_enabled")
        self.assertIn("docs/rules.md#acl-001", explanation["docs"])
        self.assertIn("baseline", explanation["suppression_guidance"])
        self.assertIn("evidence_paths", explanation)
        self.assertIn("source_evidence_paths", explanation)
        self.assertEqual(explanation["confidence"], "high")


class SuggestionOutputTests(unittest.TestCase):
    def test_suggestions_are_review_only_and_cover_common_rule_families(self):
        from agent_config_linter.cli import run

        repo_root = Path(__file__).resolve().parents[1]
        fixture_root = repo_root / "tests" / "fixtures" / "suggestions" / "risky-suggestions.yaml"

        exit_code, output = run(["--suggestions", str(fixture_root)])

        payload = json.loads(output)
        self.assertEqual(exit_code, 0)
        suggestions = [
            suggestion
            for report in payload["files"]
            for finding in report["findings"]
            for suggestion in finding.get("suggestions", [])
        ]
        self.assertGreaterEqual(len(suggestions), 3)
        suggestion_ids = {suggestion["id"] for suggestion in suggestions}
        self.assertIn("require-approval-gates", suggestion_ids)
        self.assertIn("narrow-filesystem-roots", suggestion_ids)
        self.assertIn("pin-remote-tool-source", suggestion_ids)
        for suggestion in suggestions:
            self.assertTrue(suggestion["review_required"])
            self.assertFalse(suggestion["applied"])
            self.assertIn("patch", suggestion)

    def test_markdown_labels_suggestions_as_review_required(self):
        from agent_config_linter.cli import run

        repo_root = Path(__file__).resolve().parents[1]
        fixture_root = repo_root / "tests" / "fixtures" / "suggestions" / "risky-suggestions.yaml"

        exit_code, output = run(["--suggestions", "--format", "markdown", str(fixture_root)])

        self.assertEqual(exit_code, 0)
        self.assertIn("Review-required remediation suggestions", output)
        self.assertIn("not applied automatically", output)


if __name__ == "__main__":
    unittest.main()
