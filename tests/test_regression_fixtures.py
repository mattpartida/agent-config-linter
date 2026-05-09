import unittest
from pathlib import Path

import yaml

from agent_config_linter.linter import lint_config

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "regression"

RISKY_FIXTURES = {
    "risky-prompt-injection-exfiltration.yaml": {
        "prompt_injection_exfiltration_bridge",
        "filesystem_write_access",
    },
    "risky-unattended-tool-use.yaml": {
        "unattended_dangerous_tools",
        "shell_enabled",
    },
    "risky-private-network-browser.yaml": {
        "browser_private_network",
    },
    "risky-weak-approval-gates.yaml": {
        "approval_gate_missing",
        "shell_enabled",
    },
    "risky-privileged-infra-control.yaml": {
        "privileged_infra_control",
    },
    "risky-weak-model.yaml": {
        "weak_model_risk",
    },
}

SAFE_FIXTURES = {
    "safe-approval-gated-shell.yaml": {"approval_gate_missing", "unattended_dangerous_tools"},
    "safe-readonly-project-files.yaml": {"filesystem_broad_access", "filesystem_write_access"},
    "safe-project-scoped-write-files.yaml": {"filesystem_broad_access"},
    "safe-browser-public-only.yaml": {"browser_private_network"},
    "safe-privileged-infra-readonly.yaml": {"privileged_infra_control"},
    "safe-strong-model.yaml": {"weak_model_risk"},
}


class RegressionFixtureTests(unittest.TestCase):
    def load_fixture(self, name):
        return yaml.safe_load((FIXTURE_DIR / name).read_text())

    def test_risky_regression_fixtures_trigger_expected_rules(self):
        for fixture_name, expected_rule_ids in RISKY_FIXTURES.items():
            with self.subTest(fixture=fixture_name):
                report = lint_config(self.load_fixture(fixture_name))
                finding_ids = {finding["id"] for finding in report["findings"]}

                self.assertTrue(expected_rule_ids <= finding_ids)
                if "weak_model_risk" in expected_rule_ids:
                    self.assertIn(report["risk_level"], {"medium", "high", "critical"})
                else:
                    self.assertIn(report["risk_level"], {"high", "critical"})

    def test_safe_regression_fixtures_avoid_known_false_positive_rules(self):
        for fixture_name, forbidden_rule_ids in SAFE_FIXTURES.items():
            with self.subTest(fixture=fixture_name):
                report = lint_config(self.load_fixture(fixture_name))
                finding_ids = {finding["id"] for finding in report["findings"]}

                self.assertTrue(finding_ids.isdisjoint(forbidden_rule_ids))

    def test_rule_coverage_doc_references_each_regression_fixture(self):
        coverage_doc = (Path(__file__).resolve().parents[1] / "docs" / "rule-coverage.md").read_text()

        for fixture_path in sorted(FIXTURE_DIR.glob("*.yaml")):
            with self.subTest(fixture=fixture_path.name):
                self.assertIn(f"tests/fixtures/regression/{fixture_path.name}", coverage_doc)

    def test_rule_coverage_doc_has_no_dedicated_fixture_gaps(self):
        coverage_doc = (Path(__file__).resolve().parents[1] / "docs" / "rule-coverage.md").read_text()

        self.assertNotIn("add a dedicated fixture when this rule changes", coverage_doc)
        self.assertNotIn("No dedicated negative fixture yet", coverage_doc)


if __name__ == "__main__":
    unittest.main()
