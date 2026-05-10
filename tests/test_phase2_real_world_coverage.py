import json
import subprocess
import sys
import unittest
from pathlib import Path

import yaml

from agent_config_linter.linter import lint_config
from agent_config_linter.rules import RULE_REGISTRY

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "examples" / "config-shapes"


def load_config(path):
    if path.suffix == ".json":
        return json.loads(path.read_text())
    return yaml.safe_load(path.read_text())


class Phase2RealWorldCoverageTests(unittest.TestCase):
    def assert_fixture(self, fixture_name, adapter, expected_findings, forbidden_findings=()):
        report = lint_config(load_config(FIXTURE_DIR / fixture_name))
        finding_ids = {finding["id"] for finding in report["findings"]}

        self.assertEqual(report["schema"]["adapter"], adapter)
        self.assertTrue(set(expected_findings) <= finding_ids, f"missing {set(expected_findings) - finding_ids}")
        self.assertTrue(finding_ids.isdisjoint(forbidden_findings), f"unexpected {finding_ids & set(forbidden_findings)}")
        return report

    def test_cursor_and_windsurf_editor_adapter_fixtures(self):
        cursor_report = self.assert_fixture(
            "cursor-risky-agent-settings.json",
            "cursor",
            {
                "shell_enabled",
                "filesystem_broad_access",
                "filesystem_write_access",
                "approval_gate_missing",
                "unpinned_remote_tool_source",
                "unrestricted_network_egress",
                "secret_env_to_dangerous_tool",
            },
        )
        source_paths = {
            source_path
            for finding in cursor_report["findings"]
            for source_path in finding.get("source_evidence_paths", [])
        }
        self.assertIn("cursor.agent.mcpServers.ops.command", source_paths)

        self.assert_fixture(
            "cursor-safe-agent-settings.json",
            "cursor",
            expected_findings=set(),
            forbidden_findings={
                "shell_enabled",
                "filesystem_broad_access",
                "approval_gate_missing",
                "unpinned_remote_tool_source",
                "unrestricted_network_egress",
                "secret_env_to_dangerous_tool",
            },
        )

        self.assert_fixture(
            "windsurf-risky-agent-settings.yaml",
            "windsurf",
            {
                "shell_enabled",
                "unattended_dangerous_tools",
                "runtime_package_install",
                "unrestricted_network_egress",
                "secret_env_to_dangerous_tool",
            },
        )
        self.assert_fixture(
            "windsurf-safe-agent-settings.yaml",
            "windsurf",
            expected_findings=set(),
            forbidden_findings={"runtime_package_install", "unrestricted_network_egress", "secret_env_to_dangerous_tool"},
        )

    def test_framework_deployment_adapter_fixtures(self):
        self.assert_fixture(
            "langgraph-risky-deployment.yaml",
            "langgraph",
            {
                "shell_enabled",
                "unattended_dangerous_tools",
                "runtime_package_install",
                "unrestricted_network_egress",
                "secret_env_to_dangerous_tool",
                "prompt_injection_exfiltration_bridge",
            },
        )
        self.assert_fixture(
            "langgraph-safe-deployment.yaml",
            "langgraph",
            expected_findings=set(),
            forbidden_findings={"runtime_package_install", "unrestricted_network_egress", "secret_env_to_dangerous_tool"},
        )
        self.assert_fixture(
            "crewai-risky-deployment.yaml",
            "crewai",
            {
                "shell_enabled",
                "unattended_dangerous_tools",
                "unpinned_remote_tool_source",
                "unrestricted_network_egress",
                "secret_env_to_dangerous_tool",
            },
        )
        self.assert_fixture(
            "autogen-safe-deployment.yaml",
            "autogen",
            expected_findings=set(),
            forbidden_findings={"unpinned_remote_tool_source", "unrestricted_network_egress", "secret_env_to_dangerous_tool"},
        )

    def test_phase2_rule_registry_and_docs_cover_new_rules(self):
        new_rules = {
            "ACL-011": "unpinned_remote_tool_source",
            "ACL-012": "runtime_package_install",
            "ACL-013": "unrestricted_network_egress",
            "ACL-014": "secret_env_to_dangerous_tool",
        }
        registry_by_rule = {rule.rule_id: finding_id for finding_id, rule in RULE_REGISTRY.items()}
        rules_doc = (ROOT / "docs" / "rules.md").read_text()
        coverage_doc = (ROOT / "docs" / "rule-coverage.md").read_text()
        roadmap = (ROOT / "docs" / "roadmap.md").read_text()
        readme = (ROOT / "README.md").read_text()

        for rule_id, finding_id in new_rules.items():
            with self.subTest(rule_id=rule_id):
                self.assertEqual(registry_by_rule[rule_id], finding_id)
                self.assertIn(rule_id, rules_doc)
                self.assertIn(finding_id, rules_doc)
                self.assertIn(rule_id, coverage_doc)
                self.assertIn(finding_id.replace("_", "-"), coverage_doc)
                self.assertIn(rule_id, readme)
        self.assertIn("Phase 2 status: Shipped", roadmap)
        self.assertIn("config-only boundary", readme)

    def test_cli_smoke_includes_phase2_config_shape_fixtures(self):
        env = {**__import__("os").environ, "PYTHONPATH": str(ROOT / "src")}
        result = subprocess.run(
            [sys.executable, "-m", "agent_config_linter.cli", str(FIXTURE_DIR), "--format", "json", "--fail-on", "high"],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        payload = json.loads(result.stderr)
        adapters = {entry["schema"]["adapter"] for entry in payload["files"]}
        self.assertTrue({"cursor", "windsurf", "langgraph", "crewai", "autogen"} <= adapters)


if __name__ == "__main__":
    unittest.main()
