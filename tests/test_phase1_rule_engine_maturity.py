import json
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class Phase1RuleEngineMaturityTests(unittest.TestCase):
    def test_all_documented_rules_are_registry_backed(self):
        from agent_config_linter.rules import RULE_REGISTRY

        rules_doc = (ROOT / "docs" / "rules.md").read_text()
        readme = (ROOT / "README.md").read_text()
        documented = {
            (match.group("rule_id"), match.group("finding_id"), match.group("severity"))
            for match in re.finditer(
                r"\| (?P<rule_id>ACL-\d{3}) \| `(?P<finding_id>[^`]+)` \| (?P<severity>critical|high|medium|low) \|",
                rules_doc,
            )
        }

        self.assertEqual(len(documented), 10)
        self.assertEqual(set(RULE_REGISTRY), {finding_id for _rule_id, finding_id, _severity in documented})
        self.assertEqual(len({rule.rule_id for rule in RULE_REGISTRY.values()}), len(RULE_REGISTRY))

        for rule_id, finding_id, severity in documented:
            with self.subTest(finding_id=finding_id):
                rule = RULE_REGISTRY[finding_id]
                self.assertEqual(rule.rule_id, rule_id)
                self.assertEqual(rule.default_severity, severity)
                self.assertIn(f"| {rule_id} | `{finding_id}` | {severity} |", readme)
                self.assertTrue(rule.title)
                self.assertTrue(rule.evidence)
                self.assertTrue(rule.remediation)
                self.assertTrue(callable(rule.collect_evidence))
                self.assertIn(rule.confidence, {"high", "medium", "low"})

    def test_findings_include_additive_confidence_in_json_markdown_and_sarif(self):
        from agent_config_linter.cli import run
        from agent_config_linter.linter import lint_config

        report = lint_config({"tools": {"shell": True}, "model": "small-local-7b"})
        findings = {finding["id"]: finding for finding in report["findings"]}
        self.assertEqual(findings["shell_enabled"]["confidence"], "high")
        self.assertEqual(findings["weak_model_risk"]["confidence"], "medium")

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "agent.json"
            config_path.write_text(json.dumps({"tools": {"shell": True}, "model": "small-local-7b"}))
            markdown_exit, markdown_output = run([str(config_path), "--format", "markdown"])
            github_exit, github_output = run([str(config_path), "--format", "github-markdown"])
            sarif_exit, sarif_output = run([str(config_path), "--format", "sarif"])

        self.assertEqual(markdown_exit, 0)
        self.assertEqual(github_exit, 0)
        self.assertEqual(sarif_exit, 0)
        self.assertIn("| Rule | Severity | Confidence | Finding | Title |", markdown_output)
        self.assertIn("| ACL-001 | high | high | shell_enabled | Shell execution is enabled |", markdown_output)
        self.assertIn("| File | Rule | Severity | Confidence | Finding | Remediation |", github_output)
        sarif = json.loads(sarif_output)
        shell_result = next(result for result in sarif["runs"][0]["results"] if result["ruleId"] == "ACL-001")
        self.assertEqual(shell_result["properties"]["confidence"], "high")
        shell_rule = next(rule for rule in sarif["runs"][0]["tool"]["driver"]["rules"] if rule["id"] == "ACL-001")
        self.assertEqual(shell_rule["properties"]["confidence"], "high")

    def test_policy_min_confidence_filters_lower_confidence_findings(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            config_path = tmpdir / "agent.json"
            policy_path = tmpdir / "policy.json"
            config_path.write_text(json.dumps({"tools": {"shell": True}, "model": "small-local-7b"}))
            policy_path.write_text(json.dumps({"min_confidence": "high"}))

            exit_code, output = run([str(config_path), "--policy", str(policy_path), "--format", "json"])

        self.assertEqual(exit_code, 0)
        parsed = json.loads(output)
        report = parsed["files"][0]
        self.assertEqual({finding["id"] for finding in report["findings"]}, {"shell_enabled"})
        self.assertEqual({finding["id"] for finding in report["confidence_filtered_findings"]}, {"weak_model_risk"})
        self.assertEqual(report["confidence_filtered_summary"]["medium"], 1)

    def test_invalid_policy_min_confidence_reports_field_path(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            config_path = tmpdir / "agent.json"
            policy_path = tmpdir / "policy.json"
            config_path.write_text(json.dumps({"tools": {"shell": True}}))
            policy_path.write_text(json.dumps({"min_confidence": "certain"}))

            exit_code, output = run([str(config_path), "--policy", str(policy_path), "--format", "json"])

        self.assertEqual(exit_code, 2)
        parsed = json.loads(output)
        self.assertEqual(parsed["errors"][0]["field"], "min_confidence")

    def test_adapter_findings_preserve_normalized_and_source_evidence_paths(self):
        from agent_config_linter.linter import lint_config

        fixtures = {
            "mcp": (
                {"mcpServers": {"danger-shell": {"command": "npx", "args": ["agent-shell"], "env": {"TOKEN": "placeholder"}}}},
                "shell_enabled",
                "tools.shell",
                "mcpServers.danger-shell.command",
            ),
            "github_actions": (
                {"jobs": {"scan": {"steps": [{"name": "Run unattended shell agent", "run": "python agent.py --tool shell"}]}}},
                "shell_enabled",
                "tools.shell",
                "jobs.scan.steps[0].run",
            ),
            "hermes": (
                {"hermes": {"enabled_toolsets": ["terminal"]}},
                "shell_enabled",
                "enabled_toolsets[0]",
                "hermes.enabled_toolsets[0]",
            ),
            "openclaw": (
                {"openclaw": {"browser": {"enabled": True, "allowPrivateNetwork": True}}},
                "browser_private_network",
                "tools.browser",
                "openclaw.browser.allowPrivateNetwork",
            ),
            "openai": (
                {"tools": [{"type": "code_interpreter"}]},
                "shell_enabled",
                "tools.python",
                "tools[0].type",
            ),
        }

        for adapter, (config, finding_id, normalized_path, source_path) in fixtures.items():
            with self.subTest(adapter=adapter):
                report = lint_config(config)
                self.assertEqual(report["schema"]["adapter"], adapter)
                finding = next(finding for finding in report["findings"] if finding["id"] == finding_id)
                self.assertIn(normalized_path, finding["evidence_paths"])
                self.assertIn(source_path, finding["source_evidence_paths"])

    def test_sarif_prefers_adapter_source_evidence_line(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "mcp.json"
            config_text = json.dumps(
                {
                    "mcpServers": {
                        "safe": {"command": "read-only"},
                        "danger-shell": {"command": "npx", "args": ["agent-shell"]},
                    }
                },
                indent=2,
            )
            config_path.write_text(config_text)
            config_lines = config_text.splitlines()
            exit_code, output = run([str(config_path), "--format", "sarif"])

        self.assertEqual(exit_code, 0)
        sarif = json.loads(output)
        shell_result = next(result for result in sarif["runs"][0]["results"] if result["ruleId"] == "ACL-001")
        start_line = shell_result["locations"][0]["physicalLocation"]["region"]["startLine"]
        self.assertIn("command", config_lines[start_line - 1])
        self.assertIn("source_evidence_paths", shell_result["properties"])
        self.assertIn("mcpServers.danger-shell.command", shell_result["properties"]["source_evidence_paths"])

    def test_roadmap_phase1_and_docs_are_marked_shipped(self):
        roadmap = (ROOT / "docs" / "roadmap.md").read_text()
        rules = (ROOT / "docs" / "rules.md").read_text()
        registry_docs = (ROOT / "docs" / "rule-registry.md").read_text()
        readme = (ROOT / "README.md").read_text()

        self.assertIn("Phase 1 status: Shipped", roadmap)
        self.assertIn("confidence", rules.lower())
        self.assertIn("source_evidence_paths", registry_docs)
        self.assertIn("min_confidence", readme)


if __name__ == "__main__":
    unittest.main()
