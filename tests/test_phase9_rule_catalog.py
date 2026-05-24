import json
import unittest
from pathlib import Path

from agent_config_linter.cli import run
from agent_config_linter.rules import RULE_REGISTRY


class Phase9RuleCatalogTests(unittest.TestCase):
    def test_cli_lists_rules_as_stable_json_catalog(self):
        exit_code, output = run(["--list-rules", "--format", "json"])

        self.assertEqual(exit_code, 0)
        parsed = json.loads(output)
        self.assertEqual(parsed["schema_version"], "0.1")
        self.assertEqual(parsed["rule_catalog"]["count"], len(RULE_REGISTRY))
        rules = parsed["rule_catalog"]["rules"]
        self.assertEqual([rule["rule_id"] for rule in rules], sorted(rule.rule_id for rule in RULE_REGISTRY.values()))
        first = rules[0]
        self.assertEqual(
            set(first),
            {
                "rule_id",
                "finding_id",
                "rule_name",
                "title",
                "default_severity",
                "confidence",
                "evidence",
                "remediation",
                "docs",
                "match_type",
            },
        )
        shell = next(rule for rule in rules if rule["rule_id"] == "ACL-001")
        self.assertEqual(shell["finding_id"], "shell_enabled")
        self.assertEqual(shell["docs"], "docs/rules.md#acl-001")
        self.assertIn("### ACL-001 shell-enabled", Path("docs/rules.md").read_text())
        self.assertEqual(shell["match_type"], "declarative")

    def test_cli_lists_rules_as_markdown_table_without_requiring_paths(self):
        exit_code, output = run(["--list-rules", "--format", "markdown"])

        self.assertEqual(exit_code, 0)
        self.assertIn("# Agent Config Linter Rule Catalog", output)
        self.assertIn("| Rule ID | Finding ID | Severity | Confidence | Match | Title |", output)
        self.assertIn("| ACL-001 | `shell_enabled` | high | high | declarative | Shell execution is enabled |", output)

    def test_rule_catalog_format_is_limited_to_json_and_markdown(self):
        exit_code, output = run(["--list-rules", "--format", "sarif"])

        self.assertEqual(exit_code, 2)
        parsed = json.loads(output)
        self.assertIn("--list-rules supports only json and markdown", parsed["errors"][0]["message"])


if __name__ == "__main__":
    unittest.main()
