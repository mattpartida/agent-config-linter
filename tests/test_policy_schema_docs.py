import json
import tempfile
import unittest
from pathlib import Path


class PolicySchemaDocsTests(unittest.TestCase):
    def test_invalid_policy_errors_include_exact_field_paths(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "agent.json"
            config_path.write_text(json.dumps({"tools": {"shell": True}}))

            invalid_type_policy = root / "invalid-type-policy.json"
            invalid_type_policy.write_text(json.dumps({"severity_overrides": []}))
            invalid_allowlist_policy = root / "invalid-allowlist-policy.json"
            invalid_allowlist_policy.write_text(json.dumps({"allowlists": {"paths": [{"path": "*.json", "rule_id": 123}]}}))
            invalid_severity_policy = root / "invalid-severity-policy.json"
            invalid_severity_policy.write_text(json.dumps({"severity_overrides": {"ACL-001": "urgent"}}))

            invalid_type_exit, invalid_type_output = run([str(config_path), "--policy", str(invalid_type_policy), "--format", "json"])
            invalid_allowlist_exit, invalid_allowlist_output = run([str(config_path), "--policy", str(invalid_allowlist_policy), "--format", "json"])
            invalid_severity_exit, invalid_severity_output = run([str(config_path), "--policy", str(invalid_severity_policy), "--format", "json"])

        self.assertEqual(invalid_type_exit, 2)
        self.assertIn("severity_overrides", json.loads(invalid_type_output)["errors"][0]["field"])
        self.assertEqual(invalid_allowlist_exit, 2)
        self.assertEqual(json.loads(invalid_allowlist_output)["errors"][0]["field"], "allowlists.paths[0].rule_id")
        self.assertEqual(invalid_severity_exit, 2)
        self.assertEqual(json.loads(invalid_severity_output)["errors"][0]["field"], "severity_overrides.ACL-001")

    def test_policy_schema_doc_has_minimal_staged_and_strict_examples(self):
        docs = Path(__file__).resolve().parents[1] / "docs" / "policy-schema.md"
        content = docs.read_text()

        self.assertIn("## Minimal policy", content)
        self.assertIn("## Staged adoption policy", content)
        self.assertIn("## Strict CI policy", content)
        self.assertIn("allowlists.paths[0].rule_id", content)
        self.assertIn("severity_overrides", content)
        self.assertIn("disabled_rules", content)


if __name__ == "__main__":
    unittest.main()
