import json
import unittest
from pathlib import Path

import yaml


class RulePackManifestTests(unittest.TestCase):
    def test_safe_rule_pack_manifest_validates_and_round_trips_metadata(self):
        from agent_config_linter.rule_packs import load_rule_pack_manifest

        repo_root = Path(__file__).resolve().parents[1]
        manifest = load_rule_pack_manifest(repo_root / "examples" / "rule-packs" / "metadata-only-rule-pack.yaml")

        self.assertEqual(manifest.to_dict()["schema_version"], "rule-pack/v0")
        self.assertEqual(manifest.to_dict()["name"], "metadata-only-example")
        self.assertEqual(manifest.to_dict()["rules"][0]["id"], "EXAMPLE-001")
        self.assertNotIn("command", json.dumps(manifest.to_dict()).lower())

    def test_risky_rule_pack_manifest_rejects_executable_fields(self):
        from agent_config_linter.rule_packs import RulePackManifestError, load_rule_pack_manifest

        repo_root = Path(__file__).resolve().parents[1]
        risky_manifest = repo_root / "tests" / "fixtures" / "rule-packs" / "risky-executable-rule-pack.yaml"

        with self.assertRaisesRegex(RulePackManifestError, "executable field.*rules\[0\]\.command"):
            load_rule_pack_manifest(risky_manifest)

    def test_cli_validates_rule_pack_manifest_without_linting_configs(self):
        from agent_config_linter.cli import run

        repo_root = Path(__file__).resolve().parents[1]
        manifest_path = repo_root / "examples" / "rule-packs" / "metadata-only-rule-pack.yaml"

        exit_code, output = run(["--validate-rule-pack", str(manifest_path)])

        payload = json.loads(output)
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["schema_version"], "0.1")
        self.assertEqual(payload["rule_pack"]["name"], "metadata-only-example")
        self.assertEqual(payload["rule_pack"]["rules"][0]["id"], "EXAMPLE-001")
        self.assertNotIn("files", payload)


class DeclarativeRuleSpecTests(unittest.TestCase):
    def test_simple_rules_have_non_executable_declarative_match_specs(self):
        from agent_config_linter.rules import RULE_REGISTRY

        migrated_rules = ["shell_enabled", "weak_model_risk"]
        for rule_id in migrated_rules:
            with self.subTest(rule_id=rule_id):
                spec = RULE_REGISTRY[rule_id].match_spec
                self.assertIsNotNone(spec)
                self.assertIsInstance(spec, dict)
                self.assertIn("helper", spec)
                serialized = json.dumps(spec, sort_keys=True)
                for forbidden in ("command", "entry_point", "module", "script", "hook", "import", "eval", "exec"):
                    self.assertNotIn(forbidden, serialized)
                self.assertFalse(any(callable(value) for value in spec.values()))


class PrecisionBoundaryFixtureTests(unittest.TestCase):
    def test_precision_boundary_fixtures_do_not_emit_guarded_findings(self):
        from agent_config_linter.linter import lint_config

        repo_root = Path(__file__).resolve().parents[1]
        fixture_dir = repo_root / "tests" / "fixtures" / "precision-boundaries"
        expected_absent = {
            "safe-disabled-shell.yaml": {"shell_enabled"},
            "safe-readonly-domain-egress.yaml": {
                "filesystem_broad_access",
                "filesystem_write_access",
                "unrestricted_network_egress",
            },
            "safe-public-browser-no-private.yaml": {
                "browser_private_network",
                "lethal_trifecta",
                "prompt_injection_exfiltration_bridge",
            },
            "safe-review-only-autonomy.yaml": {"unattended_dangerous_tools", "approval_gate_missing"},
            "safe-infra-readonly-no-secrets.yaml": {"privileged_infra_control"},
            "safe-pinned-remote-tools.yaml": {"unpinned_remote_tool_source", "runtime_package_install"},
            "safe-secret-names-no-dangerous-tools.yaml": {"secret_env_to_dangerous_tool"},
        }

        for fixture_name, guarded_findings in expected_absent.items():
            with self.subTest(fixture=fixture_name):
                config = yaml.safe_load((fixture_dir / fixture_name).read_text())
                report = lint_config(config)
                finding_ids = {finding["id"] for finding in report["findings"]}
                self.assertTrue((fixture_dir / fixture_name).exists())
                self.assertTrue(guarded_findings.isdisjoint(finding_ids), finding_ids)


if __name__ == "__main__":
    unittest.main()
