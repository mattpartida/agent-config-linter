import json
import tempfile
import unittest
from pathlib import Path

from agent_config_linter.linter import lint_config


class LinterTests(unittest.TestCase):
    def test_detects_lethal_trifecta_and_high_risk_tools(self):
        config = {
            "inputs": {"web": True, "discord": {"enabled": True}},
            "tools": {
                "shell": {"enabled": True},
                "filesystem": {"enabled": True, "roots": ["/"]},
                "browser": {"enabled": True, "private_network": True},
                "email": {"enabled": True},
            },
            "memory": {"enabled": True, "write": True},
            "approvals": {"send_email": False, "shell": False},
            "model": "small-local-7b",
        }

        report = lint_config(config)

        self.assertEqual(report["risk_level"], "critical")
        self.assertTrue(report["signals"]["lethal_trifecta"])
        self.assertIn("shell_enabled", report["signals"]["enabled_capabilities"])
        self.assertIn("filesystem_broad_access", report["signals"]["enabled_capabilities"])
        self.assertTrue(any(f["id"] == "approval_gate_missing" for f in report["findings"]))
        self.assertGreaterEqual(report["summary"]["critical"], 1)

    def test_disabled_features_do_not_trigger_high_risk(self):
        config = {
            "inputs": {"web": False},
            "tools": {
                "shell": {"enabled": False},
                "filesystem": {"enabled": False, "roots": ["/"]},
                "email": {"enabled": False},
            },
            "memory": {"enabled": False},
            "approvals": {"send_email": True, "shell": True},
            "model": "gpt-5.2",
        }

        report = lint_config(config)

        self.assertIn(report["risk_level"], {"low", "medium"})
        self.assertFalse(report["signals"]["lethal_trifecta"])
        self.assertNotIn("shell_enabled", report["signals"]["enabled_capabilities"])

    def test_cli_emits_json_report(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "agent.json"
            config_path.write_text(json.dumps({"inputs": {"web": True}, "tools": {"email": {"enabled": True}}}))

            exit_code, output = run([str(config_path), "--format", "json"])

        self.assertEqual(exit_code, 0)
        parsed = json.loads(output)
        self.assertTrue(parsed["files"][0]["path"].endswith("agent.json"))
        self.assertIn("risk_level", parsed["files"][0])

    def test_cli_fails_on_invalid_json(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "bad.json"
            config_path.write_text("{not json")

            exit_code, output = run([str(config_path), "--format", "json"])

        self.assertEqual(exit_code, 2)
        parsed = json.loads(output)
        self.assertTrue(parsed["errors"])
        self.assertIn("invalid", parsed["errors"][0]["message"].lower())


if __name__ == "__main__":
    unittest.main()
