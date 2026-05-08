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

    def test_detects_prompt_injection_to_exfiltration_bridge(self):
        config = {
            "inputs": {"browser": {"enabled": True}, "webhook": True},
            "tools": {
                "terminal": {"enabled": True},
                "filesystem": {"enabled": True, "mode": "rw", "paths": ["~/projects"]},
                "http": {"enabled": True, "methods": ["POST"]},
            },
            "secrets": {"env": True, "api_keys": True},
        }

        report = lint_config(config)

        self.assertEqual(report["risk_level"], "critical")
        self.assertIn("prompt_injection_exfiltration_bridge", {finding["id"] for finding in report["findings"]})
        self.assertIn("code_execution", report["signals"]["enabled_capabilities"])
        self.assertIn("secrets_access", report["signals"]["enabled_capabilities"])
        self.assertIn("network_egress", report["signals"]["enabled_capabilities"])

    def test_detects_unattended_dangerous_tool_use_without_approval_gate(self):
        config = {
            "autonomy": {"enabled": True, "mode": "unattended"},
            "schedule": {"enabled": True, "cron": "*/5 * * * *"},
            "tools": {
                "shell": True,
                "delete": True,
                "github": {"enabled": True, "write": True},
            },
        }

        report = lint_config(config)

        self.assertEqual(report["risk_level"], "critical")
        self.assertIn("unattended_dangerous_tools", {finding["id"] for finding in report["findings"]})
        self.assertIn("unattended_autonomy", report["signals"]["enabled_capabilities"])
        self.assertIn("destructive_actions", report["signals"]["enabled_capabilities"])

    def test_detects_privileged_infra_control_with_credentials_and_network(self):
        config = {
            "tools": {
                "kubernetes": {"enabled": True, "namespace": "*"},
                "docker": {"enabled": True, "socket": "/var/run/docker.sock"},
                "http": {"enabled": True},
            },
            "credentials": {"cloud": True, "kubeconfig": True},
        }

        report = lint_config(config)

        self.assertEqual(report["risk_level"], "critical")
        self.assertIn("privileged_infra_control", {finding["id"] for finding in report["findings"]})
        self.assertIn("privileged_infra", report["signals"]["enabled_capabilities"])
        self.assertIn("credentials_access", report["signals"]["enabled_capabilities"])

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

    def test_findings_include_stable_rule_ids(self):
        report = lint_config({"tools": {"shell": True}})

        shell_finding = next(finding for finding in report["findings"] if finding["id"] == "shell_enabled")

        self.assertEqual(shell_finding["rule_id"], "ACL-001")
        self.assertEqual(shell_finding["rule_name"], "shell-enabled")

    def test_cli_emits_markdown_report(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "agent.json"
            config_path.write_text(json.dumps({"tools": {"shell": True}}))

            exit_code, output = run([str(config_path), "--format", "markdown"])

        self.assertEqual(exit_code, 0)
        self.assertIn("# Agent Config Linter Report", output)
        self.assertIn("## agent.json", output)
        self.assertIn("| ACL-001 | high | shell_enabled | Shell execution is enabled |", output)

    def test_cli_emits_sarif_report(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "agent.json"
            config_path.write_text(json.dumps({"tools": {"shell": True}}))

            exit_code, output = run([str(config_path), "--format", "sarif"])

        self.assertEqual(exit_code, 0)
        parsed = json.loads(output)
        self.assertEqual(parsed["version"], "2.1.0")
        self.assertEqual(parsed["runs"][0]["tool"]["driver"]["name"], "agent-config-linter")
        self.assertIn("ACL-001", {rule["id"] for rule in parsed["runs"][0]["tool"]["driver"]["rules"]})
        self.assertEqual(parsed["runs"][0]["results"][0]["ruleId"], "ACL-001")

    def test_findings_include_deterministic_evidence_paths(self):
        report = lint_config({"tools": {"shell": {"enabled": True}}})

        shell_finding = next(finding for finding in report["findings"] if finding["id"] == "shell_enabled")

        self.assertEqual(shell_finding["evidence_paths"], ["tools.shell"])

    def test_filesystem_write_access_has_narrow_finding(self):
        report = lint_config({"tools": {"filesystem": {"enabled": True, "mode": "rw", "paths": ["~/project"]}}})

        write_finding = next(finding for finding in report["findings"] if finding["id"] == "filesystem_write_access")

        self.assertEqual(write_finding["rule_id"], "ACL-010")
        self.assertEqual(write_finding["evidence_paths"], ["tools.filesystem"])

    def test_sarif_points_to_source_line_for_evidence_path(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "agent.yaml"
            config_path.write_text("tools:\n  shell:\n    enabled: true\n")

            exit_code, output = run([str(config_path), "--format", "sarif"])

        self.assertEqual(exit_code, 0)
        parsed = json.loads(output)
        shell_result = next(result for result in parsed["runs"][0]["results"] if result["ruleId"] == "ACL-001")
        location = shell_result["locations"][0]["physicalLocation"]
        self.assertEqual(location["region"]["startLine"], 2)
        self.assertEqual(shell_result["properties"]["evidence_paths"], ["tools.shell"])

    def test_cli_lints_toml_config(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "agent.toml"
            config_path.write_text('[tools]\nshell = true\n')

            exit_code, output = run([str(config_path), "--format", "json"])

        self.assertEqual(exit_code, 0)
        parsed = json.loads(output)
        self.assertIn("ACL-001", {finding["rule_id"] for finding in parsed["files"][0]["findings"]})

    def test_cli_lints_yaml_config(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "agent.yaml"
            config_path.write_text('tools:\n  shell: true\n')

            exit_code, output = run([str(config_path), "--format", "json"])

        self.assertEqual(exit_code, 0)
        parsed = json.loads(output)
        self.assertIn("ACL-001", {finding["rule_id"] for finding in parsed["files"][0]["findings"]})

    def test_cli_rejects_unsupported_config_extension(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "agent.txt"
            config_path.write_text('{"tools": {"shell": true}}')

            exit_code, output = run([str(config_path), "--format", "json"])

        self.assertEqual(exit_code, 2)
        parsed = json.loads(output)
        self.assertIn("Unsupported config extension", parsed["errors"][0]["message"])

    def test_cli_recursively_lints_supported_files_in_directory(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "agent.json").write_text(json.dumps({"tools": {"shell": True}}))
            nested = root / "nested"
            nested.mkdir()
            (nested / "agent.yaml").write_text("tools:\n  browser:\n    enabled: true\n    private_network: true\n")
            (nested / "notes.txt").write_text("not a config")

            exit_code, output = run([str(root), "--format", "json"])

        self.assertEqual(exit_code, 0)
        parsed = json.loads(output)
        self.assertEqual([Path(report["path"]).name for report in parsed["files"]], ["agent.json", "agent.yaml"])
        finding_ids = {finding["id"] for report in parsed["files"] for finding in report["findings"]}
        self.assertIn("shell_enabled", finding_ids)
        self.assertIn("browser_private_network", finding_ids)

    def test_cli_reports_error_for_directory_without_supported_configs(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "README.md").write_text("no configs here")

            exit_code, output = run([str(root), "--format", "json"])

        self.assertEqual(exit_code, 2)
        parsed = json.loads(output)
        self.assertIn("No supported config files found", parsed["errors"][0]["message"])

    def test_cli_baseline_suppresses_matching_rule_for_path(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "agent.json"
            config_path.write_text(json.dumps({"tools": {"shell": True}}))
            baseline_path = root / "agent-config-linter-baseline.json"
            baseline_path.write_text(
                json.dumps(
                    {
                        "suppressions": [
                            {
                                "path": str(config_path),
                                "rule_id": "ACL-001",
                                "reason": "Known shell access in local development sandbox.",
                            }
                        ]
                    }
                )
            )

            exit_code, output = run([str(config_path), "--baseline", str(baseline_path), "--format", "json"])

        self.assertEqual(exit_code, 0)
        parsed = json.loads(output)
        report = parsed["files"][0]
        self.assertEqual(report["summary"]["high"], 0)
        self.assertNotIn("ACL-001", {finding["rule_id"] for finding in report["findings"]})
        self.assertEqual(report["suppressed_summary"], {"critical": 0, "high": 1, "medium": 0, "low": 0})
        self.assertEqual(report["suppressed_findings"][0]["rule_id"], "ACL-001")
        self.assertEqual(report["suppressed_findings"][0]["suppression"]["reason"], "Known shell access in local development sandbox.")

    def test_cli_baseline_does_not_suppress_different_path(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "agent.json"
            config_path.write_text(json.dumps({"tools": {"shell": True}}))
            baseline_path = root / "agent-config-linter-baseline.json"
            baseline_path.write_text(json.dumps({"suppressions": [{"path": "other.json", "rule_id": "ACL-001"}]}))

            exit_code, output = run([str(config_path), "--baseline", str(baseline_path), "--format", "json"])

        self.assertEqual(exit_code, 0)
        parsed = json.loads(output)
        report = parsed["files"][0]
        self.assertIn("ACL-001", {finding["rule_id"] for finding in report["findings"]})
        self.assertEqual(report["suppressed_findings"], [])


if __name__ == "__main__":
    unittest.main()
