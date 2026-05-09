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

    def test_composite_findings_include_evidence_paths(self):
        config = {
            "inputs": {"browser": {"enabled": True}},
            "tools": {
                "terminal": {"enabled": True},
                "filesystem": {"enabled": True, "paths": ["/var/agent"]},
                "http": {"enabled": True},
                "kubernetes": {"enabled": True},
            },
            "secrets": {"env": True},
            "credentials": {"kubeconfig": True},
            "autonomy": {"enabled": True, "mode": "unattended"},
        }

        report = lint_config(config)
        findings = {finding["id"]: finding for finding in report["findings"]}

        for finding_id in {
            "lethal_trifecta",
            "prompt_injection_exfiltration_bridge",
            "unattended_dangerous_tools",
            "privileged_infra_control",
        }:
            with self.subTest(finding_id=finding_id):
                self.assertTrue(findings[finding_id]["evidence_paths"])

    def test_sarif_points_composite_yaml_to_nested_tool_line(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "agent.yaml"
            config_path.write_text(
                "tools:\n"
                "  terminal:\n"
                "    enabled: true\n"
                "  http:\n"
                "    enabled: true\n"
                "inputs:\n"
                "  browser:\n"
                "    enabled: true\n"
                "secrets:\n"
                "  env: true\n"
            )

            exit_code, output = run([str(config_path), "--format", "sarif"])

        self.assertEqual(exit_code, 0)
        parsed = json.loads(output)
        bridge_result = next(result for result in parsed["runs"][0]["results"] if result["ruleId"] == "ACL-005")
        self.assertEqual(bridge_result["locations"][0]["physicalLocation"]["region"]["startLine"], 2)
        self.assertTrue(bridge_result["properties"]["evidence_paths"])

    def test_sarif_points_toml_table_to_nested_tool_line(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "agent.toml"
            config_path.write_text('[tools.shell]\nenabled = true\n')

            exit_code, output = run([str(config_path), "--format", "sarif"])

        self.assertEqual(exit_code, 0)
        parsed = json.loads(output)
        shell_result = next(result for result in parsed["runs"][0]["results"] if result["ruleId"] == "ACL-001")
        self.assertEqual(shell_result["locations"][0]["physicalLocation"]["region"]["startLine"], 1)

    def test_sarif_points_json_toolset_array_to_item_line(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "agent.json"
            config_path.write_text('{\n  "enabled_toolsets": [\n    "terminal"\n  ]\n}\n')

            exit_code, output = run([str(config_path), "--format", "sarif"])

        self.assertEqual(exit_code, 0)
        parsed = json.loads(output)
        shell_result = next(result for result in parsed["runs"][0]["results"] if result["ruleId"] == "ACL-001")
        self.assertEqual(shell_result["locations"][0]["physicalLocation"]["region"]["startLine"], 3)
        self.assertEqual(shell_result["properties"]["evidence_paths"], ["enabled_toolsets[0]"])

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

    def test_cli_policy_overrides_severity_and_disables_rules(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "agent.json"
            config_path.write_text(json.dumps({"tools": {"shell": True}, "model": "small-local-7b"}))
            policy_path = root / "policy.json"
            policy_path.write_text(
                json.dumps(
                    {
                        "severity_overrides": {"ACL-001": "medium"},
                        "disabled_rules": ["weak_model_risk"],
                    }
                )
            )

            exit_code, output = run([str(config_path), "--policy", str(policy_path), "--format", "json"])

        self.assertEqual(exit_code, 0)
        report = json.loads(output)["files"][0]
        findings = {finding["id"]: finding for finding in report["findings"]}
        self.assertEqual(findings["shell_enabled"]["severity"], "medium")
        self.assertNotIn("weak_model_risk", findings)
        self.assertEqual(report["summary"]["medium"], 1)
        self.assertEqual(report["summary"]["high"], 0)

    def test_cli_policy_tool_allowlist_suppresses_matching_finding(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "agent.json"
            config_path.write_text(json.dumps({"tools": {"shell": True, "browser": {"enabled": True, "private_network": True}}}))
            policy_path = root / "policy.json"
            policy_path.write_text(json.dumps({"allowlists": {"tools": ["shell"]}}))

            exit_code, output = run([str(config_path), "--policy", str(policy_path), "--format", "json"])

        self.assertEqual(exit_code, 0)
        report = json.loads(output)["files"][0]
        self.assertNotIn("shell_enabled", {finding["id"] for finding in report["findings"]})
        self.assertIn("browser_private_network", {finding["id"] for finding in report["findings"]})
        self.assertEqual(report["policy_suppressed_findings"][0]["policy"]["allowlist"], "tools.shell")

    def test_cli_generate_baseline_writes_current_findings(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "agent.json"
            baseline_path = root / "baseline.json"
            config_path.write_text(json.dumps({"tools": {"shell": True}}))

            exit_code, output = run([str(config_path), "--generate-baseline", str(baseline_path), "--format", "json"])

            self.assertEqual(exit_code, 0)
            generated = json.loads(baseline_path.read_text())

        self.assertEqual(generated["schema_version"], "0.1")
        self.assertEqual(generated["suppressions"][0]["rule_id"], "ACL-001")
        self.assertEqual(generated["suppressions"][0]["owner"], "TODO")
        self.assertEqual(generated["suppressions"][0]["ticket"], "TODO")
        parsed = json.loads(output)
        self.assertEqual(parsed["baseline"]["generated"], str(baseline_path))

    def test_cli_baseline_reports_stale_suppressions_and_can_fail(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "agent.json"
            config_path.write_text(json.dumps({"tools": {"shell": True}}))
            baseline_path = root / "baseline.json"
            baseline_path.write_text(
                json.dumps(
                    {
                        "suppressions": [
                            {"path": str(config_path), "rule_id": "ACL-001", "owner": "sec", "ticket": "SEC-1"},
                            {"path": str(config_path), "rule_id": "ACL-999", "owner": "sec", "ticket": "SEC-2"},
                        ]
                    }
                )
            )

            exit_code, output = run([str(config_path), "--baseline", str(baseline_path), "--fail-on-stale-baseline", "--format", "json"])

        self.assertEqual(exit_code, 1)
        parsed = json.loads(output)
        self.assertEqual(parsed["baseline"]["stale_count"], 1)
        self.assertEqual(parsed["baseline"]["stale_suppressions"][0]["rule_id"], "ACL-999")

    def test_cli_rejects_invalid_policy_and_baseline_metadata(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "agent.json"
            config_path.write_text(json.dumps({"tools": {"shell": True}}))
            policy_path = root / "policy.json"
            policy_path.write_text(json.dumps({"severity_overrides": {"ACL-001": "urgent"}}))
            baseline_path = root / "baseline.json"
            baseline_path.write_text(json.dumps({"suppressions": [{"path": "*", "rule_id": "ACL-001", "expires_at": "tomorrow"}]}))

            policy_exit_code, policy_output = run([str(config_path), "--policy", str(policy_path), "--format", "json"])
            baseline_exit_code, baseline_output = run([str(config_path), "--baseline", str(baseline_path), "--format", "json"])

        self.assertEqual(policy_exit_code, 2)
        self.assertIn("Invalid severity", json.loads(policy_output)["errors"][0]["message"])
        self.assertEqual(baseline_exit_code, 2)
        self.assertIn("expires_at", json.loads(baseline_output)["errors"][0]["message"])

    def test_cli_min_severity_filters_active_findings_and_recomputes_summary(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "agent.json"
            config_path.write_text(json.dumps({"tools": {"shell": True}, "model": "small-local-7b"}))

            exit_code, output = run([str(config_path), "--min-severity", "high", "--format", "json"])

        self.assertEqual(exit_code, 0)
        report = json.loads(output)["files"][0]
        self.assertEqual({finding["id"] for finding in report["findings"]}, {"shell_enabled"})
        self.assertEqual(report["summary"], {"critical": 0, "high": 1, "medium": 0, "low": 0})
        self.assertEqual(report["filtered_summary"]["medium"], 1)

    def test_cli_fail_on_returns_nonzero_for_configured_threshold(self):
        from agent_config_linter.cli import run

        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "agent.json"
            config_path.write_text(json.dumps({"tools": {"shell": True}}))

            failing_exit_code, failing_output = run([str(config_path), "--fail-on", "high", "--format", "json"])
            passing_exit_code, passing_output = run([str(config_path), "--fail-on", "critical", "--format", "json"])

        self.assertEqual(failing_exit_code, 1)
        self.assertEqual(json.loads(failing_output)["exit_policy"], {"fail_on": "high", "failed": True})
        self.assertEqual(passing_exit_code, 0)
        self.assertEqual(json.loads(passing_output)["exit_policy"], {"fail_on": "critical", "failed": False})

    def test_cli_emits_version_without_path(self):
        from agent_config_linter import __version__
        from agent_config_linter.cli import run

        exit_code, output = run(["--version"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(output.strip(), f"agent-config-linter {__version__}")


if __name__ == "__main__":
    unittest.main()
