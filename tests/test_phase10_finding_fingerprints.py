"""Phase 10, item 30: deterministic cross-run finding fingerprints."""

import json
import re
import unittest
from pathlib import Path

from agent_config_linter import cli

ROOT = Path(__file__).resolve().parents[1]
FINGERPRINT_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


class FindingFingerprintTests(unittest.TestCase):
    def test_identity_is_stable_across_path_separators_and_evidence_order(self):
        windows_style = cli._finding_fingerprint(
            "ACL-001",
            r".\configs\agent.yaml",
            ["tools.shell", "approvals.required", "tools.shell"],
        )
        posix_style = cli._finding_fingerprint(
            "ACL-001",
            "configs/agent.yaml",
            ["approvals.required", "tools.shell"],
        )

        self.assertEqual(windows_style, posix_style)
        self.assertEqual(
            cli._finding_fingerprint("ACL-001", r"C:\Repo\configs\agent.yaml", ["tools.shell"]),
            cli._finding_fingerprint("ACL-001", "c:/Repo/configs/agent.yaml", ["tools.shell"]),
        )
        self.assertEqual(
            cli._finding_fingerprint("ACL-001", r"C:Repo\configs\agent.yaml", ["tools.shell"]),
            cli._finding_fingerprint("ACL-001", "c:Repo/configs/agent.yaml", ["tools.shell"]),
        )
        drive_parent = cli._finding_fingerprint("ACL-001", r"C:foo\..\bar", ["tools.shell"])
        self.assertEqual(
            drive_parent,
            cli._finding_fingerprint("ACL-001", "c:foo/../bar", ["tools.shell"]),
        )
        self.assertNotEqual(
            drive_parent,
            cli._finding_fingerprint("ACL-001", "bar", ["tools.shell"]),
        )
        drive_current = cli._finding_fingerprint("ACL-001", r"C:foo\..", ["tools.shell"])
        self.assertEqual(
            drive_current,
            cli._finding_fingerprint("ACL-001", "c:foo/..", ["tools.shell"]),
        )
        self.assertNotEqual(
            drive_current,
            cli._finding_fingerprint("ACL-001", ".", ["tools.shell"]),
        )
        self.assertEqual(
            cli._finding_fingerprint("ACL-001", r"\\?\C:\foo\..\bar", ["tools.shell"]),
            cli._finding_fingerprint("ACL-001", "//?/c:/bar", ["tools.shell"]),
        )
        unc_parent = cli._finding_fingerprint("ACL-001", r"\\server\share\..\bar", ["tools.shell"])
        self.assertEqual(
            unc_parent,
            cli._finding_fingerprint("ACL-001", "//server/share/bar", ["tools.shell"]),
        )
        self.assertNotEqual(
            unc_parent,
            cli._finding_fingerprint("ACL-001", "//server/bar", ["tools.shell"]),
        )
        posix_parent = cli._finding_fingerprint("ACL-001", "///a/../b", ["tools.shell"])
        self.assertEqual(
            posix_parent,
            cli._finding_fingerprint("ACL-001", "/b", ["tools.shell"]),
        )
        self.assertNotEqual(
            posix_parent,
            cli._finding_fingerprint("ACL-001", "///a/b", ["tools.shell"]),
        )
        double_slash_parent = cli._finding_fingerprint("ACL-001", "//a/../b", ["tools.shell"])
        self.assertEqual(
            double_slash_parent,
            cli._finding_fingerprint("ACL-001", "//b", ["tools.shell"]),
        )
        self.assertNotEqual(
            double_slash_parent,
            cli._finding_fingerprint("ACL-001", "//a/b", ["tools.shell"]),
        )
        self.assertEqual(
            posix_style,
            "sha256:d9f7271f7009d1b818d1c157bd0858dd206406e028113a0576e5511b0bc058e4",
        )

    def test_identity_changes_at_each_documented_boundary(self):
        base = cli._finding_fingerprint("ACL-001", "configs/agent.yaml", ["tools.shell"])

        self.assertNotEqual(base, cli._finding_fingerprint("ACL-002", "configs/agent.yaml", ["tools.shell"]))
        self.assertNotEqual(base, cli._finding_fingerprint("ACL-001", "configs/other.yaml", ["tools.shell"]))
        self.assertNotEqual(base, cli._finding_fingerprint("ACL-001", "configs/agent.yaml", ["tools.browser"]))

    def test_json_and_sarif_reports_expose_the_same_fingerprints(self):
        config = ROOT / "tests" / "fixtures" / "report-contracts" / "risky.yaml"
        relative_config = config.relative_to(ROOT)

        json_exit, json_output = cli.run([str(relative_config), "--format", "json"])
        repeat_exit, repeat_output = cli.run([str(relative_config), "--format", "json"])
        sarif_exit, sarif_output = cli.run([str(relative_config), "--format", "sarif"])

        self.assertEqual((json_exit, repeat_exit, sarif_exit), (0, 0, 0))
        findings = json.loads(json_output)["files"][0]["findings"]
        repeated_findings = json.loads(repeat_output)["files"][0]["findings"]
        fingerprints = [finding["fingerprint"] for finding in findings]
        self.assertEqual(fingerprints, [finding["fingerprint"] for finding in repeated_findings])
        self.assertTrue(all(FINGERPRINT_PATTERN.fullmatch(value) for value in fingerprints))

        sarif_results = json.loads(sarif_output)["runs"][0]["results"]
        self.assertEqual(fingerprints, [result["properties"]["fingerprint"] for result in sarif_results])
        self.assertEqual(
            fingerprints,
            [result["partialFingerprints"]["agentConfigLinter/v1"] for result in sarif_results],
        )

    def test_suppressed_findings_retain_their_active_fingerprint(self):
        config = "tests/fixtures/report-contracts/risky.yaml"
        _, active_output = cli.run([config, "--format", "json"])
        active = {finding["rule_id"]: finding["fingerprint"] for finding in json.loads(active_output)["files"][0]["findings"]}

        for flag, support_file, section in (
            ("--policy", "tests/fixtures/report-contracts/disable-shell-policy.json", "policy_suppressed_findings"),
            ("--baseline", "tests/fixtures/report-contracts/suppressions.json", "suppressed_findings"),
        ):
            with self.subTest(flag=flag):
                exit_code, output = cli.run([config, flag, support_file, "--format", "json"])
                self.assertEqual(exit_code, 0, output)
                suppressed = json.loads(output)["files"][0][section]
                shell_finding = next(finding for finding in suppressed if finding["rule_id"] == "ACL-001")
                self.assertEqual(shell_finding["fingerprint"], active["ACL-001"])

    def test_schema_rejects_malformed_fingerprints_but_accepts_older_reports_without_them(self):
        report = json.loads((ROOT / "docs" / "report-contracts" / "risky.json").read_text())
        for finding in report["files"][0]["findings"]:
            finding.pop("fingerprint")
        self.assertTrue(cli._validate_stored_report(report)["valid"])

        for malformed in ("not-a-fingerprint", "sha256:" + "a" * 64 + "\n"):
            with self.subTest(malformed=repr(malformed)):
                report["files"][0]["findings"][0]["fingerprint"] = malformed
                validation = cli._validate_stored_report(report)
                self.assertFalse(validation["valid"])
                self.assertEqual(validation["errors"][0]["path"], "$.files[0].findings[0].fingerprint")

    def test_schema_documents_fingerprint_as_additive_typed_field(self):
        exit_code, output = cli.run(["--report-schema", "--format", "json"])

        self.assertEqual(exit_code, 0, output)
        finding_schema = json.loads(output)["$defs"]["finding"]
        self.assertEqual(
            finding_schema["properties"]["fingerprint"],
            {
                "type": "string",
                "pattern": "^sha256:[0-9a-f]{64}$",
                "minLength": 71,
                "maxLength": 71,
            },
        )
        self.assertNotIn("fingerprint", finding_schema["required"])

    def test_docs_define_identity_boundary_and_mark_phase_complete(self):
        roadmap = (ROOT / "docs" / "roadmap.md").read_text()
        stability = (ROOT / "docs" / "report-stability.md").read_text()
        readme = (ROOT / "README.md").read_text()
        changelog = (ROOT / "CHANGELOG.md").read_text()

        item_30 = roadmap[roadmap.index("### 30.") : roadmap.index("## Ongoing quality bar")]
        self.assertIn("**Status: Shipped.**", item_30)
        self.assertIn("Phase 10 status: Shipped", roadmap)
        self.assertIn("rule ID, normalized report path, and sorted unique evidence paths", stability)
        self.assertIn("finding fingerprint", readme.lower())
        self.assertIn("finding fingerprints", changelog.lower())


if __name__ == "__main__":
    unittest.main()
