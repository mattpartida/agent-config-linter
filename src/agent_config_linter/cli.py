"""Command-line interface for agent-config-linter."""

import argparse
import json
import sys
from pathlib import Path

from .linter import lint_config

SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def _load_json(path):
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc


def _markdown_escape(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def _format_markdown(result):
    lines = ["# Agent Config Linter Report", ""]
    if result["errors"]:
        lines.extend(["## Errors", ""])
        for error in result["errors"]:
            lines.append(f"- `{error['path']}`: {error['message']}")
        lines.append("")

    for report in result["files"]:
        path = Path(report["path"])
        lines.extend(
            [
                f"## {path.name}",
                "",
                f"- Risk level: **{report['risk_level']}**",
                f"- Score: **{report['score']}**",
                f"- Lethal trifecta: **{str(report['signals']['lethal_trifecta']).lower()}**",
                "",
            ]
        )
        findings = report.get("findings", [])
        if findings:
            lines.extend(
                [
                    "| Rule | Severity | Finding | Title |",
                    "| --- | --- | --- | --- |",
                ]
            )
            for finding in findings:
                lines.append(
                    "| {rule_id} | {severity} | {finding_id} | {title} |".format(
                        rule_id=_markdown_escape(finding.get("rule_id", finding["id"])),
                        severity=_markdown_escape(finding["severity"]),
                        finding_id=_markdown_escape(finding["id"]),
                        title=_markdown_escape(finding["title"]),
                    )
                )
            lines.append("")
        else:
            lines.extend(["No findings.", ""])
    return "\n".join(lines).rstrip() + "\n"


def _format_sarif(result):
    rules = {}
    sarif_results = []
    for report in result["files"]:
        for finding in report.get("findings", []):
            rule_id = finding.get("rule_id", finding["id"])
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": finding.get("rule_name", finding["id"].replace("_", "-")),
                    "shortDescription": {"text": finding["title"]},
                    "fullDescription": {"text": finding["evidence"]},
                    "help": {"text": finding["remediation"]},
                    "properties": {"severity": finding["severity"], "finding_id": finding["id"]},
                },
            )
            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "level": SARIF_LEVELS.get(finding["severity"], "warning"),
                    "message": {"text": f"{finding['title']}: {finding['evidence']}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": report["path"]},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                    "properties": {"finding_id": finding["id"], "remediation": finding["remediation"]},
                }
            )

    return json.dumps(
        {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "agent-config-linter",
                            "informationUri": "https://github.com/mattpartida/agent-config-linter",
                            "rules": sorted(rules.values(), key=lambda rule: rule["id"]),
                        }
                    },
                    "results": sarif_results,
                }
            ],
        },
        indent=2,
        sort_keys=True,
    ) + "\n"


def _format_result(result, output_format):
    if output_format == "json":
        return json.dumps(result, indent=2, sort_keys=True) + "\n"
    if output_format == "markdown":
        return _format_markdown(result)
    if output_format == "sarif":
        return _format_sarif(result)
    raise ValueError(f"Unsupported format: {output_format}")


def run(argv=None):
    parser = argparse.ArgumentParser(description="Lint autonomous-agent config files for risky capability combinations")
    parser.add_argument("paths", nargs="+", help="JSON config file paths")
    parser.add_argument("--format", choices=["json", "markdown", "sarif"], default="json")
    args = parser.parse_args(argv)

    result = {"schema_version": "0.1", "files": [], "errors": []}
    exit_code = 0

    for raw_path in args.paths:
        path = Path(raw_path)
        try:
            config = _load_json(path)
            report = lint_config(config)
            report["path"] = str(path)
            result["files"].append(report)
        except OSError as exc:
            exit_code = 2
            result["errors"].append({"path": str(path), "message": str(exc)})
        except ValueError as exc:
            exit_code = 2
            result["errors"].append({"path": str(path), "message": str(exc)})

    return exit_code, _format_result(result, args.format)


def main(argv=None):
    exit_code, output = run(argv)
    stream = sys.stderr if exit_code else sys.stdout
    stream.write(output)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
