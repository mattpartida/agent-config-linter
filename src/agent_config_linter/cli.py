"""Command-line interface for agent-config-linter."""

import argparse
import fnmatch
import json
import re
import sys
import tomllib
from pathlib import Path

import yaml

from .linter import lint_config

SEVERITIES = ("critical", "high", "medium", "low")

SUPPORTED_SUFFIXES = {".json", ".toml", ".yaml", ".yml"}

SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def _load_config(path):
    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            return json.loads(path.read_text())
        if suffix == ".toml":
            return tomllib.loads(path.read_text())
        if suffix in {".yaml", ".yml"}:
            return yaml.safe_load(path.read_text()) or {}
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Invalid TOML: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML: {exc}") from exc
    raise ValueError(f"Unsupported config extension: {suffix or '(none)'}")


def _load_baseline(path):
    baseline = _load_config(path)
    if not isinstance(baseline, dict):
        raise ValueError("Baseline must be a mapping with a suppressions list")
    suppressions = baseline.get("suppressions", [])
    if not isinstance(suppressions, list):
        raise ValueError("Baseline suppressions must be a list")
    for suppression in suppressions:
        if not isinstance(suppression, dict):
            raise ValueError("Each baseline suppression must be a mapping")
    return suppressions


def _expand_path(path):
    if path.is_dir():
        config_paths = sorted(
            child for child in path.rglob("*") if child.is_file() and child.suffix.lower() in SUPPORTED_SUFFIXES
        )
        if not config_paths:
            raise ValueError(f"No supported config files found under directory: {path}")
        return config_paths
    return [path]


def _markdown_escape(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def _path_matches(pattern, path):
    normalized_pattern = str(pattern).replace("\\", "/")
    normalized_path = str(path).replace("\\", "/")
    path_name = Path(path).name
    return (
        normalized_pattern in {normalized_path, path_name}
        or fnmatch.fnmatch(normalized_path, normalized_pattern)
        or fnmatch.fnmatch(path_name, normalized_pattern)
    )


def _suppression_matches(suppression, path, finding):
    suppression_path = suppression.get("path", "*")
    if not _path_matches(suppression_path, path):
        return False

    rule_id = suppression.get("rule_id")
    finding_id = suppression.get("finding_id") or suppression.get("id")
    if rule_id and rule_id != finding.get("rule_id"):
        return False
    if finding_id and finding_id != finding.get("id"):
        return False
    return bool(rule_id or finding_id)


def _risk_from_summary(summary):
    score = summary["critical"] * 40 + summary["high"] * 15 + summary["medium"] * 5 + summary["low"]
    if summary["critical"] or score >= 60:
        return "critical", score
    if summary["high"] or score >= 25:
        return "high", score
    if summary["medium"]:
        return "medium", score
    return "low", score


def _apply_baseline(report, path, suppressions):
    remaining_findings = []
    suppressed_findings = []
    for finding in report.get("findings", []):
        matching_suppression = next(
            (suppression for suppression in suppressions if _suppression_matches(suppression, path, finding)), None
        )
        if matching_suppression:
            suppressed = dict(finding)
            suppressed["suppression"] = {
                key: matching_suppression[key]
                for key in ("path", "rule_id", "finding_id", "id", "reason")
                if key in matching_suppression
            }
            suppressed_findings.append(suppressed)
        else:
            remaining_findings.append(finding)

    report["findings"] = remaining_findings
    report["suppressed_findings"] = suppressed_findings
    report["summary"] = {
        severity: sum(1 for finding in remaining_findings if finding["severity"] == severity) for severity in SEVERITIES
    }
    report["suppressed_summary"] = {
        severity: sum(1 for finding in suppressed_findings if finding["severity"] == severity) for severity in SEVERITIES
    }
    report["risk_level"], report["score"] = _risk_from_summary(report["summary"])
    report["recommended_next_actions"] = [finding["remediation"] for finding in remaining_findings[:5]]
    return report


def _source_line_for_evidence(path, evidence_paths):
    """Best-effort line lookup for SARIF locations from dotted evidence paths."""
    if not evidence_paths:
        return 1
    try:
        lines = Path(path).read_text().splitlines()
    except OSError:
        return 1
    for evidence_path in evidence_paths:
        parts = [part.split("[")[0] for part in str(evidence_path).split(".") if part]
        for key in reversed(parts):
            key_pattern = re.compile(rf"^\s*(?:[\"']?{re.escape(key)}[\"']?\s*[:=]|\[{re.escape(key)}\])")
            for line_number, line in enumerate(lines, start=1):
                if key_pattern.search(line):
                    return line_number
    return 1


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
            evidence_paths = finding.get("evidence_paths", [])
            sarif_results.append(
                {
                    "ruleId": rule_id,
                    "level": SARIF_LEVELS.get(finding["severity"], "warning"),
                    "message": {"text": f"{finding['title']}: {finding['evidence']}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": report["path"]},
                                "region": {"startLine": _source_line_for_evidence(report["path"], evidence_paths)},
                            }
                        }
                    ],
                    "properties": {
                        "finding_id": finding["id"],
                        "remediation": finding["remediation"],
                        "evidence_paths": evidence_paths,
                    },
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
    parser.add_argument("paths", nargs="+", help="Config file or directory paths. Directories are scanned recursively for JSON, YAML, and TOML files.")
    parser.add_argument("--format", choices=["json", "markdown", "sarif"], default="json")
    parser.add_argument("--baseline", help="JSON, YAML, or TOML file containing accepted finding suppressions")
    args = parser.parse_args(argv)

    result = {"schema_version": "0.1", "files": [], "errors": []}
    exit_code = 0
    suppressions = []

    if args.baseline:
        baseline_path = Path(args.baseline)
        try:
            suppressions = _load_baseline(baseline_path)
        except OSError as exc:
            exit_code = 2
            result["errors"].append({"path": str(baseline_path), "message": str(exc)})
        except ValueError as exc:
            exit_code = 2
            result["errors"].append({"path": str(baseline_path), "message": str(exc)})

    for raw_path in args.paths:
        input_path = Path(raw_path)
        try:
            config_paths = _expand_path(input_path)
        except OSError as exc:
            exit_code = 2
            result["errors"].append({"path": str(input_path), "message": str(exc)})
            continue
        except ValueError as exc:
            exit_code = 2
            result["errors"].append({"path": str(input_path), "message": str(exc)})
            continue

        for path in config_paths:
            try:
                config = _load_config(path)
                report = lint_config(config)
                report["path"] = str(path)
                if args.baseline:
                    report = _apply_baseline(report, path, suppressions)
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
